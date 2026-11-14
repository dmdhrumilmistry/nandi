//! Export of events and administrative actions to SIEMs, webhooks and files.
//!
//! Every recorded event (and every admin action, which is an event too) is
//! offered to each configured export. An export filters it (minimum verdict,
//! event kinds, admin actions), queues it, and a background task per export
//! batches, formats and delivers it, retrying transient failures. A full
//! queue drops events and counts them; agents are never slowed down.
//!
//! Destinations: generic webhooks (JSON, HMAC-signed, one request per event
//! or batched), Splunk HTTP Event Collector, Elasticsearch / OpenSearch
//! `_bulk`, RFC 5424 syslog over UDP, TCP or TLS, and JSON lines files.
//! Formats: nandi's own JSON, OCSF 1.3, Elastic Common Schema and CEF.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use nandi_core::config::{ExportConfig, ExportFormat, ExportKind, resolve_secret};
use nandi_core::util::{new_id, now_ms};
use nandi_core::{EventKind, Severity, Verdict};

use crate::client::{HttpClient, full};
use crate::recorder::LiveEvent;

/// Events waiting per export before new ones are dropped.
const QUEUE: usize = 4096;
/// Delivery attempts per batch.
const ATTEMPTS: u32 = 3;
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Delivery counters of one export.
#[derive(Default)]
pub struct Stats {
    pub sent: AtomicU64,
    pub failed: AtomicU64,
    pub dropped: AtomicU64,
    pub last_ok_ms: AtomicU64,
    pub last_error: Mutex<Option<String>>,
}

/// Status of an export, for `GET /v1/exports`.
#[derive(Debug, Serialize)]
pub struct Status {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ExportKind,
    pub format: ExportFormat,
    /// Where it goes, without credentials.
    pub target: String,
    pub sent: u64,
    pub failed: u64,
    pub dropped: u64,
    pub last_ok_ms: u64,
    pub last_error: Option<String>,
}

struct Sink {
    cfg: ExportConfig,
    tx: mpsc::Sender<Arc<LiveEvent>>,
    stats: Arc<Stats>,
}

/// All configured exports.
pub struct Exports {
    sinks: Vec<Sink>,
    client: HttpClient,
}

impl Exports {
    /// Start one delivery task per export. Must run inside a Tokio runtime
    /// when there are exports.
    pub fn start(cfgs: &[ExportConfig], client: HttpClient) -> anyhow::Result<Arc<Self>> {
        let mut sinks = Vec::new();
        for cfg in cfgs {
            cfg.check().map_err(anyhow::Error::msg)?;
            if sinks.iter().any(|s: &Sink| s.cfg.name == cfg.name) {
                anyhow::bail!("two exports are named {}", cfg.name);
            }
            let (tx, rx) = mpsc::channel(QUEUE);
            let stats = Arc::new(Stats::default());
            let worker = Worker { cfg: cfg.clone(), client: client.clone(), stats: stats.clone(), conn: None };
            tokio::spawn(worker.run(rx));
            sinks.push(Sink { cfg: cfg.clone(), tx, stats });
        }
        Ok(Arc::new(Self { sinks, client }))
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// Offer a recorded event to every export. Never blocks.
    pub fn send(&self, ev: &Arc<LiveEvent>) {
        for s in &self.sinks {
            if !wanted(&s.cfg, ev) {
                continue;
            }
            if s.tx.try_send(ev.clone()).is_err() {
                s.stats.dropped.fetch_add(1, Relaxed);
            }
        }
    }

    pub fn status(&self) -> Vec<Status> {
        self.sinks
            .iter()
            .map(|s| Status {
                name: s.cfg.name.clone(),
                kind: s.cfg.kind,
                format: s.cfg.format(),
                target: target_of(&s.cfg),
                sent: s.stats.sent.load(Relaxed),
                failed: s.stats.failed.load(Relaxed),
                dropped: s.stats.dropped.load(Relaxed),
                last_ok_ms: s.stats.last_ok_ms.load(Relaxed),
                last_error: s.stats.last_error.lock().clone(),
            })
            .collect()
    }

    /// Deliver one test event to `name` now, bypassing the filters.
    pub async fn test(&self, name: &str, by: &str) -> anyhow::Result<()> {
        let s = self.sinks.iter().find(|s| s.cfg.name == name).ok_or_else(|| anyhow::anyhow!("no export {name}"))?;
        let ev = nandi_core::Event::new(
            nandi_core::Source::Admin,
            by,
            "admin",
            EventKind::Admin(nandi_core::AdminAction {
                actor: by.into(),
                action: "export.test".into(),
                target: name.into(),
                outcome: "ok".into(),
                details: json!({ "note": "test event from nandi" }),
            }),
        );
        let live = Arc::new(LiveEvent {
            seq: None,
            event: ev,
            decision: nandi_core::Decision::allow(),
            applied: Verdict::Allow,
        });
        let mut w = Worker { cfg: s.cfg.clone(), client: self.client.clone(), stats: s.stats.clone(), conn: None };
        w.deliver(&[live]).await
    }

    /// Delivery counters per export.
    pub fn series(&self) -> Vec<crate::metrics::Series> {
        use crate::metrics::{Series, SeriesKind};
        type Counter = (&'static str, &'static str, &'static str, fn(&Stats) -> u64);
        let counters: [Counter; 3] = [
            ("nandi_export_sent_total", "nandi.export.sent", "Events delivered, per export.", |s| s.sent.load(Relaxed)),
            (
                "nandi_export_failed_total",
                "nandi.export.failed",
                "Events that could not be delivered after retries.",
                |s| s.failed.load(Relaxed),
            ),
            (
                "nandi_export_dropped_total",
                "nandi.export.dropped",
                "Events dropped because the export queue was full.",
                |s| s.dropped.load(Relaxed),
            ),
        ];
        counters
            .into_iter()
            .map(|(name, otel, help, f)| Series {
                name,
                otel,
                help,
                unit: "{event}",
                kind: SeriesKind::Counter,
                points: self.sinks.iter().map(|s| (vec![("export", s.cfg.name.clone())], f(&s.stats) as f64)).collect(),
            })
            .collect()
    }

    /// Prometheus counters per export.
    pub fn metrics(&self) -> String {
        crate::metrics::render(&self.series())
    }
}

fn wanted(cfg: &ExportConfig, ev: &LiveEvent) -> bool {
    if matches!(ev.event.kind, EventKind::Admin(_)) {
        return cfg.admin;
    }
    if !cfg.kinds.is_empty() && !cfg.kinds.iter().any(|k| k == ev.event.kind_name()) {
        return false;
    }
    ev.decision.verdict.max(ev.applied) >= cfg.min_verdict
}

fn target_of(cfg: &ExportConfig) -> String {
    let strip = |u: &str| {
        // drop user:password@ from URLs
        match (u.find("://"), u.find('@')) {
            (Some(s), Some(a)) if a > s => format!("{}{}", &u[..s + 3], &u[a + 1..]),
            _ => u.to_string(),
        }
    };
    match cfg.kind {
        ExportKind::Syslog => cfg.address.clone().unwrap_or_default(),
        ExportKind::File => cfg.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
        _ => cfg.url.as_deref().map(strip).unwrap_or_default(),
    }
}

// ----- delivery ------------------------------------------------------------------

/// A syslog TCP or TLS connection.
trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Stream for T {}
type Conn = Box<dyn Stream>;

/// Whether the peer closed the connection. TCP accepts writes into a
/// connection the other side has already closed, losing them, so this is
/// checked before every write: a pending read means it is still open.
async fn closed(conn: &mut Conn) -> bool {
    let mut b = [0u8; 64];
    match tokio::time::timeout(Duration::from_millis(1), conn.read(&mut b)).await {
        Err(_) => false,                // nothing to read: open
        Ok(Ok(0)) | Ok(Err(_)) => true, // end of stream or error
        Ok(Ok(_)) => false,             // the server said something; ignore it
    }
}

struct Worker {
    cfg: ExportConfig,
    client: HttpClient,
    stats: Arc<Stats>,
    /// Open syslog TCP / TLS connection.
    conn: Option<Conn>,
}

impl Worker {
    async fn run(mut self, mut rx: mpsc::Receiver<Arc<LiveEvent>>) {
        let mut batch = Vec::with_capacity(self.cfg.max_batch);
        loop {
            if rx.recv_many(&mut batch, self.cfg.max_batch).await == 0 {
                break;
            }
            // Gather a batch for at most flush_ms.
            let deadline = tokio::time::Instant::now() + Duration::from_millis(self.cfg.flush_ms);
            while batch.len() < self.cfg.max_batch {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(ev)) => batch.push(ev),
                    _ => break,
                }
            }
            let n = batch.len() as u64;
            let mut attempt = 0;
            loop {
                attempt += 1;
                match self.deliver(&batch).await {
                    Ok(()) => {
                        self.stats.sent.fetch_add(n, Relaxed);
                        self.stats.last_ok_ms.store(now_ms(), Relaxed);
                        *self.stats.last_error.lock() = None;
                        break;
                    }
                    Err(e) => {
                        let permanent = e.downcast_ref::<Permanent>().is_some();
                        *self.stats.last_error.lock() = Some(format!("{e:#}"));
                        if permanent || attempt >= ATTEMPTS {
                            self.stats.failed.fetch_add(n, Relaxed);
                            tracing::warn!(export = %self.cfg.name, events = n, error = %e, "export failed");
                            break;
                        }
                        tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
                    }
                }
            }
            batch.clear();
        }
    }

    async fn deliver(&mut self, batch: &[Arc<LiveEvent>]) -> anyhow::Result<()> {
        let fmt = self.cfg.format();
        match self.cfg.kind {
            ExportKind::Webhook => {
                let docs: Vec<Value> = batch.iter().map(|e| doc(fmt, e)).collect();
                if self.cfg.batch {
                    let body = serde_json::to_vec(&docs)?;
                    self.webhook(body, "batch").await
                } else {
                    for (d, e) in docs.iter().zip(batch) {
                        self.webhook(serde_json::to_vec(d)?, event_type(e)).await?;
                    }
                    Ok(())
                }
            }
            ExportKind::SplunkHec => {
                let host = nandi_discover::hostname();
                let mut body = Vec::new();
                for e in batch {
                    let mut ev = json!({
                        "time": e.event.ts_ms as f64 / 1000.0,
                        "host": host,
                        "source": "nandi",
                        "sourcetype": format!("nandi:{}", fmt_name(fmt)),
                        "event": doc(fmt, e),
                    });
                    if let Some(i) = &self.cfg.index {
                        ev["index"] = json!(i);
                    }
                    serde_json::to_writer(&mut body, &ev)?;
                    body.push(b'\n');
                }
                let token = secret(&self.cfg.token)?.unwrap_or_default();
                let url = format!("{}/services/collector/event", self.url()?);
                self.post(&url, "application/json", body, &[("Authorization".into(), format!("Splunk {token}"))])
                    .await?;
                Ok(())
            }
            ExportKind::Elastic => {
                let index = self.cfg.index.clone().unwrap_or_else(|| "nandi-events".into());
                let mut body = Vec::new();
                for e in batch {
                    serde_json::to_writer(&mut body, &json!({ "create": { "_index": index } }))?;
                    body.push(b'\n');
                    serde_json::to_writer(&mut body, &doc(fmt, e))?;
                    body.push(b'\n');
                }
                let mut auth = Vec::new();
                if let Some(k) = secret(&self.cfg.api_key)? {
                    auth.push(("Authorization".into(), format!("ApiKey {k}")));
                }
                let url = format!("{}/_bulk", self.url()?);
                let resp = self.post(&url, "application/x-ndjson", body, &auth).await?;
                let v: Value = serde_json::from_slice(&resp).unwrap_or(Value::Null);
                if v["errors"] == json!(true) {
                    let first = v["items"]
                        .as_array()
                        .and_then(|a| a.iter().find_map(|i| i["create"]["error"]["reason"].as_str()))
                        .unwrap_or("unknown");
                    return Err(Permanent(format!("Elasticsearch rejected documents: {first}")).into());
                }
                Ok(())
            }
            ExportKind::Syslog => {
                let mut out = Vec::new();
                for e in batch {
                    out.push(syslog_line(&self.cfg, fmt, e));
                }
                self.syslog(&out).await
            }
            ExportKind::File => {
                let path = self.cfg.path.clone().unwrap_or_default();
                let max = self.cfg.max_file_mb.max(1) * 1024 * 1024;
                let lines: Vec<String> = batch.iter().map(|e| line(fmt, e)).collect();
                tokio::task::spawn_blocking(move || write_file(&path, &lines, max)).await??;
                Ok(())
            }
        }
    }

    fn url(&self) -> anyhow::Result<String> {
        Ok(self.cfg.url.as_deref().ok_or_else(|| anyhow::anyhow!("no url"))?.trim_end_matches('/').to_string())
    }

    async fn webhook(&self, body: Vec<u8>, event: &str) -> anyhow::Result<()> {
        let mut headers = vec![("X-Nandi-Event".to_string(), event.to_string()), ("X-Nandi-Delivery".into(), new_id())];
        if let Some(secret) = secret(&self.cfg.secret)? {
            let t = now_ms() / 1000;
            let mut signed = format!("{t}.").into_bytes();
            signed.extend_from_slice(&body);
            headers.push((
                "X-Nandi-Signature".into(),
                format!("t={t},v1={}", hex::encode(hmac_sha256(secret.as_bytes(), &signed))),
            ));
        }
        self.post(&self.url()?, "application/json", body, &headers).await?;
        Ok(())
    }

    /// POST with the export's own headers. 4xx other than 408 and 429 are
    /// permanent failures, not retried.
    async fn post(&self, url: &str, ctype: &str, body: Vec<u8>, extra: &[(String, String)]) -> anyhow::Result<Bytes> {
        let mut req = http::Request::post(url)
            .header(http::header::CONTENT_TYPE, ctype)
            .header(http::header::USER_AGENT, format!("nandi/{VERSION}"));
        for (k, v) in extra {
            req = req.header(k.as_str(), v.as_str());
        }
        for (k, v) in &self.cfg.headers {
            req = req.header(k.as_str(), resolve_secret(v).map_err(|e| anyhow::anyhow!("header {k}: {e}"))?);
        }
        let req = req.body(full(body))?;
        let resp = tokio::time::timeout(Duration::from_secs(15), self.client.request(req))
            .await
            .map_err(|_| anyhow::anyhow!("timed out"))??;
        let status = resp.status();
        let bytes =
            Limited::new(resp.into_body(), 1 << 20).collect().await.map_err(|e| anyhow::anyhow!("{e}"))?.to_bytes();
        if status.is_success() {
            return Ok(bytes);
        }
        let msg = format!("{} {}", status.as_u16(), String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).trim());
        if status.is_client_error() && status.as_u16() != 408 && status.as_u16() != 429 {
            return Err(Permanent(msg).into());
        }
        Err(anyhow::anyhow!(msg))
    }

    async fn syslog(&mut self, lines: &[String]) -> anyhow::Result<()> {
        let addr = self.cfg.address.clone().unwrap_or_default();
        let (scheme, hostport) = addr.split_once("://").unwrap_or(("udp", addr.as_str()));
        if scheme == "udp" {
            let sock =
                tokio::net::UdpSocket::bind(if hostport.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" }).await?;
            for l in lines {
                sock.send_to(l.as_bytes(), hostport).await?;
            }
            return Ok(());
        }
        // TCP: newline-delimited; TLS: octet counting (RFC 5425).
        let octet = scheme == "tls";
        let mut payload = Vec::new();
        for l in lines {
            if octet {
                payload.extend_from_slice(format!("{} ", l.len()).as_bytes());
                payload.extend_from_slice(l.as_bytes());
            } else {
                payload.extend_from_slice(l.as_bytes());
                payload.push(b'\n');
            }
        }
        if let Some(c) = self.conn.as_mut()
            && closed(c).await
        {
            self.conn = None;
        }
        for _ in 0..2 {
            if self.conn.is_none() {
                self.conn = Some(connect(scheme, hostport, self.cfg.ca_file.as_deref()).await?);
            }
            let conn = self.conn.as_mut().expect("connected");
            match async {
                conn.write_all(&payload).await?;
                conn.flush().await
            }
            .await
            {
                Ok(()) => return Ok(()),
                // The connection may have been closed by the server: reconnect once.
                Err(e) => {
                    self.conn = None;
                    tracing::debug!(error = %e, "syslog connection lost, reconnecting");
                }
            }
        }
        Err(anyhow::anyhow!("could not write to {addr}"))
    }
}

/// A failure retrying will not fix (bad credentials, rejected documents).
#[derive(Debug)]
struct Permanent(String);

impl std::fmt::Display for Permanent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Permanent {}

async fn connect(scheme: &str, hostport: &str, ca_file: Option<&std::path::Path>) -> anyhow::Result<Conn> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(hostport))
        .await
        .map_err(|_| anyhow::anyhow!("connecting to {hostport} timed out"))??;
    tcp.set_nodelay(true)?;
    match scheme {
        "tcp" => Ok(Box::new(tcp)),
        "tls" => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(path) = ca_file {
                use rustls_pki_types::pem::PemObject;
                let certs = rustls_pki_types::CertificateDer::pem_file_iter(path)
                    .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
                for c in certs {
                    roots.add(c.map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?)?;
                }
            }
            let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
            let host = hostport.rsplit_once(':').map_or(hostport, |(h, _)| h).trim_matches(['[', ']']);
            let name = rustls_pki_types::ServerName::try_from(host.to_string())?;
            let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await?;
            Ok(Box::new(tls))
        }
        other => anyhow::bail!("unknown syslog scheme {other}:// (udp, tcp or tls)"),
    }
}

fn secret(v: &Option<String>) -> anyhow::Result<Option<String>> {
    v.as_deref().map(|s| resolve_secret(s).map_err(|e| anyhow::anyhow!("{e}"))).transpose()
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let pad = |b: u8| k.iter().map(|x| x ^ b).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(msg).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

fn write_file(path: &std::path::Path, lines: &[String], max: u64) -> anyhow::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    if std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) >= max {
        // events.jsonl -> events.jsonl.1 -> ... -> .5
        for i in (1..5).rev() {
            let _ = std::fs::rename(format!("{}.{i}", path.display()), format!("{}.{}", path.display(), i + 1));
        }
        std::fs::rename(path, format!("{}.1", path.display()))?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    let mut buf = String::new();
    for l in lines {
        buf.push_str(l);
        buf.push('\n');
    }
    f.write_all(buf.as_bytes())?;
    Ok(())
}

// ----- formats -------------------------------------------------------------------

fn fmt_name(f: ExportFormat) -> &'static str {
    match f {
        ExportFormat::Json => "json",
        ExportFormat::Ocsf => "ocsf",
        ExportFormat::Ecs => "ecs",
        ExportFormat::Cef => "cef",
    }
}

fn event_type(e: &LiveEvent) -> &'static str {
    if matches!(e.event.kind, EventKind::Admin(_)) { "admin" } else { "decision" }
}

/// One event as a JSON document (CEF is wrapped as `{"cef": ...}`).
pub fn doc(fmt: ExportFormat, e: &LiveEvent) -> Value {
    match fmt {
        ExportFormat::Json => native(e),
        ExportFormat::Ocsf => ocsf(e),
        ExportFormat::Ecs => ecs(e),
        ExportFormat::Cef => json!({ "cef": cef(e) }),
    }
}

/// One event as a line of text (files and syslog).
pub fn line(fmt: ExportFormat, e: &LiveEvent) -> String {
    match fmt {
        ExportFormat::Cef => cef(e),
        f => doc(f, e).to_string(),
    }
}

fn native(e: &LiveEvent) -> Value {
    json!({
        "schema": "nandi.event.v1",
        "type": event_type(e),
        "seq": e.seq,
        "event": &e.event,
        "decision": &e.decision,
        "applied": e.applied,
    })
}

/// Highest finding severity, if any.
fn top_severity(e: &LiveEvent) -> Option<Severity> {
    e.decision.findings.iter().map(|f| f.severity).max()
}

fn rules(e: &LiveEvent) -> Vec<String> {
    e.decision.findings.iter().map(|f| f.rule.clone()).collect()
}

/// `server/tool`, a model, a peer, or what an admin action targeted.
pub fn target(e: &LiveEvent) -> String {
    match &e.event.kind {
        EventKind::ToolCall(c) => format!("{}/{}", c.server, c.tool),
        EventKind::ToolResult(r) => format!("{}/{}", r.server, r.tool),
        EventKind::ToolList(l) => l.server.clone(),
        EventKind::LlmRequest(r) => format!("{}/{}", r.provider, r.model),
        EventKind::LlmResponse(r) => format!("{}/{}", r.provider, r.model),
        EventKind::A2aMessage(m) => m.peer.clone(),
        EventKind::AgentCard(c) => c.peer.clone(),
        EventKind::Admin(a) => a.target.clone(),
        _ => e.event.kind_name().to_string(),
    }
}

pub(crate) fn summary(e: &LiveEvent) -> String {
    match &e.event.kind {
        EventKind::Admin(a) => format!("{} {} {} ({})", a.actor, a.action, a.target, a.outcome),
        _ if e.decision.findings.is_empty() => {
            format!("{} {} {}: {}", e.event.agent, e.event.kind_name(), target(e), e.applied.as_str())
        }
        _ => format!("{} {} {}: {}", e.event.agent, e.event.kind_name(), target(e), e.decision.summary()),
    }
}

/// OCSF 1.3: flagged decisions are Detection Findings (2004), other
/// decisions and admin actions API Activity (6003).
fn ocsf(e: &LiveEvent) -> Value {
    let sev_id = match top_severity(e) {
        None | Some(Severity::Info) => 1,
        Some(Severity::Low) => 2,
        Some(Severity::Medium) => 3,
        Some(Severity::High) => 4,
        Some(Severity::Critical) => 5,
    };
    let (disp_id, disp) = match e.applied {
        Verdict::Allow => (1, "Allowed"),
        Verdict::Deny => (2, "Blocked"),
        Verdict::Ask => (99, "Held for approval"),
        Verdict::Redact => (99, "Redacted"),
        Verdict::Alert => (99, "Alerted"),
    };
    let metadata = json!({
        "version": "1.3.0",
        "uid": e.event.id,
        "correlation_uid": e.event.session,
        "product": { "name": "nandi", "vendor_name": "nandi", "version": VERSION },
    });
    let unmapped = json!({ "nandi": native(e) });
    if let EventKind::Admin(a) = &e.event.kind {
        return json!({
            "class_uid": 6003, "class_name": "API Activity", "category_uid": 6, "category_name": "Application Activity",
            "activity_id": 99, "activity_name": a.action, "type_uid": 600399,
            "time": e.event.ts_ms, "severity_id": 1, "message": summary(e),
            "status_id": if a.outcome == "ok" { 1 } else { 2 }, "status": a.outcome,
            "actor": { "user": { "name": a.actor } },
            "api": { "operation": a.action, "service": { "name": "nandi admin API" } },
            "resources": [{ "name": a.target }],
            "metadata": metadata, "unmapped": unmapped,
        });
    }
    let common = json!({
        "time": e.event.ts_ms,
        "severity_id": sev_id,
        "message": summary(e),
        "disposition_id": disp_id,
        "disposition": disp,
        "actor": { "user": { "name": e.event.agent }, "session": { "uid": e.event.session } },
        "api": { "operation": e.event.kind_name(), "service": { "name": target(e) } },
        "resources": [{ "name": target(e) }],
        "metadata": metadata,
        "unmapped": unmapped,
    });
    let mut out = if e.decision.findings.is_empty() {
        json!({
            "class_uid": 6003, "class_name": "API Activity", "category_uid": 6, "category_name": "Application Activity",
            "activity_id": 99, "activity_name": e.event.kind_name(), "type_uid": 600399,
            "status_id": if e.applied == Verdict::Deny { 2 } else { 1 },
        })
    } else {
        json!({
            "class_uid": 2004, "class_name": "Detection Finding", "category_uid": 2, "category_name": "Findings",
            "activity_id": 1, "activity_name": "Create", "type_uid": 200401,
            "status_id": 1, "status": "New",
            "finding_info": {
                "uid": e.event.id,
                "title": e.decision.summary(),
                "types": rules(e),
                "desc": e.decision.findings.iter().map(|f| f.message.as_str()).collect::<Vec<_>>().join("; "),
            },
        })
    };
    if let (Some(o), Some(c)) = (out.as_object_mut(), common.as_object()) {
        o.extend(c.clone());
    }
    out
}

/// Elastic Common Schema.
fn ecs(e: &LiveEvent) -> Value {
    let flagged = !e.decision.findings.is_empty();
    let admin = matches!(e.event.kind, EventKind::Admin(_));
    let severity = top_severity(e).map_or(0, |s| match s {
        Severity::Info => 1,
        Severity::Low => 21,
        Severity::Medium => 47,
        Severity::High => 73,
        Severity::Critical => 99,
    });
    let (action, user, outcome) = match &e.event.kind {
        EventKind::Admin(a) => {
            (a.action.clone(), a.actor.clone(), if a.outcome == "ok" { "success" } else { "failure" })
        }
        _ => (
            e.event.kind_name().to_string(),
            e.event.agent.clone(),
            if e.applied == Verdict::Deny { "failure" } else { "success" },
        ),
    };
    let mut event = json!({
        "id": e.event.id,
        "kind": if flagged { "alert" } else { "event" },
        "action": action,
        "outcome": outcome,
        "severity": severity,
        "dataset": "nandi.events",
        "module": "nandi",
        "reason": summary(e),
        "type": [if admin { "change" } else { match e.applied { Verdict::Deny => "denied", Verdict::Allow => "allowed", _ => "info" } }],
    });
    if flagged {
        event["category"] = json!(["intrusion_detection"]);
    } else if admin {
        event["category"] = json!(["configuration"]);
    }
    let mut out = json!({
        "@timestamp": rfc3339(e.event.ts_ms),
        "message": summary(e),
        "event": event,
        "user": { "name": user },
        "observer": { "vendor": "nandi", "product": "nandi", "version": VERSION, "hostname": nandi_discover::hostname() },
        "labels": { "session": e.event.session, "target": target(e), "verdict": e.applied.as_str() },
        "nandi": native(e),
    });
    if flagged {
        out["rule"] = json!({ "id": rules(e).join(","), "name": e.decision.summary() });
    }
    out
}

fn cef_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn cef_ext(s: &str) -> String {
    s.replace('\\', "\\\\").replace('=', "\\=").replace('\r', "").replace('\n', "\\n")
}

/// ArcSight Common Event Format.
pub fn cef(e: &LiveEvent) -> String {
    let sev = top_severity(e).map_or(0, |s| match s {
        Severity::Info => 1,
        Severity::Low => 3,
        Severity::Medium => 5,
        Severity::High => 8,
        Severity::Critical => 10,
    });
    let (sig, user, act) = match &e.event.kind {
        EventKind::Admin(a) => (format!("admin.{}", a.action), a.actor.clone(), a.outcome.clone()),
        _ => (
            e.decision.findings.first().map_or_else(|| e.event.kind_name().to_string(), |f| f.rule.clone()),
            e.event.agent.clone(),
            e.applied.as_str().to_string(),
        ),
    };
    let name: String = summary(e).chars().take(200).collect();
    let ext = [
        ("rt", e.event.ts_ms.to_string()),
        ("suser", user),
        ("act", act),
        ("cat", e.event.kind_name().to_string()),
        ("request", target(e)),
        ("externalId", e.event.id.clone()),
        ("cs1Label", "rules".into()),
        ("cs1", rules(e).join(",")),
        ("cs2Label", "session".into()),
        ("cs2", e.event.session.clone()),
        ("msg", name.clone()),
    ]
    .iter()
    .filter(|(_, v)| !v.is_empty())
    .map(|(k, v)| format!("{k}={}", cef_ext(v)))
    .collect::<Vec<_>>()
    .join(" ");
    format!("CEF:0|nandi|nandi|{VERSION}|{}|{}|{sev}|{ext}", cef_header(&sig), cef_header(&name))
}

/// One RFC 5424 syslog line.
fn syslog_line(cfg: &ExportConfig, fmt: ExportFormat, e: &LiveEvent) -> String {
    let sev = match top_severity(e) {
        Some(Severity::Critical) => 2,
        Some(Severity::High) => 3,
        Some(Severity::Medium) => 4,
        Some(Severity::Low) => 5,
        _ => 6,
    };
    let pri = u32::from(cfg.facility) * 8 + sev;
    let host: String = nandi_discover::hostname().chars().filter(|c| c.is_ascii_graphic()).take(255).collect();
    format!("<{pri}>1 {} {} nandi - {} - {}", rfc3339(e.event.ts_ms), host, event_type(e), line(fmt, e))
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn rfc3339(ms: u64) -> String {
    let secs = ms / 1000;
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", (secs / 3600) % 24, (secs / 60) % 60, secs % 60, ms % 1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Bytes as AxBytes;
    use axum::http::{HeaderMap, StatusCode, Uri};
    use nandi_core::{Category, Decision, Event, Finding, Source, ToolCall};
    use std::sync::atomic::AtomicUsize;

    type Seen = Arc<Mutex<Vec<(String, HeaderMap, Vec<u8>)>>>;

    /// A local HTTP receiver; answers `fail_first` requests with 503, or
    /// everything with `status`.
    async fn receiver(fail_first: usize, status: u16, reply: &'static str) -> (String, Seen) {
        let seen: Seen = Arc::default();
        let count = Arc::new(AtomicUsize::new(0));
        let s2 = seen.clone();
        let app = Router::new().fallback(move |uri: Uri, headers: HeaderMap, body: AxBytes| {
            let (seen, count) = (s2.clone(), count.clone());
            async move {
                seen.lock().push((uri.path().to_string(), headers, body.to_vec()));
                if count.fetch_add(1, Relaxed) < fail_first {
                    return (StatusCode::SERVICE_UNAVAILABLE, "busy");
                }
                (StatusCode::from_u16(status).unwrap(), reply)
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), seen)
    }

    fn live(tool: &str, verdict: Verdict) -> Arc<LiveEvent> {
        let ev = Event::new(
            Source::Eval,
            "billing-agent",
            "s1",
            EventKind::ToolCall(ToolCall {
                server: "bank".into(),
                tool: tool.into(),
                call_id: None,
                args: json!({ "amount": 48000 }),
            }),
        );
        let mut d = Decision::allow();
        if verdict != Verdict::Allow {
            d.push(Finding::new(
                "policy.large-payment",
                Category::Policy,
                Severity::High,
                verdict,
                "Payments above 1000 need a human",
            ));
        }
        Arc::new(LiveEvent { seq: Some(7), event: ev, decision: d, applied: verdict })
    }

    fn cfg(kind: ExportKind) -> ExportConfig {
        ExportConfig { name: "t".into(), kind, flush_ms: 10, ..ExportConfig::default() }
    }

    async fn settle(x: &Exports, sent: u64) {
        for _ in 0..200 {
            if x.status()[0].sent + x.status()[0].failed >= sent {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(hex::encode(mac), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        // A key longer than the block is hashed first (test case 6).
        let mac = hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(hex::encode(mac), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    #[test]
    fn formats() {
        let e = live("pay_invoice", Verdict::Ask);
        let o = ocsf(&e);
        assert_eq!(
            (o["class_uid"].as_u64(), o["type_uid"].as_u64(), o["severity_id"].as_u64()),
            (Some(2004), Some(200401), Some(4))
        );
        assert_eq!(o["finding_info"]["types"], json!(["policy.large-payment"]));
        assert_eq!(o["actor"]["user"]["name"], "billing-agent");
        assert_eq!(o["unmapped"]["nandi"]["seq"], 7);
        let clean = ocsf(&live("get_balance", Verdict::Allow));
        assert_eq!((clean["class_uid"].as_u64(), clean["disposition_id"].as_u64()), (Some(6003), Some(1)));
        let x = ecs(&e);
        assert_eq!(x["event"]["kind"], "alert");
        assert_eq!(x["event"]["category"], json!(["intrusion_detection"]));
        assert!(x["@timestamp"].as_str().unwrap().ends_with('Z'));
        let c = cef(&e);
        assert!(c.starts_with("CEF:0|nandi|nandi|"), "{c}");
        assert!(
            c.contains("|policy.large-payment|")
                && c.contains("|8|")
                && c.contains("suser=billing-agent")
                && c.contains("act=ask")
        );
        assert!(c.contains("request=bank/pay_invoice"));
        // Escaping: = in extensions, | in the header.
        assert_eq!(cef_ext("a=b\\c\nd"), "a\\=b\\\\c\\nd");
        assert_eq!(cef_header("x|y"), "x\\|y");
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_794_586_531_613), "2026-11-13T16:15:31.613Z");
    }

    #[test]
    fn filters() {
        let mut c = cfg(ExportKind::Webhook);
        c.url = Some("http://x".into());
        assert!(!wanted(&c, &live("a", Verdict::Allow)), "alert and above by default");
        assert!(wanted(&c, &live("a", Verdict::Deny)));
        c.min_verdict = Verdict::Allow;
        assert!(wanted(&c, &live("a", Verdict::Allow)));
        c.kinds = vec!["llm_request".into()];
        assert!(!wanted(&c, &live("a", Verdict::Deny)));
        let admin = Arc::new(LiveEvent {
            seq: None,
            event: Event::new(
                Source::Admin,
                "asha",
                "admin",
                EventKind::Admin(nandi_core::AdminAction {
                    actor: "asha".into(),
                    action: "agent.kill".into(),
                    target: "bot".into(),
                    outcome: "ok".into(),
                    details: Value::Null,
                }),
            ),
            decision: Decision::allow(),
            applied: Verdict::Allow,
        });
        assert!(wanted(&c, &admin), "admin actions follow `admin`, not the verdict filter");
        c.admin = false;
        assert!(!wanted(&c, &admin));
        assert!(
            ExportConfig { name: "x".into(), kind: ExportKind::SplunkHec, url: Some("u".into()), ..Default::default() }
                .check()
                .is_err()
        );
        assert!(
            ExportConfig {
                name: "x".into(),
                kind: ExportKind::Webhook,
                url: Some("u".into()),
                format: Some(ExportFormat::Cef),
                ..Default::default()
            }
            .check()
            .is_err()
        );
    }

    #[tokio::test]
    async fn signed_webhook_with_retry() {
        let (url, seen) = receiver(1, 200, "ok").await;
        let mut c = cfg(ExportKind::Webhook);
        c.url = Some(url + "/hook");
        c.secret = Some("s3cret".into());
        c.headers.insert("X-Team".into(), "sec".into());
        let x = Exports::start(&[c], crate::client::build()).unwrap();
        x.send(&live("pay_invoice", Verdict::Deny));
        x.send(&live("get_balance", Verdict::Allow)); // filtered out
        settle(&x, 1).await;
        let st = &x.status()[0];
        assert_eq!((st.sent, st.failed, st.dropped), (1, 0, 0), "{:?}", st.last_error);
        let reqs = seen.lock().clone();
        assert_eq!(reqs.len(), 2, "one 503, then delivered");
        let (path, h, body) = &reqs[1];
        assert_eq!(path, "/hook");
        assert_eq!(h["x-nandi-event"], "decision");
        assert_eq!(h["x-team"], "sec");
        // Verify the signature the way a receiver would.
        let sig = h["x-nandi-signature"].to_str().unwrap();
        let (t, v1) = sig.split_once(',').unwrap();
        let mut signed = format!("{}.", t.trim_start_matches("t=")).into_bytes();
        signed.extend_from_slice(body);
        assert_eq!(v1.trim_start_matches("v1="), hex::encode(hmac_sha256(b"s3cret", &signed)));
        let v: Value = serde_json::from_slice(body).unwrap();
        assert_eq!((v["schema"].as_str(), v["applied"].as_str()), (Some("nandi.event.v1"), Some("deny")));
    }

    #[tokio::test]
    async fn splunk_and_elastic_and_permanent_errors() {
        let (url, seen) = receiver(0, 200, "{\"text\":\"Success\",\"code\":0}").await;
        let mut c = cfg(ExportKind::SplunkHec);
        c.url = Some(url);
        c.token = Some("hec-token".into());
        c.index = Some("security".into());
        c.format = Some(ExportFormat::Ocsf);
        let x = Exports::start(&[c], crate::client::build()).unwrap();
        x.send(&live("pay_invoice", Verdict::Deny));
        x.send(&live("refund", Verdict::Ask));
        settle(&x, 2).await;
        assert_eq!(x.status()[0].sent, 2);
        let reqs = seen.lock().clone();
        let (path, h, body) = &reqs[0];
        assert_eq!(path, "/services/collector/event");
        assert_eq!(h["authorization"], "Splunk hec-token");
        let lines: Vec<Value> =
            std::str::from_utf8(body).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2, "one request for the batch");
        assert_eq!(
            (lines[0]["index"].as_str(), lines[0]["sourcetype"].as_str()),
            (Some("security"), Some("nandi:ocsf"))
        );
        assert_eq!(lines[0]["event"]["class_uid"], 2004);

        // Elasticsearch: bulk NDJSON; a document error is reported, not retried.
        let (url, seen) =
            receiver(0, 200, r#"{"errors":true,"items":[{"create":{"error":{"reason":"mapper_parsing_exception"}}}]}"#)
                .await;
        let mut c = cfg(ExportKind::Elastic);
        c.url = Some(url);
        c.api_key = Some("key".into());
        let x = Exports::start(&[c], crate::client::build()).unwrap();
        x.send(&live("pay_invoice", Verdict::Deny));
        settle(&x, 1).await;
        let st = &x.status()[0];
        assert_eq!((st.sent, st.failed), (0, 1));
        assert!(st.last_error.as_deref().unwrap().contains("mapper_parsing_exception"));
        let reqs = seen.lock().clone();
        assert_eq!(reqs.len(), 1, "not retried");
        let (path, h, body) = &reqs[0];
        assert_eq!((path.as_str(), h["authorization"].to_str().unwrap()), ("/_bulk", "ApiKey key"));
        let lines: Vec<Value> =
            std::str::from_utf8(body).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines[0]["create"]["_index"], "nandi-events");
        assert_eq!(lines[1]["event"]["kind"], "alert");

        // 401: bad credentials are permanent.
        let (url, seen) = receiver(0, 401, "nope").await;
        let mut c = cfg(ExportKind::Webhook);
        c.url = Some(url);
        let x = Exports::start(&[c], crate::client::build()).unwrap();
        x.send(&live("a", Verdict::Deny));
        settle(&x, 1).await;
        assert_eq!(x.status()[0].failed, 1);
        assert_eq!(seen.lock().len(), 1);
    }

    #[tokio::test]
    async fn syslog_udp_and_tcp() {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut c = cfg(ExportKind::Syslog);
        c.address = Some(format!("udp://{}", udp.local_addr().unwrap()));
        let x = Exports::start(&[c], crate::client::build()).unwrap();
        x.send(&live("pay_invoice", Verdict::Deny));
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), udp.recv(&mut buf)).await.unwrap().unwrap();
        let msg = std::str::from_utf8(&buf[..n]).unwrap();
        // local0 (16) * 8 + err (3)
        assert!(msg.starts_with("<131>1 ") && msg.contains(" nandi - decision - CEF:0|nandi|nandi|"), "{msg}");

        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut c = cfg(ExportKind::Syslog);
        c.address = Some(format!("tcp://{}", tcp.local_addr().unwrap()));
        c.format = Some(ExportFormat::Json);
        let x = Exports::start(&[c], crate::client::build()).unwrap();
        x.send(&live("a", Verdict::Deny));
        x.send(&live("b", Verdict::Alert));
        let (mut sock, _) = tcp.accept().await.unwrap();
        let mut got = String::new();
        let mut buf = vec![0u8; 8192];
        while got.lines().count() < 2 {
            let n = tokio::time::timeout(Duration::from_secs(5), tokio::io::AsyncReadExt::read(&mut sock, &mut buf))
                .await
                .unwrap()
                .unwrap();
            got.push_str(std::str::from_utf8(&buf[..n]).unwrap());
        }
        let first = got.lines().next().unwrap();
        let json_part = &first[first.find(" - {").unwrap() + 3..];
        assert_eq!(serde_json::from_str::<Value>(json_part).unwrap()["schema"], "nandi.event.v1");
    }

    #[tokio::test]
    async fn file_rotates() {
        let dir = std::env::temp_dir().join(format!("nandi-export-{}", new_id()));
        let path = dir.join("events.jsonl");
        let line = "x".repeat(600 * 1024);
        write_file(&path, std::slice::from_ref(&line), 1024 * 1024).unwrap();
        write_file(&path, std::slice::from_ref(&line), 1024 * 1024).unwrap();
        write_file(&path, std::slice::from_ref(&line), 1024 * 1024).unwrap(); // over 1 MiB: rotates first
        assert!(path.with_extension("jsonl.1").exists());
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);

        let mut c = cfg(ExportKind::File);
        c.path = Some(dir.join("ocsf.jsonl"));
        c.format = Some(ExportFormat::Ocsf);
        let x = Exports::start(&[c], crate::client::build()).unwrap();
        x.send(&live("pay_invoice", Verdict::Deny));
        settle(&x, 1).await;
        let text = std::fs::read_to_string(dir.join("ocsf.jsonl")).unwrap();
        assert_eq!(serde_json::from_str::<Value>(text.trim()).unwrap()["class_uid"], 2004);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
