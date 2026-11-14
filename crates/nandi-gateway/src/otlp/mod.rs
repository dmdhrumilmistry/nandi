//! OpenTelemetry export: traces, logs and metrics over OTLP/HTTP.
//!
//! - **Traces**: a span per decision, nested under the caller's span when it
//!   propagated W3C trace context, and the parent of whatever the upstream
//!   records (the proxy passes nandi's span on in `traceparent`).
//! - **Logs**: a log record per decision (at or above
//!   `telemetry.otlp_logs_min_verdict`) and per administrative action,
//!   linked to the span.
//! - **Metrics**: the same series as the Prometheus endpoint, as cumulative
//!   sums, gauges and a histogram, pushed every
//!   `telemetry.otlp_metrics_interval_secs`.
//!
//! Encoding is `http/protobuf` (the OpenTelemetry default) or `http/json`,
//! optionally gzip-compressed. Settings come from `telemetry` in the
//! configuration and fall back to the standard `OTEL_*` environment
//! variables, so the usual collector setups and Kubernetes injection work.
//!
//! Like exports, OTLP never slows agents down: records go into a bounded
//! queue, a background task batches and delivers them with retries, and a
//! full queue drops records and counts them.

pub mod model;
pub mod pb;

use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering::Relaxed};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};

use nandi_core::Verdict;
use nandi_core::config::{OtlpCompression, OtlpProtocol, TelemetryConfig, resolve_secret};
use nandi_core::util::now_ms;

use crate::client::{HttpClient, full};
use crate::exports::Stats;
use crate::metrics::{Series, SeriesKind};
use crate::recorder::LiveEvent;
use pb::Request;

const QUEUE: usize = 8192;
const BATCH: usize = 512;
const FLUSH: Duration = Duration::from_secs(1);
const ATTEMPTS: u32 = 3;
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where one signal goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub url: String,
    pub headers: Vec<(String, String)>,
}

/// Resolved OTLP settings: configuration over `OTEL_*` environment variables.
#[derive(Debug, Clone)]
pub struct Settings {
    pub traces: Option<Endpoint>,
    pub metrics: Option<Endpoint>,
    pub logs: Option<Endpoint>,
    pub protocol: OtlpProtocol,
    pub compression: OtlpCompression,
    pub timeout: Duration,
    pub metrics_interval: Duration,
    pub logs_min_verdict: Verdict,
    pub propagate: bool,
    /// Resource attributes, in order.
    pub resource: Vec<(String, Value)>,
}

/// `k1=v1,k2=v2` with percent-encoded values (W3C Baggage style), as used by
/// `OTEL_EXPORTER_OTLP_HEADERS` and `OTEL_RESOURCE_ATTRIBUTES`.
pub fn parse_pairs(s: &str) -> Vec<(String, String)> {
    s.split(',')
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            let k = k.trim();
            (!k.is_empty()).then(|| (percent_decode(k), percent_decode(v.trim())))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn set(attrs: &mut Vec<(String, Value)>, k: &str, v: Value) {
    match attrs.iter_mut().find(|(key, _)| key == k) {
        Some(slot) => slot.1 = v,
        None => attrs.push((k.to_string(), v)),
    }
}

impl Settings {
    /// Resolve from the configuration and the process environment. `None`
    /// when no signal has an endpoint.
    pub fn from_env(cfg: &TelemetryConfig) -> anyhow::Result<Option<Self>> {
        Self::resolve(cfg, |k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
    }

    /// Resolve with `env` for environment lookups.
    pub fn resolve(cfg: &TelemetryConfig, env: impl Fn(&str) -> Option<String>) -> anyhow::Result<Option<Self>> {
        if env("OTEL_SDK_DISABLED").is_some_and(|v| v.trim().eq_ignore_ascii_case("true")) {
            return Ok(None);
        }
        let base = cfg.otlp_endpoint.clone().or_else(|| env("OTEL_EXPORTER_OTLP_ENDPOINT"));
        let mut common = env("OTEL_EXPORTER_OTLP_HEADERS").map(|h| parse_pairs(&h)).unwrap_or_default();
        for (k, v) in &cfg.otlp_headers {
            let v = resolve_secret(v).map_err(|e| anyhow::anyhow!("telemetry.otlp_headers.{k}: {e}"))?;
            common.retain(|(key, _)| !key.eq_ignore_ascii_case(k));
            common.push((k.clone(), v));
        }
        let endpoint = |on: bool, own: &Option<String>, signal: &str| -> Option<Endpoint> {
            let upper = signal.to_ascii_uppercase();
            // OTEL_<SIGNAL>_EXPORTER lists exporters; without `otlp` the signal is off.
            let listed = env(&format!("OTEL_{upper}_EXPORTER"))
                .is_none_or(|v| v.split(',').any(|e| e.trim().eq_ignore_ascii_case("otlp")));
            if !on || !listed {
                return None;
            }
            let url = own
                .clone()
                .or_else(|| env(&format!("OTEL_EXPORTER_OTLP_{upper}_ENDPOINT")))
                .or_else(|| base.as_ref().map(|b| format!("{}/v1/{signal}", b.trim_end_matches('/'))))?;
            let mut headers = common.clone();
            for (k, v) in
                env(&format!("OTEL_EXPORTER_OTLP_{upper}_HEADERS")).map(|h| parse_pairs(&h)).unwrap_or_default()
            {
                if !cfg.otlp_headers.keys().any(|c| c.eq_ignore_ascii_case(&k)) {
                    headers.retain(|(key, _)| !key.eq_ignore_ascii_case(&k));
                    headers.push((k, v));
                }
            }
            Some(Endpoint { url, headers })
        };
        let traces = endpoint(cfg.otlp_signals.traces, &cfg.otlp_traces_endpoint, "traces");
        let metrics = endpoint(cfg.otlp_signals.metrics, &cfg.otlp_metrics_endpoint, "metrics");
        let logs = endpoint(cfg.otlp_signals.logs, &cfg.otlp_logs_endpoint, "logs");
        if traces.is_none() && metrics.is_none() && logs.is_none() {
            return Ok(None);
        }
        for e in [&traces, &metrics, &logs].into_iter().flatten() {
            let uri: http::Uri = e.url.parse().map_err(|err| anyhow::anyhow!("OTLP endpoint {}: {err}", e.url))?;
            if !matches!(uri.scheme_str(), Some("http" | "https")) {
                anyhow::bail!("OTLP endpoint {} must be an http:// or https:// URL", e.url);
            }
        }

        let protocol = match cfg.otlp_protocol {
            Some(p) => p,
            None => match env("OTEL_EXPORTER_OTLP_PROTOCOL").as_deref().map(str::trim) {
                None | Some("http/protobuf") => OtlpProtocol::HttpProtobuf,
                Some("http/json") => OtlpProtocol::HttpJson,
                Some(other) => {
                    tracing::warn!(
                        "OTEL_EXPORTER_OTLP_PROTOCOL={other} is not supported; using http/protobuf \
                         (point the endpoint at the collector's OTLP/HTTP port, usually 4318)"
                    );
                    OtlpProtocol::HttpProtobuf
                }
            },
        };
        let compression = match cfg.otlp_compression {
            Some(c) => c,
            None => match env("OTEL_EXPORTER_OTLP_COMPRESSION").as_deref().map(str::trim) {
                Some("gzip") => OtlpCompression::Gzip,
                _ => OtlpCompression::None,
            },
        };
        let millis = |name: &str| env(name).and_then(|v| v.trim().parse::<u64>().ok()).filter(|v| *v > 0);
        let timeout = Duration::from_millis(millis("OTEL_EXPORTER_OTLP_TIMEOUT").unwrap_or(10_000));
        let metrics_interval = match cfg.otlp_metrics_interval_secs {
            Some(s) => Duration::from_secs(s.max(1)),
            None => Duration::from_millis(millis("OTEL_METRIC_EXPORT_INTERVAL").unwrap_or(60_000).max(1000)),
        };

        // Resource: defaults, then OTEL_RESOURCE_ATTRIBUTES, OTEL_SERVICE_NAME,
        // the configured attributes and a configured service name.
        let mut resource: Vec<(String, Value)> = vec![
            ("service.name".into(), json!("nandi")),
            ("service.version".into(), json!(VERSION)),
            ("service.instance.id".into(), json!(nandi_core::util::new_id())),
            ("host.name".into(), json!(nandi_discover::hostname())),
            ("os.type".into(), json!(os_type())),
            ("process.pid".into(), json!(std::process::id())),
            ("telemetry.sdk.name".into(), json!("nandi")),
            ("telemetry.sdk.language".into(), json!("rust")),
            ("telemetry.sdk.version".into(), json!(VERSION)),
        ];
        for (k, v) in env("OTEL_RESOURCE_ATTRIBUTES").map(|a| parse_pairs(&a)).unwrap_or_default() {
            set(&mut resource, &k, json!(v));
        }
        if let Some(name) = env("OTEL_SERVICE_NAME") {
            set(&mut resource, "service.name", json!(name.trim()));
        }
        for (k, v) in &cfg.resource_attributes {
            set(&mut resource, k, json!(v));
        }
        if cfg.service_name != TelemetryConfig::default().service_name {
            set(&mut resource, "service.name", json!(cfg.service_name));
        }

        Ok(Some(Self {
            traces,
            metrics,
            logs,
            protocol,
            compression,
            timeout,
            metrics_interval,
            logs_min_verdict: cfg.otlp_logs_min_verdict,
            propagate: cfg.propagate_trace_context,
            resource,
        }))
    }
}

/// `os.type` semantic convention value.
fn os_type() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

/// Status of one signal, for `GET /v1/exports`.
#[derive(Debug, Serialize)]
pub struct SignalStatus {
    pub signal: &'static str,
    /// Where it goes, without query string or credentials.
    pub target: String,
    pub protocol: &'static str,
    pub sent: u64,
    pub failed: u64,
    pub dropped: u64,
    pub last_ok_ms: u64,
    pub last_error: Option<String>,
}

enum Msg {
    Event(Arc<LiveEvent>, u64),
    /// A ready-made span (a proxied request).
    Span(Value),
    Flush(oneshot::Sender<()>),
}

/// Unix time in nanoseconds.
pub fn now_ns() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

/// nandi's span for one proxied request (`SERVER` kind, HTTP semantic
/// conventions). Decisions made for the request and the upstream's own spans
/// are its children. It is exported when dropped, so it covers the whole
/// request, streamed responses included.
pub struct RequestSpan {
    otlp: Arc<Otlp>,
    pub trace_id: String,
    pub span_id: String,
    parent: Option<String>,
    name: String,
    attrs: Vec<(&'static str, Value)>,
    start_ns: u64,
    status: AtomicU16,
}

impl RequestSpan {
    pub fn start(
        otlp: &Arc<Otlp>,
        trace_id: &str,
        parent: Option<&str>,
        name: String,
        attrs: Vec<(&'static str, Value)>,
    ) -> Arc<Self> {
        Arc::new(Self {
            otlp: otlp.clone(),
            trace_id: trace_id.into(),
            span_id: model::new_span_id(),
            parent: parent.map(str::to_string),
            name,
            attrs,
            start_ns: now_ns(),
            status: AtomicU16::new(0),
        })
    }

    /// Record the HTTP status returned to the caller.
    pub fn set_status(&self, code: u16) {
        self.status.store(code, Relaxed);
    }
}

impl Drop for RequestSpan {
    fn drop(&mut self) {
        let status = self.status.load(Relaxed);
        let mut attrs: Vec<Value> = self.attrs.iter().map(|(k, v)| model::kv(k, v.clone())).collect();
        if status != 0 {
            attrs.push(model::kv("http.response.status_code", json!(status)));
        }
        let mut span = json!({
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "name": self.name,
            "kind": 2,
            "startTimeUnixNano": self.start_ns.to_string(),
            "endTimeUnixNano": now_ns().max(self.start_ns + 1).to_string(),
            "attributes": attrs,
            // Server spans are errors for 5xx only.
            "status": { "code": if status >= 500 { 2 } else { 0 } },
        });
        if let Some(p) = &self.parent {
            span["parentSpanId"] = json!(p);
        }
        self.otlp.record_span(span);
    }
}

/// The OTLP exporter.
pub struct Otlp {
    settings: Arc<Settings>,
    resource: Value,
    client: HttpClient,
    tx: mpsc::Sender<Msg>,
    traces: Arc<Stats>,
    metrics: Arc<Stats>,
    logs: Arc<Stats>,
    started_ns: u64,
}

impl Otlp {
    /// Start delivering. Must run inside a Tokio runtime. Metrics need
    /// [`Otlp::spawn_metrics`] as well.
    pub fn start(settings: Settings, client: HttpClient) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(QUEUE);
        let otlp = Arc::new(Self {
            resource: model::resource(&settings.resource),
            settings: Arc::new(settings),
            client,
            tx,
            traces: Arc::default(),
            metrics: Arc::default(),
            logs: Arc::default(),
            started_ns: now_ms() * 1_000_000,
        });
        for (name, e) in
            [("traces", &otlp.settings.traces), ("metrics", &otlp.settings.metrics), ("logs", &otlp.settings.logs)]
        {
            if let Some(e) = e {
                tracing::info!(signal = name, endpoint = %redact_url(&e.url), "exporting OpenTelemetry");
            }
        }
        if otlp.settings.traces.is_some() || otlp.settings.logs.is_some() {
            tokio::spawn(otlp.clone().run(rx));
        }
        otlp
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Whether the proxy should start or continue traces and pass nandi's
    /// span upstream.
    pub fn propagates(&self) -> bool {
        self.settings.propagate && self.settings.traces.is_some()
    }

    /// Offer a recorded event. Never blocks.
    pub fn record(&self, ev: &Arc<LiveEvent>, eval_ns: u64) {
        let span = self.settings.traces.is_some() && !matches!(ev.event.kind, nandi_core::EventKind::Admin(_));
        let log = self.settings.logs.is_some() && self.wants_log(ev);
        if !span && !log {
            return;
        }
        if self.tx.try_send(Msg::Event(ev.clone(), eval_ns)).is_err() {
            if span {
                self.traces.dropped.fetch_add(1, Relaxed);
            }
            if log {
                self.logs.dropped.fetch_add(1, Relaxed);
            }
        }
    }

    /// Offer a ready-made span. Never blocks.
    pub fn record_span(&self, span: Value) {
        if self.settings.traces.is_some() && self.tx.try_send(Msg::Span(span)).is_err() {
            self.traces.dropped.fetch_add(1, Relaxed);
        }
    }

    fn wants_log(&self, ev: &LiveEvent) -> bool {
        matches!(ev.event.kind, nandi_core::EventKind::Admin(_))
            || ev.decision.verdict.max(ev.applied) >= self.settings.logs_min_verdict
    }

    /// Wait until queued spans and log records are delivered (shutdown).
    /// Gives up after five seconds.
    pub async fn flush(&self) {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Msg::Flush(tx)).await.is_ok() {
            let _ = tokio::time::timeout(Duration::from_secs(5), rx).await;
        }
    }

    /// Push metrics every interval while `collect` returns them (it returns
    /// `None` once the application is gone).
    pub fn spawn_metrics(self: &Arc<Self>, collect: impl Fn() -> Option<Vec<Series>> + Send + 'static) {
        let Some(endpoint) = self.settings.metrics.clone() else { return };
        let me = Arc::downgrade(self);
        let interval = self.settings.metrics_interval;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                let (Some(otlp), Some(mut series)) = (me.upgrade(), collect()) else { break };
                series.extend(otlp.series());
                otlp.push_metrics(&endpoint, &series).await;
            }
        });
    }

    /// Export `series` once now.
    pub async fn push_metrics(&self, endpoint: &Endpoint, series: &[Series]) {
        let points: usize =
            series.iter().map(|s| if matches!(s.kind, SeriesKind::Histogram(_)) { 1 } else { s.points.len() }).sum();
        let body =
            model::metrics_request(&self.resource, model::metrics(series, self.started_ns, now_ms() * 1_000_000));
        self.deliver(endpoint, Request::Metrics, &body, points as u64, &self.metrics).await;
    }

    /// Delivery counters per signal, as metric series.
    pub fn series(&self) -> Vec<Series> {
        let signals = [("traces", &self.traces), ("metrics", &self.metrics), ("logs", &self.logs)];
        let row = |f: fn(&Stats) -> u64| -> Vec<(Vec<(&'static str, String)>, f64)> {
            signals.iter().map(|(n, s)| (vec![("signal", n.to_string())], f(s) as f64)).collect()
        };
        vec![
            Series {
                name: "nandi_otlp_sent_total",
                otel: "nandi.otlp.sent",
                help: "Spans, log records and metric points delivered over OTLP.",
                unit: "{item}",
                kind: SeriesKind::Counter,
                points: row(|s| s.sent.load(Relaxed)),
            },
            Series {
                name: "nandi_otlp_failed_total",
                otel: "nandi.otlp.failed",
                help: "OTLP items that could not be delivered after retries.",
                unit: "{item}",
                kind: SeriesKind::Counter,
                points: row(|s| s.failed.load(Relaxed)),
            },
            Series {
                name: "nandi_otlp_dropped_total",
                otel: "nandi.otlp.dropped",
                help: "OTLP items dropped because the queue was full.",
                unit: "{item}",
                kind: SeriesKind::Counter,
                points: row(|s| s.dropped.load(Relaxed)),
            },
        ]
    }

    /// Status of each enabled signal.
    pub fn status(&self) -> Vec<SignalStatus> {
        let protocol = match self.settings.protocol {
            OtlpProtocol::HttpProtobuf => "http/protobuf",
            OtlpProtocol::HttpJson => "http/json",
        };
        [
            ("traces", &self.settings.traces, &self.traces),
            ("metrics", &self.settings.metrics, &self.metrics),
            ("logs", &self.settings.logs, &self.logs),
        ]
        .into_iter()
        .filter_map(|(signal, e, s)| {
            let e = e.as_ref()?;
            Some(SignalStatus {
                signal,
                target: redact_url(&e.url),
                protocol,
                sent: s.sent.load(Relaxed),
                failed: s.failed.load(Relaxed),
                dropped: s.dropped.load(Relaxed),
                last_ok_ms: s.last_ok_ms.load(Relaxed),
                last_error: s.last_error.lock().clone(),
            })
        })
        .collect()
    }

    async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<Msg>) {
        let mut msgs = Vec::with_capacity(BATCH);
        loop {
            if rx.recv_many(&mut msgs, BATCH).await == 0 {
                break;
            }
            // Let a batch build up unless someone waits on a flush.
            if msgs.len() < BATCH && !msgs.iter().any(|m| matches!(m, Msg::Flush(_))) {
                let deadline = tokio::time::Instant::now() + FLUSH;
                while msgs.len() < BATCH {
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Some(m)) => {
                            let flush = matches!(m, Msg::Flush(_));
                            msgs.push(m);
                            if flush {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            }
            let mut spans = Vec::new();
            let mut logs = Vec::new();
            let mut waiters = Vec::new();
            let observed = now_ns();
            for m in msgs.drain(..) {
                match m {
                    Msg::Event(ev, eval_ns) => {
                        if self.settings.traces.is_some()
                            && let Some(s) = model::span(&ev, eval_ns)
                        {
                            spans.push(s);
                        }
                        if self.settings.logs.is_some() && self.wants_log(&ev) {
                            logs.push(model::log_record(&ev, observed));
                        }
                    }
                    Msg::Span(span) => spans.push(span),
                    Msg::Flush(w) => waiters.push(w),
                }
            }
            if let (Some(e), false) = (&self.settings.traces, spans.is_empty()) {
                let n = spans.len() as u64;
                self.deliver(e, Request::Traces, &model::traces_request(&self.resource, spans), n, &self.traces).await;
            }
            if let (Some(e), false) = (&self.settings.logs, logs.is_empty()) {
                let n = logs.len() as u64;
                self.deliver(e, Request::Logs, &model::logs_request(&self.resource, logs), n, &self.logs).await;
            }
            for w in waiters {
                let _ = w.send(());
            }
        }
    }

    /// Encode and POST one export request, retrying transient failures.
    async fn deliver(&self, e: &Endpoint, kind: Request, doc: &Value, items: u64, stats: &Stats) {
        let result = match self.encode(kind, doc) {
            Ok((body, ctype)) => self.post_with_retries(e, body, ctype).await,
            Err(err) => Err(anyhow::anyhow!("encoding failed: {err}")),
        };
        match result {
            Ok(()) => {
                stats.sent.fetch_add(items, Relaxed);
                stats.last_ok_ms.store(now_ms(), Relaxed);
            }
            Err(err) => {
                stats.failed.fetch_add(items, Relaxed);
                let msg = format!("{err:#}");
                tracing::warn!(endpoint = %redact_url(&e.url), "OTLP export failed: {msg}");
                *stats.last_error.lock() = Some(msg);
            }
        }
    }

    fn encode(&self, kind: Request, doc: &Value) -> anyhow::Result<(Bytes, &'static str)> {
        let (raw, ctype) = match self.settings.protocol {
            OtlpProtocol::HttpProtobuf => {
                (pb::encode(kind, doc).map_err(anyhow::Error::msg)?, "application/x-protobuf")
            }
            OtlpProtocol::HttpJson => (serde_json::to_vec(doc)?, "application/json"),
        };
        let body = match self.settings.compression {
            OtlpCompression::None => raw,
            OtlpCompression::Gzip => {
                let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                gz.write_all(&raw)?;
                gz.finish()?
            }
        };
        Ok((Bytes::from(body), ctype))
    }

    async fn post_with_retries(&self, e: &Endpoint, body: Bytes, ctype: &str) -> anyhow::Result<()> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.post(e, body.clone(), ctype).await {
                Ok(()) => return Ok(()),
                Err(Failure::Permanent(err)) => return Err(err),
                Err(Failure::Retry(err)) if attempt >= ATTEMPTS => return Err(err),
                Err(Failure::Retry(_)) => tokio::time::sleep(Duration::from_secs(u64::from(attempt))).await,
            }
        }
    }

    async fn post(&self, e: &Endpoint, body: Bytes, ctype: &str) -> Result<(), Failure> {
        let mut req = http::Request::post(&e.url).header(http::header::CONTENT_TYPE, ctype);
        if self.settings.compression == OtlpCompression::Gzip {
            req = req.header(http::header::CONTENT_ENCODING, "gzip");
        }
        req = req.header(http::header::USER_AGENT, concat!("nandi/", env!("CARGO_PKG_VERSION")));
        for (k, v) in &e.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let req = req.body(full(body)).map_err(|err| Failure::Permanent(err.into()))?;
        let resp = match tokio::time::timeout(self.settings.timeout, self.client.request(req)).await {
            Ok(Ok(r)) => r,
            Ok(Err(err)) => return Err(Failure::Retry(anyhow::anyhow!("{err}"))),
            Err(_) => return Err(Failure::Retry(anyhow::anyhow!("no response within {:?}", self.settings.timeout))),
        };
        let status = resp.status();
        // Drain (bounded) so the connection can be reused and errors shown.
        let text = http_body_util::Limited::new(resp.into_body(), 4096)
            .collect()
            .await
            .map(|b| String::from_utf8_lossy(&b.to_bytes()).trim().to_string())
            .unwrap_or_default();
        if status.is_success() {
            return Ok(());
        }
        let err = anyhow::anyhow!(
            "HTTP {status}{}",
            if text.is_empty() { String::new() } else { format!(": {}", clip(&text)) }
        );
        // OTLP/HTTP: 429, 502, 503 and 504 are retryable; the rest are not.
        if matches!(status.as_u16(), 408 | 429 | 502 | 503 | 504) {
            Err(Failure::Retry(err))
        } else {
            Err(Failure::Permanent(err))
        }
    }
}

enum Failure {
    Retry(anyhow::Error),
    Permanent(anyhow::Error),
}

fn clip(s: &str) -> String {
    if s.len() <= 200 {
        return s.to_string();
    }
    let mut end = 200;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// A URL without credentials or query string.
pub fn redact_url(url: &str) -> String {
    match url.parse::<http::Uri>() {
        Ok(u) => {
            let host = u.authority().map(|a| a.as_str().rsplit('@').next().unwrap_or_default().to_string());
            format!("{}://{}{}", u.scheme_str().unwrap_or("http"), host.unwrap_or_default(), u.path())
        }
        Err(_) => "(invalid URL)".into(),
    }
}

#[cfg(test)]
mod tests;
