//! Clients for a running nandi's admin API (`nandi status`, `nandi tail`, ...).

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use http_body_util::BodyExt;
use serde_json::{Value, json};

use nandi_core::Config;
use nandi_core::config::resolve_secret;
use nandi_gateway::client::{self, HttpClient};

/// Where to reach the admin API.
#[derive(Debug, Clone, Args)]
pub struct AdminOpts {
    /// Admin API base URL (default: `admin.listen` from the config, else
    /// http://127.0.0.1:8788).
    #[arg(long, value_name = "URL")]
    pub admin: Option<String>,
    /// Admin bearer token (default: `admin.token` from the config).
    #[arg(long, env = "NANDI_ADMIN_TOKEN", hide_env_values = true)]
    pub token: Option<String>,
    /// Print raw JSON instead of a summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum ApprovalsCmd {
    /// List calls waiting for a decision.
    List,
    /// Let a held call through.
    Approve { id: String },
    /// Block a held call.
    Deny { id: String },
}

#[derive(Debug, Subcommand)]
pub enum PinsCmd {
    /// List pinned tool (or card) definitions and pending changes.
    List,
    /// Accept the changed definition of `server/tool`.
    Approve { id: String },
    /// Drop a pin; the next sighting is pinned afresh.
    Forget { id: String },
}

/// Default admin URL for a listen address from the config.
pub fn admin_url_from_listen(listen: &str) -> String {
    let listen = listen.trim();
    if listen.is_empty() {
        return "http://127.0.0.1:8788".into();
    }
    // A wildcard bind is reachable on loopback.
    let listen = listen.replacen("0.0.0.0", "127.0.0.1", 1).replacen("[::]", "[::1]", 1);
    format!("http://{listen}")
}

/// Fill in URL and token defaults from the config file, when it exists.
pub fn resolve_target(opts: &AdminOpts, config: &Path) -> (String, Option<String>) {
    let cfg = config.exists().then(|| Config::load(config).ok()).flatten();
    let url = opts.admin.clone().unwrap_or_else(|| {
        cfg.as_ref().map_or_else(|| "http://127.0.0.1:8788".to_string(), |c| admin_url_from_listen(&c.admin.listen))
    });
    let token = opts
        .token
        .clone()
        .filter(|t| !t.is_empty())
        .or_else(|| cfg.as_ref().and_then(|c| c.admin.token.as_deref()).and_then(|t| resolve_secret(t).ok()));
    (url.trim_end_matches('/').to_string(), token)
}

pub struct Remote {
    client: HttpClient,
    base: String,
    token: Option<String>,
}

impl Remote {
    pub fn new(base: String, token: Option<String>) -> Self {
        Self { client: client::build(), base, token }
    }

    fn request(&self, method: &str, path: &str, body: Option<&Value>) -> anyhow::Result<http::Request<client::Body>> {
        let mut req = http::Request::builder().method(method).uri(format!("{}{path}", self.base));
        if let Some(t) = &self.token {
            req = req.header(http::header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let body = match body {
            Some(v) => {
                req = req.header(http::header::CONTENT_TYPE, "application/json");
                client::full(serde_json::to_vec(v)?)
            }
            None => client::empty(),
        };
        Ok(req.body(body)?)
    }

    /// Send a request and parse the JSON response; non-2xx is an error.
    pub async fn call(&self, method: &str, path: &str, body: Option<&Value>) -> anyhow::Result<Value> {
        let req = self.request(method, path, body)?;
        let resp = tokio::time::timeout(Duration::from_secs(30), self.client.request(req))
            .await
            .context("admin API timed out")?
            .with_context(|| format!("cannot reach the admin API at {}", self.base))?;
        let status = resp.status();
        let bytes = resp.into_body().collect().await.map_err(|e| anyhow::anyhow!("reading response: {e}"))?.to_bytes();
        let v: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        if !status.is_success() {
            let msg = v.get("error").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| v.to_string());
            bail!("{status}: {msg}");
        }
        Ok(v)
    }

    pub async fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.call("GET", path, None).await
    }

    pub async fn post(&self, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
        self.call("POST", path, body.as_ref()).await
    }

    /// Stream `/v1/events/stream`, calling `f` for every event payload.
    pub async fn tail(&self, query: &str, mut f: impl FnMut(&str, &str)) -> anyhow::Result<()> {
        let req = self.request("GET", &format!("/v1/events/stream{query}"), None)?;
        let resp =
            self.client.request(req).await.with_context(|| format!("cannot reach the admin API at {}", self.base))?;
        if !resp.status().is_success() {
            bail!("{}", resp.status());
        }
        let mut body = resp.into_body();
        let mut buf = String::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| anyhow::anyhow!("stream: {e}"))?;
            let Ok(data) = frame.into_data() else { continue };
            buf.push_str(&String::from_utf8_lossy(&data));
            while let Some(i) = buf.find("\n\n") {
                let block: String = buf.drain(..i + 2).collect();
                let (mut kind, mut payload) = ("message", String::new());
                for line in block.lines() {
                    if let Some(k) = line.strip_prefix("event:") {
                        kind = if k.trim() == "event" {
                            "event"
                        } else if k.trim() == "lagged" {
                            "lagged"
                        } else {
                            "other"
                        };
                    } else if let Some(d) = line.strip_prefix("data:") {
                        payload.push_str(d.strip_prefix(' ').unwrap_or(d));
                    }
                }
                if !payload.is_empty() {
                    f(kind, &payload);
                }
            }
        }
        Ok(())
    }
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Short "server/tool" or "provider/model" description of an event.
pub fn target(ev: &Value) -> String {
    let k = &ev["kind"];
    match s(k, "type") {
        "tool_call" | "tool_result" => format!("{}/{}", s(k, "server"), s(k, "tool")),
        "tool_list" => s(k, "server").to_string(),
        "llm_request" | "llm_response" => format!("{}/{}", s(k, "provider"), s(k, "model")),
        "a2a_message" => format!("{} {}", s(k, "peer"), s(k, "method")),
        "agent_card" => s(k, "peer").to_string(),
        "process" => s(k, "filename").to_string(),
        "file" => s(k, "path").to_string(),
        "network" => format!("{}:{}", k.get("host").and_then(Value::as_str).unwrap_or(s(k, "daddr")), k["dport"]),
        _ => String::new(),
    }
}

pub fn rules_of(decision: &Value) -> String {
    decision["findings"]
        .as_array()
        .map(|f| f.iter().map(|f| s(f, "rule")).collect::<Vec<_>>().join(","))
        .unwrap_or_default()
}

pub async fn status(r: &Remote, json_out: bool) -> anyhow::Result<()> {
    let v = r.get("/v1/status").await?;
    if json_out {
        print_json(&v);
        return Ok(());
    }
    println!(
        "nandi {} mode={} fail_mode={} uptime={}s",
        s(&v, "version"),
        s(&v, "mode"),
        s(&v, "fail_mode"),
        v["uptime_secs"]
    );
    println!(
        "sessions={} approvals_pending={} agents_killed={}",
        v["sessions"], v["approvals_pending"], v["agents_killed"]
    );
    if v["audit"]["enabled"] == json!(true) {
        println!(
            "audit records={} head={}:{} public_key={}",
            v["audit"]["records"],
            v["audit"]["head"]["seq"],
            s(&v["audit"]["head"], "hash"),
            s(&v["audit"], "public_key")
        );
    } else {
        println!("audit disabled");
    }
    for route in v["routes"].as_array().into_iter().flatten() {
        println!(
            "route {} {} -> {} ({})",
            s(route, "name"),
            s(route, "prefix"),
            s(route, "upstream"),
            s(route, "kind")
        );
    }
    Ok(())
}

pub async fn sessions(r: &Remote, json_out: bool) -> anyhow::Result<()> {
    let v = r.get("/v1/sessions").await?;
    if json_out {
        print_json(&v);
        return Ok(());
    }
    let list = v.as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("no active sessions");
    }
    for x in list {
        println!(
            "{:<20} {:<38} calls={:<5} risk={:.2} {}",
            s(&x, "agent"),
            s(&x, "session"),
            x["calls"],
            x["risk"].as_f64().unwrap_or(0.0),
            if x["tainted"] == json!(true) { "TAINTED" } else { "" }
        );
    }
    Ok(())
}

pub async fn approvals(r: &Remote, cmd: Option<ApprovalsCmd>, json_out: bool) -> anyhow::Result<()> {
    match cmd.unwrap_or(ApprovalsCmd::List) {
        ApprovalsCmd::List => {
            let v = r.get("/v1/approvals").await?;
            if json_out {
                print_json(&v);
                return Ok(());
            }
            let list = v.as_array().cloned().unwrap_or_default();
            if list.is_empty() {
                println!("no pending approvals");
            }
            for p in list {
                println!("{}  {}", s(&p, "id"), s(&p, "summary"));
            }
        }
        ApprovalsCmd::Approve { id } => {
            r.post(&format!("/v1/approvals/{id}/approve"), Some(json!({ "by": cli_user() }))).await?;
            println!("approved {id}");
        }
        ApprovalsCmd::Deny { id } => {
            r.post(&format!("/v1/approvals/{id}/deny"), Some(json!({ "by": cli_user() }))).await?;
            println!("denied {id}");
        }
    }
    Ok(())
}

fn cli_user() -> String {
    std::env::var("USER").map(|u| format!("cli:{u}")).unwrap_or_else(|_| "cli".into())
}

/// Path segment encoding for agent ids.
fn seg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub async fn kill(r: &Remote, agent: &str) -> anyhow::Result<()> {
    r.post(&format!("/v1/agents/{}/kill", seg(agent)), None).await?;
    println!("killed {agent}: every action it takes is now denied");
    Ok(())
}

pub async fn revive(r: &Remote, agent: &str) -> anyhow::Result<()> {
    let v = r.post(&format!("/v1/agents/{}/revive", seg(agent)), None).await?;
    if v["was_killed"] == json!(true) {
        println!("revived {agent}");
    } else {
        println!("{agent} was not killed");
    }
    Ok(())
}

pub async fn pins(r: &Remote, cmd: Option<PinsCmd>, cards: bool, json_out: bool) -> anyhow::Result<()> {
    let base = if cards { "/v1/pins/cards" } else { "/v1/pins/tools" };
    match cmd.unwrap_or(PinsCmd::List) {
        PinsCmd::List => {
            let v = r.get(base).await?;
            if json_out {
                print_json(&v);
                return Ok(());
            }
            let list = v.as_array().cloned().unwrap_or_default();
            if list.is_empty() {
                println!("nothing pinned yet");
            }
            for p in list {
                let hash = s(&p, "hash");
                match p.get("pending").and_then(Value::as_str) {
                    Some(pending) => println!(
                        "{:<40} {}  CHANGED -> {} (approve with `nandi pins approve {}`)",
                        s(&p, "id"),
                        &hash[..hash.len().min(12)],
                        &pending[..pending.len().min(12)],
                        s(&p, "id")
                    ),
                    None => println!("{:<40} {}", s(&p, "id"), &hash[..hash.len().min(12)]),
                }
            }
        }
        PinsCmd::Approve { id } => {
            r.post(&format!("{base}/approve"), Some(json!({ "id": id }))).await?;
            println!("approved new definition of {id}");
        }
        PinsCmd::Forget { id } => {
            r.post(&format!("{base}/forget"), Some(json!({ "id": id }))).await?;
            println!("forgot pin {id}");
        }
    }
    Ok(())
}

/// One line per server: name, risk, approval, pinning, spec and the
/// heaviest capabilities.
pub fn server_line(x: &Value) -> String {
    let spec = match x.get("package").filter(|p| p.is_object()) {
        Some(p) => {
            let v = p.get("version").and_then(Value::as_str).map(|v| format!("@{v}")).unwrap_or_default();
            format!("{}:{}{v}", s(p, "ecosystem"), s(p, "name"))
        }
        None => match x.get("spec") {
            Some(spec) if spec.get("url").is_some() => s(spec, "url").to_string(),
            Some(spec) => {
                let args: Vec<&str> = spec["args"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                format!("{} {}", s(spec, "command"), args.join(" ")).trim_end().to_string()
            }
            None => "(seen through hooks)".into(),
        },
    };
    let pinned = match x.get("pinned").and_then(Value::as_bool) {
        Some(true) => "pinned",
        Some(false) => "UNPINNED",
        None => "-",
    };
    let approval = match s(x, "approval") {
        "not_required" => "-",
        "approved" => "approved",
        "unapproved" => "UNAPPROVED",
        "mismatch" => "MISMATCH",
        other => other,
    };
    let caps: Vec<&str> = x["capabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|c| *c != "read_only")
        .take(4)
        .collect();
    let mut flags = String::new();
    if x["quarantined"] == json!(true) {
        flags.push_str(" QUARANTINED");
    }
    if x["binary_changed"] == json!(true) {
        flags.push_str(" BINARY-CHANGED");
    }
    format!(
        "{:<20} {:<8} {:>3}  {:<10} {:<8} {:<48} {}{flags}",
        s(x, "name"),
        s(x, "level"),
        x["score"],
        approval,
        pinned,
        clip(&spec, 48),
        if caps.is_empty() { "-".to_string() } else { caps.join(",") }
    )
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(n.saturating_sub(3)).collect::<String>())
    }
}

pub async fn servers(r: &Remote, json_out: bool) -> anyhow::Result<()> {
    let v = r.get("/v1/servers").await?;
    if json_out {
        print_json(&v);
        return Ok(());
    }
    let list = v.as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("no MCP servers seen yet");
        return Ok(());
    }
    println!("{:<20} {:<8} {:>3}  {:<10} {:<8} {:<48} CAPABILITIES", "NAME", "RISK", "", "APPROVAL", "PINNED", "SPEC");
    for x in list {
        println!("{}", server_line(&x));
    }
    Ok(())
}

/// Print live events until interrupted.
pub async fn tail(r: &Remote, agent: Option<&str>, min_verdict: Option<&str>, json_out: bool) -> anyhow::Result<()> {
    let mut q = Vec::new();
    if let Some(a) = agent {
        q.push(format!("agent={}", seg(a)));
    }
    if let Some(v) = min_verdict {
        q.push(format!("min_verdict={}", seg(v)));
    }
    let query = if q.is_empty() { String::new() } else { format!("?{}", q.join("&")) };
    let stdout = std::io::stdout();
    r.tail(&query, |kind, data| {
        let mut out = stdout.lock();
        match kind {
            "event" if json_out => {
                let _ = writeln!(out, "{data}");
            }
            "event" => {
                let Ok(v) = serde_json::from_str::<Value>(data) else { return };
                let (ev, d) = (&v["event"], &v["decision"]);
                let (verdict, applied) = (s(d, "verdict"), s(&v, "applied"));
                // Show "deny" when both agree, "deny>allow" when monitor mode
                // or an operator changed the outcome.
                let decision = if verdict == applied || applied.is_empty() {
                    verdict.to_string()
                } else {
                    format!("{verdict}>{applied}")
                };
                let _ = writeln!(
                    out,
                    "{}  {:<16} {:<12} {:<34} {:<12} {}",
                    clock(ev["ts_ms"].as_u64().unwrap_or(0)),
                    s(ev, "agent"),
                    s(&ev["kind"], "type"),
                    target(ev),
                    decision,
                    rules_of(d)
                );
            }
            "lagged" => {
                let _ = writeln!(out, "... skipped {data} events (slow reader)");
            }
            _ => {}
        }
        let _ = out.flush();
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_url_defaults() {
        assert_eq!(admin_url_from_listen("127.0.0.1:8788"), "http://127.0.0.1:8788");
        assert_eq!(admin_url_from_listen("0.0.0.0:9000"), "http://127.0.0.1:9000");
        assert_eq!(admin_url_from_listen(""), "http://127.0.0.1:8788");
    }

    #[test]
    fn segments_are_encoded() {
        assert_eq!(seg("a b/c"), "a%20b%2Fc");
        assert_eq!(seg("bot-1.x"), "bot-1.x");
    }

    #[test]
    fn server_lines() {
        let x = json!({
            "name": "github", "level": "high", "score": 62, "approval": "unapproved", "pinned": false,
            "package": {"ecosystem": "npm", "name": "@scope/srv", "pinned": false},
            "capabilities": ["payment", "external_send", "read_only"], "quarantined": true, "binary_changed": false
        });
        let line = server_line(&x);
        assert!(line.starts_with("github"), "{line}");
        for part in ["high", "62", "UNAPPROVED", "UNPINNED", "npm:@scope/srv", "payment,external_send", "QUARANTINED"] {
            assert!(line.contains(part), "{part} missing in {line}");
        }
        let http = json!({"name": "web", "level": "low", "score": 0, "approval": "not_required",
            "spec": {"transport": "http", "url": "https://x/mcp"}, "capabilities": []});
        let line = server_line(&http);
        assert!(line.contains("https://x/mcp") && line.ends_with(" -"), "{line}");
        assert_eq!(clip("abcdef", 5), "ab...");
    }

    #[test]
    fn targets() {
        let ev = json!({ "kind": { "type": "tool_call", "server": "fs", "tool": "read" } });
        assert_eq!(target(&ev), "fs/read");
    }
}

/// `HH:MM:SS.mmm` in UTC for a Unix-millisecond timestamp.
fn clock(ms: u64) -> String {
    let secs = ms / 1000;
    format!("{:02}:{:02}:{:02}.{:03}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60, ms % 1000)
}

#[cfg(test)]
mod clock_tests {
    #[test]
    fn formats_utc_clock() {
        assert_eq!(super::clock(1_794_314_325_688), "12:38:45.688");
        assert_eq!(super::clock(0), "00:00:00.000");
    }
}
