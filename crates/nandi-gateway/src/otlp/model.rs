//! OTLP data built from nandi's events, decisions and metrics, in the OTLP
//! JSON encoding. The protobuf encoding is derived from it ([`super::pb`]).
//!
//! Spans and log records follow the OpenTelemetry GenAI and MCP semantic
//! conventions where they apply (`execute_tool {name}`, `chat {model}`,
//! `invoke_agent {peer}`, `gen_ai.*`, `mcp.*`), plus `nandi.*` attributes for
//! the decision.

use serde_json::{Value, json};

use nandi_core::{EventKind, Verdict};

use crate::metrics::{Series, SeriesKind};
use crate::recorder::LiveEvent;

/// Attribute names in one place so semantic-convention renames are a
/// one-line change.
pub mod attr {
    pub const OPERATION: &str = "gen_ai.operation.name";
    pub const PROVIDER: &str = "gen_ai.provider.name";
    pub const MODEL: &str = "gen_ai.request.model";
    pub const TOOL_NAME: &str = "gen_ai.tool.name";
    pub const TOOL_CALL_ID: &str = "gen_ai.tool.call.id";
    pub const AGENT_ID: &str = "gen_ai.agent.id";
    pub const CONVERSATION: &str = "gen_ai.conversation.id";
    pub const INPUT_TOKENS: &str = "gen_ai.usage.input_tokens";
    pub const OUTPUT_TOKENS: &str = "gen_ai.usage.output_tokens";
    pub const MCP_METHOD: &str = "mcp.method.name";
    pub const MCP_SERVER: &str = "mcp.server.name";
}

/// Log record event names.
pub const DECISION_EVENT: &str = "nandi.decision";
pub const ADMIN_EVENT: &str = "nandi.admin";

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// An OTLP `AnyValue`.
pub fn any(value: Value) -> Value {
    match value {
        Value::Bool(b) => json!({ "boolValue": b }),
        Value::Number(n) if n.is_i64() || n.is_u64() => json!({ "intValue": n.to_string() }),
        Value::Number(n) => json!({ "doubleValue": n.as_f64() }),
        Value::String(s) => json!({ "stringValue": s }),
        other => json!({ "stringValue": other.to_string() }),
    }
}

/// An OTLP `KeyValue`.
pub fn kv(key: &str, value: Value) -> Value {
    json!({ "key": key, "value": any(value) })
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && s.bytes().any(|b| b != b'0')
}

/// 32 lowercase hex digits from a UUID (trace ids).
pub fn uuid_hex(id: &str) -> String {
    id.replace('-', "").to_ascii_lowercase()
}

/// A new random-enough span id: the random tail of a UUIDv7.
pub fn new_span_id() -> String {
    uuid_hex(&nandi_core::util::new_id())[16..].to_string()
}

/// A new trace id: a UUIDv7, whose last 7 bytes are random.
pub fn new_trace_id() -> String {
    uuid_hex(&nandi_core::util::new_id())
}

/// Trace id of an event: the propagated one, else one derived from the
/// event id (the event is then a trace of its own).
pub fn trace_id(ev: &nandi_core::Event) -> String {
    match &ev.trace_id {
        Some(t) if is_hex(t, 32) => t.clone(),
        _ => uuid_hex(&ev.id),
    }
}

/// Span id of an event, derived from the event id so spans and log records
/// agree without storing it.
pub fn span_id(ev: &nandi_core::Event) -> String {
    let h = uuid_hex(&ev.id);
    if is_hex(&h, 32) { h[16..].to_string() } else { new_span_id() }
}

fn parent_span_id(ev: &nandi_core::Event) -> Option<&str> {
    ev.parent_span_id.as_deref().filter(|p| is_hex(p, 16))
}

/// Name and attributes shared by the span and the log record of a decision.
fn describe(e: &LiveEvent) -> (String, Vec<Value>) {
    let (ev, d) = (&e.event, &e.decision);
    let mut attrs = vec![
        kv(attr::AGENT_ID, json!(ev.agent)),
        kv(attr::CONVERSATION, json!(ev.session)),
        kv("nandi.event.id", json!(ev.id)),
        kv("nandi.event.kind", json!(ev.kind_name())),
        kv("nandi.source", json!(format!("{:?}", ev.source).to_lowercase())),
        kv("nandi.verdict", json!(d.verdict.as_str())),
        kv("nandi.applied", json!(e.applied.as_str())),
        kv("nandi.enforced", json!(d.enforced)),
        kv("nandi.risk", json!(d.risk as f64)),
        kv("nandi.findings", json!(d.findings.len())),
    ];
    if let Some(seq) = e.seq {
        attrs.push(kv("nandi.audit.seq", json!(seq)));
    }
    if !d.findings.is_empty() {
        let rules: Vec<&str> = d.findings.iter().map(|f| f.rule.as_str()).collect();
        attrs.push(kv("nandi.rules", json!(rules.join(","))));
        if let Some(s) = d.findings.iter().map(|f| f.severity).max() {
            attrs.push(kv("nandi.severity", json!(s)));
        }
    }
    let name = match &ev.kind {
        EventKind::ToolCall(c) => {
            attrs.push(kv(attr::OPERATION, json!("execute_tool")));
            attrs.push(kv(attr::TOOL_NAME, json!(c.tool)));
            attrs.push(kv(attr::MCP_SERVER, json!(c.server)));
            attrs.push(kv(attr::MCP_METHOD, json!("tools/call")));
            if let Some(id) = &c.call_id {
                attrs.push(kv(attr::TOOL_CALL_ID, json!(id)));
            }
            format!("execute_tool {}", c.tool)
        }
        EventKind::ToolResult(r) => {
            attrs.push(kv(attr::TOOL_NAME, json!(r.tool)));
            attrs.push(kv(attr::MCP_SERVER, json!(r.server)));
            attrs.push(kv("nandi.tool.is_error", json!(r.is_error)));
            format!("tool_result {}", r.tool)
        }
        EventKind::ToolList(l) => {
            attrs.push(kv(attr::MCP_SERVER, json!(l.server)));
            attrs.push(kv(attr::MCP_METHOD, json!("tools/list")));
            attrs.push(kv("nandi.tools.count", json!(l.tools.len())));
            format!("tools/list {}", l.server)
        }
        EventKind::LlmRequest(r) => {
            attrs.push(kv(attr::OPERATION, json!("chat")));
            attrs.push(kv(attr::PROVIDER, json!(r.provider)));
            attrs.push(kv(attr::MODEL, json!(r.model)));
            format!("chat {}", r.model)
        }
        EventKind::LlmResponse(r) => {
            attrs.push(kv(attr::OPERATION, json!("chat")));
            attrs.push(kv(attr::PROVIDER, json!(r.provider)));
            attrs.push(kv(attr::MODEL, json!(r.model)));
            attrs.push(kv(attr::INPUT_TOKENS, json!(r.usage.input)));
            attrs.push(kv(attr::OUTPUT_TOKENS, json!(r.usage.output)));
            format!("chat {} response", r.model)
        }
        EventKind::A2aMessage(m) => {
            attrs.push(kv(attr::OPERATION, json!("invoke_agent")));
            attrs.push(kv("nandi.a2a.method", json!(m.method)));
            format!("invoke_agent {}", m.peer)
        }
        EventKind::Admin(a) => {
            attrs.push(kv("user.name", json!(a.actor)));
            attrs.push(kv("nandi.admin.action", json!(a.action)));
            attrs.push(kv("nandi.admin.target", json!(a.target)));
            attrs.push(kv("nandi.admin.outcome", json!(a.outcome)));
            if !a.details.is_null() {
                attrs.push(kv("nandi.admin.details", json!(a.details.to_string())));
            }
            format!("admin {}", a.action)
        }
        other => other.name().to_string(),
    };
    (name, attrs)
}

/// One span for an evaluated event, timed by its evaluation. Administrative
/// actions are not agent activity and have no span (they are log records).
pub fn span(e: &LiveEvent, duration_ns: u64) -> Option<Value> {
    if matches!(e.event.kind, EventKind::Admin(_)) {
        return None;
    }
    let (name, attrs) = describe(e);
    let ev = &e.event;
    let start = ev.ts_ms * 1_000_000;
    let status = if e.applied == Verdict::Deny {
        json!({ "code": 2, "message": e.decision.summary() })
    } else {
        json!({ "code": 0 })
    };
    let mut span = json!({
        "traceId": trace_id(ev),
        "spanId": span_id(ev),
        "name": name,
        "kind": 1,
        "startTimeUnixNano": start.to_string(),
        "endTimeUnixNano": (start + duration_ns.max(1)).to_string(),
        "attributes": attrs,
        "status": status,
    });
    if let Some(p) = parent_span_id(ev) {
        span["parentSpanId"] = json!(p);
    }
    Some(span)
}

/// OpenTelemetry severity of a decision: INFO for allowed, WARN for alerts,
/// redactions and holds, ERROR for denials.
fn severity(e: &LiveEvent) -> (u8, &'static str) {
    if let EventKind::Admin(a) = &e.event.kind {
        return match a.outcome.as_str() {
            "denied" | "failed" => (13, "WARN"),
            _ => (9, "INFO"),
        };
    }
    match e.decision.verdict.max(e.applied) {
        Verdict::Allow => (9, "INFO"),
        Verdict::Alert | Verdict::Redact | Verdict::Ask => (13, "WARN"),
        Verdict::Deny => (17, "ERROR"),
    }
}

/// One log record for a decision or an administrative action.
pub fn log_record(e: &LiveEvent, observed_ns: u64) -> Value {
    let (name, mut attrs) = describe(e);
    let admin = matches!(e.event.kind, EventKind::Admin(_));
    if !admin {
        attrs.push(kv("nandi.operation", json!(name)));
    }
    let (number, text) = severity(e);
    let mut rec = json!({
        "timeUnixNano": (e.event.ts_ms * 1_000_000).to_string(),
        "observedTimeUnixNano": observed_ns.to_string(),
        "severityNumber": number,
        "severityText": text,
        "eventName": if admin { ADMIN_EVENT } else { DECISION_EVENT },
        "body": any(json!(crate::exports::summary(e))),
        "attributes": attrs,
    });
    if !admin {
        rec["traceId"] = json!(trace_id(&e.event));
        rec["spanId"] = json!(span_id(&e.event));
    }
    rec
}

/// OTLP metrics for `series`: counters are cumulative monotonic sums since
/// `start_ns`, gauges are gauges, histograms carry per-bucket counts.
pub fn metrics(series: &[Series], start_ns: u64, now_ns: u64) -> Vec<Value> {
    let (start, now) = (start_ns.to_string(), now_ns.to_string());
    let attrs = |labels: &[(&str, String)]| -> Vec<Value> { labels.iter().map(|(k, v)| kv(k, json!(v))).collect() };
    series
        .iter()
        .map(|s| {
            let mut m = json!({ "name": s.otel, "description": s.help, "unit": s.unit });
            match &s.kind {
                SeriesKind::Counter => {
                    let points: Vec<Value> = s
                        .points
                        .iter()
                        .map(|(l, v)| {
                            json!({
                                "attributes": attrs(l),
                                "startTimeUnixNano": start,
                                "timeUnixNano": now,
                                "asInt": (*v as u64).to_string(),
                            })
                        })
                        .collect();
                    m["sum"] = json!({ "dataPoints": points, "aggregationTemporality": 2, "isMonotonic": true });
                }
                SeriesKind::Gauge => {
                    let points: Vec<Value> = s
                        .points
                        .iter()
                        .map(|(l, v)| json!({ "attributes": attrs(l), "timeUnixNano": now, "asDouble": v }))
                        .collect();
                    m["gauge"] = json!({ "dataPoints": points });
                }
                SeriesKind::Histogram(h) => {
                    // Prometheus buckets are cumulative; OTLP wants the count
                    // in each bucket, plus one for values above the last bound.
                    let mut counts = Vec::with_capacity(h.cumulative.len() + 1);
                    let mut prev = 0u64;
                    for c in h.cumulative.iter().chain(std::iter::once(&h.count)) {
                        counts.push(c.saturating_sub(prev).to_string());
                        prev = (*c).max(prev);
                    }
                    m["histogram"] = json!({
                        "dataPoints": [{
                            "startTimeUnixNano": start,
                            "timeUnixNano": now,
                            "count": h.count.to_string(),
                            "sum": h.sum,
                            "bucketCounts": counts,
                            "explicitBounds": h.bounds,
                        }],
                        "aggregationTemporality": 2,
                    });
                }
            }
            m
        })
        .collect()
}

fn scope() -> Value {
    json!({ "name": "nandi", "version": VERSION })
}

/// An `ExportTraceServiceRequest`.
pub fn traces_request(resource: &Value, spans: Vec<Value>) -> Value {
    json!({ "resourceSpans": [{ "resource": resource, "scopeSpans": [{ "scope": scope(), "spans": spans }] }] })
}

/// An `ExportLogsServiceRequest`.
pub fn logs_request(resource: &Value, records: Vec<Value>) -> Value {
    json!({ "resourceLogs": [{ "resource": resource, "scopeLogs": [{ "scope": scope(), "logRecords": records }] }] })
}

/// An `ExportMetricsServiceRequest`.
pub fn metrics_request(resource: &Value, metrics: Vec<Value>) -> Value {
    json!({ "resourceMetrics": [{ "resource": resource, "scopeMetrics": [{ "scope": scope(), "metrics": metrics }] }] })
}

/// A `Resource` with the given attributes.
pub fn resource(attrs: &[(String, Value)]) -> Value {
    json!({ "attributes": attrs.iter().map(|(k, v)| kv(k, v.clone())).collect::<Vec<_>>() })
}
