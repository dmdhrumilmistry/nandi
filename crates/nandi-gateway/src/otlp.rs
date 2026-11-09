//! Minimal OTLP/HTTP JSON trace exporter.
//!
//! Spans follow the OpenTelemetry GenAI semantic conventions where they
//! apply (`execute_tool {name}`, `chat {model}`, `invoke_agent {peer}`,
//! `gen_ai.*` attributes, `mcp.method.name`), plus `nandi.*` attributes for
//! the decision. JSON encoding avoids pulling in protobuf and gRPC.

use serde_json::{Value, json};

use nandi_core::util::new_id;
use nandi_core::{Decision, Event, EventKind, Verdict};

/// Attribute names in one place so semantic-convention renames are a
/// one-line change.
mod attr {
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

fn kv(key: &str, value: Value) -> Value {
    let v = match value {
        Value::Bool(b) => json!({ "boolValue": b }),
        Value::Number(n) if n.is_i64() || n.is_u64() => json!({ "intValue": n.to_string() }),
        Value::Number(n) => json!({ "doubleValue": n.as_f64() }),
        Value::String(s) => json!({ "stringValue": s }),
        other => json!({ "stringValue": other.to_string() }),
    };
    json!({ "key": key, "value": v })
}

fn hex_id(bytes: usize) -> String {
    // UUIDv7 ids are unique and cheap; take hex digits from two of them.
    let mut s = new_id().replace('-', "");
    s.push_str(&new_id().replace('-', ""));
    s.chars().rev().take(bytes * 2).collect()
}

/// Build one span for an evaluated event.
pub fn span(ev: &Event, d: &Decision, applied: Verdict, duration_ns: u64) -> Value {
    let mut attrs = vec![
        kv(attr::AGENT_ID, json!(ev.agent)),
        kv(attr::CONVERSATION, json!(ev.session)),
        kv("nandi.source", json!(format!("{:?}", ev.source).to_lowercase())),
        kv("nandi.verdict", json!(d.verdict.as_str())),
        kv("nandi.applied", json!(applied.as_str())),
        kv("nandi.enforced", json!(d.enforced)),
        kv("nandi.risk", json!(d.risk as f64)),
        kv("nandi.findings", json!(d.findings.len())),
    ];
    if !d.findings.is_empty() {
        let rules: Vec<&str> = d.findings.iter().map(|f| f.rule.as_str()).collect();
        attrs.push(kv("nandi.rules", json!(rules.join(","))));
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
        other => other.name().to_string(),
    };
    let end = ev.ts_ms * 1_000_000 + duration_ns.max(1);
    let trace_id = ev.trace_id.clone().filter(|t| t.len() == 32).unwrap_or_else(|| hex_id(16));
    let status = if applied == Verdict::Deny { json!({"code": 2, "message": d.summary()}) } else { json!({"code": 0}) };
    json!({
        "traceId": trace_id,
        "spanId": hex_id(8),
        "name": name,
        "kind": 1,
        "startTimeUnixNano": (ev.ts_ms * 1_000_000).to_string(),
        "endTimeUnixNano": end.to_string(),
        "attributes": attrs,
        "status": status,
    })
}

/// Wrap spans in an `ExportTraceServiceRequest`.
pub fn export_request(service_name: &str, spans: Vec<Value>) -> Value {
    json!({
        "resourceSpans": [{
            "resource": { "attributes": [kv("service.name", json!(service_name))] },
            "scopeSpans": [{
                "scope": { "name": "nandi", "version": env!("CARGO_PKG_VERSION") },
                "spans": spans,
            }]
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::{Source, ToolCall};

    #[test]
    fn tool_call_span_uses_genai_conventions() {
        let ev = Event::new(
            Source::Proxy,
            "agent-1",
            "s1",
            EventKind::ToolCall(ToolCall {
                server: "github".into(),
                tool: "create_issue".into(),
                call_id: Some("c1".into()),
                args: json!({}),
            }),
        );
        let s = span(&ev, &Decision::allow(), Verdict::Allow, 1000);
        assert_eq!(s["name"], "execute_tool create_issue");
        assert_eq!(s["traceId"].as_str().unwrap().len(), 32);
        assert_eq!(s["spanId"].as_str().unwrap().len(), 16);
        let text = s.to_string();
        assert!(text.contains("gen_ai.tool.name"));
        assert!(text.contains("\"mcp.method.name\""));
        let req = export_request("nandi", vec![s]);
        assert_eq!(req["resourceSpans"][0]["scopeSpans"][0]["spans"].as_array().unwrap().len(), 1);
    }
}
