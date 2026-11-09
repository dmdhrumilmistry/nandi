//! MCP routes (Streamable HTTP). The server name is the route name.
//!
//! POSTed JSON-RPC messages are checked against the mirrored `Mcp-Method` /
//! `Mcp-Name` headers, and every `tools/call` is decided before it is
//! forwarded. A blocked call never reaches the server: its id is answered
//! with a tool error result. Responses (JSON or an SSE stream) are matched to
//! the requests of the same POST: `tools/list` results are filtered and
//! `tools/call` results are decided, blocked or rewritten. GET (the
//! server-to-client stream), DELETE and everything else pass through.

use std::collections::HashSet;
use std::sync::Arc;

use bytes::Bytes;
use http::{Response, StatusCode};
use serde_json::{Value, json};

use nandi_core::{Category, Decision, EventKind, Finding, Severity, ToolCall, ToolList, ToolResult, Verdict};
use nandi_proto::mcp::{self, IdTracker, JsonRpc};
use nandi_proto::sse::SseEvent;

use super::{
    Ctx, Outbound, Proxy, RouteState, buffer_body, header_str, id_string, is_json, is_sse, json_response, sse_relay,
    with_body, with_bytes,
};
use crate::App;
use crate::client::{Body, full};

enum CallOutcome {
    Pass,
    Rewrite(Value),
    Blocked(String),
}

pub(super) async fn handle(px: &Proxy, rs: &RouteState, ctx: Arc<Ctx>, out: Outbound, body: Bytes) -> Response<Body> {
    let server = rs.route.name.as_str();
    let mut doc: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(%server, "MCP body is not JSON ({e}), forwarding uninspected");
            return px.forward_bytes(rs, out, body).await;
        }
    };
    let msgs = match mcp::parse_value(&doc) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(%server, "MCP body is not JSON-RPC ({e}), forwarding uninspected");
            return px.forward_bytes(rs, out, body).await;
        }
    };
    let method_h = header_str(&out.headers, mcp::HEADER_METHOD);
    let name_h = header_str(&out.headers, mcp::HEADER_NAME);
    for m in &msgs {
        if let Err(e) = mcp::check_headers(method_h, name_h, m) {
            let id = m.id().cloned().unwrap_or(Value::Null);
            return json_response(StatusCode::BAD_REQUEST, &mcp::error_response(id, mcp::HEADER_MISMATCH, &e));
        }
    }

    let mut tracker = IdTracker::new(msgs.len());
    let mut synthesized: Vec<Value> = Vec::new();
    let mut blocked = vec![false; msgs.len()];
    let mut changed = false;
    for (i, m) in msgs.iter().enumerate() {
        let JsonRpc::Request { id, method, params } = m else { continue };
        if method == "tools/call"
            && let Some((tool, args)) = mcp::tool_call_params(params)
        {
            match inspect_call(&px.app, &ctx, server, id, tool, args).await {
                CallOutcome::Blocked(reason) => {
                    synthesized.push(json!({"jsonrpc": "2.0", "id": id, "result": mcp::blocked_call_result(&reason)}));
                    blocked[i] = true;
                    changed = true;
                    continue;
                }
                CallOutcome::Rewrite(args) => {
                    let item = if doc.is_array() { &mut doc[i] } else { &mut doc };
                    if let Some(params) = item.get_mut("params").and_then(Value::as_object_mut) {
                        params.insert("arguments".into(), args);
                        changed = true;
                    }
                }
                CallOutcome::Pass => {}
            }
        }
        tracker.track(m);
    }
    drop(msgs);
    let batch = doc.is_array();
    if blocked.iter().all(|b| *b) {
        // Nothing left to forward.
        let reply = if batch { Value::Array(synthesized) } else { synthesized.pop().unwrap_or(Value::Null) };
        return json_response(StatusCode::OK, &reply);
    }
    let fwd = if !changed {
        body
    } else {
        if let Value::Array(items) = &mut doc {
            let mut keep = blocked.iter().map(|b| !b);
            items.retain(|_| keep.next().unwrap_or(true));
        }
        Bytes::from(serde_json::to_vec(&doc).unwrap_or_default())
    };
    drop(doc);

    let resp = match px.send(rs, out.with_len(fwd.len()), full(fwd)).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let (parts, incoming) = resp.into_parts();
    if is_sse(&parts.headers) {
        let (mut relay, body) = sse_relay(incoming);
        let app = px.app.clone();
        let server = server.to_string();
        tokio::spawn(async move {
            for msg in &synthesized {
                if !relay.send(&SseEvent::data(msg.to_string())).await {
                    return;
                }
            }
            while let Some(events) = relay.next_events().await {
                for mut ev in events {
                    if !tracker.is_empty()
                        && let Ok(mut v) = serde_json::from_str::<Value>(&ev.data)
                        && process_messages(&app, &ctx, &server, &mut tracker, &mut v).await
                    {
                        ev.data = v.to_string();
                    }
                    if !relay.send(&ev).await {
                        return;
                    }
                }
            }
        });
        return with_body(parts, body, None);
    }
    if !is_json(&parts.headers) {
        if synthesized.is_empty() {
            return with_body(parts, super::passthrough_body(incoming), None);
        }
        // Typically 202 for forwarded notifications: answer the blocked calls.
        let reply = if batch { Value::Array(synthesized) } else { synthesized.pop().unwrap_or(Value::Null) };
        return json_response(StatusCode::OK, &reply);
    }
    let bytes = match buffer_body(incoming, super::MAX_BODY).await {
        Ok(b) => b,
        Err(body) => return with_body(parts, body, None),
    };
    if tracker.is_empty() && synthesized.is_empty() {
        return with_bytes(parts, bytes);
    }
    let mut v: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) if bytes.trim_ascii().is_empty() && !synthesized.is_empty() => Value::Array(Vec::new()),
        Err(e) => {
            tracing::debug!(%server, "MCP response is not JSON ({e}), passing through");
            return with_bytes(parts, bytes);
        }
    };
    let mut changed = process_messages(&px.app, &ctx, server, &mut tracker, &mut v).await;
    if !synthesized.is_empty() {
        let mut items = match v {
            Value::Array(items) => items,
            one => vec![one],
        };
        items.extend(synthesized);
        v = Value::Array(items);
        changed = true;
    }
    if !changed {
        return with_bytes(parts, bytes);
    }
    let mut parts = parts;
    parts.status = StatusCode::OK;
    with_bytes(parts, Bytes::from(serde_json::to_vec(&v).unwrap_or_default()))
}

async fn inspect_call(app: &App, ctx: &Ctx, server: &str, id: &Value, tool: String, args: Value) -> CallOutcome {
    let denied = match &ctx.principal.grant {
        Some(_) => app.auth.authorize_tool(&ctx.principal, server, &tool).err(),
        None => None,
    };
    let ev = ctx.event(EventKind::ToolCall(ToolCall {
        server: server.to_string(),
        tool,
        call_id: Some(id_string(id)),
        args,
    }));
    if let Some(e) = denied {
        // The capability token does not cover this tool: always enforced.
        let mut d = Decision { enforced: true, risk: 1.0, ..Decision::allow() };
        d.push(Finding::new(
            "identity.biscuit-scope",
            Category::Identity,
            Severity::High,
            Verdict::Deny,
            format!("the presented capability token does not allow this tool: {e}"),
        ));
        let reason = d.summary();
        app.metrics.observe(&ev, &d, 0);
        app.recorder.record(ev, d, Verdict::Deny, 0);
        return CallOutcome::Blocked(reason);
    }
    let v = app.decide(ev, ctx.groups()).await;
    if v.blocked() {
        CallOutcome::Blocked(v.reason())
    } else if let Some(rw) = v.rewrite() {
        CallOutcome::Rewrite(rw.clone())
    } else {
        CallOutcome::Pass
    }
}

/// Process one JSON-RPC message or a batch from the server. Returns true
/// when anything was rewritten.
async fn process_messages(app: &App, ctx: &Ctx, server: &str, tracker: &mut IdTracker, v: &mut Value) -> bool {
    match v {
        Value::Array(items) => {
            let mut changed = false;
            for item in items {
                changed |= process_message(app, ctx, server, tracker, item).await;
            }
            changed
        }
        one => process_message(app, ctx, server, tracker, one).await,
    }
}

async fn process_message(app: &App, ctx: &Ctx, server: &str, tracker: &mut IdTracker, msg: &mut Value) -> bool {
    let Some(obj) = msg.as_object_mut() else { return false };
    let Some(id) = obj.get("id").filter(|id| id.is_string() || id.is_number()) else { return false };
    if obj.contains_key("method") {
        // A server-to-client request, not a response.
        return false;
    }
    let Some((method, name)) = tracker.resolve(id) else { return false };
    let call_id = id_string(id);
    let Some(result) = obj.get_mut("result") else { return false };
    match method.as_str() {
        "tools/list" => {
            let Some(tools) = mcp::tools_list_result(result) else { return false };
            let ev = ctx.event(EventKind::ToolList(ToolList { server: server.to_string(), tools }));
            let v = app.decide(ev, ctx.groups()).await;
            let Some(keep) = v.rewrite().and_then(|rw| rw.get("keep")).and_then(Value::as_array) else {
                return false;
            };
            let keep: HashSet<&str> = keep.iter().filter_map(Value::as_str).collect();
            *result = mcp::rewrite_tools_list(result, &|t| keep.contains(t.name.as_str()));
            true
        }
        "tools/call" => {
            let (content, is_error) = mcp::call_result_content(result);
            let ev = ctx.event(EventKind::ToolResult(ToolResult {
                server: server.to_string(),
                tool: name.unwrap_or_default(),
                call_id: Some(call_id),
                content,
                is_error,
            }));
            let v = app.decide(ev, ctx.groups()).await;
            if v.blocked() {
                *result = mcp::blocked_call_result(&v.reason());
                return true;
            }
            match v.rewrite() {
                Some(rw) => apply_content_rewrite(result, rw),
                None => false,
            }
        }
        _ => false,
    }
}

/// Put a rewritten content array (as built by `call_result_content`) back
/// into a `tools/call` result: the `structuredContent` item becomes
/// `result.structuredContent` again, everything else is `result.content`.
fn apply_content_rewrite(result: &mut Value, rewrite: &Value) -> bool {
    let (Some(items), Some(obj)) = (rewrite.as_array(), result.as_object_mut()) else { return false };
    let mut content = Vec::with_capacity(items.len());
    let mut structured = None;
    for item in items {
        if item.get("type").and_then(Value::as_str) == Some("structuredContent") {
            structured = item.get("structuredContent").cloned();
        } else {
            content.push(item.clone());
        }
    }
    obj.insert("content".into(), Value::Array(content));
    match structured {
        Some(sc) => {
            obj.insert("structuredContent".into(), sc);
        }
        None => {
            obj.remove("structuredContent");
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_rewrite_splits_structured_content_back_out() {
        let mut result = json!({
            "content": [{"type": "text", "text": "secret"}],
            "structuredContent": {"v": "secret"},
            "isError": false
        });
        let (content, _) = mcp::call_result_content(&result);
        let mut rewritten = content.clone();
        rewritten[0]["text"] = json!("[redacted]");
        rewritten[1]["structuredContent"]["v"] = json!("[redacted]");
        assert!(apply_content_rewrite(&mut result, &rewritten));
        assert_eq!(result["content"], json!([{"type": "text", "text": "[redacted]"}]));
        assert_eq!(result["structuredContent"], json!({"v": "[redacted]"}));
        assert_eq!(result["isError"], json!(false));
    }
}
