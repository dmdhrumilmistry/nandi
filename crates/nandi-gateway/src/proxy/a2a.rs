//! A2A routes. The peer name is the route name.
//!
//! Agent Cards fetched through the gateway are verified against the trusted
//! keys and decided (unsigned or tampered cards can be refused). Outbound
//! messages are decided before they are forwarded; inbound messages, tasks
//! and stream events are decided before the caller sees them, and a blocked
//! one is replaced with a JSON-RPC error.

use std::sync::Arc;

use http::{Method, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::Value;

use nandi_core::{A2aMessage, AgentCardSeen, Direction, EventKind};
use nandi_identity::verify_card;
use nandi_proto::a2a;
use nandi_proto::mcp::{BLOCKED_BY_POLICY, BLOCKED_BY_POLICY_MESSAGE, error_response};

use super::{
    Ctx, Outbound, Proxy, RouteState, buffer_body, is_json, is_sse, json_response, passthrough, passthrough_body,
    policy_block, read_body, sse_relay, with_body, with_bytes,
};
use crate::App;
use crate::client::{Body, empty, full};

pub(super) async fn handle(
    px: &Proxy,
    rs: &RouteState,
    ctx: Arc<Ctx>,
    out: Outbound,
    body: Incoming,
) -> Response<Body> {
    let path = out.uri.path().to_string();
    if out.method == Method::GET && a2a::is_card_path(&path) {
        return card(px, rs, &ctx, out).await;
    }
    let peer = rs.route.name.as_str();
    let mut method: Option<String> = None;
    let mut jsonrpc = false;
    let mut req_id = Value::Null;
    let resp = if out.method == Method::POST {
        let bytes = match read_body(&out.headers, body).await {
            Ok(b) => b,
            Err(r) => return r,
        };
        let doc = if bytes.trim_ascii().is_empty() { Ok(Value::Null) } else { serde_json::from_slice(&bytes) };
        match doc {
            Ok(doc) => {
                jsonrpc = doc.get("jsonrpc").is_some();
                req_id = doc.get("id").cloned().unwrap_or(Value::Null);
                if let Some(req) = a2a::parse_request_value(&path, &doc) {
                    method = Some(req.method.clone());
                    let ev = ctx.event(EventKind::A2aMessage(A2aMessage {
                        peer: peer.to_string(),
                        method: req.method,
                        direction: Direction::Outbound,
                        context_id: req.context_id,
                        task_id: req.task_id,
                        skill: req.skill,
                        text: req.text,
                    }));
                    let v = px.app.decide(ev, ctx.groups()).await;
                    if v.blocked() {
                        let reason = v.reason();
                        return if jsonrpc { blocked_rpc(req_id, &reason) } else { policy_block(&reason) };
                    }
                } else {
                    tracing::debug!(%peer, %path, "unrecognized A2A request, forwarding uninspected");
                }
            }
            Err(e) => tracing::debug!(%peer, "A2A request is not JSON ({e}), forwarding uninspected"),
        }
        px.send(rs, out.with_len(bytes.len()), full(bytes)).await
    } else {
        px.send(rs, out, passthrough_body(body)).await
    };
    let resp = match resp {
        Ok(r) => r,
        Err(r) => return r,
    };
    if !resp.status().is_success() {
        return passthrough(resp);
    }
    let method = method.unwrap_or_else(|| "response".into());
    let (parts, incoming) = resp.into_parts();
    if is_sse(&parts.headers) {
        let (mut relay, body) = sse_relay(incoming);
        let app = px.app.clone();
        let peer = peer.to_string();
        tokio::spawn(async move {
            while let Some(events) = relay.next_events().await {
                for mut ev in events {
                    if let Ok(v) = serde_json::from_str::<Value>(&ev.data)
                        && let Some(reason) = inbound(&app, &ctx, &peer, &method, &v).await
                    {
                        let id = v.get("id").cloned().unwrap_or_else(|| req_id.clone());
                        ev.data = blocked_error(id, &reason).to_string();
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
        return with_body(parts, passthrough_body(incoming), None);
    }
    let bytes = match buffer_body(incoming, super::MAX_BODY).await {
        Ok(b) => b,
        Err(body) => return with_body(parts, body, None),
    };
    let Ok(mut v) = serde_json::from_slice::<Value>(&bytes) else {
        return with_bytes(parts, bytes);
    };
    let mut changed = false;
    match &mut v {
        Value::Array(items) => {
            for item in items {
                if let Some(reason) = inbound(&px.app, &ctx, peer, &method, item).await {
                    *item = blocked_error(item.get("id").cloned().unwrap_or(Value::Null), &reason);
                    changed = true;
                }
            }
        }
        one => {
            if let Some(reason) = inbound(&px.app, &ctx, peer, &method, one).await {
                if !jsonrpc && one.get("jsonrpc").is_none() {
                    return policy_block(&reason);
                }
                *one = blocked_error(one.get("id").cloned().unwrap_or(req_id), &reason);
                changed = true;
            }
        }
    }
    if !changed {
        return with_bytes(parts, bytes);
    }
    with_bytes(parts, serde_json::to_vec(&v).unwrap_or_default().into())
}

/// Decide one inbound message / task / event. Returns the block reason.
async fn inbound(app: &App, ctx: &Ctx, peer: &str, method: &str, v: &Value) -> Option<String> {
    let info = a2a::parse_response_value(v)?;
    let ev = ctx.event(EventKind::A2aMessage(A2aMessage {
        peer: peer.to_string(),
        method: method.to_string(),
        direction: Direction::Inbound,
        context_id: info.context_id,
        task_id: info.task_id,
        skill: None,
        text: info.text,
    }));
    let v = app.decide(ev, ctx.groups()).await;
    v.blocked().then(|| v.reason())
}

async fn card(px: &Proxy, rs: &RouteState, ctx: &Ctx, out: Outbound) -> Response<Body> {
    let resp = match px.send(rs, out, empty()).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    if !resp.status().is_success() {
        return passthrough(resp);
    }
    let (parts, incoming) = resp.into_parts();
    let bytes = match buffer_body(incoming, super::MAX_BODY).await {
        Ok(b) => b,
        Err(body) => return with_body(parts, body, None),
    };
    let Ok(doc) = serde_json::from_slice::<Value>(&bytes) else {
        tracing::debug!(peer = %rs.route.name, "Agent Card is not JSON, passing through");
        return with_bytes(parts, bytes);
    };
    let verification = verify_card(&doc, &px.app.card_keys);
    if let Some(e) = &verification.error {
        tracing::debug!(peer = %rs.route.name, "Agent Card signature: {e}");
    }
    let info = a2a::parse_card(&doc);
    let ev = ctx.event(EventKind::AgentCard(AgentCardSeen {
        peer: rs.route.name.clone(),
        url: info.url,
        name: info.name,
        digest: verification.digest,
        signature_valid: verification.signature_valid,
        signer: verification.signer,
        skills: info.skills,
    }));
    let v = px.app.decide(ev, ctx.groups()).await;
    if v.blocked() {
        return policy_block(&v.reason());
    }
    with_bytes(parts, bytes)
}

fn blocked_error(id: Value, reason: &str) -> Value {
    error_response(id, BLOCKED_BY_POLICY, &format!("{BLOCKED_BY_POLICY_MESSAGE}: {reason}"))
}

fn blocked_rpc(id: Value, reason: &str) -> Response<Body> {
    json_response(StatusCode::OK, &blocked_error(id, reason))
}
