//! LLM provider routes (OpenAI, Anthropic, Gemini and compatible APIs).
//!
//! The request is parsed into an `LlmRequest` event and decided before it is
//! forwarded (blocked: 403, redact: the body is redacted). Non-streaming
//! responses are decided before the client sees them, so a response asking
//! for a denied tool is replaced with a 403. Streaming responses pass
//! through byte for byte while being assembled on the side; the assembled
//! `LlmResponse` is recorded when the stream ends.

use std::sync::Arc;

use bytes::Bytes;
use serde_json::Value;

use nandi_core::util::sha256_hex;
use nandi_core::{EventKind, LlmRequest, Role};
use nandi_proto::llm::{self, Provider, StreamAssembler};
use nandi_proto::sse::SseParser;

use super::{
    Ctx, Outbound, Proxy, RouteState, StreamTap, TapBody, buffer_body, decide_later, is_json, is_sse, policy_block,
    with_body, with_bytes,
};
use crate::App;
use crate::client::{Body, full};
use http::Response;
use http_body_util::BodyExt;

pub(super) async fn handle(px: &Proxy, rs: &RouteState, mut ctx: Ctx, out: Outbound, body: Bytes) -> Response<Body> {
    let path = out.uri.path().to_string();
    let Some(provider) = rs.provider.or_else(|| Provider::detect(&path, out.uri.host().unwrap_or(""))) else {
        tracing::debug!(route = %rs.route.name, %path, "unknown LLM API, forwarding uninspected");
        return px.forward_bytes(rs, out, body).await;
    };
    let doc: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(route = %rs.route.name, "LLM request is not JSON ({e}), forwarding uninspected");
            return px.forward_bytes(rs, out, body).await;
        }
    };
    let Some(req) = llm::parse_request_value(provider, &path, &doc) else {
        tracing::debug!(route = %rs.route.name, %path, "unrecognized LLM request, forwarding uninspected");
        return px.forward_bytes(rs, out, body).await;
    };
    if !ctx.explicit_session
        && let Some(fp) = fingerprint(&req)
    {
        ctx.session = fp;
    }
    let ctx = Arc::new(ctx);
    let model = req.model.clone();
    let v = px.app.decide(ctx.event(EventKind::LlmRequest(req)), ctx.groups()).await;
    if v.blocked() {
        return policy_block(&v.reason());
    }
    let body = match v.rewrite() {
        Some(rw) if rw.get("redact").and_then(Value::as_bool) == Some(true) => match px.app.engine.redact(&doc) {
            Some(redacted) => serde_json::to_vec(&redacted).map(Bytes::from).unwrap_or(body),
            None => body,
        },
        _ => body,
    };
    drop(doc);

    let resp = match px.send(rs, out.with_len(body.len()), full(body)).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    if !resp.status().is_success() {
        return super::passthrough(resp);
    }
    let sse = is_sse(resp.headers());
    if sse || path.contains(":streamGenerateContent") {
        let (parts, incoming) = resp.into_parts();
        let tap = LlmTap {
            app: px.app.clone(),
            ctx,
            model,
            parser: sse.then(SseParser::new),
            asm: StreamAssembler::new(provider),
        };
        return with_body(parts, TapBody::new(incoming, Box::new(tap)).boxed(), None);
    }
    if !is_json(resp.headers()) {
        return super::passthrough(resp);
    }
    let (parts, incoming) = resp.into_parts();
    let bytes = match buffer_body(incoming, super::MAX_BODY).await {
        Ok(b) => b,
        Err(body) => return with_body(parts, body, None),
    };
    let Some(mut parsed) = llm::parse_response(provider, &bytes) else {
        tracing::debug!(route = %rs.route.name, "unrecognized LLM response, passing through");
        return with_bytes(parts, bytes);
    };
    if parsed.model.is_empty() {
        parsed.model = model;
    }
    let v = px.app.decide(ctx.event(EventKind::LlmResponse(parsed)), ctx.groups()).await;
    if v.blocked() {
        return policy_block(&v.reason());
    }
    with_bytes(parts, bytes)
}

/// Stable session id for a conversation: hash of the first system and the
/// first user message, so every turn of one conversation maps to the same
/// session without the agent naming it.
fn fingerprint(req: &LlmRequest) -> Option<String> {
    let first = |role: Role| req.messages.iter().find(|m| m.role == role).map(|m| m.text.as_str());
    let (system, user) = (first(Role::System), first(Role::User));
    if system.is_none() && user.is_none() {
        return None;
    }
    let mut buf = String::with_capacity(system.map_or(0, str::len) + user.map_or(0, str::len) + 1);
    buf.push_str(system.unwrap_or(""));
    buf.push('\u{1f}');
    buf.push_str(user.unwrap_or(""));
    let hex = sha256_hex(buf.as_bytes());
    Some(format!("llm-{}", &hex[..16]))
}

/// Assembles a streamed response on the side and records it at the end.
struct LlmTap {
    app: Arc<App>,
    ctx: Arc<Ctx>,
    model: String,
    /// `None` for Gemini's streamed JSON array.
    parser: Option<SseParser>,
    asm: StreamAssembler,
}

impl StreamTap for LlmTap {
    fn data(&mut self, chunk: &[u8]) {
        match &mut self.parser {
            Some(parser) => {
                for ev in parser.feed(chunk) {
                    self.asm.feed_event(&ev);
                }
            }
            None => self.asm.feed_bytes(chunk),
        }
    }

    fn end(self: Box<Self>) {
        let LlmTap { app, ctx, model, parser, mut asm } = *self;
        if let Some(ev) = parser.and_then(SseParser::finish) {
            asm.feed_event(&ev);
        }
        let mut resp = asm.finish();
        if resp.model.is_empty() {
            resp.model = model;
        }
        // The bytes are already with the client: record only.
        decide_later(&app, ctx.event(EventKind::LlmResponse(resp)), ctx.principal.groups.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::Message;

    fn msg(role: Role, text: &str) -> Message {
        Message { role, text: text.into(), tool_call_id: None, tool_name: None }
    }

    #[test]
    fn fingerprint_is_stable_across_turns() {
        let mut req = LlmRequest {
            provider: "openai".into(),
            model: "m".into(),
            stream: false,
            tools_offered: vec![],
            messages: vec![msg(Role::System, "be nice"), msg(Role::User, "hello")],
        };
        let a = fingerprint(&req).unwrap();
        req.messages.push(msg(Role::Assistant, "hi"));
        req.messages.push(msg(Role::User, "more"));
        assert_eq!(fingerprint(&req).unwrap(), a);
        req.messages[1].text = "other".into();
        assert_ne!(fingerprint(&req).unwrap(), a);
        req.messages.clear();
        assert_eq!(fingerprint(&req), None);
    }
}
