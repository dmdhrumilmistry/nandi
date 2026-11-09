//! Agent2Agent (A2A) protocol parsing.
//!
//! Understands A2A v1.0 (PascalCase JSON-RPC methods such as `SendMessage`,
//! `{"task": ...}` style response wrappers, parts without a `kind`,
//! `TASK_STATE_*` enums) and the pre-1.0 forms (`message/send`, `kind`
//! discriminators, lowercase states), over both the JSON-RPC binding and the
//! HTTP+JSON binding (`POST /message:send`, `GET /tasks/{id}`, ...).

use nandi_core::util::{canonical_json, flatten_text};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::util::{arr, get_any, push_text, s};

/// Well-known Agent Card path.
pub const WELL_KNOWN_CARD_PATH: &str = "/.well-known/agent-card.json";
/// Agent Card path used before A2A v0.3.
pub const LEGACY_CARD_PATH: &str = "/.well-known/agent.json";

/// True when `path` (query ignored) is a well-known Agent Card path.
pub fn is_card_path(path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or("");
    path.ends_with(WELL_KNOWN_CARD_PATH) || path.ends_with(LEGACY_CARD_PATH)
}

/// Map a pre-1.0 JSON-RPC method name to its v1.0 name. Unknown and v1.0
/// names are returned unchanged.
pub fn normalize_method(method: &str) -> &str {
    match method {
        "message/send" => "SendMessage",
        "message/stream" => "SendStreamingMessage",
        "tasks/get" => "GetTask",
        "tasks/cancel" => "CancelTask",
        "tasks/list" => "ListTasks",
        "tasks/resubscribe" => "SubscribeToTask",
        "agent/getAuthenticatedExtendedCard" | "agent/getExtendedCard" => "GetExtendedAgentCard",
        "tasks/pushNotificationConfig/set" => "CreateTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/get" => "GetTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/list" => "ListTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/delete" => "DeleteTaskPushNotificationConfig",
        other => other,
    }
}

/// True for methods answered with an SSE stream.
pub fn is_streaming_method(method: &str) -> bool {
    matches!(normalize_method(method), "SendStreamingMessage" | "SubscribeToTask")
}

/// Normalize a task state to the short lowercase form
/// (`TASK_STATE_INPUT_REQUIRED` and `input-required` both become
/// `input-required`).
pub fn normalize_state(state: &str) -> String {
    let st = state.strip_prefix("TASK_STATE_").unwrap_or(state).to_ascii_lowercase().replace('_', "-");
    if st == "cancelled" { "canceled".into() } else { st }
}

/// What nandi needs from an outbound A2A request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct A2aRequest {
    /// JSON-RPC method as sent, or the v1.0 name for the HTTP+JSON binding.
    pub method: String,
    pub context_id: Option<String>,
    pub task_id: Option<String>,
    /// Text of the message parts (data parts flattened to their strings).
    pub text: String,
    /// Requested skill from `message.metadata.skill`, `params.metadata.skill`
    /// or `params.configuration.skill`.
    pub skill: Option<String>,
    pub message_id: Option<String>,
}

/// What nandi needs from an A2A response or stream event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct A2aResponseInfo {
    /// `task`, `message`, `status-update` or `artifact-update`.
    pub kind: String,
    pub context_id: Option<String>,
    pub task_id: Option<String>,
    /// Normalized task state (see [`normalize_state`]).
    pub state: Option<String>,
    pub text: String,
}

/// Method and task id for an HTTP+JSON binding path.
fn http_binding(path: &str) -> Option<(String, Option<String>)> {
    let path = path.split(['?', '#']).next().unwrap_or("").trim_end_matches('/');
    if path.ends_with("/message:send") {
        return Some(("SendMessage".into(), None));
    }
    if path.ends_with("/message:stream") {
        return Some(("SendStreamingMessage".into(), None));
    }
    if path.ends_with("/extendedAgentCard") || path.ends_with("/card") {
        return Some(("GetExtendedAgentCard".into(), None));
    }
    if path.ends_with("/tasks") {
        return Some(("ListTasks".into(), None));
    }
    let rest = &path[path.rfind("/tasks/")? + "/tasks/".len()..];
    let (task, tail) = match rest.split_once('/') {
        Some((t, tail)) => (t, Some(tail)),
        None => (rest, None),
    };
    if tail.is_some_and(|t| t.starts_with("pushNotificationConfigs")) {
        return Some(("TaskPushNotificationConfig".into(), Some(task.to_string())));
    }
    let (id, method) = if let Some(id) = task.strip_suffix(":cancel") {
        (id, "CancelTask")
    } else if let Some(id) = task.strip_suffix(":subscribe") {
        (id, "SubscribeToTask")
    } else {
        (task, "GetTask")
    };
    (!id.is_empty()).then(|| (method.to_string(), Some(id.to_string())))
}

/// Text of message / artifact parts. Text parts (`kind`/`type` `text`, or a
/// v1.0 part with a `text` field) contribute their text; data parts their
/// string leaves. File parts are skipped.
pub fn parts_text(parts: &[Value]) -> String {
    let mut out = String::new();
    for p in parts {
        let kind = s(p, "kind").or_else(|| s(p, "type"));
        match (kind, s(p, "text")) {
            (None | Some("text"), Some(t)) => push_text(&mut out, t),
            _ if kind == Some("data") || (kind.is_none() && p.get("data").is_some()) => {
                push_text(&mut out, &flatten_text(p.get("data").unwrap_or(&Value::Null)))
            }
            _ => {}
        }
    }
    out
}

fn str_any(v: &Value, keys: &[&str]) -> Option<String> {
    get_any(v, keys).and_then(Value::as_str).map(str::to_string)
}

fn skill_of(v: Option<&Value>) -> Option<String> {
    v.and_then(|m| str_any(m, &["skill", "skillId", "skill_id"]))
}

/// Parse an outbound request: a JSON-RPC envelope (any binding path), or an
/// HTTP+JSON binding request identified by `path` (body may be empty for
/// `GET /tasks/{id}`).
pub fn parse_request(path: &str, body: &[u8]) -> Option<A2aRequest> {
    let trimmed = body.trim_ascii();
    let v: Value = if trimmed.is_empty() { Value::Null } else { serde_json::from_slice(trimmed).ok()? };
    parse_request_value(path, &v)
}

/// [`parse_request`] on an already parsed body.
pub fn parse_request_value(path: &str, v: &Value) -> Option<A2aRequest> {
    let (method, params, path_task) = match s(v, "method") {
        Some(m) if v.get("jsonrpc").is_some() || v.get("id").is_some() => {
            (m.to_string(), v.get("params").unwrap_or(&Value::Null), None)
        }
        _ => {
            let (m, task) = http_binding(path)?;
            (m, v, task)
        }
    };
    let message = params.get("message").or_else(|| params.get("msg")).filter(|m| m.is_object());
    let empty = Value::Null;
    let msg = message.unwrap_or(&empty);
    let task_id = path_task
        .or_else(|| str_any(msg, &["taskId", "task_id"]))
        .or_else(|| str_any(params, &["taskId", "task_id", "id"]))
        .or_else(|| {
            s(params, "name")
                .and_then(|n| n.strip_prefix("tasks/"))
                .map(|n| n.split('/').next().unwrap_or(n).to_string())
        });
    Some(A2aRequest {
        method,
        context_id: str_any(msg, &["contextId", "context_id"])
            .or_else(|| str_any(params, &["contextId", "context_id"])),
        task_id,
        text: parts_text(arr(msg, "parts")),
        skill: skill_of(msg.get("metadata"))
            .or_else(|| skill_of(params.get("metadata")))
            .or_else(|| skill_of(params.get("configuration"))),
        message_id: str_any(msg, &["messageId", "message_id"]),
    })
}

/// Parse a response body or one SSE `data:` payload.
pub fn parse_response(body: &[u8]) -> Option<A2aResponseInfo> {
    let v: Value = serde_json::from_slice(body.trim_ascii()).ok()?;
    parse_response_value(&v)
}

/// [`parse_response`] on an already parsed value. JSON-RPC errors give `None`.
pub fn parse_response_value(v: &Value) -> Option<A2aResponseInfo> {
    let mut v = v;
    if v.get("jsonrpc").is_some() || v.get("error").is_some() {
        if v.get("error").is_some_and(|e| !e.is_null()) {
            return None;
        }
        v = v.get("result")?;
    }
    let mut kind = s(v, "kind").map(str::to_string);
    if kind.is_none() {
        let wrappers = [
            ("task", "task"),
            ("message", "message"),
            ("msg", "message"),
            ("statusUpdate", "status-update"),
            ("artifactUpdate", "artifact-update"),
        ];
        for (key, k) in wrappers {
            if let Some(inner) = v.get(key).filter(|i| i.is_object())
                && v.get("parts").is_none()
                && v.get("status").is_none()
            {
                v = inner;
                kind = Some(k.into());
                break;
            }
        }
    }
    let kind = match kind {
        Some(k) => k,
        None if v.get("artifact").is_some() => "artifact-update".into(),
        None if v.get("status").is_some() && v.get("taskId").is_some() => "status-update".into(),
        None if v.get("status").is_some() && v.get("id").is_some() => "task".into(),
        None if v.get("parts").is_some() => "message".into(),
        None => return None,
    };
    let status = v.get("status").unwrap_or(&Value::Null);
    let state = s(status, "state").map(normalize_state);
    let status_text = status.get("message").map(|m| parts_text(arr(m, "parts"))).unwrap_or_default();
    let mut info = A2aResponseInfo {
        kind: kind.clone(),
        context_id: str_any(v, &["contextId", "context_id"]),
        task_id: str_any(v, &["taskId", "task_id"]),
        state,
        text: String::new(),
    };
    match kind.as_str() {
        "task" => {
            info.task_id = str_any(v, &["id"]).or(info.task_id);
            push_text(&mut info.text, &status_text);
            for a in arr(v, "artifacts") {
                push_text(&mut info.text, &parts_text(arr(a, "parts")));
            }
        }
        "message" => info.text = parts_text(arr(v, "parts")),
        "status-update" => info.text = status_text,
        "artifact-update" => {
            info.text = v.get("artifact").map(|a| parts_text(arr(a, "parts"))).unwrap_or_default();
        }
        _ => return None,
    }
    Some(info)
}

/// One JWS signature attached to an Agent Card.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CardSignature {
    /// Base64url protected header (JSON with `alg`, `kid`, ...).
    pub protected: String,
    /// Base64url signature.
    pub signature: String,
    /// Unprotected header, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Value>,
}

/// The parts of an Agent Card nandi uses.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CardInfo {
    pub name: String,
    /// Primary endpoint: `url`, else the first `supportedInterfaces` /
    /// `additionalInterfaces` entry.
    pub url: String,
    /// Skill ids (name when a skill has no id).
    pub skills: Vec<String>,
    pub signatures: Vec<CardSignature>,
}

/// Extract [`CardInfo`] from an Agent Card. Missing fields are left empty;
/// malformed signature entries are skipped.
pub fn parse_card(card: &Value) -> CardInfo {
    let url = s(card, "url").map(str::to_string).or_else(|| {
        ["supportedInterfaces", "additionalInterfaces"]
            .iter()
            .flat_map(|k| arr(card, k))
            .find_map(|i| s(i, "url").map(str::to_string))
    });
    CardInfo {
        name: s(card, "name").unwrap_or_default().to_string(),
        url: url.unwrap_or_default(),
        skills: arr(card, "skills")
            .iter()
            .filter_map(|sk| s(sk, "id").or_else(|| s(sk, "name")).map(str::to_string))
            .collect(),
        signatures: arr(card, "signatures").iter().filter_map(|sig| serde_json::from_value(sig.clone()).ok()).collect(),
    }
}

/// The bytes an Agent Card signature covers: canonical JSON (RFC 8785
/// style) of the card with `signatures` removed.
pub fn card_signing_payload(card: &Value) -> String {
    let mut c = card.clone();
    if let Some(obj) = c.as_object_mut() {
        obj.remove("signatures");
    }
    canonical_json(&c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn card_paths_and_methods() {
        assert!(is_card_path("/.well-known/agent-card.json"));
        assert!(is_card_path("/agents/x/.well-known/agent.json?v=1"));
        assert!(!is_card_path("/message:send"));
        assert_eq!(normalize_method("message/send"), "SendMessage");
        assert_eq!(normalize_method("SendMessage"), "SendMessage");
        assert!(is_streaming_method("message/stream"));
        assert!(is_streaming_method("SubscribeToTask"));
        assert!(!is_streaming_method("GetTask"));
        assert_eq!(normalize_state("TASK_STATE_INPUT_REQUIRED"), "input-required");
        assert_eq!(normalize_state("completed"), "completed");
        assert_eq!(normalize_state("TASK_STATE_CANCELLED"), "canceled");
    }

    #[test]
    fn v1_send_message_jsonrpc() {
        let body = json!({
            "jsonrpc": "2.0", "id": "req-1", "method": "SendMessage",
            "params": {
                "message": {
                    "role": "ROLE_USER", "messageId": "m-1", "contextId": "ctx-9",
                    "parts": [{"text": "Book a flight to Lisbon"}, {"data": {"budget": "500 EUR"}}],
                    "metadata": {"skill": "book_flight"}
                },
                "configuration": {"acceptedOutputModes": ["text/plain"]}
            }
        });
        let r = parse_request("/a2a", body.to_string().as_bytes()).unwrap();
        assert_eq!(r.method, "SendMessage");
        assert_eq!(r.context_id.as_deref(), Some("ctx-9"));
        assert_eq!(r.message_id.as_deref(), Some("m-1"));
        assert_eq!(r.skill.as_deref(), Some("book_flight"));
        assert_eq!(r.text, "Book a flight to Lisbon\n500 EUR");
        assert_eq!(r.task_id, None);
    }

    #[test]
    fn legacy_message_send() {
        let body = json!({
            "jsonrpc": "2.0", "id": 1, "method": "message/send",
            "params": {
                "message": {"kind": "message", "role": "user", "messageId": "m-2", "taskId": "t-1",
                    "parts": [{"kind": "text", "text": "status?"}, {"kind": "file", "file": {"uri": "x"}}]},
                "metadata": {"skillId": "lookup"}
            }
        });
        let r = parse_request("/", body.to_string().as_bytes()).unwrap();
        assert_eq!(r.method, "message/send");
        assert_eq!(r.task_id.as_deref(), Some("t-1"));
        assert_eq!(r.skill.as_deref(), Some("lookup"));
        assert_eq!(r.text, "status?");

        let get =
            parse_request("/", br#"{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"t-7"}}"#).unwrap();
        assert_eq!(get.task_id.as_deref(), Some("t-7"));
    }

    #[test]
    fn http_json_binding() {
        let body =
            json!({"message": {"messageId": "m", "parts": [{"text": "hi"}]}, "configuration": {"skill": "chat"}});
        let r = parse_request("/v1/message:send", body.to_string().as_bytes()).unwrap();
        assert_eq!(r.method, "SendMessage");
        assert_eq!(r.skill.as_deref(), Some("chat"));
        assert_eq!(parse_request("/v1/message:stream", b"{}").unwrap().method, "SendStreamingMessage");
        let get = parse_request("/v1/tasks/abc", b"").unwrap();
        assert_eq!((get.method.as_str(), get.task_id.as_deref()), ("GetTask", Some("abc")));
        let cancel = parse_request("/v1/tasks/abc:cancel", b"{}").unwrap();
        assert_eq!((cancel.method.as_str(), cancel.task_id.as_deref()), ("CancelTask", Some("abc")));
        assert_eq!(parse_request("/v1/tasks/abc:subscribe", b"").unwrap().method, "SubscribeToTask");
        assert_eq!(parse_request("/v1/tasks", b"").unwrap().method, "ListTasks");
        assert_eq!(parse_request("/v1/extendedAgentCard", b"").unwrap().method, "GetExtendedAgentCard");
        assert!(parse_request("/v1/other", b"{}").is_none());
    }

    #[test]
    fn responses_v1_and_legacy() {
        let v1_task = json!({"jsonrpc": "2.0", "id": "1", "result": {"task": {
            "id": "t-1", "contextId": "c-1",
            "status": {"state": "TASK_STATE_COMPLETED", "message": {"role": "ROLE_AGENT", "parts": [{"text": "Done."}]}},
            "artifacts": [{"artifactId": "a", "parts": [{"text": "Ticket #42"}]}]
        }}});
        let i = parse_response(v1_task.to_string().as_bytes()).unwrap();
        assert_eq!(i.kind, "task");
        assert_eq!(i.task_id.as_deref(), Some("t-1"));
        assert_eq!(i.context_id.as_deref(), Some("c-1"));
        assert_eq!(i.state.as_deref(), Some("completed"));
        assert_eq!(i.text, "Done.\nTicket #42");

        let legacy_msg = json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message", "role": "agent", "messageId": "x",
            "contextId": "c-2", "parts": [{"kind": "text", "text": "Hello"}]}});
        let i = parse_response(legacy_msg.to_string().as_bytes()).unwrap();
        assert_eq!((i.kind.as_str(), i.text.as_str(), i.state), ("message", "Hello", None));

        let status = json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "status-update", "taskId": "t", "contextId": "c",
            "status": {"state": "input-required", "message": {"parts": [{"kind": "text", "text": "Which date?"}]}}, "final": false}});
        let i = parse_response(status.to_string().as_bytes()).unwrap();
        assert_eq!(i.state.as_deref(), Some("input-required"));
        assert_eq!(i.text, "Which date?");

        let artifact =
            json!({"artifactUpdate": {"taskId": "t", "contextId": "c", "artifact": {"parts": [{"text": "chunk"}]}}});
        let i = parse_response(artifact.to_string().as_bytes()).unwrap();
        assert_eq!((i.kind.as_str(), i.text.as_str()), ("artifact-update", "chunk"));

        let status_v1 =
            json!({"statusUpdate": {"taskId": "t", "contextId": "c", "status": {"state": "TASK_STATE_WORKING"}}});
        assert_eq!(parse_response(status_v1.to_string().as_bytes()).unwrap().state.as_deref(), Some("working"));

        assert!(
            parse_response(br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}"#).is_none()
        );
        assert!(parse_response(br#"{"tasks":[]}"#).is_none());
    }

    #[test]
    fn card_parsing_and_payload() {
        let card = json!({
            "name": "Travel Agent",
            "description": "Books trips",
            "supportedInterfaces": [{"url": "https://travel.example/a2a", "protocolBinding": "JSONRPC"}],
            "skills": [{"id": "book_flight", "name": "Book flight"}, {"name": "no_id"}],
            "signatures": [{"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "c2ln", "header": {"kid": "k1"}}, {"bogus": 1}]
        });
        let info = parse_card(&card);
        assert_eq!(info.name, "Travel Agent");
        assert_eq!(info.url, "https://travel.example/a2a");
        assert_eq!(info.skills, vec!["book_flight", "no_id"]);
        assert_eq!(info.signatures.len(), 1);
        assert_eq!(info.signatures[0].header, Some(json!({"kid": "k1"})));
        let payload = card_signing_payload(&card);
        assert!(!payload.contains("signatures"));
        assert!(payload.starts_with("{\"description\":"));
        let mut reordered = card.clone();
        reordered["signatures"] = json!([]);
        assert_eq!(card_signing_payload(&reordered), payload);
        assert_eq!(parse_card(&json!({"url": "https://x"})).url, "https://x");
    }
}
