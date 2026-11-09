//! Proxy integration tests against mock upstreams on loopback.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use nandi_core::config::{ApiKey, Mode, Route, RouteKind, Spotlight};
use nandi_core::{Config, EventKind};
use nandi_identity::hash_key;
use nandi_policy::PolicySet;

use super::serve_on;
use crate::App;
use crate::client::full;

/// A request as the mock upstream received it.
#[derive(Clone, Debug)]
struct Seen {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
}

impl Seen {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

struct Reply {
    status: u16,
    content_type: &'static str,
    chunks: Vec<Bytes>,
}

fn json_reply(v: Value) -> Reply {
    Reply { status: 200, content_type: "application/json", chunks: vec![Bytes::from(v.to_string())] }
}

fn sse_reply(chunks: &[&str]) -> Reply {
    Reply {
        status: 200,
        content_type: "text/event-stream",
        chunks: chunks.iter().map(|c| Bytes::from(c.to_string())).collect(),
    }
}

struct Mock {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Mock {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().clone()
    }
}

async fn mock(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let handler = Arc::new(handler);
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (log, handler) = (log.clone(), handler.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let (log, handler) = (log.clone(), handler.clone());
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body.collect().await.unwrap().to_bytes();
                        let seen = Seen { method: parts.method, uri: parts.uri, headers: parts.headers, body };
                        let reply = handler(&seen);
                        log.lock().push(seen);
                        let frames = reply.chunks.into_iter().map(|c| Ok::<_, Infallible>(Frame::data(c)));
                        let resp = http::Response::builder()
                            .status(reply.status)
                            .header("content-type", reply.content_type)
                            .body(StreamBody::new(futures_util::stream::iter(frames)))
                            .unwrap();
                        Ok::<_, Infallible>(resp)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    Mock { url, seen }
}

fn route(name: &str, prefix: &str, upstream: &str, kind: RouteKind) -> Route {
    Route {
        name: name.into(),
        prefix: prefix.into(),
        upstream: upstream.into(),
        kind,
        provider: None,
        inject_headers: Default::default(),
        strip_headers: Vec::new(),
        timeout_secs: 10,
    }
}

fn enforce(routes: Vec<Route>) -> Config {
    Config { mode: Mode::Enforce, routes, ..Config::default() }
}

async fn start(cfg: Config, rules: &str) -> (Arc<App>, String) {
    let sources: Vec<&str> = if rules.is_empty() { Vec::new() } else { vec![rules] };
    let policy = PolicySet::from_sources(cfg.policy.default, None, None, &sources).unwrap();
    let app = App::ephemeral(cfg, policy).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve_on(app.clone(), listener, std::future::pending::<()>()));
    (app, url)
}

async fn send(
    app: &App,
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
    body: impl Into<Bytes>,
) -> (StatusCode, HeaderMap, Bytes) {
    let mut req = Request::builder().method(method).uri(url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = app.client.request(req.body(full(body.into())).unwrap()).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}

async fn post_json(app: &App, url: &str, headers: &[(&str, &str)], body: &Value) -> (StatusCode, HeaderMap, Bytes) {
    let mut all = vec![("content-type", "application/json"), ("accept", "application/json, text/event-stream")];
    all.extend_from_slice(headers);
    send(app, Method::POST, url, &all, body.to_string()).await
}

fn parse(body: &Bytes) -> Value {
    serde_json::from_slice(body).unwrap()
}

fn chat(model: &str) -> Value {
    json!({"model": model, "messages": [{"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}]})
}

fn completion() -> Value {
    json!({
        "id": "c1", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6}
    })
}

fn tools_list(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"})
}

fn tools_call(id: u64, name: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})
}

fn call_result(id: &Value, text: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": text}], "isError": false}})
}

/// Echo every `tools/call` in the body (single or batch) with a text result.
fn echo_calls(seen: &Seen) -> Reply {
    let replies: Vec<Value> = match seen.json() {
        Value::Array(items) => items.iter().map(|m| call_result(&m["id"], "ok")).collect(),
        one => return json_reply(call_result(&one["id"], "ok")),
    };
    json_reply(Value::Array(replies))
}

#[tokio::test]
async fn llm_json_passthrough_injects_upstream_credential() {
    let up = mock(|_| json_reply(completion())).await;
    let mut r = route("openai", "/openai", &format!("{}/v1", up.url), RouteKind::Llm);
    r.inject_headers.insert("authorization".into(), "Bearer upstream-test-token".into());
    let mut cfg = Config { routes: vec![r], ..Config::default() };
    cfg.identity.allow_anonymous = false;
    cfg.identity.api_keys =
        vec![ApiKey { agent: "bot".into(), sha256: hash_key("agent-test-key"), groups: vec!["ops".into()] }];
    let (app, url) = start(cfg, "").await;

    let (status, _, body) = post_json(
        &app,
        &format!("{url}/openai/chat/completions?trace=1"),
        &[("x-nandi-key", "agent-test-key"), ("authorization", "Bearer agent-supplied")],
        &chat("gpt-4o"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse(&body), completion());
    let seen = up.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, Method::POST);
    assert_eq!(seen[0].uri.to_string(), "/v1/chat/completions?trace=1");
    assert_eq!(seen[0].headers["authorization"], "Bearer upstream-test-token");
    assert!(!seen[0].headers.contains_key("x-nandi-key"));
    assert_eq!(seen[0].json(), chat("gpt-4o"));
    assert_eq!(app.metrics.upstream_requests.load(Relaxed), 1);
}

#[tokio::test]
async fn llm_request_blocked_by_model_rule() {
    let up = mock(|_| json_reply(completion())).await;
    let cfg = enforce(vec![route("openai", "/openai", &up.url, RouteKind::Llm)]);
    let rules = "rules:\n  - id: no-gpt3\n    match: { kind: llm, model: 'gpt-3*' }\n    action: deny\n";
    let (app, url) = start(cfg, rules).await;
    let (status, _, body) = post_json(&app, &format!("{url}/openai/v1/chat/completions"), &[], &chat("gpt-3.5")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let v = parse(&body);
    assert_eq!(v["error"]["type"], "nandi_policy");
    assert!(v["error"]["message"].as_str().unwrap().contains("no-gpt3"));
    assert!(up.seen().is_empty());
}

#[tokio::test]
async fn openai_stream_passes_through_and_records_tool_call() {
    const CHUNKS: &[&str] = &[
        "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n",
        "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\":\"}}]}}]}\n\n",
        "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"Paris\\\"}\"}}]}}]}\n\n",
        "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n",
    ];
    let up = mock(|_| sse_reply(CHUNKS)).await;
    let (app, url) = start(enforce(vec![route("openai", "/openai", &up.url, RouteKind::Llm)]), "").await;
    let mut live = app.recorder.subscribe();
    let mut req = chat("gpt-4o");
    req["stream"] = json!(true);
    let (status, headers, body) = post_json(&app, &format!("{url}/openai/v1/chat/completions"), &[], &req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers["content-type"].to_str().unwrap().starts_with("text/event-stream"));
    assert_eq!(body, Bytes::from(CHUNKS.concat()));

    let resp = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let entry = live.recv().await.unwrap();
            if let EventKind::LlmResponse(r) = &entry.event.kind {
                return r.clone();
            }
        }
    })
    .await
    .expect("llm_response recorded");
    assert_eq!(resp.tool_calls.len(), 1);
    assert_eq!(resp.tool_calls[0].name, "get_weather");
    assert_eq!(resp.tool_calls[0].args, json!({"city": "Paris"}));
}

#[tokio::test]
async fn mcp_drifted_tool_is_filtered_in_enforce_mode() {
    let n = Arc::new(AtomicUsize::new(0));
    let count = n.clone();
    let up = mock(move |seen| {
        let desc = if count.fetch_add(1, Relaxed) == 0 { "Search the web." } else { "Search the web for pages." };
        json_reply(json!({"jsonrpc": "2.0", "id": seen.json()["id"], "result": {"tools": [
            {"name": "search", "description": desc, "inputSchema": {"type": "object"}},
            {"name": "read_doc", "description": "Read a document.", "inputSchema": {"type": "object"}}
        ]}}))
    })
    .await;
    let (app, url) = start(enforce(vec![route("docs", "/mcp", &up.url, RouteKind::Mcp)]), "").await;
    let names = |body: &Bytes| -> Vec<String> {
        parse(body)["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().into()).collect()
    };
    let (status, _, body) = post_json(&app, &format!("{url}/mcp"), &[], &tools_list(1)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(names(&body), ["search", "read_doc"]);
    let (_, _, body) = post_json(&app, &format!("{url}/mcp"), &[], &tools_list(2)).await;
    assert_eq!(names(&body), ["read_doc"]);
}

#[tokio::test]
async fn mcp_denied_call_never_reaches_upstream() {
    let up = mock(echo_calls).await;
    let rules = "rules:\n  - id: no-delete\n    match: { tool: 'delete*' }\n    action: deny\n";
    let (app, url) = start(enforce(vec![route("git", "/mcp", &up.url, RouteKind::Mcp)]), rules).await;
    let (status, _, body) =
        post_json(&app, &format!("{url}/mcp"), &[], &tools_call(7, "delete_repo", json!({"repo": "x"}))).await;
    assert_eq!(status, StatusCode::OK);
    let v = parse(&body);
    assert_eq!(v["id"], 7);
    assert_eq!(v["result"]["isError"], true);
    assert!(v["result"]["content"][0]["text"].as_str().unwrap().contains("no-delete"));
    assert!(up.seen().is_empty());
}

#[tokio::test]
async fn mcp_mixed_batch_forwards_allowed_subset_and_merges_replies() {
    let up = mock(echo_calls).await;
    let rules = "rules:\n  - id: no-delete\n    match: { tool: 'delete*' }\n    action: deny\n";
    let (app, url) = start(enforce(vec![route("git", "/mcp", &up.url, RouteKind::Mcp)]), rules).await;
    let batch = json!([tools_call(1, "delete_repo", json!({})), tools_call(2, "list_repos", json!({}))]);
    let (status, _, body) = post_json(&app, &format!("{url}/mcp"), &[], &batch).await;
    assert_eq!(status, StatusCode::OK);
    let seen = up.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].json().as_array().unwrap().len(), 1);
    assert_eq!(seen[0].json()[0]["id"], 2);
    let v = parse(&body);
    let items = v.as_array().unwrap();
    assert_eq!(items.len(), 2);
    let blocked = items.iter().find(|m| m["id"] == 1).unwrap();
    assert_eq!(blocked["result"]["isError"], true);
    let allowed = items.iter().find(|m| m["id"] == 2).unwrap();
    assert_eq!(allowed["result"]["content"][0]["text"], "ok");
}

#[tokio::test]
async fn mcp_secret_in_arguments_is_redacted_before_upstream() {
    let up = mock(echo_calls).await;
    let (app, url) = start(enforce(vec![route("notes", "/mcp", &up.url, RouteKind::Mcp)]), "").await;
    let key = concat!("AKIA", "QYLPMN5HHHFPZAM2");
    let call = tools_call(3, "save_note", json!({"text": format!("my key is {key}")}));
    let (status, _, body) = post_json(&app, &format!("{url}/mcp"), &[], &call).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse(&body)["id"], 3);
    let seen = up.seen();
    assert_eq!(seen.len(), 1);
    let forwarded = seen[0].json();
    let text = forwarded["params"]["arguments"]["text"].as_str().unwrap();
    assert!(!text.contains(key), "secret reached upstream: {text}");
    assert!(text.starts_with("my key is "));
    assert_eq!(forwarded["params"]["name"], "save_note");
}

#[tokio::test]
async fn mcp_sse_tool_result_is_processed_per_event() {
    let up = mock(|seen| {
        let id = seen.json()["id"].clone();
        let progress = json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}});
        let result = call_result(&id, "hello world");
        sse_reply(&[&format!("data: {progress}\n\n"), &format!("event: message\ndata: {result}\n\n")])
    })
    .await;
    let mut cfg = enforce(vec![route("web", "/mcp", &up.url, RouteKind::Mcp)]);
    cfg.taint.spotlight = Spotlight::Delimit;
    let (app, url) = start(cfg, "").await;
    let (status, headers, body) =
        post_json(&app, &format!("{url}/mcp"), &[], &tools_call(1, "fetch_page", json!({"url": "https://a.example"})))
            .await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers["content-type"].to_str().unwrap().starts_with("text/event-stream"));
    let mut parser = nandi_proto::SseParser::new();
    let events = parser.feed(&body);
    assert_eq!(events.len(), 2);
    assert!(events[0].data.contains("notifications/progress"));
    assert_eq!(events[1].event.as_deref(), Some("message"));
    let msg: Value = serde_json::from_str(&events[1].data).unwrap();
    let text = msg["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("<<untrusted_tool_output>>") && text.contains("hello world"), "{text}");
}

#[tokio::test]
async fn mcp_header_mismatch_is_rejected() {
    let up = mock(echo_calls).await;
    let (app, url) = start(enforce(vec![route("git", "/mcp", &up.url, RouteKind::Mcp)]), "").await;
    let (status, _, body) = post_json(
        &app,
        &format!("{url}/mcp"),
        &[("mcp-method", "tools/call"), ("mcp-name", "read_file")],
        &tools_call(4, "delete_repo", json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let v = parse(&body);
    assert_eq!(v["error"]["code"], nandi_proto::mcp::HEADER_MISMATCH);
    assert_eq!(v["id"], 4);
    assert!(up.seen().is_empty());
}

#[tokio::test]
async fn missing_credentials_are_rejected_when_anonymous_is_off() {
    let up = mock(|_| json_reply(completion())).await;
    let mut cfg = Config { routes: vec![route("openai", "/openai", &up.url, RouteKind::Llm)], ..Config::default() };
    cfg.identity.allow_anonymous = false;
    let (app, url) = start(cfg, "").await;
    let (status, _, body) = post_json(&app, &format!("{url}/openai/v1/chat/completions"), &[], &chat("m")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(parse(&body)["error"].is_string());
    assert_eq!(app.metrics.auth_failures.load(Relaxed), 1);
    assert!(up.seen().is_empty());
}

#[tokio::test]
async fn unknown_route_and_dead_upstream() {
    let (app, url) = start(enforce(vec![route("dead", "/dead", "http://127.0.0.1:1", RouteKind::Llm)]), "").await;
    let (status, _, body) = send(&app, Method::GET, &format!("{url}/nowhere"), &[], "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse(&body), json!({"error": "no route"}));
    let (status, _, _) = send(&app, Method::GET, &format!("{url}/dead/models"), &[], "").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(app.metrics.upstream_errors.load(Relaxed), 1);
}

#[tokio::test]
async fn unsigned_agent_card_is_refused_when_signatures_are_required() {
    let up =
        mock(|_| json_reply(json!({"name": "Billing", "url": "https://billing.example", "skills": [{"id": "pay"}]})))
            .await;
    let mut cfg = enforce(vec![route("billing", "/billing", &up.url, RouteKind::A2a)]);
    cfg.a2a.require_signed_cards = true;
    let (app, url) = start(cfg, "").await;
    let (status, _, body) =
        send(&app, Method::GET, &format!("{url}/billing/.well-known/agent-card.json"), &[], "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(parse(&body)["error"]["message"].as_str().unwrap().contains("a2a.card-unsigned"));
    assert_eq!(up.seen()[0].uri.path(), "/.well-known/agent-card.json");
}

#[tokio::test]
async fn a2a_outbound_message_is_forwarded() {
    let reply = json!({"jsonrpc": "2.0", "id": 1, "result": {"message": {
        "role": "ROLE_AGENT", "messageId": "m2", "contextId": "ctx-1", "parts": [{"text": "invoice paid"}]
    }}});
    let r2 = reply.clone();
    let up = mock(move |_| json_reply(r2.clone())).await;
    let (app, url) = start(enforce(vec![route("billing", "/billing", &up.url, RouteKind::A2a)]), "").await;
    let mut live = app.recorder.subscribe();
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": {
        "role": "ROLE_USER", "messageId": "m1", "contextId": "ctx-1", "parts": [{"text": "pay invoice 42"}]
    }}});
    let (status, _, body) = post_json(&app, &format!("{url}/billing"), &[], &req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse(&body), reply);
    assert_eq!(up.seen()[0].json()["method"], "SendMessage");

    let mut directions = Vec::new();
    while directions.len() < 2 {
        let entry = tokio::time::timeout(Duration::from_secs(5), live.recv()).await.unwrap().unwrap();
        if let EventKind::A2aMessage(m) = &entry.event.kind {
            assert_eq!(m.peer, "billing");
            directions.push(m.direction);
        }
    }
    assert_eq!(directions, [nandi_core::Direction::Outbound, nandi_core::Direction::Inbound]);
}
