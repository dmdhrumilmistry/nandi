//! Admin API, dashboard and metrics endpoint.
//!
//! All endpoints speak JSON except `/metrics` (Prometheus text), `/` (the
//! dashboard page) and `/v1/events/stream` (server-sent events).
//!
//! Access control:
//! - With `admin.token` set, every endpoint except `/healthz` and the
//!   dashboard page requires `Authorization: Bearer <token>`. The page's own
//!   script sends the token for its API calls.
//! - Without a token, only loopback peers are accepted, the `Host` header
//!   must name a loopback address (DNS rebinding) and state-changing requests
//!   carrying a foreign `Origin` are refused (cross-site requests).

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, Query as QueryParams, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{broadcast, watch};

use nandi_audit::Query;
use nandi_core::Verdict;
use nandi_core::config::resolve_secret;
use nandi_core::util::sha256_hex;
use nandi_discover::Inventory;
use nandi_policy::PolicySet;

use crate::App;
use crate::hook::{self, HookFormat};
use crate::recorder::LiveEvent;
use crate::users::{Origin, Permission, Principal};

/// Largest inventory accepted by `POST /v1/inventory`.
const MAX_INVENTORY_BYTES: usize = 2 << 20;
/// State store prefix of reported inventories, one key per host.
const INVENTORY_PREFIX: &str = "inventory/";

/// Default and maximum page size of `GET /v1/events`.
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

/// The dashboard, a single self-contained page.
const INDEX_HTML: &str = include_str!("../ui/index.html");

#[derive(Clone)]
struct AdminState {
    app: Arc<App>,
    /// SHA-256 of the configured bearer token, when one is set.
    token_hash: Option<String>,
    /// SHA-256 of `admin.report_token`: may only `POST /v1/inventory`.
    report_hash: Option<String>,
    /// Flips to `true` when the server shuts down, ending SSE streams.
    shutdown: watch::Receiver<bool>,
}

type ApiResult = Result<Response, ApiError>;

/// JSON error response `{"error": "..."}`.
struct ApiError(StatusCode, String);

impl ApiError {
    fn not_found(msg: impl Into<String>) -> Self {
        Self(StatusCode::NOT_FOUND, msg.into())
    }
    fn bad_request(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }
    fn internal(msg: impl std::fmt::Display) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, msg.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, axum::Json(json!({ "error": self.1 }))).into_response()
    }
}

fn ok_json(v: impl serde::Serialize) -> ApiResult {
    Ok(axum::Json(v).into_response())
}

/// Serve the admin listener (`cfg.admin.listen`) until `shutdown` resolves.
pub async fn serve(app: Arc<App>, shutdown: impl Future<Output = ()> + Send + 'static) -> anyhow::Result<()> {
    if let Some(t) = &app.cfg.admin.token {
        resolve_secret(t).map_err(|e| anyhow::anyhow!("admin.token: {e}"))?;
    }
    let addr = app.cfg.admin.listen.clone();
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| anyhow::anyhow!("binding admin listener {addr}: {e}"))?;
    serve_on(app, listener, shutdown).await
}

/// Serve the admin API on an already bound listener until `shutdown`
/// resolves. Open event streams are closed on shutdown.
pub async fn serve_on(
    app: Arc<App>,
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    if let Ok(addr) = listener.local_addr() {
        let auth = if app.cfg.admin.token.is_some() { "bearer token" } else { "loopback only" };
        tracing::info!(%addr, auth, "admin API listening");
    }
    let (tx, rx) = watch::channel(false);
    let router = build(app, rx);
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async move {
            shutdown.await;
            let _ = tx.send(true);
        })
        .await?;
    Ok(())
}

/// The admin router. Requests must carry `ConnectInfo<SocketAddr>` (as set by
/// [`serve_on`]) to pass the loopback check when no token is configured.
pub fn router(app: Arc<App>) -> Router {
    let (tx, rx) = watch::channel(false);
    // Keep the sender alive for the life of the process so streams only end
    // when their client goes away.
    std::mem::forget(tx);
    build(app, rx)
}

fn build(app: Arc<App>, shutdown: watch::Receiver<bool>) -> Router {
    let token_hash = app.cfg.admin.token.as_deref().map(|t| match resolve_secret(t) {
        Ok(t) if !t.is_empty() => sha256_hex(t),
        Ok(_) | Err(_) => {
            // Fail closed: an unresolvable token locks the API.
            tracing::error!("admin.token cannot be resolved; admin API locked");
            sha256_hex(nandi_core::util::new_id())
        }
    });
    let report_hash = app.cfg.admin.report_token.as_deref().and_then(|t| match resolve_secret(t) {
        Ok(t) if !t.is_empty() => Some(sha256_hex(t)),
        _ => {
            tracing::error!("admin.report_token cannot be resolved; inventory reports need the admin token");
            None
        }
    });
    let state = AdminState { app, token_hash, report_hash, shutdown };
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/v1/status", get(status))
        .route("/v1/events", get(events))
        .route("/v1/events/stream", get(events_stream))
        .route("/v1/sessions", get(sessions))
        .route("/v1/approvals", get(approvals))
        .route("/v1/approvals/{id}/approve", post(approve))
        .route("/v1/approvals/{id}/deny", post(deny))
        .route("/v1/agents/killed", get(killed))
        .route("/v1/agents/{agent}/kill", post(kill))
        .route("/v1/agents/{agent}/revive", post(revive))
        .route("/v1/pins/tools", get(tool_pins))
        .route("/v1/pins/tools/approve", post(tool_pin_approve))
        .route("/v1/pins/tools/forget", post(tool_pin_forget))
        .route("/v1/servers", get(servers))
        .route("/v1/servers/accept-binary", post(server_accept_binary))
        .route("/v1/pins/cards", get(card_pins))
        .route("/v1/pins/cards/approve", post(card_pin_approve))
        .route("/v1/pins/cards/forget", post(card_pin_forget))
        .route("/v1/behavior/{agent}", get(behavior).delete(behavior_reset))
        .route("/v1/usage", get(usage))
        .route("/v1/policy/reload", post(policy_reload))
        .route("/v1/audit/verify", get(audit_verify))
        .route("/v1/hook/{format}", post(hook_endpoint))
        .route("/v1/graph", get(graph))
        .route(
            "/v1/inventory",
            get(inventory_list).post(inventory_report).layer(DefaultBodyLimit::max(MAX_INVENTORY_BYTES)),
        )
        .route("/v1/policies", get(policies_overview))
        .route("/v1/policies/packs/{name}", get(policy_pack))
        .route("/v1/policies/docs/{name}/versions", get(policy_versions))
        .route("/v1/policies/validate", post(policy_validate))
        .route("/v1/policies/preview", post(policy_preview))
        .route("/v1/policies/changes", get(policy_changes).post(policy_propose))
        .route("/v1/policies/changes/{id}", get(policy_change))
        .route("/v1/policies/changes/{id}/approve", post(policy_approve))
        .route("/v1/policies/changes/{id}/reject", post(policy_reject))
        .route("/v1/policies/changes/{id}/withdraw", post(policy_withdraw))
        .route("/v1/me", get(me))
        .route("/v1/users", get(users_list).post(user_create))
        .route("/v1/users/{name}", axum::routing::patch(user_update).delete(user_delete))
        .route("/v1/users/{name}/rotate", post(user_rotate))
        .route("/v1/audit/admin", get(admin_audit))
        .route("/v1/tokens/revoked", get(tokens_revoked))
        .route("/v1/tokens/revoke", post(token_revoke))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

// ----- access control --------------------------------------------------------

async fn guard(State(st): State<AdminState>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if path == "/healthz" || path == "/" {
        return next.run(req).await;
    }
    let principal = match authenticate(&st, &req) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let method = req.method().clone();
    if let Some(need) = required(&method, &path)
        && !principal.can(need)
    {
        if !matches!(principal.origin, Origin::ReportToken) {
            st.app.record_admin(
                &principal,
                "access.denied",
                &format!("{method} {path}"),
                "denied",
                json!({ "needs": need }),
            );
        }
        return ApiError(
            StatusCode::FORBIDDEN,
            format!("{} may not do this (needs {})", principal.name, need.as_str()),
        )
        .into_response();
    }
    // Every change made through the admin API is recorded, attributed to
    // the principal, with its body (agent traffic is recorded as events).
    let audited = method != Method::GET
        && method != Method::HEAD
        && !path.starts_with("/v1/hook/")
        && !matches!(path.as_str(), "/v1/inventory" | "/v1/policies/validate" | "/v1/policies/preview");
    if !audited {
        let mut req = req;
        req.extensions_mut().insert(principal);
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_AUDITED_BODY).await {
        Ok(b) => b,
        Err(_) => return ApiError(StatusCode::PAYLOAD_TOO_LARGE, "request body too large".into()).into_response(),
    };
    let details = serde_json::from_slice::<Value>(&bytes).map(redact_secrets).unwrap_or(Value::Null);
    let mut req = Request::from_parts(parts, axum::body::Body::from(bytes));
    req.extensions_mut().insert(principal.clone());
    let resp = next.run(req).await;
    let (action, mut target) = describe(&method, &path);
    if target.is_empty() {
        // e.g. user.create, pin approvals: the body names what was acted on.
        target = ["name", "id", "title"]
            .iter()
            .find_map(|k| details.get(*k).and_then(Value::as_str))
            .unwrap_or_default()
            .to_string();
    }
    let outcome = if resp.status().is_success() { "ok" } else { "failed" };
    let details = if resp.status().is_success() {
        details
    } else {
        json!({ "request": details, "status": resp.status().as_u16() })
    };
    st.app.record_admin(&principal, &action, &target, outcome, details);
    resp
}

/// Largest admin request body that is buffered for the audit record.
const MAX_AUDITED_BODY: usize = 4 << 20;

/// Who is calling: the admin token, a user, the report token, or local
/// loopback access when no admin token is configured.
fn authenticate(st: &AdminState, req: &Request) -> Result<Principal, Box<Response>> {
    if let Some(hash) = bearer_hash(req.headers()) {
        if st.token_hash.as_deref().is_some_and(|e| constant_time_eq(hash.as_bytes(), e.as_bytes())) {
            return Ok(Principal::admin());
        }
        if let Some(p) = st.app.users.authenticate(&hash) {
            return Ok(p);
        }
        if st.report_hash.as_deref().is_some_and(|e| constant_time_eq(hash.as_bytes(), e.as_bytes())) {
            return Ok(Principal::reporter());
        }
    }
    if st.token_hash.is_some() {
        let mut resp = ApiError(StatusCode::UNAUTHORIZED, "missing or invalid bearer token".into()).into_response();
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return Err(Box::new(resp));
    }
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    if !peer.is_some_and(|ip| is_loopback(&ip)) {
        return Err(Box::new(forbidden("admin API without a token accepts loopback connections only")));
    }
    if !host_is_loopback(req.headers()) {
        return Err(Box::new(forbidden("Host header must name a loopback address")));
    }
    if req.method() != Method::GET && req.method() != Method::HEAD && !same_origin(req.headers()) {
        return Err(Box::new(forbidden("cross-origin request refused")));
    }
    Ok(Principal::local())
}

/// The permission a route needs; `None` for routes every principal may use.
/// Anything not listed needs `manage_users` (admin), so a new route is never
/// open by accident.
fn required(method: &Method, path: &str) -> Option<Permission> {
    use Permission::*;
    let read = method == Method::GET || method == Method::HEAD;
    Some(match path {
        "/v1/me" => return None,
        p if p.starts_with("/v1/users") => ManageUsers,
        p if p.starts_with("/v1/hook/") && method == Method::POST => Hook,
        "/v1/inventory" if method == Method::POST => Report,
        "/v1/policy/reload" => PolicyApprove,
        _ if read => Read,
        p if p.starts_with("/v1/policies/changes/") && (p.ends_with("/approve") || p.ends_with("/reject")) => {
            PolicyApprove
        }
        p if p.starts_with("/v1/policies") => PolicyPropose,
        p if p.starts_with("/v1/approvals/")
            || p.starts_with("/v1/agents/")
            || p.starts_with("/v1/pins/")
            || p.starts_with("/v1/behavior/")
            || p == "/v1/servers/accept-binary"
            || p == "/v1/tokens/revoke" =>
        {
            Operate
        }
        _ => ManageUsers,
    })
}

/// A stable action name and its target for the audit record.
fn describe(method: &Method, path: &str) -> (String, String) {
    let seg: Vec<&str> = path.trim_start_matches("/v1/").split('/').collect();
    let m = method.as_str().to_ascii_lowercase();
    match seg.as_slice() {
        ["approvals", id, verb] => (format!("approval.{verb}"), id.to_string()),
        ["agents", agent, verb] => (format!("agent.{verb}"), agent.to_string()),
        ["pins", kind, verb] => (format!("pin.{}.{verb}", kind.trim_end_matches('s')), String::new()),
        ["behavior", agent] => ("behavior.reset".into(), agent.to_string()),
        ["servers", "accept-binary"] => ("server.accept_binary".into(), String::new()),
        ["tokens", "revoke"] => ("token.revoke".into(), String::new()),
        ["policy", "reload"] => ("policy.reload".into(), String::new()),
        ["users"] => ("user.create".into(), String::new()),
        ["policies", "changes"] => ("policy.change.propose".into(), String::new()),
        ["policies", "changes", id, verb] => (format!("policy.change.{verb}"), id.to_string()),
        ["users", name] if m == "patch" => ("user.update".into(), name.to_string()),
        ["users", name] if m == "delete" => ("user.delete".into(), name.to_string()),
        ["users", name, verb] => (format!("user.{verb}"), name.to_string()),
        _ => (format!("{m} {path}"), String::new()),
    }
}

/// Drop values whose key looks secret before a body is recorded.
fn redact_secrets(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| {
                    let lk = k.to_ascii_lowercase();
                    if ["token", "secret", "password", "key"].iter().any(|s| lk.contains(s)) {
                        (k, json!("[redacted]"))
                    } else {
                        (k, redact_secrets(v))
                    }
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(redact_secrets).collect()),
        v => v,
    }
}

fn forbidden(msg: &str) -> Response {
    ApiError(StatusCode::FORBIDDEN, msg.into()).into_response()
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
    }
}

/// Hostname part of a `host[:port]` or `[v6]:port` authority.
fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    authority.rsplit_once(':').map_or(authority, |(h, _)| h)
}

fn host_is_loopback(headers: &HeaderMap) -> bool {
    // HTTP/1.1 requires Host; a missing one comes from a non-browser client.
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else { return true };
    let name = authority_host(host).to_ascii_lowercase();
    name == "localhost" || name.ends_with(".localhost") || name.parse::<IpAddr>().is_ok_and(|ip| is_loopback(&ip))
}

/// `Origin`, when present, must match `Host`.
fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|h| h.to_str().ok()) else { return true };
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let origin_authority = origin.split_once("://").map_or("", |(_, a)| a);
    !host.is_empty() && origin_authority.eq_ignore_ascii_case(host)
}

/// SHA-256 of the bearer token, if the request has one.
fn bearer_hash(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))?.trim();
    (!token.is_empty()).then(|| sha256_hex(token))
}

/// Compare without early exit. Inputs are fixed-length digests.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ----- dashboard ---------------------------------------------------------------

/// CSP allowing exactly the page's inline script and style (by hash).
fn csp() -> &'static str {
    static CSP: OnceLock<String> = OnceLock::new();
    CSP.get_or_init(|| {
        let hash = |open: &str, close: &str| -> String {
            let Some(start) = INDEX_HTML.find(open).map(|i| i + open.len()) else { return String::new() };
            let Some(len) = INDEX_HTML[start..].find(close) else { return String::new() };
            let digest = hex_to_bytes(&sha256_hex(&INDEX_HTML[start..start + len]));
            format!(" 'sha256-{}'", base64::engine::general_purpose::STANDARD.encode(digest))
        };
        format!(
            "default-src 'none'; script-src{}; style-src{}; connect-src 'self'; img-src 'self' data:; \
             base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            hash("<script>", "</script>"),
            hash("<style>", "</style>"),
        )
    })
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()).collect()
}

async fn index(State(st): State<AdminState>) -> Response {
    if !st.app.cfg.admin.ui {
        return ApiError::not_found("dashboard disabled (admin.ui: false)").into_response();
    }
    let mut resp = INDEX_HTML.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    if let Ok(v) = HeaderValue::from_str(csp()) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

// ----- status ------------------------------------------------------------------

async fn healthz(State(st): State<AdminState>) -> ApiResult {
    ok_json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": st.app.cfg.mode,
        "uptime_secs": st.app.started.elapsed().as_secs(),
    }))
}

async fn metrics(State(st): State<AdminState>) -> Response {
    if !st.app.cfg.telemetry.prometheus {
        return ApiError::not_found("metrics disabled (telemetry.prometheus: false)").into_response();
    }
    let app = &st.app;
    let gauges = [
        ("nandi_sessions", "Active sessions.", app.engine.sessions().len() as f64),
        ("nandi_approvals_pending", "Calls waiting for an operator.", app.approvals.len() as f64),
        ("nandi_agents_killed", "Agents stopped by the kill switch.", app.engine.killed().len() as f64),
    ];
    let mut resp = app.metrics.render(&gauges).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; version=0.0.4"));
    resp
}

/// Host of an upstream URL, without scheme, credentials, port or path.
fn upstream_host(upstream: &str) -> String {
    upstream.parse::<http::Uri>().ok().and_then(|u| u.host().map(str::to_string)).unwrap_or_default()
}

async fn status(State(st): State<AdminState>) -> ApiResult {
    let app = st.app.clone();
    let routes: Vec<Value> = app
        .cfg
        .routes
        .iter()
        .map(|r| json!({ "name": r.name, "prefix": r.prefix, "kind": r.kind, "upstream": upstream_host(&r.upstream) }))
        .collect();
    let audit = match app.audit.clone() {
        Some(log) => {
            let (records, (seq, hash), public_key) =
                tokio::task::spawn_blocking(move || (log.len().unwrap_or(0), log.head(), log.public_key_hex()))
                    .await
                    .map_err(ApiError::internal)?;
            json!({ "enabled": true, "records": records, "head": { "seq": seq, "hash": hash }, "public_key": public_key })
        }
        None => json!({ "enabled": false }),
    };
    ok_json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": app.cfg.mode,
        "fail_mode": app.cfg.fail_mode,
        "managed": app.cfg.managed_sources,
        "uptime_secs": app.started.elapsed().as_secs(),
        "routes": routes,
        "sessions": app.engine.sessions().len(),
        "approvals_pending": app.approvals.len(),
        "agents_killed": app.engine.killed().len(),
        "audit": audit,
    }))
}

// ----- events --------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct EventsParams {
    agent: Option<String>,
    session: Option<String>,
    min_verdict: Option<Verdict>,
    kind: Option<String>,
    since_seq: Option<u64>,
    limit: Option<usize>,
}

/// Treat `?agent=` (empty) as no filter.
fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|s| !s.is_empty())
}

async fn events(State(st): State<AdminState>, QueryParams(p): QueryParams<EventsParams>) -> ApiResult {
    let Some(log) = st.app.audit.clone() else { return Err(ApiError::not_found("audit log disabled")) };
    let q = Query {
        agent: non_empty(p.agent),
        session: non_empty(p.session),
        min_verdict: p.min_verdict,
        kind: non_empty(p.kind),
        since_seq: p.since_seq,
        since_ts_ms: None,
        limit: p.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT),
    };
    let records = tokio::task::spawn_blocking(move || log.query(&q))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    ok_json(records)
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct GraphParams {
    window_secs: Option<u64>,
    buckets: Option<usize>,
    /// End of the window, Unix milliseconds (default: now), to draw a past
    /// range.
    until_ms: Option<u64>,
}

/// Agents, destinations, tools and a decision timeline for the dashboard map.
async fn graph(State(st): State<AdminState>, QueryParams(p): QueryParams<GraphParams>) -> ApiResult {
    let Some(log) = st.app.audit.clone() else { return Err(ApiError::not_found("audit log disabled")) };
    let (window, buckets) = (p.window_secs.unwrap_or(3600), p.buckets.unwrap_or(30));
    let now = nandi_core::util::now_ms();
    let until = p.until_ms.map_or(now, |u| u.min(now));
    let g = tokio::task::spawn_blocking(move || crate::graph::build(&log, until, window, buckets))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    ok_json(g)
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct StreamParams {
    agent: Option<String>,
    min_verdict: Option<Verdict>,
}

fn live_matches(ev: &LiveEvent, agent: Option<&str>, min: Option<Verdict>) -> bool {
    agent.is_none_or(|a| ev.event.agent == a) && min.is_none_or(|m| ev.decision.verdict >= m)
}

async fn events_stream(State(st): State<AdminState>, QueryParams(p): QueryParams<StreamParams>) -> Response {
    let agent = non_empty(p.agent);
    let min = p.min_verdict;
    let rx = st.app.recorder.subscribe();
    let stream = futures_util::stream::unfold((rx, st.shutdown.clone()), move |(mut rx, mut stop)| {
        let agent = agent.clone();
        async move {
            loop {
                if *stop.borrow() {
                    return None;
                }
                let next = tokio::select! {
                    r = rx.recv() => r,
                    _ = stop.changed() => return None,
                };
                let ev = match next {
                    Ok(ev) if live_matches(&ev, agent.as_deref(), min) => {
                        let data = serde_json::to_string(&*ev).unwrap_or_else(|_| "{}".into());
                        let mut sse = SseEvent::default().event("event").data(data);
                        if let Some(seq) = ev.seq {
                            sse = sse.id(seq.to_string());
                        }
                        sse
                    }
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        SseEvent::default().event("lagged").data(n.to_string())
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                };
                return Some((Ok::<_, Infallible>(ev), (rx, stop)));
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default()).into_response()
}

// ----- sessions, approvals, kill switch -------------------------------------------

async fn sessions(State(st): State<AdminState>) -> ApiResult {
    ok_json(st.app.engine.sessions())
}

async fn approvals(State(st): State<AdminState>) -> ApiResult {
    ok_json(st.app.approvals.list())
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ResolveBody {
    by: Option<String>,
}

fn resolve_approval(st: &AdminState, who: &Principal, id: &str, approve: bool, body: &Bytes) -> ApiResult {
    let note = if body.iter().all(u8::is_ascii_whitespace) {
        None
    } else {
        serde_json::from_slice::<ResolveBody>(body).map_err(|e| ApiError::bad_request(format!("invalid body: {e}")))?.by
    };
    // Named users are recorded as themselves. The shared admin token and
    // local access can still say who they are with {"by": ...}.
    let by = match (&who.origin, note.filter(|b| !b.is_empty())) {
        (Origin::AdminToken | Origin::Local, Some(n)) => format!("{} ({n})", who.name),
        _ => who.name.clone(),
    };
    if !st.app.approvals.resolve(id, approve, Some(by.clone())) {
        return Err(ApiError::not_found(format!("no pending approval {id}")));
    }
    tracing::info!(id, approve, by = %by, "approval resolved via admin API");
    ok_json(json!({ "ok": true, "id": id, "approved": approve, "by": by }))
}

async fn approve(
    State(st): State<AdminState>,
    Extension(who): Extension<Principal>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult {
    resolve_approval(&st, &who, &id, true, &body)
}

async fn deny(
    State(st): State<AdminState>,
    Extension(who): Extension<Principal>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult {
    resolve_approval(&st, &who, &id, false, &body)
}

// ----- policies and change requests ------------------------------------------

use crate::policies::{ChangeError, Op};

fn change_error(e: ChangeError) -> ApiError {
    let code = match e {
        ChangeError::Invalid(_) => StatusCode::BAD_REQUEST,
        ChangeError::NotFound => StatusCode::NOT_FOUND,
        ChangeError::Forbidden(_) => StatusCode::FORBIDDEN,
        ChangeError::Closed(_) | ChangeError::SecondPersonRequired | ChangeError::Conflict(_) => StatusCode::CONFLICT,
    };
    ApiError(code, e.to_string())
}

fn changes_allowed(st: &AdminState) -> Result<(), ApiError> {
    if st.app.policy_changes_enabled() {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::CONFLICT,
            "policy changes are off here (managed settings apply; set policy.changes.enabled to allow them)".into(),
        ))
    }
}

async fn policies_overview(State(st): State<AdminState>) -> ApiResult {
    let app = &st.app;
    let read = |p: &std::path::Path, kind: &str| {
        let path = app.base_dir.join(p);
        json!({ "path": path.display().to_string(), "kind": kind,
                "content": std::fs::read_to_string(&path).unwrap_or_else(|e| format!("# cannot read: {e}")) })
    };
    let mut files: Vec<Value> = app.cfg.policy.rules.iter().map(|p| read(p, "rules")).collect();
    files.extend(app.cfg.policy.cedar.iter().map(|p| read(p, "cedar")));
    let packs: Vec<Value> =
        nandi_policy::packs::PACKS.iter().map(|p| json!({ "name": p.name, "summary": p.summary() })).collect();
    ok_json(json!({
        "editable": app.policy_changes_enabled(),
        "require_review": app.cfg.policy.changes.require_review,
        "default": app.cfg.policy.default,
        "files": files,
        "documents": app.policies.docs(),
        "packs": packs,
        "pending": app.policies.changes().iter().filter(|c| c.status == crate::policies::Status::Pending).count(),
    }))
}

async fn policy_pack(Path(name): Path<String>) -> ApiResult {
    let p = nandi_policy::packs::find(&name).ok_or_else(|| ApiError::not_found(format!("no pack {name}")))?;
    ok_json(json!({ "name": p.name, "summary": p.summary(), "content": p.yaml }))
}

async fn policy_versions(State(st): State<AdminState>, Path(name): Path<String>) -> ApiResult {
    ok_json(st.app.policies.versions(&name))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpsBody {
    ops: Vec<Op>,
}

fn parse<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|e| ApiError::bad_request(format!("invalid body: {e}")))
}

async fn policy_validate(State(st): State<AdminState>, body: Bytes) -> ApiResult {
    let b: OpsBody = parse(&body)?;
    let app = st.app.clone();
    let v = tokio::task::spawn_blocking(move || app.policies.validate(&app.cfg, &app.base_dir, &b.ops))
        .await
        .map_err(ApiError::internal)?;
    ok_json(v)
}

/// Validate `ops` and, when they compile and the audit log is on, replay
/// recent events through the current and the candidate policy.
fn validate_and_preview(app: &App, ops: &[Op]) -> (crate::policies::Validation, Option<crate::policies::Impact>) {
    let v = app.policies.validate(&app.cfg, &app.base_dir, ops);
    if !v.ok {
        return (v, None);
    }
    let impact = app.audit.as_ref().and_then(|log| {
        let current = PolicySet::load_with(&app.cfg.policy, &app.base_dir, &app.policies.sources()).ok()?;
        let candidate = app.policies.compile(&app.cfg, &app.base_dir, ops).ok()?;
        Some(crate::policies::preview(&app.cfg, log, current, candidate, app.cfg.policy.changes.preview_events))
    });
    (v, impact)
}

async fn policy_preview(State(st): State<AdminState>, body: Bytes) -> ApiResult {
    let b: OpsBody = parse(&body)?;
    let app = st.app.clone();
    let (validation, impact) =
        tokio::task::spawn_blocking(move || validate_and_preview(&app, &b.ops)).await.map_err(ApiError::internal)?;
    ok_json(json!({ "validation": validation, "impact": impact }))
}

async fn policy_changes(State(st): State<AdminState>) -> ApiResult {
    ok_json(st.app.policies.changes())
}

async fn policy_change(State(st): State<AdminState>, Path(id): Path<String>) -> ApiResult {
    ok_json(st.app.policies.change(&id).ok_or_else(|| ApiError::not_found("no such change"))?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposeBody {
    title: String,
    #[serde(default)]
    description: String,
    ops: Vec<Op>,
}

async fn policy_propose(State(st): State<AdminState>, Extension(who): Extension<Principal>, body: Bytes) -> ApiResult {
    changes_allowed(&st)?;
    let b: ProposeBody = parse(&body)?;
    let app = st.app.clone();
    let c = tokio::task::spawn_blocking(move || {
        let (validation, impact) = validate_and_preview(&app, &b.ops);
        app.policies.propose(&who.name, &b.title, &b.description, b.ops, validation, impact)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(change_error)?;
    ok_json(c)
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct CommentBody {
    #[serde(default)]
    comment: String,
}

fn comment_of(body: &Bytes) -> Result<String, ApiError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(String::new());
    }
    Ok(parse::<CommentBody>(body)?.comment)
}

async fn policy_approve(
    State(st): State<AdminState>,
    Extension(who): Extension<Principal>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult {
    changes_allowed(&st)?;
    let comment = comment_of(&body)?;
    let app = st.app.clone();
    let c = tokio::task::spawn_blocking(move || -> Result<_, ChangeError> {
        let author = app.policies.change(&id).map(|c| c.author).unwrap_or_default();
        let others = app.others_can_approve(&author);
        let (c, set) =
            app.policies.approve(&id, &who.name, &comment, app.cfg.policy.changes.require_review, others, |ops| {
                app.policies.compile(&app.cfg, &app.base_dir, ops)
            })?;
        app.engine.set_policy(set);
        tracing::info!(change = %c.id, by = %who.name, "policy change applied");
        Ok(c)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(change_error)?;
    ok_json(c)
}

async fn policy_reject(
    State(st): State<AdminState>,
    Extension(who): Extension<Principal>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult {
    let comment = comment_of(&body)?;
    ok_json(st.app.policies.reject(&id, &who.name, &comment).map_err(change_error)?)
}

async fn policy_withdraw(
    State(st): State<AdminState>,
    Extension(who): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult {
    ok_json(st.app.policies.withdraw(&id, &who.name).map_err(change_error)?)
}

// ----- users and the admin audit trail ---------------------------------------------

async fn me(State(st): State<AdminState>, Extension(who): Extension<Principal>) -> ApiResult {
    ok_json(json!({
        "name": who.name,
        "roles": who.roles,
        "origin": who.origin,
        "permissions": who.permissions(),
        "users": st.app.users.list().len(),
    }))
}

async fn users_list(State(st): State<AdminState>) -> ApiResult {
    ok_json(st.app.users.list())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewUser {
    name: String,
    roles: Vec<nandi_core::config::Role>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserPatch {
    roles: Option<Vec<nandi_core::config::Role>>,
    disabled: Option<bool>,
}

fn user_error(e: crate::users::UserError) -> ApiError {
    use crate::users::UserError::*;
    let code = match e {
        Invalid(_) => StatusCode::BAD_REQUEST,
        NotFound => StatusCode::NOT_FOUND,
        Exists | ReadOnly => StatusCode::CONFLICT,
    };
    ApiError(code, e.to_string())
}

async fn user_create(State(st): State<AdminState>, Extension(who): Extension<Principal>, body: Bytes) -> ApiResult {
    let b: NewUser = serde_json::from_slice(&body)
        .map_err(|e| ApiError::bad_request(format!("expected {{\"name\": ..., \"roles\": [...]}}: {e}")))?;
    let (user, token) = st.app.users.create(&b.name, b.roles, &who.name).map_err(user_error)?;
    ok_json(json!({ "user": user, "token": token, "note": "The token is shown only now." }))
}

async fn user_update(State(st): State<AdminState>, Path(name): Path<String>, body: Bytes) -> ApiResult {
    let b: UserPatch =
        serde_json::from_slice(&body).map_err(|e| ApiError::bad_request(format!("invalid body: {e}")))?;
    ok_json(st.app.users.update(&name, b.roles, b.disabled).map_err(user_error)?)
}

async fn user_rotate(State(st): State<AdminState>, Path(name): Path<String>) -> ApiResult {
    let token = st.app.users.rotate(&name).map_err(user_error)?;
    ok_json(json!({ "name": name, "token": token, "note": "The token is shown only now." }))
}

async fn user_delete(State(st): State<AdminState>, Path(name): Path<String>) -> ApiResult {
    st.app.users.delete(&name).map_err(user_error)?;
    ok_json(json!({ "ok": true, "name": name }))
}

#[derive(Deserialize)]
struct AdminAuditParams {
    actor: Option<String>,
    action: Option<String>,
    limit: Option<usize>,
}

/// Administrative actions from the audit log, newest first.
async fn admin_audit(State(st): State<AdminState>, QueryParams(p): QueryParams<AdminAuditParams>) -> ApiResult {
    let Some(log) = st.app.audit.clone() else { return Err(ApiError::not_found("audit log disabled")) };
    let limit = p.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let q = Query { kind: Some("admin".into()), ..Query::default() };
    let records = tokio::task::spawn_blocking(move || log.query(&q))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    // The log answers newest first.
    let rows: Vec<Value> = records
        .into_iter()
        .filter_map(|r| match r.event.kind {
            nandi_core::EventKind::Admin(a) => Some((r.seq, r.event.ts_ms, a)),
            _ => None,
        })
        .filter(|(_, _, a)| p.actor.as_deref().is_none_or(|x| a.actor == x))
        .filter(|(_, _, a)| p.action.as_deref().is_none_or(|x| a.action.starts_with(x)))
        .take(limit)
        .map(|(seq, ts, a)| {
            json!({ "seq": seq, "ts_ms": ts, "actor": a.actor, "action": a.action,
            "target": a.target, "outcome": a.outcome, "details": a.details })
        })
        .collect();
    ok_json(rows)
}

async fn killed(State(st): State<AdminState>) -> ApiResult {
    ok_json(st.app.engine.killed())
}

async fn kill(State(st): State<AdminState>, Path(agent): Path<String>) -> ApiResult {
    if agent.is_empty() {
        return Err(ApiError::bad_request("agent must not be empty"));
    }
    st.app.engine.kill(&agent);
    tracing::warn!(agent = %agent, "agent killed via admin API");
    ok_json(json!({ "ok": true, "agent": agent, "killed": true }))
}

async fn tokens_revoked(State(st): State<AdminState>) -> ApiResult {
    ok_json(json!({ "revoked": st.app.auth.revoked() }))
}

async fn token_revoke(State(st): State<AdminState>, body: axum::body::Bytes) -> ApiResult {
    let v: Value = serde_json::from_slice(&body).map_err(|e| ApiError::bad_request(format!("invalid JSON: {e}")))?;
    let id = v.get("id").and_then(Value::as_str).map(str::trim).unwrap_or("");
    if id.len() < 32 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request("id must be a hex revocation identifier (see `nandi token inspect`)"));
    }
    let added = st.app.revoke_token(id);
    tracing::warn!(id = %id, added, "biscuit token revoked via admin API");
    ok_json(json!({ "ok": true, "id": id.to_ascii_lowercase(), "newly_revoked": added }))
}

async fn revive(State(st): State<AdminState>, Path(agent): Path<String>) -> ApiResult {
    let was_killed = st.app.engine.revive(&agent);
    tracing::warn!(agent = %agent, was_killed, "agent revived via admin API");
    ok_json(json!({ "ok": true, "agent": agent, "killed": false, "was_killed": was_killed }))
}

// ----- pins ------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PinBody {
    id: String,
}

/// Pins as JSON objects with their `id`. `extra` adds fields per pin.
fn pin_list(pins: &nandi_engine::pins::Pins, extra: impl Fn(&str, &mut serde_json::Map<String, Value>)) -> ApiResult {
    let v: Vec<Value> = pins
        .list()
        .into_iter()
        .map(|(id, pin)| {
            let mut v = serde_json::to_value(pin).unwrap_or_default();
            if let Some(obj) = v.as_object_mut() {
                extra(&id, obj);
                obj.insert("id".into(), Value::String(id));
            }
            v
        })
        .collect();
    ok_json(v)
}

fn parse_pin_body(body: &Bytes) -> Result<String, ApiError> {
    let b: PinBody =
        serde_json::from_slice(body).map_err(|e| ApiError::bad_request(format!("expected {{\"id\": ...}}: {e}")))?;
    Ok(b.id)
}

fn pin_approve(pins: &nandi_engine::pins::Pins, body: &Bytes) -> ApiResult {
    let id = parse_pin_body(body)?;
    if !pins.approve(&id) {
        return Err(ApiError::not_found(format!("no pending definition for {id}")));
    }
    tracing::info!(id = %id, "pin approved via admin API");
    ok_json(json!({ "ok": true, "id": id }))
}

fn pin_forget(pins: &nandi_engine::pins::Pins, body: &Bytes) -> ApiResult {
    let id = parse_pin_body(body)?;
    if !pins.forget(&id) {
        return Err(ApiError::not_found(format!("no pin for {id}")));
    }
    tracing::info!(id = %id, "pin forgotten via admin API");
    ok_json(json!({ "ok": true, "id": id }))
}

async fn tool_pins(State(st): State<AdminState>) -> ApiResult {
    let engine = &st.app.engine;
    pin_list(engine.tool_pins(), |id, obj| {
        let Some((server, tool)) = id.split_once('/') else { return };
        if let Some(risk) = engine.tool_risk(server, tool) {
            obj.insert("capabilities".into(), json!(risk.capabilities));
            obj.insert("score".into(), json!(risk.score));
            obj.insert("level".into(), json!(risk.level));
        }
    })
}

async fn tool_pin_approve(State(st): State<AdminState>, body: Bytes) -> ApiResult {
    pin_approve(st.app.engine.tool_pins(), &body)
}

async fn tool_pin_forget(State(st): State<AdminState>, body: Bytes) -> ApiResult {
    pin_forget(st.app.engine.tool_pins(), &body)
}

async fn card_pins(State(st): State<AdminState>) -> ApiResult {
    pin_list(st.app.engine.card_pins(), |_, _| {})
}

async fn card_pin_approve(State(st): State<AdminState>, body: Bytes) -> ApiResult {
    pin_approve(st.app.engine.card_pins(), &body)
}

async fn card_pin_forget(State(st): State<AdminState>, body: Bytes) -> ApiResult {
    pin_forget(st.app.engine.card_pins(), &body)
}

// ----- servers ---------------------------------------------------------------------

async fn servers(State(st): State<AdminState>) -> ApiResult {
    ok_json(st.app.engine.servers())
}

#[derive(Debug, Deserialize)]
struct ServerBody {
    name: String,
}

async fn server_accept_binary(State(st): State<AdminState>, body: Bytes) -> ApiResult {
    let b: ServerBody =
        serde_json::from_slice(&body).map_err(|e| ApiError::bad_request(format!("expected {{\"name\": ...}}: {e}")))?;
    if !st.app.engine.accept_server_binary(&b.name) {
        return Err(ApiError::not_found(format!("no changed binary for server {}", b.name)));
    }
    tracing::info!(server = %b.name, "server binary accepted via admin API");
    ok_json(json!({ "ok": true, "name": b.name }))
}

// ----- behaviour, usage, policy, audit, hooks ----------------------------------------

async fn behavior(State(st): State<AdminState>, Path(agent): Path<String>) -> ApiResult {
    match st.app.engine.behavior().model(&agent) {
        Some(model) => ok_json(json!({ "agent": agent, "model": model })),
        None => Err(ApiError::not_found(format!("no behaviour model for {agent}"))),
    }
}

async fn behavior_reset(State(st): State<AdminState>, Path(agent): Path<String>) -> ApiResult {
    st.app.engine.behavior().reset(&agent);
    tracing::info!(agent = %agent, "behaviour model reset via admin API");
    ok_json(json!({ "ok": true, "agent": agent }))
}

async fn usage(State(st): State<AdminState>) -> ApiResult {
    let v: Vec<Value> = st
        .app
        .engine
        .budgets()
        .all_usage()
        .into_iter()
        .map(|(agent, u)| json!({ "agent": agent, "day": u.day, "tokens": u.tokens, "tool_calls": u.tool_calls }))
        .collect();
    ok_json(v)
}

async fn policy_reload(State(st): State<AdminState>) -> ApiResult {
    let app = st.app.clone();
    match tokio::task::spawn_blocking(move || app.reload_policy()).await.map_err(ApiError::internal)? {
        Ok(warnings) => {
            tracing::info!(warnings = warnings.len(), "policy reloaded via admin API");
            ok_json(json!({ "ok": true, "warnings": warnings }))
        }
        Err(e) => {
            tracing::warn!(error = %e, "policy reload failed");
            Err(ApiError::bad_request(format!("{e:#}")))
        }
    }
}

async fn audit_verify(State(st): State<AdminState>) -> ApiResult {
    let Some(log) = st.app.audit.clone() else { return Err(ApiError::not_found("audit log disabled")) };
    let report = tokio::task::spawn_blocking(move || log.verify())
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    ok_json(report)
}

async fn hook_endpoint(State(st): State<AdminState>, Path(format): Path<String>, body: Bytes) -> ApiResult {
    let format: HookFormat = format.parse().map_err(ApiError::bad_request)?;
    let input: Value =
        serde_json::from_slice(&body).map_err(|e| ApiError::bad_request(format!("invalid JSON payload: {e}")))?;
    let r = hook::handle(&st.app, format, input).await;
    ok_json(serde_json::to_value(crate::hook::HookWire::from(r)).unwrap_or_default())
}

// ----- AI footprint inventory --------------------------------------------------------

/// Store the latest inventory of a host (`nandi discover --report`).
async fn inventory_report(State(st): State<AdminState>, body: Bytes) -> ApiResult {
    let mut inv: Inventory =
        serde_json::from_slice(&body).map_err(|e| ApiError::bad_request(format!("invalid inventory: {e}")))?;
    let host = inv.host.trim().to_string();
    if host.is_empty() || host.len() > 255 || host.chars().any(char::is_control) {
        return Err(ApiError::bad_request("inventory host must be 1 to 255 printable characters"));
    }
    inv.host = host.clone();
    let bytes = serde_json::to_vec(&inv).map_err(ApiError::internal)?;
    let store = st.app.engine.store().clone();
    let key = format!("{INVENTORY_PREFIX}{host}");
    tokio::task::spawn_blocking(move || store.put(&key, &bytes)).await.map_err(ApiError::internal)?;
    tracing::info!(host = %host, items = inv.items.len(), "inventory reported");
    ok_json(json!({ "ok": true, "host": host, "items": inv.items.len() }))
}

/// Latest inventory of every reporting host, newest scan first.
async fn inventory_list(State(st): State<AdminState>) -> ApiResult {
    let store = st.app.engine.store().clone();
    let mut list: Vec<Inventory> = tokio::task::spawn_blocking(move || {
        store
            .keys(INVENTORY_PREFIX)
            .into_iter()
            .filter_map(|k| store.get(&k))
            .filter_map(|v| serde_json::from_slice(&v).ok())
            .collect()
    })
    .await
    .map_err(ApiError::internal)?;
    list.sort_by_key(|a| std::cmp::Reverse(a.scanned_at_ms));
    ok_json(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use nandi_core::config::Mode;
    use nandi_core::{Config, Event, EventKind, Source, ToolCall};
    use nandi_policy::PolicySet;

    const LOCAL: &str = "127.0.0.1:50000";

    fn call(tool: &str) -> Event {
        Event::new(
            Source::Eval,
            "bot",
            "s1",
            EventKind::ToolCall(ToolCall {
                server: "bank".into(),
                tool: tool.into(),
                call_id: None,
                args: json!({ "amount": 500 }),
            }),
        )
    }

    fn rules() -> PolicySet {
        let rules = "rules:\n  - id: pay-ask\n    match: { tool: pay }\n    action: ask\n  - id: no-wipe\n    match: { tool: wipe }\n    action: deny\n";
        PolicySet::from_sources(Default::default(), None, None, &[rules]).unwrap()
    }

    fn ephemeral(cfg: Config) -> Arc<App> {
        App::ephemeral(cfg, rules()).unwrap()
    }

    fn request(method: &str, uri: &str, peer: &str, token: Option<&str>, body: Option<Value>) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(uri).header(header::HOST, "127.0.0.1:8788");
        if let Some(t) = token {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let body = match body {
            Some(v) => {
                b = b.header(header::CONTENT_TYPE, "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        let mut req = b.body(body).unwrap();
        req.extensions_mut().insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        req
    }

    async fn send(r: &Router, req: Request<Body>) -> (StatusCode, Value) {
        let resp = r.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v =
            serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
        (status, v)
    }

    async fn get_json(r: &Router, uri: &str) -> (StatusCode, Value) {
        send(r, request("GET", uri, LOCAL, None, None)).await
    }

    async fn post_json(r: &Router, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        send(r, request("POST", uri, LOCAL, None, body)).await
    }

    #[tokio::test]
    async fn health_is_open_and_reports_mode() {
        let r = router(ephemeral(Config::default()));
        let (s, v) = send(&r, request("GET", "/healthz", "10.0.0.5:1234", None, None)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["status"], "ok");
        assert_eq!(v["mode"], "monitor");
    }

    #[tokio::test]
    async fn loopback_only_without_token() {
        let r = router(ephemeral(Config::default()));
        let (s, _) = send(&r, request("GET", "/v1/status", "10.0.0.5:1234", None, None)).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, v) = get_json(&r, "/v1/status").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["mode"], "monitor");

        // DNS rebinding: loopback peer, foreign Host.
        let mut req = request("GET", "/v1/status", LOCAL, None, None);
        req.headers_mut().insert(header::HOST, HeaderValue::from_static("evil.example:8788"));
        assert_eq!(send(&r, req).await.0, StatusCode::FORBIDDEN);

        // Cross-site state change.
        let mut req = request("POST", "/v1/agents/bot/kill", LOCAL, None, None);
        req.headers_mut().insert(header::ORIGIN, HeaderValue::from_static("https://evil.example"));
        assert_eq!(send(&r, req).await.0, StatusCode::FORBIDDEN);
        let mut req = request("POST", "/v1/agents/bot/kill", LOCAL, None, None);
        req.headers_mut().insert(header::ORIGIN, HeaderValue::from_static("http://127.0.0.1:8788"));
        assert_eq!(send(&r, req).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn token_is_enforced() {
        let mut cfg = Config::default();
        cfg.admin.token = Some("test-admin-token".into());
        let r = router(ephemeral(cfg));
        let remote = "10.0.0.5:1234";
        assert_eq!(send(&r, request("GET", "/v1/status", remote, None, None)).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(
            send(&r, request("GET", "/v1/status", remote, Some("wrong"), None)).await.0,
            StatusCode::UNAUTHORIZED
        );
        let (s, _) = send(&r, request("GET", "/v1/status", remote, Some("test-admin-token"), None)).await;
        assert_eq!(s, StatusCode::OK);
        // The page loads without the token; its script asks for it.
        let resp = r.clone().oneshot(request("GET", "/", remote, None, None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let csp = resp.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_string();
        assert!(csp.contains("script-src 'sha256-"), "{csp}");
        assert!(!csp.contains("unsafe-inline"));
        assert_eq!(send(&r, request("GET", "/healthz", remote, None, None)).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn users_roles_and_the_admin_audit_trail() {
        let mut cfg = Config::default();
        cfg.admin.token = Some("root-token".into());
        let app = App::ephemeral_audited(cfg, rules()).unwrap();
        let r = router(app.clone());
        let remote = "10.0.0.9:1234";
        let call = |m: &'static str, uri: &'static str, tok: Option<&'static str>, body: Option<Value>| {
            send(&r, request(m, uri, remote, tok, body))
        };

        // The admin token creates an operator and a viewer; tokens are shown once.
        let (s, v) =
            call("POST", "/v1/users", Some("root-token"), Some(json!({ "name": "asha", "roles": ["operator"] }))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let op: &'static str = Box::leak(v["token"].as_str().unwrap().to_string().into_boxed_str());
        let (_, v) =
            call("POST", "/v1/users", Some("root-token"), Some(json!({ "name": "vik", "roles": ["viewer"] }))).await;
        let viewer: &'static str = Box::leak(v["token"].as_str().unwrap().to_string().into_boxed_str());
        assert!(call("GET", "/v1/users", Some("root-token"), None).await.1.to_string().find(op).is_none());

        // Who am I, and what each role may do.
        let (_, me) = call("GET", "/v1/me", Some(op), None).await;
        assert_eq!((me["name"].as_str(), me["permissions"].as_array().unwrap().len()), (Some("asha"), 2));
        assert_eq!(call("GET", "/v1/status", Some(viewer), None).await.0, StatusCode::OK);
        assert_eq!(call("POST", "/v1/agents/bot/kill", Some(viewer), None).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call("POST", "/v1/agents/bot/kill", Some(op), None).await.0, StatusCode::OK);
        assert_eq!(call("GET", "/v1/users", Some(op), None).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call("POST", "/v1/policy/reload", Some(op), None).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call("GET", "/v1/status", Some("guess"), None).await.0, StatusCode::UNAUTHORIZED);

        // Disabled users are out.
        let (s, _) = call("PATCH", "/v1/users/vik", Some("root-token"), Some(json!({ "disabled": true }))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(call("GET", "/v1/status", Some(viewer), None).await.0, StatusCode::UNAUTHORIZED);

        // Everything above is in the signed audit log, attributed.
        app.recorder.flush().await;
        let (_, trail) = call("GET", "/v1/audit/admin", Some(op), None).await;
        let rows: Vec<(String, String, String, String)> = trail
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                let f = |k: &str| r[k].as_str().unwrap_or_default().to_string();
                (f("actor"), f("action"), f("target"), f("outcome"))
            })
            .collect();
        let has = |actor: &str, action: &str, outcome: &str| {
            rows.iter().any(|(a, ac, _, o)| a == actor && ac == action && o == outcome)
        };
        assert!(has("admin", "user.create", "ok"), "{rows:?}");
        assert!(
            has("asha", "agent.kill", "ok")
                && has("vik", "access.denied", "denied")
                && has("admin", "user.update", "ok")
        );
        assert!(rows.iter().any(|r| r.1 == "agent.kill" && r.2 == "bot"));
        // Newest first, and tokens never appear.
        assert_eq!(rows[0].1, "user.update");
        assert!(!trail.to_string().contains(op) && !trail.to_string().contains(viewer));
        assert!(app.audit.as_ref().unwrap().verify().unwrap().ok);
    }

    #[tokio::test]
    async fn policy_changes_need_a_second_person_and_take_effect() {
        let mut cfg = Config::default();
        cfg.admin.token = Some("root-token".into());
        let app = App::ephemeral_audited(cfg, rules()).unwrap();
        let r = router(app.clone());
        let remote = "10.0.0.11:1234";
        let tok = |v: &Value| -> &'static str { Box::leak(v["token"].as_str().unwrap().to_string().into_boxed_str()) };
        let (_, v) = send(
            &r,
            request(
                "POST",
                "/v1/users",
                remote,
                Some("root-token"),
                Some(json!({ "name": "ed", "roles": ["policy_editor"] })),
            ),
        )
        .await;
        let ed = tok(&v);
        let (_, v) = send(
            &r,
            request(
                "POST",
                "/v1/users",
                remote,
                Some("root-token"),
                Some(json!({ "name": "pat", "roles": ["policy_approver"] })),
            ),
        )
        .await;
        let pat = tok(&v);
        let put = json!({ "op": "put", "name": "no-curl", "kind": "rules",
            "content": "rules:\n  - { id: no-curl, match: { tool: curl }, action: deny }\n" });

        // Validation catches broken policies; proposals must compile.
        let (_, v) = send(&r, request("POST", "/v1/policies/validate", remote, Some(ed),
            Some(json!({ "ops": [{ "op": "put", "name": "x", "kind": "rules", "content": "rules: [{ id: y, action: perhaps }]" }] })))).await;
        assert_eq!(v["ok"], false, "{v}");
        let (s, _) = send(&r, request("POST", "/v1/policies/changes", remote, Some(ed),
            Some(json!({ "title": "broken", "ops": [{ "op": "put", "name": "x", "kind": "rules", "content": "rules: [" }] })))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        // The editor proposes; editors cannot approve.
        let (s, change) = send(
            &r,
            request(
                "POST",
                "/v1/policies/changes",
                remote,
                Some(ed),
                Some(json!({ "title": "Block curl", "ops": [put] })),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{change}");
        let id = change["id"].as_str().unwrap().to_string();
        let approve = Box::leak(format!("/v1/policies/changes/{id}/approve").into_boxed_str());
        assert_eq!(send(&r, request("POST", approve, remote, Some(ed), None)).await.0, StatusCode::FORBIDDEN);

        // Before approval the rule is not enforced.
        let curl = || {
            nandi_core::Event::new(
                nandi_core::Source::Eval,
                "bot",
                "s",
                nandi_core::EventKind::ToolCall(nandi_core::ToolCall {
                    server: "sh".into(),
                    tool: "curl".into(),
                    call_id: None,
                    args: json!({}),
                }),
            )
        };
        assert_eq!(app.engine.evaluate(&curl(), &[]).verdict, Verdict::Allow);
        let (s, applied) =
            send(&r, request("POST", approve, remote, Some(pat), Some(json!({ "comment": "ok" })))).await;
        assert_eq!(s, StatusCode::OK, "{applied}");
        assert_eq!(applied["status"], "applied");
        assert_eq!(app.engine.evaluate(&curl(), &[]).verdict, Verdict::Deny);

        // The policy listing shows the document at version 1, and history.
        let (_, ov) = send(&r, request("GET", "/v1/policies", remote, Some(ed), None)).await;
        assert_eq!(ov["documents"][0]["version"], 1);
        assert_eq!(ov["editable"], true);
        assert!(ov["packs"].as_array().unwrap().len() >= 5);

        // A self-approval by the approver of their own change is refused while
        // the admin token exists.
        let (_, own) = send(
            &r,
            request(
                "POST",
                "/v1/policies/changes",
                remote,
                Some(pat),
                Some(json!({ "title": "Turn it off", "ops": [{ "op": "disable", "name": "no-curl" }] })),
            ),
        )
        .await;
        let own_approve =
            Box::leak(format!("/v1/policies/changes/{}/approve", own["id"].as_str().unwrap()).into_boxed_str());
        let (s, v) = send(&r, request("POST", own_approve, remote, Some(pat), None)).await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");

        // All of it is in the audit trail.
        app.recorder.flush().await;
        let (_, trail) = send(&r, request("GET", "/v1/audit/admin?action=policy.", remote, Some(ed), None)).await;
        let actions: Vec<&str> = trail.as_array().unwrap().iter().filter_map(|r| r["action"].as_str()).collect();
        assert!(
            actions.contains(&"policy.change.propose") && actions.contains(&"policy.change.approve"),
            "{actions:?}"
        );
    }

    #[tokio::test]
    async fn report_token_may_only_post_inventories() {
        let mut cfg = Config::default();
        cfg.admin.token = Some("test-admin-token".into());
        cfg.admin.report_token = Some("test-report-token".into());
        let r = router(ephemeral(cfg));
        let remote = "10.0.0.7:1234";
        let inv = json!({ "host": "laptop", "scanned_at_ms": 1, "nandi_version": "0.1.0", "items": [],
                          "coverage": { "servers_total": 0, "servers_via_nandi": 0, "servers_wrapped": 0,
                                        "servers_routed": 0, "hook_clients": 0, "hooks_installed": 0 } });
        let (s, v) =
            send(&r, request("POST", "/v1/inventory", remote, Some("test-report-token"), Some(inv.clone()))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        // Nothing else: not reading inventories, not the rest of the API.
        for (m, uri) in [("GET", "/v1/inventory"), ("GET", "/v1/status"), ("POST", "/v1/agents/a/kill")] {
            let (s, _) = send(&r, request(m, uri, remote, Some("test-report-token"), None)).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{m} {uri}");
        }
        // The admin token still reports too.
        let (s, _) = send(&r, request("POST", "/v1/inventory", remote, Some("test-admin-token"), Some(inv))).await;
        assert_eq!(s, StatusCode::OK);
    }

    #[tokio::test]
    async fn kill_and_revive_round_trip() {
        let app = ephemeral(Config::default());
        let r = router(app.clone());
        let (s, _) = post_json(&r, "/v1/agents/bot/kill", None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(get_json(&r, "/v1/agents/killed").await.1, json!(["bot"]));
        // Killed agents are denied even in monitor mode.
        assert!(app.decide(call("balance"), &[]).await.blocked());
        let (_, v) = post_json(&r, "/v1/agents/bot/revive", None).await;
        assert_eq!(v["was_killed"], true);
        assert_eq!(get_json(&r, "/v1/agents/killed").await.1, json!([]));
        assert!(!app.decide(call("balance"), &[]).await.blocked());
    }

    #[tokio::test]
    async fn approvals_list_and_resolve_held_call() {
        let app = ephemeral(Config { mode: Mode::Enforce, ..Config::default() });
        let r = router(app.clone());
        for approve in [true, false] {
            let held = tokio::spawn({
                let app = app.clone();
                async move { app.decide(call("pay"), &[]).await }
            });
            let id = loop {
                let (_, v) = get_json(&r, "/v1/approvals").await;
                if let Some(id) = v[0]["id"].as_str() {
                    assert_eq!(v[0]["agent"], "bot");
                    break id.to_string();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            let action = if approve { "approve" } else { "deny" };
            let (s, v) = post_json(&r, &format!("/v1/approvals/{id}/{action}"), Some(json!({ "by": "ops" }))).await;
            assert_eq!(s, StatusCode::OK, "{v}");
            let verdict = held.await.unwrap();
            assert_eq!(verdict.blocked(), !approve);
            let (s, _) = post_json(&r, &format!("/v1/approvals/{id}/approve"), None).await;
            assert_eq!(s, StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn pins_approve_and_forget() {
        let app = ephemeral(Config::default());
        let pins = app.engine.tool_pins();
        pins.check("github/create_issue", "aaa");
        pins.check("github/create_issue", "bbb");
        let r = router(app.clone());
        let (_, v) = get_json(&r, "/v1/pins/tools").await;
        assert_eq!(v[0]["id"], "github/create_issue");
        assert_eq!(v[0]["pending"], "bbb");
        let body = json!({ "id": "github/create_issue" });
        let (s, _) = post_json(&r, "/v1/pins/tools/approve", Some(body.clone())).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(pins.list()[0].1.hash, "bbb");
        assert_eq!(post_json(&r, "/v1/pins/tools/approve", Some(body.clone())).await.0, StatusCode::NOT_FOUND);
        assert_eq!(post_json(&r, "/v1/pins/tools/forget", Some(body.clone())).await.0, StatusCode::OK);
        assert!(pins.list().is_empty());
        assert_eq!(post_json(&r, "/v1/pins/tools/forget", Some(json!({}))).await.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn servers_list_risk_and_tool_pins_carry_capabilities() {
        let app = ephemeral(Config::default());
        let r = router(app.clone());
        app.engine.register_server(
            "github",
            nandi_core::ServerSpec::Stdio { command: "npx".into(), args: vec!["-y".into(), "srv-gh@1.2.3".into()] },
        );
        let list = Event::new(
            Source::Eval,
            "bot",
            "s1",
            EventKind::ToolList(nandi_core::ToolList {
                server: "github".into(),
                tools: vec![nandi_core::ToolDef {
                    name: "delete_repository".into(),
                    description: "Delete a repository".into(),
                    input_schema: json!({"type": "object"}),
                    annotations: Value::Null,
                }],
            }),
        );
        app.decide(list, &[]).await;
        let (s, v) = get_json(&r, "/v1/servers").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v[0]["name"], "github");
        assert_eq!(v[0]["package"]["name"], "srv-gh");
        assert_eq!(v[0]["pinned"], true);
        assert_eq!(v[0]["approval"], "not_required");
        assert_eq!(v[0]["level"], "medium");
        assert_eq!(v[0]["capabilities"], json!(["data_deletion"]));
        let (_, pins) = get_json(&r, "/v1/pins/tools").await;
        assert_eq!(pins[0]["id"], "github/delete_repository");
        assert_eq!(pins[0]["capabilities"], json!(["data_deletion"]));
        assert_eq!(pins[0]["score"], 30);
        let missing = post_json(&r, "/v1/servers/accept-binary", Some(json!({"name": "github"}))).await;
        assert_eq!(missing.0, StatusCode::NOT_FOUND);
        assert_eq!(post_json(&r, "/v1/servers/accept-binary", Some(json!({}))).await.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn events_query_after_decide() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config { data_dir: Some(dir.path().join("data")), ..Config::default() };
        let app = App::build(cfg, dir.path(), None).unwrap();
        app.engine.set_policy(rules());
        app.decide(call("wipe"), &[]).await;
        app.decide(call("balance"), &[]).await;
        let r = router(app.clone());
        let records = loop {
            let (s, v) = get_json(&r, "/v1/events?min_verdict=deny&agent=bot").await;
            assert_eq!(s, StatusCode::OK);
            if !v.as_array().unwrap().is_empty() {
                break v;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(records.as_array().unwrap().len(), 1);
        assert_eq!(records[0]["event"]["kind"]["tool"], "wipe");
        assert_eq!(records[0]["decision"]["verdict"], "deny");

        let (_, v) = get_json(&r, "/v1/status").await;
        assert!(v["audit"]["records"].as_u64().unwrap() >= 1);
        assert_eq!(v["audit"]["public_key"].as_str().unwrap().len(), 64);
        let (_, v) = get_json(&r, "/v1/audit/verify").await;
        assert_eq!(v["ok"], true, "{v}");
    }

    #[tokio::test]
    async fn metrics_text() {
        let app = ephemeral(Config::default());
        app.decide(call("balance"), &[]).await;
        let r = router(app.clone());
        let (s, v) = get_json(&r, "/metrics").await;
        assert_eq!(s, StatusCode::OK);
        let text = v.as_str().unwrap();
        assert!(text.contains("nandi_events_total{kind=\"tool_call\"} 1"), "{text}");
        assert!(text.contains("nandi_approvals_pending 0"));

        let mut cfg = Config::default();
        cfg.telemetry.prometheus = false;
        let r = router(ephemeral(cfg));
        assert_eq!(get_json(&r, "/metrics").await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn policy_reload_and_unknown_hook_format() {
        let r = router(ephemeral(Config::default()));
        let (s, v) = post_json(&r, "/v1/policy/reload", None).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["ok"], true);
        let (s, _) = post_json(&r, "/v1/hook/nope", Some(json!({}))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, v) = post_json(&r, "/v1/hook/generic", Some(json!({}))).await;
        assert_eq!(s, StatusCode::OK);
        assert!(v.get("exit_code").is_some());
    }

    #[tokio::test]
    async fn inventory_report_and_list() {
        let app = ephemeral(Config::default());
        let r = router(app.clone());
        assert_eq!(get_json(&r, "/v1/inventory").await.1, json!([]));
        let inventory = |host: &str, at: u64| {
            json!({
                "host": host,
                "scanned_at_ms": at,
                "nandi_version": "0.1.0",
                "items": [{
                    "type": "mcp_server", "client": "cursor", "scope": "user", "name": "github",
                    "source": "~/.cursor/mcp.json", "transport": "stdio", "command": "npx",
                    "args": ["-y", "server-github"], "env": ["GITHUB_TOKEN"], "via_nandi": null,
                    "findings": [{ "rule": "coverage.unwrapped-server", "category": "policy", "severity": "medium",
                                   "verdict": "alert", "message": "MCP server github bypasses nandi" }],
                    "unknown_field": "dropped"
                }],
                "coverage": { "servers_total": 1, "servers_via_nandi": 0, "servers_wrapped": 0, "servers_routed": 0,
                              "hook_clients": 0, "hooks_installed": 0 }
            })
        };
        let (s, v) = post_json(&r, "/v1/inventory", Some(inventory("laptop-a", 1_000))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["items"], 1);
        post_json(&r, "/v1/inventory", Some(inventory("laptop-b", 3_000))).await;
        // A newer report replaces the host's previous one.
        post_json(&r, "/v1/inventory", Some(inventory("laptop-a", 5_000))).await;
        let (s, v) = get_json(&r, "/v1/inventory").await;
        assert_eq!(s, StatusCode::OK);
        let hosts: Vec<&str> = v.as_array().unwrap().iter().map(|i| i["host"].as_str().unwrap()).collect();
        assert_eq!(hosts, ["laptop-a", "laptop-b"]);
        assert_eq!(v[0]["scanned_at_ms"], 5_000);
        assert_eq!(v[0]["items"][0]["name"], "github");
        assert!(v[0]["items"][0].get("unknown_field").is_none());
        assert!(app.engine.store().get("inventory/laptop-b").is_some());

        assert_eq!(post_json(&r, "/v1/inventory", Some(json!({ "host": 1 }))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(post_json(&r, "/v1/inventory", Some(inventory(" ", 1))).await.0, StatusCode::BAD_REQUEST);
        let mut big = inventory("big", 1);
        big["warnings"] = json!(["x".repeat(3 << 20)]);
        assert_eq!(post_json(&r, "/v1/inventory", Some(big)).await.0, StatusCode::PAYLOAD_TOO_LARGE);
        // Remote peers need the token like every other endpoint.
        let req = request("POST", "/v1/inventory", "10.0.0.5:1234", None, Some(inventory("x", 1)));
        assert_eq!(send(&r, req).await.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn sse_stream_ends_on_shutdown() {
        let app = ephemeral(Config::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_on(app.clone(), listener, async move {
            let _ = rx.await;
        }));
        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        sock.write_all(format!("GET /v1/events/stream?min_verdict=deny HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        // Wait for the response head, then publish events.
        let mut buf = vec![0u8; 8192];
        let n = sock.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("text/event-stream"));
        app.decide(call("balance"), &[]).await;
        app.decide(call("wipe"), &[]).await;
        let mut seen = String::new();
        while !seen.contains("wipe") {
            let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await.unwrap().unwrap();
            seen.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        assert!(seen.contains("event: event"));
        assert!(!seen.contains("balance"), "filtered by min_verdict");
        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
    }
}
