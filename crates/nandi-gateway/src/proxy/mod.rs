//! HTTP gateway in front of LLM APIs, MCP servers and A2A agents.
//!
//! Every request is matched against `cfg.routes` (longest prefix wins),
//! authenticated, turned into [`Event`]s that go through [`App::decide`],
//! and forwarded to the route's upstream with nandi's own headers removed
//! and the route's credentials injected. Protocol specifics live in
//! [`llm`], [`mcp`] and [`a2a`]; this module holds the server, routing,
//! authentication and the forwarding and body plumbing they share.
//!
//! Request bodies that are inspected are buffered (up to [`MAX_BODY`]).
//! Responses stream: SSE is never buffered, it is inspected event by event
//! (MCP, A2A) or tapped while the bytes pass through unchanged (LLM).

mod a2a;
mod llm;
mod mcp;
mod tls;

#[cfg(test)]
mod tests;

pub use tls::peer_identity;

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, bail};
use bytes::{Bytes, BytesMut};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use nandi_core::config::{Route, RouteKind, resolve_secret};
use nandi_core::{Event, EventKind, ServerSpec, Source};
use nandi_identity::Principal;
use nandi_proto::llm::Provider;
use nandi_proto::sse::{self, SseEvent, SseParser};

use crate::App;
use crate::client::{Body, BoxError, full};

/// Largest request body buffered for inspection, and the bound for buffered
/// JSON responses and single SSE events. Larger responses pass through
/// uninspected; larger requests are rejected with 413.
pub const MAX_BODY: usize = 16 * 1024 * 1024;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const MCP_SESSION_HEADER: &str = "mcp-session-id";

/// Serve the proxy listener (`cfg.listen.proxy`) until `shutdown` resolves.
pub async fn serve(app: Arc<App>, shutdown: impl Future<Output = ()> + Send + 'static) -> anyhow::Result<()> {
    let addr = app.cfg.listen.proxy.clone();
    let listener = TcpListener::bind(&addr).await.with_context(|| format!("binding proxy listener {addr}"))?;
    serve_on(app, listener, shutdown).await
}

/// Serve the proxy on an already bound listener until `shutdown` resolves,
/// then let in-flight connections finish (up to 30 s).
pub async fn serve_on(
    app: Arc<App>,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let tls = app.cfg.listen.tls.as_ref().map(|t| tls::acceptor(t, &app.base_dir)).transpose()?;
    let proxy = Arc::new(Proxy::new(app)?);
    let builder = auto::Builder::new(TokioExecutor::new());
    let graceful = GracefulShutdown::new();
    tracing::info!(addr = %listener.local_addr()?, tls = tls.is_some(), routes = proxy.routes.len(), "proxy listening");
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            res = listener.accept() => match res {
                Ok(conn) => conn,
                Err(e) => {
                    // Usually EMFILE; back off instead of spinning.
                    tracing::warn!("proxy accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let _ = stream.set_nodelay(true);
        let proxy = proxy.clone();
        let builder = builder.clone();
        let watcher = graceful.watcher();
        let tls = tls.clone();
        tokio::spawn(async move {
            let Some(acceptor) = tls else {
                return serve_conn(&builder, watcher, stream, proxy, None).await;
            };
            let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return tracing::debug!(%peer, "TLS handshake failed: {e}"),
                Err(_) => return tracing::debug!(%peer, "TLS handshake timed out"),
            };
            let identity = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .and_then(|leaf| tls::peer_identity(leaf.as_ref()))
                .map(Arc::<str>::from);
            serve_conn(&builder, watcher, stream, proxy, identity).await
        });
    }
    drop(listener);
    if tokio::time::timeout(DRAIN_TIMEOUT, graceful.shutdown()).await.is_err() {
        tracing::warn!("proxy shutdown: connections still open after {}s", DRAIN_TIMEOUT.as_secs());
    }
    Ok(())
}

async fn serve_conn<I>(
    builder: &auto::Builder<TokioExecutor>,
    watcher: Watcher,
    io: I,
    proxy: Arc<Proxy>,
    mtls: Option<Arc<str>>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| {
        let proxy = proxy.clone();
        let mtls = mtls.clone();
        async move { Ok::<_, Infallible>(proxy.handle(req, mtls.as_deref()).await) }
    });
    if let Err(e) = watcher.watch(builder.serve_connection(TokioIo::new(io), svc)).await {
        tracing::debug!("proxy connection ended with error: {e}");
    }
}

/// A route with everything resolved at startup.
pub(super) struct RouteState {
    pub route: Route,
    upstream: Uri,
    pub provider: Option<Provider>,
    inject: Vec<(HeaderName, HeaderValue)>,
    strip: Vec<HeaderName>,
    timeout: Duration,
}

pub(super) struct Proxy {
    pub app: Arc<App>,
    /// Sorted by descending prefix length, so the first match is the longest.
    routes: Vec<RouteState>,
    /// nandi's own request headers, never forwarded.
    own_headers: Vec<HeaderName>,
}

impl Proxy {
    fn new(app: Arc<App>) -> anyhow::Result<Self> {
        let mut routes = Vec::with_capacity(app.cfg.routes.len());
        for route in &app.cfg.routes {
            routes.push(route_state(route).with_context(|| format!("route {:?}", route.name))?);
            if route.kind == RouteKind::Mcp {
                app.engine.register_server(&route.name, ServerSpec::Http { url: route.upstream.clone() });
            }
        }
        routes.sort_by_key(|r| std::cmp::Reverse(r.route.prefix.trim_end_matches('/').len()));
        let id = &app.cfg.identity;
        let mut own = vec![id.api_key_header.as_str(), id.session_header.as_str(), "x-nandi-biscuit"];
        if let Some(b) = &id.biscuit {
            own.push(b.header.as_str());
        }
        let own_headers = own.into_iter().filter_map(|h| HeaderName::from_bytes(h.as_bytes()).ok()).collect();
        Ok(Self { app, routes, own_headers })
    }

    fn find_route(&self, path: &str) -> Option<(&RouteState, usize)> {
        self.routes.iter().find_map(|r| route_rest(&r.route.prefix, path).map(|rest| (r, path.len() - rest.len())))
    }

    async fn handle(&self, req: Request<Incoming>, mtls: Option<&str>) -> Response<Body> {
        let Some((rs, cut)) = self.find_route(req.uri().path()) else {
            return json_error(StatusCode::NOT_FOUND, "no route");
        };
        let principal = match self.app.auth.authenticate(req.headers(), mtls) {
            Ok(p) => p,
            Err(e) => {
                self.app.metrics.auth_failures.fetch_add(1, Relaxed);
                tracing::debug!(route = %rs.route.name, "authentication failed: {e}");
                return json_error(StatusCode::UNAUTHORIZED, &e.to_string());
            }
        };
        let Some(uri) = join_uri(&rs.upstream, &req.uri().path()[cut..], req.uri().query()) else {
            return json_error(StatusCode::BAD_REQUEST, "invalid request path");
        };
        let (parts, body) = req.into_parts();
        let ctx = self.context(&parts.headers, principal);
        let headers = self.upstream_headers(rs, parts.headers);
        let out = Outbound { method: parts.method, uri, headers };
        match rs.route.kind {
            RouteKind::Llm if has_body(&out.method) => match read_body(&out.headers, body).await {
                Ok(bytes) => llm::handle(self, rs, ctx, out, bytes).await,
                Err(resp) => resp,
            },
            RouteKind::Mcp if out.method == Method::POST => match read_body(&out.headers, body).await {
                Ok(bytes) => mcp::handle(self, rs, Arc::new(ctx), out, bytes).await,
                Err(resp) => resp,
            },
            RouteKind::A2a => a2a::handle(self, rs, Arc::new(ctx), out, body).await,
            _ => self.forward(rs, out, body.map_err(BoxError::from).boxed()).await,
        }
    }

    fn context(&self, headers: &HeaderMap, principal: Principal) -> Ctx {
        let session = header_str(headers, &self.app.cfg.identity.session_header)
            .or_else(|| header_str(headers, MCP_SESSION_HEADER))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        Ctx {
            principal,
            explicit_session: session.is_some(),
            session: session.unwrap_or_else(|| "default".into()),
            trace_id: trace_id(headers),
        }
    }

    /// Request headers as sent upstream.
    fn upstream_headers(&self, rs: &RouteState, mut h: HeaderMap) -> HeaderMap {
        strip_hop_by_hop(&mut h);
        // The client sets Host (HTTP/1.1) or :authority (HTTP/2) from the
        // upstream URI.
        h.remove(header::HOST);
        for name in self.own_headers.iter().chain(&rs.strip) {
            h.remove(name);
        }
        // A JWT presented to nandi is nandi's credential, not the upstream's.
        if self.app.cfg.identity.jwt.is_some()
            && header_str(&h, "authorization").is_some_and(|v| {
                v.split_once(' ').is_some_and(|(s, t)| s.eq_ignore_ascii_case("bearer") && t.matches('.').count() == 2)
            })
        {
            h.remove(header::AUTHORIZATION);
        }
        for (name, value) in &rs.inject {
            h.insert(name.clone(), value.clone());
        }
        // Inspected bodies must not be compressed.
        h.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        h
    }

    /// Send a request upstream. Errors come back as ready-made 502 responses.
    // The error is the response to return as is; boxing it buys nothing.
    #[allow(clippy::result_large_err)]
    pub(super) async fn send(
        &self,
        rs: &RouteState,
        out: Outbound,
        body: Body,
    ) -> Result<Response<Incoming>, Response<Body>> {
        let mut req = Request::new(body);
        *req.method_mut() = out.method;
        *req.uri_mut() = out.uri;
        *req.headers_mut() = out.headers;
        self.app.metrics.upstream_requests.fetch_add(1, Relaxed);
        let err = match tokio::time::timeout(rs.timeout, self.app.client.request(req)).await {
            Ok(Ok(resp)) => return Ok(resp),
            Ok(Err(e)) => format!("upstream request failed: {e}"),
            Err(_) => format!("upstream did not respond within {}s", rs.timeout.as_secs()),
        };
        self.app.metrics.upstream_errors.fetch_add(1, Relaxed);
        tracing::warn!(route = %rs.route.name, "{err}");
        Err(json_error(StatusCode::BAD_GATEWAY, &err))
    }

    /// Forward a streaming body and stream the response back untouched.
    pub(super) async fn forward(&self, rs: &RouteState, out: Outbound, body: Body) -> Response<Body> {
        match self.send(rs, out, body).await {
            Ok(resp) => passthrough(resp),
            Err(resp) => resp,
        }
    }

    /// Forward a buffered body and stream the response back untouched.
    pub(super) async fn forward_bytes(&self, rs: &RouteState, out: Outbound, body: Bytes) -> Response<Body> {
        self.forward(rs, out.with_len(body.len()), full(body)).await
    }
}

fn route_state(route: &Route) -> anyhow::Result<RouteState> {
    if !route.prefix.starts_with('/') {
        bail!("prefix {:?} must start with '/'", route.prefix);
    }
    let upstream: Uri = route.upstream.parse().with_context(|| format!("invalid upstream {:?}", route.upstream))?;
    if upstream.scheme().is_none() || upstream.authority().is_none() {
        bail!("upstream {:?} must be an absolute http(s) URL", route.upstream);
    }
    let provider = match &route.provider {
        Some(name) => Some(Provider::from_name(name).with_context(|| format!("unknown provider {name:?}"))?),
        None => None,
    };
    let mut inject = Vec::with_capacity(route.inject_headers.len());
    for (name, value) in &route.inject_headers {
        let header =
            HeaderName::from_bytes(name.as_bytes()).with_context(|| format!("invalid header name {name:?}"))?;
        let resolved = resolve_secret(value).with_context(|| format!("resolving inject_headers.{name}"))?;
        let mut value = HeaderValue::from_str(resolved.trim())
            .with_context(|| format!("inject_headers.{name} is not a valid header value"))?;
        value.set_sensitive(true);
        inject.push((header, value));
    }
    let strip = route
        .strip_headers
        .iter()
        .map(|h| HeaderName::from_bytes(h.as_bytes()).with_context(|| format!("invalid header name {h:?}")))
        .collect::<anyhow::Result<_>>()?;
    Ok(RouteState {
        route: route.clone(),
        upstream,
        provider,
        inject,
        strip,
        timeout: Duration::from_secs(route.timeout_secs.max(1)),
    })
}

/// The part of `path` after `prefix`, when the prefix matches on a segment
/// boundary (`/openai` matches `/openai` and `/openai/x`, not `/openaix`).
fn route_rest<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    let prefix = prefix.trim_end_matches('/');
    let rest = path.strip_prefix(prefix)?;
    (rest.is_empty() || rest.starts_with('/')).then_some(rest)
}

/// Upstream URI: the upstream's base path joined with `rest`, plus `query`.
fn join_uri(upstream: &Uri, rest: &str, query: Option<&str>) -> Option<Uri> {
    let base = upstream.path().trim_end_matches('/');
    let mut pq = String::with_capacity(base.len() + rest.len() + query.map_or(0, |q| q.len() + 1) + 1);
    pq.push_str(base);
    pq.push_str(rest);
    if pq.is_empty() {
        pq.push('/');
    }
    if let Some(q) = query {
        pq.push('?');
        pq.push_str(q);
    }
    Uri::builder()
        .scheme(upstream.scheme()?.clone())
        .authority(upstream.authority()?.clone())
        .path_and_query(pq)
        .build()
        .ok()
}

/// Method, URI and headers of the request sent upstream.
pub(super) struct Outbound {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
}

impl Outbound {
    /// Set `Content-Length` for a replaced, buffered body.
    pub fn with_len(mut self, len: usize) -> Self {
        self.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
        self
    }
}

/// Who is calling and in which session / trace.
pub(super) struct Ctx {
    pub principal: Principal,
    pub session: String,
    /// The session came from a request header (not derived).
    pub explicit_session: bool,
    pub trace_id: Option<String>,
}

impl Ctx {
    pub fn event(&self, kind: EventKind) -> Event {
        let mut ev = Event::new(Source::Proxy, self.principal.agent.as_str(), self.session.as_str(), kind);
        ev.trace_id.clone_from(&self.trace_id);
        ev
    }

    pub fn groups(&self) -> &[String] {
        &self.principal.groups
    }
}

/// Trace id of a W3C `traceparent` header.
fn trace_id(headers: &HeaderMap) -> Option<String> {
    let v = header_str(headers, "traceparent")?.trim();
    let mut parts = v.split('-');
    let (version, id, span) = (parts.next()?, parts.next()?, parts.next()?);
    let lower_hex = |s: &str| s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let valid = version.len() == 2
        && version != "ff"
        && lower_hex(version)
        && id.len() == 32
        && lower_hex(id)
        && id.bytes().any(|b| b != b'0')
        && span.len() == 16;
    valid.then(|| id.to_string())
}

pub(super) fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn has_body(method: &Method) -> bool {
    matches!(*method, Method::POST | Method::PUT | Method::PATCH)
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn strip_hop_by_hop(h: &mut HeaderMap) {
    let listed: Vec<HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for name in &listed {
        h.remove(name);
    }
    for name in HOP_BY_HOP {
        h.remove(*name);
    }
}

/// Buffer a request body up to [`MAX_BODY`].
#[allow(clippy::result_large_err)]
async fn read_body(headers: &HeaderMap, body: Incoming) -> Result<Bytes, Response<Body>> {
    let too_large = || json_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    if header_str(headers, "content-length").and_then(|v| v.parse::<u64>().ok()).is_some_and(|n| n > MAX_BODY as u64) {
        return Err(too_large());
    }
    match Limited::new(body, MAX_BODY).collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(e) if e.is::<LengthLimitError>() => Err(too_large()),
        Err(e) => {
            tracing::debug!("reading request body failed: {e}");
            Err(json_error(StatusCode::BAD_REQUEST, "reading request body failed"))
        }
    }
}

/// Buffer a response body up to `limit`. A larger (or failing) body comes
/// back as a body that replays what was read and streams the rest.
pub(super) async fn buffer_body(mut body: Incoming, limit: usize) -> Result<Bytes, Body> {
    let mut buf = BytesMut::new();
    loop {
        match body.frame().await {
            None => return Ok(buf.freeze()),
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    buf.extend_from_slice(&data);
                    if buf.len() > limit {
                        return Err(PrefixBody { prefix: Some(buf.freeze()), inner: Some(body), error: None }.boxed());
                    }
                }
            }
            Some(Err(e)) => {
                return Err(PrefixBody { prefix: Some(buf.freeze()), inner: None, error: Some(e.into()) }.boxed());
            }
        }
    }
}

/// Upstream response streamed back as is.
pub(super) fn passthrough(resp: Response<Incoming>) -> Response<Body> {
    let (mut parts, body) = resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    Response::from_parts(parts, body.map_err(BoxError::from).boxed())
}

/// An upstream body as a client body, unchanged.
pub(super) fn passthrough_body(body: Incoming) -> Body {
    body.map_err(BoxError::from).boxed()
}

/// Upstream response with its body replaced (or re-streamed).
pub(super) fn with_body(mut parts: http::response::Parts, body: Body, len: Option<usize>) -> Response<Body> {
    strip_hop_by_hop(&mut parts.headers);
    match len {
        Some(n) => {
            parts.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(n));
        }
        None => {
            parts.headers.remove(header::CONTENT_LENGTH);
        }
    }
    Response::from_parts(parts, body)
}

/// Upstream response with a buffered replacement body.
pub(super) fn with_bytes(parts: http::response::Parts, bytes: Bytes) -> Response<Body> {
    let len = bytes.len();
    with_body(parts, full(bytes), Some(len))
}

pub(super) fn json_response(status: StatusCode, value: &Value) -> Response<Body> {
    let body = serde_json::to_vec(value).unwrap_or_default();
    let mut resp = Response::new(full(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

pub(super) fn json_error(status: StatusCode, message: &str) -> Response<Body> {
    json_response(status, &json!({ "error": message }))
}

/// 403 for a request or response blocked by policy.
pub(super) fn policy_block(reason: &str) -> Response<Body> {
    json_response(StatusCode::FORBIDDEN, &json!({"error": {"type": "nandi_policy", "message": reason}}))
}

fn content_type(h: &HeaderMap) -> &str {
    header_str(h, "content-type").unwrap_or("")
}

pub(super) fn is_sse(h: &HeaderMap) -> bool {
    content_type(h).trim_start().to_ascii_lowercase().starts_with("text/event-stream")
}

pub(super) fn is_json(h: &HeaderMap) -> bool {
    content_type(h).to_ascii_lowercase().contains("json")
}

/// JSON-RPC id as a call id string (`"a"` -> `a`, `7` -> `7`).
pub(super) fn id_string(id: &Value) -> String {
    match id {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Run `app.decide` in the background (record-only decisions).
pub(super) fn decide_later(app: &Arc<App>, ev: Event, groups: Vec<String>) {
    let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
    let app = app.clone();
    rt.spawn(async move {
        app.decide(ev, &groups).await;
    });
}

/// Observer of a passing-through response stream.
pub(super) trait StreamTap: Send + Sync {
    fn data(&mut self, chunk: &[u8]);
    /// End of stream, upstream error or client disconnect. Called once.
    fn end(self: Box<Self>);
}

/// Streams an upstream body unchanged while showing every chunk to a tap.
pub(super) struct TapBody {
    inner: Incoming,
    tap: Option<Box<dyn StreamTap>>,
}

impl TapBody {
    pub fn new(inner: Incoming, tap: Box<dyn StreamTap>) -> Self {
        Self { inner, tap: Some(tap) }
    }

    fn finish(&mut self) {
        if let Some(tap) = self.tap.take() {
            tap.end();
        }
    }
}

impl HttpBody for TapBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(data), Some(tap)) = (frame.data_ref(), this.tap.as_mut()) {
                    tap.data(data);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.finish();
                Poll::Ready(Some(Err(e.into())))
            }
            Poll::Ready(None) => {
                this.finish();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for TapBody {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Replays a buffered prefix, then the rest of a body (or an error).
struct PrefixBody {
    prefix: Option<Bytes>,
    inner: Option<Incoming>,
    error: Option<BoxError>,
}

impl HttpBody for PrefixBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        if let Some(p) = this.prefix.take().filter(|p| !p.is_empty()) {
            return Poll::Ready(Some(Ok(Frame::data(p))));
        }
        if let Some(e) = this.error.take() {
            return Poll::Ready(Some(Err(e)));
        }
        match this.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_frame(cx).map_err(BoxError::from),
            None => Poll::Ready(None),
        }
    }
}

/// Response body fed by a task through a channel.
pub(super) struct ChannelBody {
    rx: mpsc::Receiver<Result<Bytes, BoxError>>,
}

impl HttpBody for ChannelBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.rx.poll_recv(cx).map(|item| item.map(|r| r.map(Frame::data)))
    }
}

/// Re-streams an upstream SSE body event by event (see [`SseRelay`]).
pub(super) fn sse_relay(body: Incoming) -> (SseRelay, Body) {
    let (tx, rx) = mpsc::channel(16);
    (SseRelay { body, parser: SseParser::with_limit(MAX_BODY), tx, done: false }, ChannelBody { rx }.boxed())
}

/// Reads SSE events from upstream and writes (possibly rewritten) events to
/// the client.
pub(super) struct SseRelay {
    body: Incoming,
    parser: SseParser,
    tx: mpsc::Sender<Result<Bytes, BoxError>>,
    done: bool,
}

impl SseRelay {
    /// Next batch of complete events; `None` at end of stream or on error
    /// (the error is passed on to the client).
    pub async fn next_events(&mut self) -> Option<Vec<SseEvent>> {
        while !self.done {
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        let events = self.parser.feed(&data);
                        if !events.is_empty() {
                            return Some(events);
                        }
                    }
                }
                Some(Err(e)) => {
                    self.done = true;
                    let _ = self.tx.send(Err(e.into())).await;
                }
                None => {
                    self.done = true;
                    return std::mem::take(&mut self.parser).finish().map(|ev| vec![ev]);
                }
            }
        }
        None
    }

    /// Send one event; false once the client is gone.
    pub async fn send(&self, ev: &SseEvent) -> bool {
        self.tx.send(Ok(Bytes::from(sse::encode(ev)))).await.is_ok()
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn prefix_matches_on_segment_boundary() {
        assert_eq!(route_rest("/openai", "/openai/v1/chat"), Some("/v1/chat"));
        assert_eq!(route_rest("/openai/", "/openai"), Some(""));
        assert_eq!(route_rest("/openai", "/openaix"), None);
        assert_eq!(route_rest("/", "/x"), Some("/x"));
    }

    #[test]
    fn joins_upstream_path_and_query() {
        let up: Uri = "https://api.example.com/v1/".parse().unwrap();
        assert_eq!(join_uri(&up, "/chat", Some("a=1")).unwrap().to_string(), "https://api.example.com/v1/chat?a=1");
        assert_eq!(join_uri(&up, "", None).unwrap().to_string(), "https://api.example.com/v1");
        let bare: Uri = "http://127.0.0.1:9".parse().unwrap();
        assert_eq!(join_uri(&bare, "", None).unwrap().path(), "/");
    }

    #[test]
    fn parses_traceparent() {
        let mut h = HeaderMap::new();
        h.insert("traceparent", HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"));
        assert_eq!(trace_id(&h).as_deref(), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
        h.insert("traceparent", HeaderValue::from_static("00-00000000000000000000000000000000-00f067aa0ba902b7-01"));
        assert_eq!(trace_id(&h), None);
        h.insert("traceparent", HeaderValue::from_static("garbage"));
        assert_eq!(trace_id(&h), None);
    }

    #[test]
    fn strips_hop_by_hop_and_connection_listed_headers() {
        let mut h = HeaderMap::new();
        h.insert(header::CONNECTION, HeaderValue::from_static("keep-alive, x-private"));
        h.insert("x-private", HeaderValue::from_static("1"));
        h.insert(header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        h.insert("x-keep", HeaderValue::from_static("1"));
        strip_hop_by_hop(&mut h);
        assert_eq!(h.len(), 1);
        assert!(h.contains_key("x-keep"));
    }

    #[test]
    fn rejects_unresolvable_injected_secret() {
        let route = Route {
            name: "r".into(),
            prefix: "/r".into(),
            upstream: "http://127.0.0.1:1".into(),
            kind: RouteKind::Llm,
            provider: None,
            inject_headers: [("authorization".to_string(), "env:NANDI_PROXY_TEST_UNSET_VAR".to_string())].into(),
            strip_headers: Vec::new(),
            timeout_secs: 5,
        };
        let err = route_state(&route).err().unwrap();
        assert!(format!("{err:#}").contains("NANDI_PROXY_TEST_UNSET_VAR"));
    }
}
