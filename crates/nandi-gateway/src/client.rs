//! Shared outbound HTTP client (upstreams, webhooks, OTLP).

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// Body type used for everything the gateway sends or streams.
pub type Body = BoxBody<Bytes, BoxError>;
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type HttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>;

/// Build the client: HTTP/1.1 and HTTP/2 over rustls (ring) with the bundled
/// Mozilla root store, so static builds need no system certificates.
pub fn build() -> HttpClient {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_connect_timeout(Some(Duration::from_secs(10)));
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(8)
        .build(https)
}

pub fn full(data: impl Into<Bytes>) -> Body {
    Full::new(data.into()).map_err(|never| match never {}).boxed()
}

pub fn empty() -> Body {
    full(Bytes::new())
}

/// POST a JSON document and ignore the response body (webhooks, OTLP).
pub async fn post_json(
    client: &HttpClient,
    url: &str,
    headers: &[(String, String)],
    body: &serde_json::Value,
) -> anyhow::Result<u16> {
    let mut req = http::Request::post(url).header(http::header::CONTENT_TYPE, "application/json");
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let req = req.body(full(serde_json::to_vec(body)?))?;
    let resp = tokio::time::timeout(Duration::from_secs(10), client.request(req)).await??;
    let status = resp.status().as_u16();
    // Drain so the connection can be reused.
    let _ = resp.into_body().collect().await;
    Ok(status)
}
