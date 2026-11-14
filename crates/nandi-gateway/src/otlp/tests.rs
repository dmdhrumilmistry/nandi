use std::collections::HashMap;
use std::io::Read as _;
use std::sync::atomic::AtomicUsize;

use axum::Router;
use axum::body::Bytes as AxBytes;
use axum::http::{HeaderMap, StatusCode, Uri};
use parking_lot::Mutex;
use prost::Message as _;

use nandi_core::config::OtlpSignals;
use nandi_core::{AdminAction, Category, Decision, Event, EventKind, Finding, Severity, Source, ToolCall};

use super::*;

/// OTLP messages decoded with prost, independently of nandi's encoder.
/// Field numbers from opentelemetry-proto.
mod proto {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct AnyValue {
        #[prost(oneof = "any::Value", tags = "1, 2, 3, 4")]
        pub value: Option<any::Value>,
    }
    pub mod any {
        #[derive(Clone, PartialEq, prost::Oneof)]
        pub enum Value {
            #[prost(string, tag = "1")]
            Str(String),
            #[prost(bool, tag = "2")]
            Bool(bool),
            #[prost(int64, tag = "3")]
            Int(i64),
            #[prost(double, tag = "4")]
            Double(f64),
        }
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct KeyValue {
        #[prost(string, tag = "1")]
        pub key: String,
        #[prost(message, optional, tag = "2")]
        pub value: Option<AnyValue>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Resource {
        #[prost(message, repeated, tag = "1")]
        pub attributes: Vec<KeyValue>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Scope {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(string, tag = "2")]
        pub version: String,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Status {
        #[prost(string, tag = "2")]
        pub message: String,
        #[prost(int32, tag = "3")]
        pub code: i32,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Span {
        #[prost(bytes = "vec", tag = "1")]
        pub trace_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        pub span_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "4")]
        pub parent_span_id: Vec<u8>,
        #[prost(string, tag = "5")]
        pub name: String,
        #[prost(int32, tag = "6")]
        pub kind: i32,
        #[prost(fixed64, tag = "7")]
        pub start_time_unix_nano: u64,
        #[prost(fixed64, tag = "8")]
        pub end_time_unix_nano: u64,
        #[prost(message, repeated, tag = "9")]
        pub attributes: Vec<KeyValue>,
        #[prost(message, optional, tag = "15")]
        pub status: Option<Status>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ScopeSpans {
        #[prost(message, optional, tag = "1")]
        pub scope: Option<Scope>,
        #[prost(message, repeated, tag = "2")]
        pub spans: Vec<Span>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ResourceSpans {
        #[prost(message, optional, tag = "1")]
        pub resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")]
        pub scope_spans: Vec<ScopeSpans>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Traces {
        #[prost(message, repeated, tag = "1")]
        pub resource_spans: Vec<ResourceSpans>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct LogRecord {
        #[prost(fixed64, tag = "1")]
        pub time_unix_nano: u64,
        #[prost(int32, tag = "2")]
        pub severity_number: i32,
        #[prost(string, tag = "3")]
        pub severity_text: String,
        #[prost(message, optional, tag = "5")]
        pub body: Option<AnyValue>,
        #[prost(message, repeated, tag = "6")]
        pub attributes: Vec<KeyValue>,
        #[prost(bytes = "vec", tag = "9")]
        pub trace_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "10")]
        pub span_id: Vec<u8>,
        #[prost(fixed64, tag = "11")]
        pub observed_time_unix_nano: u64,
        #[prost(string, tag = "12")]
        pub event_name: String,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ScopeLogs {
        #[prost(message, optional, tag = "1")]
        pub scope: Option<Scope>,
        #[prost(message, repeated, tag = "2")]
        pub log_records: Vec<LogRecord>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ResourceLogs {
        #[prost(message, optional, tag = "1")]
        pub resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")]
        pub scope_logs: Vec<ScopeLogs>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Logs {
        #[prost(message, repeated, tag = "1")]
        pub resource_logs: Vec<ResourceLogs>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct NumberDataPoint {
        #[prost(fixed64, tag = "2")]
        pub start_time_unix_nano: u64,
        #[prost(fixed64, tag = "3")]
        pub time_unix_nano: u64,
        #[prost(message, repeated, tag = "7")]
        pub attributes: Vec<KeyValue>,
        #[prost(oneof = "number::Value", tags = "4, 6")]
        pub value: Option<number::Value>,
    }
    pub mod number {
        #[derive(Clone, PartialEq, prost::Oneof)]
        pub enum Value {
            #[prost(double, tag = "4")]
            Double(f64),
            #[prost(sfixed64, tag = "6")]
            Int(i64),
        }
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct HistogramDataPoint {
        #[prost(fixed64, tag = "2")]
        pub start_time_unix_nano: u64,
        #[prost(fixed64, tag = "3")]
        pub time_unix_nano: u64,
        #[prost(fixed64, tag = "4")]
        pub count: u64,
        #[prost(double, optional, tag = "5")]
        pub sum: Option<f64>,
        #[prost(fixed64, repeated, tag = "6")]
        pub bucket_counts: Vec<u64>,
        #[prost(double, repeated, tag = "7")]
        pub explicit_bounds: Vec<f64>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Gauge {
        #[prost(message, repeated, tag = "1")]
        pub data_points: Vec<NumberDataPoint>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Sum {
        #[prost(message, repeated, tag = "1")]
        pub data_points: Vec<NumberDataPoint>,
        #[prost(int32, tag = "2")]
        pub aggregation_temporality: i32,
        #[prost(bool, tag = "3")]
        pub is_monotonic: bool,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Histogram {
        #[prost(message, repeated, tag = "1")]
        pub data_points: Vec<HistogramDataPoint>,
        #[prost(int32, tag = "2")]
        pub aggregation_temporality: i32,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Metric {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(string, tag = "2")]
        pub description: String,
        #[prost(string, tag = "3")]
        pub unit: String,
        #[prost(oneof = "metric::Data", tags = "5, 7, 9")]
        pub data: Option<metric::Data>,
    }
    pub mod metric {
        #[derive(Clone, PartialEq, prost::Oneof)]
        pub enum Data {
            #[prost(message, tag = "5")]
            Gauge(super::Gauge),
            #[prost(message, tag = "7")]
            Sum(super::Sum),
            #[prost(message, tag = "9")]
            Histogram(super::Histogram),
        }
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ScopeMetrics {
        #[prost(message, optional, tag = "1")]
        pub scope: Option<Scope>,
        #[prost(message, repeated, tag = "2")]
        pub metrics: Vec<Metric>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ResourceMetrics {
        #[prost(message, optional, tag = "1")]
        pub resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")]
        pub scope_metrics: Vec<ScopeMetrics>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Metrics {
        #[prost(message, repeated, tag = "1")]
        pub resource_metrics: Vec<ResourceMetrics>,
    }

    pub fn attr<'a>(attrs: &'a [KeyValue], key: &str) -> Option<&'a any::Value> {
        attrs.iter().find(|a| a.key == key).and_then(|a| a.value.as_ref()).and_then(|v| v.value.as_ref())
    }

    pub fn str_attr(attrs: &[KeyValue], key: &str) -> Option<String> {
        match attr(attrs, key) {
            Some(any::Value::Str(s)) => Some(s.clone()),
            _ => None,
        }
    }
}

type Seen = Arc<Mutex<Vec<(String, HeaderMap, Vec<u8>)>>>;

/// A local OTLP/HTTP receiver; answers `fail_first` requests with 503, then
/// everything with `status`.
async fn receiver(fail_first: usize, status: u16) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let count = Arc::new(AtomicUsize::new(0));
    let s2 = seen.clone();
    let app = Router::new().fallback(move |uri: Uri, headers: HeaderMap, body: AxBytes| {
        let (seen, count) = (s2.clone(), count.clone());
        async move {
            seen.lock().push((uri.path().to_string(), headers, body.to_vec()));
            if count.fetch_add(1, Relaxed) < fail_first {
                return (StatusCode::SERVICE_UNAVAILABLE, "busy");
            }
            (StatusCode::from_u16(status).unwrap(), "{}")
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    move |k| map.get(k).cloned()
}

fn tool_call(verdict: Verdict) -> Arc<LiveEvent> {
    let mut ev = Event::new(
        Source::Proxy,
        "billing-agent",
        "s1",
        EventKind::ToolCall(ToolCall {
            server: "bank".into(),
            tool: "transfer".into(),
            call_id: Some("c1".into()),
            args: json!({ "amount": 48000 }),
        }),
    );
    ev.trace_id = Some("4bf92f3577b34da6a3ce929d0e0e4736".into());
    ev.parent_span_id = Some("00f067aa0ba902b7".into());
    let mut d = Decision::allow();
    if verdict != Verdict::Allow {
        d.push(Finding::new("policy.large-payment", Category::Policy, Severity::High, verdict, "needs a human"));
    }
    Arc::new(LiveEvent { seq: Some(3), event: ev, decision: d, applied: verdict })
}

fn admin_action() -> Arc<LiveEvent> {
    let ev = Event::new(
        Source::Admin,
        "alice",
        "admin",
        EventKind::Admin(AdminAction {
            actor: "alice".into(),
            action: "killswitch.disable".into(),
            target: "billing-agent".into(),
            outcome: "ok".into(),
            details: Value::Null,
        }),
    );
    Arc::new(LiveEvent { seq: Some(4), event: ev, decision: Decision::allow(), applied: Verdict::Allow })
}

#[test]
fn settings_follow_config_then_environment() {
    let cfg = TelemetryConfig::default();
    assert!(Settings::resolve(&cfg, env(&[])).unwrap().is_none());

    // The standard variables alone turn everything on.
    let s = Settings::resolve(
        &cfg,
        env(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318/"),
            ("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "http://logs:4318/custom"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer%20abc,x-scope=team-a"),
            ("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "x-scope=team-b"),
            ("OTEL_METRICS_EXPORTER", "none"),
            ("OTEL_SERVICE_NAME", "gate-eu"),
            ("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment.name=prod,service.name=ignored"),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json"),
            ("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip"),
            ("OTEL_METRIC_EXPORT_INTERVAL", "15000"),
        ]),
    )
    .unwrap()
    .unwrap();
    let traces = s.traces.unwrap();
    assert_eq!(traces.url, "http://collector:4318/v1/traces");
    assert!(traces.headers.contains(&("authorization".into(), "Bearer abc".into())));
    assert!(traces.headers.contains(&("x-scope".into(), "team-b".into())));
    assert_eq!(s.logs.unwrap().url, "http://logs:4318/custom");
    assert!(s.metrics.is_none());
    assert_eq!(s.protocol, OtlpProtocol::HttpJson);
    assert_eq!(s.compression, OtlpCompression::Gzip);
    assert_eq!(s.metrics_interval, Duration::from_secs(15));
    let get = |k: &str| s.resource.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
    assert_eq!(get("service.name"), Some(json!("gate-eu")));
    assert_eq!(get("deployment.environment.name"), Some(json!("prod")));
    assert_eq!(get("service.version"), Some(json!(VERSION)));

    // The configuration wins over the environment.
    let cfg = TelemetryConfig {
        otlp_endpoint: Some("https://otlp.example.com".into()),
        otlp_protocol: Some(OtlpProtocol::HttpProtobuf),
        otlp_signals: OtlpSignals { traces: true, metrics: true, logs: false },
        service_name: "nandi-prod".into(),
        resource_attributes: [("deployment.environment.name".to_string(), "staging".to_string())].into(),
        ..TelemetryConfig::default()
    };
    let s = Settings::resolve(
        &cfg,
        env(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://ignored:4318"),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json"),
            ("OTEL_SERVICE_NAME", "ignored"),
            ("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment.name=prod"),
        ]),
    )
    .unwrap()
    .unwrap();
    assert_eq!(s.traces.unwrap().url, "https://otlp.example.com/v1/traces");
    assert_eq!(s.metrics.unwrap().url, "https://otlp.example.com/v1/metrics");
    assert!(s.logs.is_none());
    assert_eq!(s.protocol, OtlpProtocol::HttpProtobuf);
    let get = |k: &str| s.resource.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
    assert_eq!(get("service.name"), Some(json!("nandi-prod")));
    assert_eq!(get("deployment.environment.name"), Some(json!("staging")));

    // OTEL_SDK_DISABLED turns it all off; bad URLs are errors.
    assert!(Settings::resolve(&cfg, env(&[("OTEL_SDK_DISABLED", "true")])).unwrap().is_none());
    let bad = TelemetryConfig { otlp_endpoint: Some("collector:4318".into()), ..TelemetryConfig::default() };
    assert!(Settings::resolve(&bad, env(&[])).is_err());
}

#[test]
fn pairs_are_percent_decoded() {
    assert_eq!(
        parse_pairs("a=b%3Dc, k%20x = v%2C1 ,broken,=x,%zz=%"),
        vec![("a".into(), "b=c".into()), ("k x".into(), "v,1".into()), ("%zz".into(), "%".into())]
    );
    assert_eq!(
        redact_url("https://user:pw@otlp.example.com:443/v1/traces?key=s"),
        "https://otlp.example.com:443/v1/traces"
    );
}

#[test]
fn spans_and_logs_link_and_follow_conventions() {
    let e = tool_call(Verdict::Deny);
    let span = model::span(&e, 2_000).unwrap();
    assert_eq!(span["name"], "execute_tool transfer");
    assert_eq!(span["traceId"], "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(span["parentSpanId"], "00f067aa0ba902b7");
    assert_eq!(span["status"]["code"], 2);
    let log = model::log_record(&e, 1);
    assert_eq!(log["traceId"], span["traceId"]);
    assert_eq!(log["spanId"], span["spanId"]);
    assert_eq!((log["severityNumber"].as_u64(), log["severityText"].as_str()), (Some(17), Some("ERROR")));
    assert_eq!(log["eventName"], model::DECISION_EVENT);

    // An event without trace context is a trace of its own, with ids
    // derived from the event id (stable across span and log).
    let mut plain = (*tool_call(Verdict::Alert)).clone();
    plain.event.trace_id = None;
    plain.event.parent_span_id = None;
    let span = model::span(&plain, 1).unwrap();
    assert_eq!(span["traceId"].as_str().unwrap(), plain.event.id.replace('-', ""));
    assert!(span.get("parentSpanId").is_none());
    assert_eq!(model::log_record(&plain, 1)["spanId"], span["spanId"]);
    assert_eq!(model::log_record(&plain, 1)["severityText"], "WARN");

    // Admin actions are log records only.
    let a = admin_action();
    assert!(model::span(&a, 1).is_none());
    let log = model::log_record(&a, 1);
    assert_eq!(log["eventName"], model::ADMIN_EVENT);
    assert!(log.get("traceId").is_none());
    assert!(log.to_string().contains("killswitch.disable"));
}

#[test]
fn histogram_buckets_are_per_bucket() {
    let m = crate::metrics::Metrics::new();
    let ev = tool_call(Verdict::Allow);
    for us in [40, 120, 120, 60_000] {
        m.observe(&ev.event, &ev.decision, us);
    }
    let out = model::metrics(&m.series(&[]), 1, 2);
    let h = out.iter().find(|m| m["name"] == "nandi.eval.duration").unwrap();
    let p = &h["histogram"]["dataPoints"][0];
    let counts: Vec<&str> = p["bucketCounts"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    // Bounds 50us, 100us, 250us, ... 50ms, then the overflow bucket.
    assert_eq!(counts, ["1", "0", "2", "0", "0", "0", "0", "0", "0", "1"]);
    assert_eq!(p["count"], "4");
    let sum = out.iter().find(|m| m["name"] == "nandi.decisions").unwrap();
    assert_eq!(sum["sum"]["isMonotonic"], true);
}

fn settings(base: &str, protocol: OtlpProtocol, compression: OtlpCompression) -> Settings {
    let cfg = TelemetryConfig {
        otlp_endpoint: Some(base.into()),
        otlp_protocol: Some(protocol),
        otlp_compression: Some(compression),
        otlp_headers: [("x-api-key".to_string(), "k1".to_string())].into(),
        ..TelemetryConfig::default()
    };
    Settings::resolve(&cfg, env(&[])).unwrap().unwrap()
}

fn find<'a>(seen: &'a [(String, HeaderMap, Vec<u8>)], path: &str) -> &'a (String, HeaderMap, Vec<u8>) {
    seen.iter().find(|(p, ..)| p == path).unwrap_or_else(|| panic!("nothing sent to {path}"))
}

#[tokio::test]
async fn delivers_protobuf_that_decodes() {
    let (base, seen) = receiver(0, 200).await;
    let otlp = Otlp::start(settings(&base, OtlpProtocol::HttpProtobuf, OtlpCompression::None), crate::client::build());
    otlp.record(&tool_call(Verdict::Deny), 1_500);
    otlp.record(&admin_action(), 0);
    otlp.flush().await;
    let m = crate::metrics::Metrics::new();
    m.observe(&tool_call(Verdict::Deny).event, &tool_call(Verdict::Deny).decision, 120);
    let endpoint = otlp.settings().metrics.clone().unwrap();
    otlp.push_metrics(&endpoint, &m.series(&[])).await;

    let seen = seen.lock().clone();
    let (_, headers, body) = find(&seen, "/v1/traces");
    assert_eq!(headers["content-type"], "application/x-protobuf");
    assert_eq!(headers["x-api-key"], "k1");
    let traces = proto::Traces::decode(body.as_slice()).unwrap();
    let rs = &traces.resource_spans[0];
    let res = &rs.resource.as_ref().unwrap().attributes;
    assert_eq!(proto::str_attr(res, "service.name").as_deref(), Some("nandi"));
    assert_eq!(rs.scope_spans[0].scope.as_ref().unwrap().name, "nandi");
    let spans = &rs.scope_spans[0].spans;
    assert_eq!(spans.len(), 1, "admin actions have no span");
    let s = &spans[0];
    assert_eq!(s.name, "execute_tool transfer");
    assert_eq!(hex::encode(&s.trace_id), "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(hex::encode(&s.parent_span_id), "00f067aa0ba902b7");
    assert_eq!(s.span_id.len(), 8);
    assert_eq!(s.end_time_unix_nano - s.start_time_unix_nano, 1_500);
    assert_eq!(s.status.as_ref().unwrap().code, 2);
    assert_eq!(proto::str_attr(&s.attributes, "gen_ai.tool.name").as_deref(), Some("transfer"));
    assert_eq!(proto::str_attr(&s.attributes, "nandi.rules").as_deref(), Some("policy.large-payment"));
    assert!(matches!(proto::attr(&s.attributes, "nandi.audit.seq"), Some(proto::any::Value::Int(3))));
    assert!(matches!(proto::attr(&s.attributes, "nandi.enforced"), Some(proto::any::Value::Bool(_))));

    let (_, _, body) = find(&seen, "/v1/logs");
    let logs = proto::Logs::decode(body.as_slice()).unwrap();
    let records = &logs.resource_logs[0].scope_logs[0].log_records;
    assert_eq!(records.len(), 2);
    let decision = records.iter().find(|r| r.event_name == model::DECISION_EVENT).unwrap();
    assert_eq!((decision.severity_number, decision.severity_text.as_str()), (17, "ERROR"));
    assert_eq!(decision.trace_id, s.trace_id);
    assert_eq!(decision.span_id, s.span_id);
    assert!(decision.time_unix_nano > 0 && decision.observed_time_unix_nano > 0);
    let admin = records.iter().find(|r| r.event_name == model::ADMIN_EVENT).unwrap();
    assert_eq!(proto::str_attr(&admin.attributes, "user.name").as_deref(), Some("alice"));
    assert!(admin.trace_id.is_empty());
    assert!(matches!(
        admin.body.as_ref().and_then(|b| b.value.as_ref()),
        Some(proto::any::Value::Str(s)) if s.contains("killswitch.disable")
    ));

    let (_, _, body) = find(&seen, "/v1/metrics");
    let metrics = proto::Metrics::decode(body.as_slice()).unwrap();
    let all = &metrics.resource_metrics[0].scope_metrics[0].metrics;
    let decisions = all.iter().find(|m| m.name == "nandi.decisions").unwrap();
    let Some(proto::metric::Data::Sum(sum)) = &decisions.data else { panic!("not a sum") };
    assert!(sum.is_monotonic);
    assert_eq!(sum.aggregation_temporality, 2);
    let deny =
        sum.data_points.iter().find(|p| proto::str_attr(&p.attributes, "verdict").as_deref() == Some("deny")).unwrap();
    assert_eq!(deny.value, Some(proto::number::Value::Int(1)));
    assert!(deny.start_time_unix_nano > 0 && deny.time_unix_nano >= deny.start_time_unix_nano);
    let latency = all.iter().find(|m| m.name == "nandi.eval.duration").unwrap();
    assert_eq!(latency.unit, "s");
    let Some(proto::metric::Data::Histogram(h)) = &latency.data else { panic!("not a histogram") };
    let p = &h.data_points[0];
    assert_eq!(p.count, 1);
    assert_eq!(p.bucket_counts.len(), p.explicit_bounds.len() + 1);
    assert_eq!(p.bucket_counts.iter().sum::<u64>(), 1);
    assert!((p.sum.unwrap() - 0.00012).abs() < 1e-9);

    let status = otlp.status();
    assert_eq!(status.len(), 3);
    assert!(status.iter().all(|s| s.failed == 0 && s.last_error.is_none()));
    assert_eq!(status.iter().find(|s| s.signal == "traces").unwrap().sent, 1);
    assert_eq!(status.iter().find(|s| s.signal == "logs").unwrap().sent, 2);
}

#[tokio::test]
async fn json_gzip_retries_and_failures() {
    let (base, seen) = receiver(1, 200).await;
    let otlp = Otlp::start(settings(&base, OtlpProtocol::HttpJson, OtlpCompression::Gzip), crate::client::build());
    otlp.record(&tool_call(Verdict::Allow), 1_000);
    otlp.flush().await;
    {
        let seen = seen.lock();
        let traces: Vec<_> = seen.iter().filter(|(p, ..)| p == "/v1/traces").collect();
        assert_eq!(traces.len(), 2, "a 503 is retried");
        let (_, headers, body) = traces[1];
        assert_eq!(headers["content-encoding"], "gzip");
        assert_eq!(headers["content-type"], "application/json");
        let mut text = String::new();
        flate2::read::GzDecoder::new(body.as_slice()).read_to_string(&mut text).unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"], "execute_tool transfer");
    }
    let traces = otlp.status().into_iter().find(|s| s.signal == "traces").unwrap();
    assert_eq!((traces.sent, traces.failed), (1, 0));

    // A 400 is not retried and is reported.
    let (base, seen) = receiver(0, 400).await;
    let otlp = Otlp::start(settings(&base, OtlpProtocol::HttpJson, OtlpCompression::None), crate::client::build());
    otlp.record(&tool_call(Verdict::Allow), 1_000);
    otlp.flush().await;
    assert_eq!(seen.lock().iter().filter(|(p, ..)| p == "/v1/traces").count(), 1);
    let traces = otlp.status().into_iter().find(|s| s.signal == "traces").unwrap();
    assert_eq!((traces.sent, traces.failed), (0, 1));
    assert!(traces.last_error.unwrap().contains("400"));
}

#[tokio::test]
async fn log_records_follow_the_minimum_verdict() {
    let (base, seen) = receiver(0, 200).await;
    let cfg = TelemetryConfig {
        otlp_endpoint: Some(base),
        otlp_logs_min_verdict: Verdict::Alert,
        otlp_protocol: Some(OtlpProtocol::HttpJson),
        ..TelemetryConfig::default()
    };
    let otlp = Otlp::start(Settings::resolve(&cfg, env(&[])).unwrap().unwrap(), crate::client::build());
    otlp.record(&tool_call(Verdict::Allow), 1);
    otlp.record(&tool_call(Verdict::Redact), 1);
    otlp.record(&admin_action(), 0);
    otlp.flush().await;
    let seen = seen.lock();
    let (_, _, body) = find(&seen, "/v1/logs");
    let doc: Value = serde_json::from_slice(body).unwrap();
    let records = doc["resourceLogs"][0]["scopeLogs"][0]["logRecords"].as_array().unwrap();
    let texts: Vec<&str> = records.iter().map(|r| r["severityText"].as_str().unwrap()).collect();
    assert_eq!(texts, ["WARN", "INFO"], "the allowed call is left out, the admin action kept");
    let (_, _, body) = find(&seen, "/v1/traces");
    let doc: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(doc["resourceSpans"][0]["scopeSpans"][0]["spans"].as_array().unwrap().len(), 2);
}
