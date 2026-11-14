//! Prometheus metrics with fixed label sets and atomic counters.
//!
//! Hand-rolled to keep the dependency tree and memory small: every series is
//! known up front (event kinds, verdicts, finding categories), so a few
//! arrays of atomics cover everything.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use nandi_core::{Category, Decision, Event, Verdict};

const KINDS: &[&str] = &[
    "llm_request",
    "llm_response",
    "tool_list",
    "tool_call",
    "tool_result",
    "a2a_message",
    "agent_card",
    "plan_declared",
    "process",
    "file",
    "network",
];
const VERDICTS: &[Verdict] = &[Verdict::Allow, Verdict::Alert, Verdict::Redact, Verdict::Ask, Verdict::Deny];
const CATEGORIES: &[(Category, &str)] = &[
    (Category::Policy, "policy"),
    (Category::Identity, "identity"),
    (Category::Integrity, "integrity"),
    (Category::Taint, "taint"),
    (Category::Secret, "secret"),
    (Category::Pii, "pii"),
    (Category::Injection, "injection"),
    (Category::Exfiltration, "exfiltration"),
    (Category::Ssrf, "ssrf"),
    (Category::Behavior, "behavior"),
    (Category::Temporal, "temporal"),
    (Category::Plan, "plan"),
    (Category::Budget, "budget"),
    (Category::RateLimit, "rate_limit"),
    (Category::A2a, "a2a"),
    (Category::Sensor, "sensor"),
    (Category::KillSwitch, "kill_switch"),
    (Category::Ml, "ml"),
];
/// Upper bounds (microseconds) of the evaluation latency histogram.
const LATENCY_BUCKETS_US: &[u64] = &[50, 100, 250, 500, 1000, 2500, 5000, 10_000, 50_000];

#[derive(Default)]
pub struct Metrics {
    events: [AtomicU64; 11],
    verdicts: [AtomicU64; 5],
    enforced: [AtomicU64; 5],
    findings: [AtomicU64; 18],
    tokens: AtomicU64,
    latency_buckets: [AtomicU64; 9],
    latency_count: AtomicU64,
    latency_sum_us: AtomicU64,
    pub upstream_requests: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub auth_failures: AtomicU64,
    pub approvals_requested: AtomicU64,
    pub approvals_granted: AtomicU64,
    pub approvals_denied: AtomicU64,
    pub approvals_timed_out: AtomicU64,
    pub recorder_dropped: AtomicU64,
    pub audit_errors: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one evaluated event.
    pub fn observe(&self, ev: &Event, d: &Decision, eval_us: u64) {
        if let Some(i) = KINDS.iter().position(|k| *k == ev.kind_name()) {
            self.events[i].fetch_add(1, Relaxed);
        }
        if let Some(i) = VERDICTS.iter().position(|v| *v == d.verdict) {
            self.verdicts[i].fetch_add(1, Relaxed);
        }
        if let Some(i) = VERDICTS.iter().position(|v| *v == d.effective()) {
            self.enforced[i].fetch_add(1, Relaxed);
        }
        for f in &d.findings {
            if let Some(i) = CATEGORIES.iter().position(|(c, _)| *c == f.category) {
                self.findings[i].fetch_add(1, Relaxed);
            }
        }
        if let nandi_core::EventKind::LlmResponse(r) = &ev.kind {
            self.tokens.fetch_add(r.usage.total(), Relaxed);
        }
        for (i, b) in LATENCY_BUCKETS_US.iter().enumerate() {
            if eval_us <= *b {
                self.latency_buckets[i].fetch_add(1, Relaxed);
            }
        }
        self.latency_count.fetch_add(1, Relaxed);
        self.latency_sum_us.fetch_add(eval_us, Relaxed);
    }

    /// Every series with its current values: the one list both the
    /// Prometheus endpoint and the OTLP metrics export are built from.
    /// `gauges` adds point-in-time values.
    pub fn series(&self, gauges: &[Gauge]) -> Vec<Series> {
        let labelled = |name, otel, help, unit, key: &'static str, rows: Vec<(String, u64)>| Series {
            name,
            otel,
            help,
            unit,
            kind: SeriesKind::Counter,
            points: rows.into_iter().map(|(l, v)| (vec![(key, l)], v as f64)).collect(),
        };
        let mut out = vec![
            labelled(
                "nandi_events_total",
                "nandi.events",
                "Events evaluated, by kind.",
                "{event}",
                "kind",
                KINDS.iter().zip(&self.events).map(|(k, v)| (k.to_string(), v.load(Relaxed))).collect(),
            ),
            labelled(
                "nandi_decisions_total",
                "nandi.decisions",
                "Decisions by verdict before monitor mode is applied.",
                "{decision}",
                "verdict",
                VERDICTS.iter().zip(&self.verdicts).map(|(k, v)| (k.as_str().to_string(), v.load(Relaxed))).collect(),
            ),
            labelled(
                "nandi_enforced_total",
                "nandi.enforced",
                "Decisions by applied verdict.",
                "{decision}",
                "verdict",
                VERDICTS.iter().zip(&self.enforced).map(|(k, v)| (k.as_str().to_string(), v.load(Relaxed))).collect(),
            ),
            labelled(
                "nandi_findings_total",
                "nandi.findings",
                "Findings by category.",
                "{finding}",
                "category",
                CATEGORIES.iter().zip(&self.findings).map(|((_, k), v)| (k.to_string(), v.load(Relaxed))).collect(),
            ),
        ];
        let simple = [
            ("nandi_llm_tokens_total", "nandi.llm.tokens", "LLM tokens consumed.", "{token}", &self.tokens),
            (
                "nandi_upstream_requests_total",
                "nandi.upstream.requests",
                "Requests forwarded upstream.",
                "{request}",
                &self.upstream_requests,
            ),
            (
                "nandi_upstream_errors_total",
                "nandi.upstream.errors",
                "Upstream connection or protocol errors.",
                "{error}",
                &self.upstream_errors,
            ),
            (
                "nandi_auth_failures_total",
                "nandi.auth.failures",
                "Rejected credentials.",
                "{failure}",
                &self.auth_failures,
            ),
            (
                "nandi_approvals_requested_total",
                "nandi.approvals.requested",
                "Calls held for human approval.",
                "{call}",
                &self.approvals_requested,
            ),
            (
                "nandi_approvals_granted_total",
                "nandi.approvals.granted",
                "Approved held calls.",
                "{call}",
                &self.approvals_granted,
            ),
            (
                "nandi_approvals_denied_total",
                "nandi.approvals.denied",
                "Denied held calls.",
                "{call}",
                &self.approvals_denied,
            ),
            (
                "nandi_approvals_timed_out_total",
                "nandi.approvals.timed_out",
                "Held calls that timed out.",
                "{call}",
                &self.approvals_timed_out,
            ),
            (
                "nandi_recorder_dropped_total",
                "nandi.recorder.dropped",
                "Events dropped because the recorder queue was full.",
                "{event}",
                &self.recorder_dropped,
            ),
            (
                "nandi_audit_errors_total",
                "nandi.audit.errors",
                "Audit log write failures.",
                "{error}",
                &self.audit_errors,
            ),
        ];
        for (name, otel, help, unit, v) in simple {
            out.push(Series {
                name,
                otel,
                help,
                unit,
                kind: SeriesKind::Counter,
                points: vec![(Vec::new(), v.load(Relaxed) as f64)],
            });
        }
        let cumulative: Vec<u64> = self.latency_buckets.iter().map(|c| c.load(Relaxed)).collect();
        out.push(Series {
            name: "nandi_eval_duration_seconds",
            otel: "nandi.eval.duration",
            help: "Engine evaluation latency.",
            unit: "s",
            kind: SeriesKind::Histogram(Histogram {
                bounds: LATENCY_BUCKETS_US.iter().map(|b| *b as f64 / 1e6).collect(),
                cumulative,
                count: self.latency_count.load(Relaxed),
                sum: self.latency_sum_us.load(Relaxed) as f64 / 1e6,
            }),
            points: Vec::new(),
        });
        for g in gauges {
            out.push(Series {
                name: g.name,
                otel: g.otel,
                help: g.help,
                unit: g.unit,
                kind: SeriesKind::Gauge,
                points: vec![(Vec::new(), g.value)],
            });
        }
        out
    }

    /// Prometheus text exposition. `gauges` adds point-in-time values.
    pub fn render(&self, gauges: &[Gauge]) -> String {
        render(&self.series(gauges))
    }
}

/// A point-in-time value computed by the caller.
#[derive(Debug, Clone, Copy)]
pub struct Gauge {
    pub name: &'static str,
    pub otel: &'static str,
    pub help: &'static str,
    pub unit: &'static str,
    pub value: f64,
}

/// What a series measures.
#[derive(Debug, Clone)]
pub enum SeriesKind {
    /// Monotonic total since start.
    Counter,
    Gauge,
    Histogram(Histogram),
}

/// A latency histogram; bucket counts are cumulative as in Prometheus.
#[derive(Debug, Clone)]
pub struct Histogram {
    pub bounds: Vec<f64>,
    pub cumulative: Vec<u64>,
    pub count: u64,
    pub sum: f64,
}

/// One metric with its values per label set.
#[derive(Debug, Clone)]
pub struct Series {
    /// Prometheus name.
    pub name: &'static str,
    /// OpenTelemetry name.
    pub otel: &'static str,
    pub help: &'static str,
    /// UCUM unit for OpenTelemetry.
    pub unit: &'static str,
    pub kind: SeriesKind,
    /// Label pairs and value (unused for histograms).
    pub points: Vec<(Vec<(&'static str, String)>, f64)>,
}

/// Prometheus text exposition of `series`.
pub fn render(series: &[Series]) -> String {
    let mut out = String::with_capacity(4096);
    for s in series {
        let name = s.name;
        let ty = match s.kind {
            SeriesKind::Counter => "counter",
            SeriesKind::Gauge => "gauge",
            SeriesKind::Histogram(_) => "histogram",
        };
        let _ = writeln!(out, "# HELP {name} {}\n# TYPE {name} {ty}", s.help);
        if let SeriesKind::Histogram(h) = &s.kind {
            for (b, c) in h.bounds.iter().zip(&h.cumulative) {
                let _ = writeln!(out, "{name}_bucket{{le=\"{b}\"}} {c}");
            }
            let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {}", h.count);
            let _ = writeln!(out, "{name}_sum {}", h.sum);
            let _ = writeln!(out, "{name}_count {}", h.count);
            continue;
        }
        for (labels, v) in &s.points {
            let labels = if labels.is_empty() {
                String::new()
            } else {
                let inner: Vec<String> =
                    labels.iter().map(|(k, v)| format!("{k}=\"{}\"", v.replace(['"', '\\', '\n'], ""))).collect();
                format!("{{{}}}", inner.join(","))
            };
            match s.kind {
                SeriesKind::Counter => {
                    let _ = writeln!(out, "{name}{labels} {}", *v as u64);
                }
                _ => {
                    let _ = writeln!(out, "{name}{labels} {v}");
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::{EventKind, Finding, Severity, Source, ToolCall};

    #[test]
    fn renders_counts() {
        let m = Metrics::new();
        let ev = Event::new(
            Source::Eval,
            "a",
            "s",
            EventKind::ToolCall(ToolCall {
                server: "x".into(),
                tool: "y".into(),
                call_id: None,
                args: Default::default(),
            }),
        );
        let mut d = Decision::allow();
        d.push(Finding::new("r", Category::Secret, Severity::High, Verdict::Deny, "m"));
        m.observe(&ev, &d, 120);
        let text = m.render(&[Gauge {
            name: "nandi_sessions",
            otel: "nandi.sessions",
            help: "Active sessions.",
            unit: "{session}",
            value: 3.0,
        }]);
        assert!(text.contains("nandi_events_total{kind=\"tool_call\"} 1"));
        assert!(text.contains("nandi_decisions_total{verdict=\"deny\"} 1"));
        assert!(text.contains("nandi_enforced_total{verdict=\"allow\"} 1"));
        assert!(text.contains("nandi_findings_total{category=\"secret\"} 1"));
        assert!(text.contains("nandi_eval_duration_seconds_bucket{le=\"0.00025\"} 1"));
        assert!(text.contains("nandi_eval_duration_seconds_bucket{le=\"0.0001\"} 0"));
        assert!(text.contains("nandi_sessions 3"));
    }
}
