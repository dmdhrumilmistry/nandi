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

    /// Prometheus text exposition. `gauges` adds point-in-time values.
    pub fn render(&self, gauges: &[(&str, &str, f64)]) -> String {
        let mut out = String::with_capacity(4096);
        let mut counter = |name: &str, help: &str, rows: Vec<(String, u64)>| {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
            for (labels, v) in rows {
                let _ = writeln!(out, "{name}{labels} {v}");
            }
        };
        counter(
            "nandi_events_total",
            "Events evaluated, by kind.",
            KINDS.iter().zip(&self.events).map(|(k, v)| (format!("{{kind=\"{k}\"}}"), v.load(Relaxed))).collect(),
        );
        counter(
            "nandi_decisions_total",
            "Decisions by verdict before monitor mode is applied.",
            VERDICTS
                .iter()
                .zip(&self.verdicts)
                .map(|(k, v)| (format!("{{verdict=\"{}\"}}", k.as_str()), v.load(Relaxed)))
                .collect(),
        );
        counter(
            "nandi_enforced_total",
            "Decisions by applied verdict.",
            VERDICTS
                .iter()
                .zip(&self.enforced)
                .map(|(k, v)| (format!("{{verdict=\"{}\"}}", k.as_str()), v.load(Relaxed)))
                .collect(),
        );
        counter(
            "nandi_findings_total",
            "Findings by category.",
            CATEGORIES
                .iter()
                .zip(&self.findings)
                .map(|((_, k), v)| (format!("{{category=\"{k}\"}}"), v.load(Relaxed)))
                .collect(),
        );
        let simple = [
            ("nandi_llm_tokens_total", "LLM tokens consumed.", &self.tokens),
            ("nandi_upstream_requests_total", "Requests forwarded upstream.", &self.upstream_requests),
            ("nandi_upstream_errors_total", "Upstream connection or protocol errors.", &self.upstream_errors),
            ("nandi_auth_failures_total", "Rejected credentials.", &self.auth_failures),
            ("nandi_approvals_requested_total", "Calls held for human approval.", &self.approvals_requested),
            ("nandi_approvals_granted_total", "Approved held calls.", &self.approvals_granted),
            ("nandi_approvals_denied_total", "Denied held calls.", &self.approvals_denied),
            ("nandi_approvals_timed_out_total", "Held calls that timed out.", &self.approvals_timed_out),
            (
                "nandi_recorder_dropped_total",
                "Events dropped because the recorder queue was full.",
                &self.recorder_dropped,
            ),
            ("nandi_audit_errors_total", "Audit log write failures.", &self.audit_errors),
        ];
        for (name, help, v) in simple {
            counter(name, help, vec![(String::new(), v.load(Relaxed))]);
        }
        let _ = writeln!(
            out,
            "# HELP nandi_eval_duration_seconds Engine evaluation latency.\n# TYPE nandi_eval_duration_seconds histogram"
        );
        for (b, c) in LATENCY_BUCKETS_US.iter().zip(&self.latency_buckets) {
            let _ =
                writeln!(out, "nandi_eval_duration_seconds_bucket{{le=\"{}\"}} {}", *b as f64 / 1e6, c.load(Relaxed));
        }
        let count = self.latency_count.load(Relaxed);
        let _ = writeln!(out, "nandi_eval_duration_seconds_bucket{{le=\"+Inf\"}} {count}");
        let _ = writeln!(out, "nandi_eval_duration_seconds_sum {}", self.latency_sum_us.load(Relaxed) as f64 / 1e6);
        let _ = writeln!(out, "nandi_eval_duration_seconds_count {count}");
        for (name, help, v) in gauges {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
        }
        out
    }
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
        let text = m.render(&[("nandi_sessions", "Active sessions.", 3.0)]);
        assert!(text.contains("nandi_events_total{kind=\"tool_call\"} 1"));
        assert!(text.contains("nandi_decisions_total{verdict=\"deny\"} 1"));
        assert!(text.contains("nandi_enforced_total{verdict=\"allow\"} 1"));
        assert!(text.contains("nandi_findings_total{category=\"secret\"} 1"));
        assert!(text.contains("nandi_eval_duration_seconds_bucket{le=\"0.00025\"} 1"));
        assert!(text.contains("nandi_eval_duration_seconds_bucket{le=\"0.0001\"} 0"));
        assert!(text.contains("nandi_sessions 3"));
    }
}
