//! Findings and decisions produced by the engine.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What should happen to the observed action.
///
/// Variants are ordered from least to most restrictive, so combining the
/// verdicts of several findings is `max()`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Let it through silently.
    #[default]
    Allow,
    /// Let it through and raise an alert.
    Alert,
    /// Let it through after rewriting sensitive parts.
    Redact,
    /// Hold it until a human approves or denies.
    Ask,
    /// Block it.
    Deny,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Alert => "alert",
            Verdict::Redact => "redact",
            Verdict::Ask => "ask",
            Verdict::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Which subsystem produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Policy,
    Identity,
    Integrity,
    Taint,
    Secret,
    Pii,
    Injection,
    Exfiltration,
    Ssrf,
    Behavior,
    Temporal,
    Plan,
    Budget,
    RateLimit,
    A2a,
    Sensor,
    KillSwitch,
    Ml,
}

/// One reason for a decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule id, e.g. `secret.aws-access-key` or `policy.no-shell`.
    pub rule: String,
    pub category: Category,
    pub severity: Severity,
    /// Verdict this finding asks for.
    pub verdict: Verdict,
    pub message: String,
    /// Short, already-masked evidence. Never put raw secrets here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

impl Finding {
    pub fn new(
        rule: impl Into<String>,
        category: Category,
        severity: Severity,
        verdict: Verdict,
        message: impl Into<String>,
    ) -> Self {
        Self { rule: rule.into(), category, severity, verdict, message: message.into(), evidence: None }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }
}

/// The engine's answer for one event.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    /// Combined verdict of all findings (before applying monitor mode).
    pub verdict: Verdict,
    /// `false` in monitor mode: the verdict is recorded but not applied.
    pub enforced: bool,
    pub findings: Vec<Finding>,
    /// Replacement payload when the verdict is `Redact` (or when content was
    /// rewritten, e.g. spotlighting). The capture point substitutes it for
    /// the original arguments / content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite: Option<Value>,
    /// 0.0 - 1.0 risk estimate for dashboards and anomaly tracking.
    #[serde(default)]
    pub risk: f32,
}

impl Decision {
    pub fn allow() -> Self {
        Self::default()
    }

    /// Add a finding and raise the verdict if needed.
    pub fn push(&mut self, finding: Finding) {
        self.verdict = self.verdict.max(finding.verdict);
        self.findings.push(finding);
    }

    /// Verdict the capture point must apply. In monitor mode everything is
    /// allowed through (redactions included), only recorded.
    pub fn effective(&self) -> Verdict {
        if self.enforced { self.verdict } else { Verdict::Allow }
    }

    /// Highest severity among findings.
    pub fn max_severity(&self) -> Severity {
        self.findings.iter().map(|f| f.severity).max().unwrap_or_default()
    }

    /// Human-readable one-line summary for error messages returned to agents.
    pub fn summary(&self) -> String {
        if self.findings.is_empty() {
            return self.verdict.as_str().to_string();
        }
        let reasons: Vec<String> = self
            .findings
            .iter()
            .filter(|f| f.verdict == self.verdict)
            .map(|f| format!("{}: {}", f.rule, f.message))
            .collect();
        format!("{} ({})", self.verdict.as_str(), reasons.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_order_is_restrictiveness() {
        assert!(Verdict::Deny > Verdict::Ask);
        assert!(Verdict::Ask > Verdict::Redact);
        assert!(Verdict::Redact > Verdict::Alert);
        assert!(Verdict::Alert > Verdict::Allow);
    }

    #[test]
    fn push_raises_verdict_and_monitor_mode_allows() {
        let mut d = Decision::allow();
        d.push(Finding::new("a", Category::Policy, Severity::Low, Verdict::Alert, "x"));
        d.push(Finding::new("b", Category::Secret, Severity::High, Verdict::Deny, "y"));
        d.push(Finding::new("c", Category::Pii, Severity::Medium, Verdict::Redact, "z"));
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.effective(), Verdict::Allow);
        d.enforced = true;
        assert_eq!(d.effective(), Verdict::Deny);
        assert_eq!(d.max_severity(), Severity::High);
        assert_eq!(d.summary(), "deny (b: y)");
    }
}
