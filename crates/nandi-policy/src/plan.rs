//! Plan-locked execution: once a session declares a [`PlanSpec`], each tool
//! call must map to a declared step whose prerequisites have run and whose
//! call budget is not exhausted.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use nandi_core::util::tool_glob_match;
use nandi_core::{Error, PlanSpec, Result};

use crate::matcher::ArgsMatcher;

/// Persisted form of a [`PlanTracker`].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlanState {
    spec: PlanSpec,
    counts: Vec<u32>,
}

/// Per-session plan state. Serializes as `{ spec, counts }`; compiled
/// matchers are rebuilt on deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "PlanState", into = "PlanState")]
pub struct PlanTracker {
    spec: PlanSpec,
    counts: Vec<u32>,
    args: Vec<ArgsMatcher>,
    /// Resolved `after` step indices per step.
    deps: Vec<Vec<usize>>,
}

impl PlanTracker {
    /// Compile a plan. Fails on duplicate step ids, unknown `after`
    /// references, self references or invalid argument matchers.
    pub fn new(spec: PlanSpec) -> Result<Self> {
        let counts = vec![0; spec.steps.len()];
        Self::from_state(PlanState { spec, counts })
    }

    fn from_state(state: PlanState) -> Result<Self> {
        let PlanState { spec, counts } = state;
        if counts.len() != spec.steps.len() {
            return Err(Error::Policy("plan state does not match its step count".into()));
        }
        let mut ids = HashMap::new();
        for (i, step) in spec.steps.iter().enumerate() {
            if let Some(id) = &step.id
                && ids.insert(id.as_str(), i).is_some()
            {
                return Err(Error::Policy(format!("plan: duplicate step id `{id}`")));
            }
        }
        let mut args = Vec::with_capacity(spec.steps.len());
        let mut deps = Vec::with_capacity(spec.steps.len());
        for (i, step) in spec.steps.iter().enumerate() {
            let name = step_name(&spec, i);
            args.push(ArgsMatcher::parse(&step.args).map_err(|e| Error::Policy(format!("plan step {name}: {e}")))?);
            let mut d = Vec::with_capacity(step.after.len());
            for after in &step.after {
                match ids.get(after.as_str()) {
                    Some(&j) if j != i => d.push(j),
                    Some(_) => return Err(Error::Policy(format!("plan step {name} cannot run after itself"))),
                    None => return Err(Error::Policy(format!("plan step {name}: unknown `after` step `{after}`"))),
                }
            }
            deps.push(d);
        }
        Ok(Self { spec, counts, args, deps })
    }

    /// The declared plan.
    pub fn spec(&self) -> &PlanSpec {
        &self.spec
    }

    /// Map a tool call to the first eligible plan step, or explain why it
    /// deviates from the plan.
    pub fn check(&self, server: &str, tool: &str, args: &Value) -> std::result::Result<usize, String> {
        let mut first_problem: Option<String> = None;
        let mut tool_matched = false;
        for (i, step) in self.spec.steps.iter().enumerate() {
            if !tool_glob_match(&step.tool, server, tool) {
                continue;
            }
            tool_matched = true;
            if !self.args[i].matches(args) {
                continue;
            }
            let problem = if let Some(&dep) = self.deps[i].iter().find(|&&d| self.counts[d] == 0) {
                format!("step {} requires step {} first", step_name(&self.spec, i), step_name(&self.spec, dep))
            } else if step.max_calls != 0 && self.counts[i] >= step.max_calls {
                let n = step.max_calls;
                format!(
                    "step {} already used its {n} allowed call{}",
                    step_name(&self.spec, i),
                    if n == 1 { "" } else { "s" }
                )
            } else {
                return Ok(i);
            };
            first_problem.get_or_insert(problem);
        }
        Err(match (first_problem, tool_matched) {
            (Some(p), _) => p,
            (None, true) => format!("arguments for tool `{server}/{tool}` do not match any plan step"),
            (None, false) => format!("tool `{server}/{tool}` is not in the declared plan"),
        })
    }

    /// Record that `step` ran. Out-of-range indices are ignored.
    pub fn record(&mut self, step: usize) {
        if let Some(c) = self.counts.get_mut(step) {
            *c = c.saturating_add(1);
        }
    }

    /// Steps that have not run yet, by id (or `#<n> <tool>` for steps
    /// without an id).
    pub fn remaining(&self) -> Vec<String> {
        (0..self.spec.steps.len()).filter(|&i| self.counts[i] == 0).map(|i| step_name(&self.spec, i)).collect()
    }

    /// True when every step has run at least once.
    pub fn is_complete(&self) -> bool {
        self.counts.iter().all(|&c| c > 0)
    }
}

fn step_name(spec: &PlanSpec, i: usize) -> String {
    let step = &spec.steps[i];
    match &step.id {
        Some(id) => format!("`{id}`"),
        None => format!("#{} `{}`", i + 1, step.tool),
    }
}

impl TryFrom<PlanState> for PlanTracker {
    type Error = Error;

    fn try_from(state: PlanState) -> Result<Self> {
        Self::from_state(state)
    }
}

impl From<PlanTracker> for PlanState {
    fn from(t: PlanTracker) -> Self {
        PlanState { spec: t.spec, counts: t.counts }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plan(v: Value) -> PlanTracker {
        PlanTracker::new(serde_json::from_value(v).unwrap()).unwrap()
    }

    #[test]
    fn ordering_and_max_calls() {
        let mut t = plan(json!({"task": "triage", "steps": [
            {"id": "search", "tool": "github/search_issues", "max_calls": 0},
            {"id": "read", "tool": "get_issue", "after": ["search"], "max_calls": 2},
            {"id": "label", "tool": "add_label", "args": {"label": {"in": ["bug", "triage"]}}, "after": ["read"]}
        ]}));
        let a = json!({});
        assert_eq!(t.remaining(), vec!["`search`", "`read`", "`label`"]);

        let err = t.check("github", "get_issue", &a).unwrap_err();
        assert_eq!(err, "step `read` requires step `search` first");
        assert!(t.check("gitlab", "search_issues", &a).unwrap_err().contains("not in the declared plan"));
        assert!(t.check("github", "delete_repo", &a).unwrap_err().contains("not in the declared plan"));

        for _ in 0..5 {
            let s = t.check("github", "search_issues", &a).unwrap();
            t.record(s);
        }
        let r = t.check("github", "get_issue", &a).unwrap();
        assert_eq!(r, 1);
        t.record(r);
        t.record(t.check("github", "get_issue", &a).unwrap());
        assert_eq!(t.check("github", "get_issue", &a).unwrap_err(), "step `read` already used its 2 allowed calls");

        let bad = json!({"label": "wontfix"});
        assert!(t.check("github", "add_label", &bad).unwrap_err().contains("do not match any plan step"));
        let good = json!({"label": "bug"});
        t.record(t.check("github", "add_label", &good).unwrap());
        assert!(t.check("github", "add_label", &good).unwrap_err().contains("1 allowed call"));
        assert!(t.remaining().is_empty());
        assert!(t.is_complete());
    }

    #[test]
    fn first_eligible_step_wins() {
        let mut t = plan(json!({"steps": [
            {"tool": "fetch", "args": {"url": {"prefix": "https://a"}}},
            {"tool": "fetch"},
            {"tool": "summarize", "id": "sum"}
        ]}));
        let a = json!({"url": "https://a/x"});
        assert_eq!(t.check("web", "fetch", &a), Ok(0));
        t.record(0);
        assert_eq!(t.check("web", "fetch", &a), Ok(1));
        t.record(1);
        assert_eq!(t.check("web", "fetch", &a).unwrap_err(), "step #1 `fetch` already used its 1 allowed call");
        assert_eq!(t.remaining(), vec!["`sum`"]);
        t.record(99);
    }

    #[test]
    fn invalid_plans() {
        let bad = |v: Value| PlanTracker::new(serde_json::from_value(v).unwrap()).is_err();
        assert!(bad(json!({"steps": [{"id": "a", "tool": "x"}, {"id": "a", "tool": "y"}]})));
        assert!(bad(json!({"steps": [{"id": "a", "tool": "x", "after": ["b"]}]})));
        assert!(bad(json!({"steps": [{"id": "a", "tool": "x", "after": ["a"]}]})));
        assert!(bad(json!({"steps": [{"tool": "x", "args": {"p": {"regex": "("}}}]})));
    }

    #[test]
    fn serde_round_trip_keeps_counts() {
        let mut t = plan(json!({"steps": [
            {"id": "a", "tool": "x", "args": {"n": {"lt": 5}}},
            {"id": "b", "tool": "y", "after": ["a"]}
        ]}));
        t.record(t.check("s", "x", &json!({"n": 1})).unwrap());
        let saved = serde_json::to_string(&t).unwrap();
        let back: PlanTracker = serde_json::from_str(&saved).unwrap();
        assert_eq!(back.remaining(), vec!["`b`"]);
        assert_eq!(back.check("s", "y", &json!({})), Ok(1));
        assert!(back.check("s", "x", &json!({"n": 9})).is_err());
        assert!(serde_json::from_str::<PlanTracker>(r#"{"spec":{"steps":[{"tool":"x"}]},"counts":[]}"#).is_err());
    }
}
