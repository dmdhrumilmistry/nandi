//! Daily token and tool-call budgets per agent, plus a per-minute call rate.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use nandi_core::config::Budget;
use nandi_core::util::glob_match;
use nandi_core::{Category, Finding, Severity, StateStore, Verdict};

const DAY_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Day number (Unix ms / 86 400 000) the counters belong to.
    pub day: u64,
    pub tokens: u64,
    pub tool_calls: u64,
}

pub struct Budgets {
    rules: Vec<Budget>,
    max_per_minute: u32,
    usage: Mutex<HashMap<String, Usage>>,
    recent: Mutex<HashMap<String, VecDeque<u64>>>,
    store: Arc<dyn StateStore>,
}

impl Budgets {
    pub fn new(rules: Vec<Budget>, max_per_minute: u32, store: Arc<dyn StateStore>) -> Self {
        let mut usage = HashMap::new();
        for key in store.keys("usage/") {
            if let Some(bytes) = store.get(&key)
                && let Ok(u) = serde_json::from_slice::<Usage>(&bytes)
            {
                usage.insert(key.trim_start_matches("usage/").to_string(), u);
            }
        }
        Self { rules, max_per_minute, usage: Mutex::new(usage), recent: Mutex::new(HashMap::new()), store }
    }

    fn rule_for(&self, agent: &str) -> Option<&Budget> {
        self.rules.iter().find(|b| glob_match(&b.agent, agent))
    }

    fn with_usage<R>(&self, agent: &str, now_ms: u64, f: impl FnOnce(&mut Usage) -> R) -> R {
        let day = now_ms / DAY_MS;
        let mut usage = self.usage.lock();
        let u = usage.entry(agent.to_string()).or_default();
        if u.day != day {
            *u = Usage { day, ..Usage::default() };
        }
        f(u)
    }

    /// Check before an LLM request.
    pub fn check_tokens(&self, agent: &str, now_ms: u64) -> Option<Finding> {
        let rule = self.rule_for(agent)?;
        let limit = rule.tokens_per_day?;
        let used = self.with_usage(agent, now_ms, |u| u.tokens);
        (used >= limit).then(|| {
            Finding::new(
                "budget.tokens",
                Category::Budget,
                Severity::Medium,
                rule.verdict,
                format!("daily token budget exhausted ({used}/{limit})"),
            )
        })
    }

    /// Check before a tool call and count it.
    pub fn check_call(&self, agent: &str, now_ms: u64) -> Vec<Finding> {
        let mut out = Vec::new();
        if let Some(rule) = self.rule_for(agent)
            && let Some(limit) = rule.tool_calls_per_day
        {
            let used = self.with_usage(agent, now_ms, |u| u.tool_calls);
            if used >= limit {
                out.push(Finding::new(
                    "budget.tool-calls",
                    Category::Budget,
                    Severity::Medium,
                    rule.verdict,
                    format!("daily tool-call budget exhausted ({used}/{limit})"),
                ));
            }
        }
        if self.max_per_minute > 0 {
            let mut recent = self.recent.lock();
            let q = recent.entry(agent.to_string()).or_default();
            while q.front().is_some_and(|&t| t + 60_000 <= now_ms) {
                q.pop_front();
            }
            if q.len() as u32 >= self.max_per_minute {
                out.push(Finding::new(
                    "ratelimit.tool-calls",
                    Category::RateLimit,
                    Severity::Medium,
                    Verdict::Deny,
                    format!("more than {} tool calls in the last minute", self.max_per_minute),
                ));
            } else {
                q.push_back(now_ms);
            }
        }
        out
    }

    pub fn add_tokens(&self, agent: &str, tokens: u64, now_ms: u64) {
        self.with_usage(agent, now_ms, |u| u.tokens += tokens);
    }

    pub fn add_call(&self, agent: &str, now_ms: u64) {
        self.with_usage(agent, now_ms, |u| u.tool_calls += 1);
    }

    pub fn usage(&self, agent: &str) -> Usage {
        self.usage.lock().get(agent).cloned().unwrap_or_default()
    }

    pub fn all_usage(&self) -> Vec<(String, Usage)> {
        let mut v: Vec<_> = self.usage.lock().iter().map(|(k, u)| (k.clone(), u.clone())).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    pub fn flush(&self) {
        let usage = self.usage.lock().clone();
        for (agent, u) in usage {
            if let Ok(bytes) = serde_json::to_vec(&u) {
                self.store.put(&format!("usage/{agent}"), &bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::MemoryStore;

    fn budgets(max_per_minute: u32) -> Budgets {
        Budgets::new(
            vec![Budget {
                agent: "bot-*".into(),
                tokens_per_day: Some(1000),
                tool_calls_per_day: Some(2),
                verdict: Verdict::Deny,
            }],
            max_per_minute,
            Arc::new(MemoryStore::new()),
        )
    }

    #[test]
    fn token_budget_resets_daily() {
        let b = budgets(0);
        let t = 10 * DAY_MS;
        assert!(b.check_tokens("bot-1", t).is_none());
        b.add_tokens("bot-1", 1000, t);
        assert!(b.check_tokens("bot-1", t).is_some());
        assert!(b.check_tokens("bot-1", t + DAY_MS).is_none());
        assert!(b.check_tokens("other", t).is_none());
    }

    #[test]
    fn call_budget_and_rate_limit() {
        let b = budgets(3);
        let t = 5 * DAY_MS;
        for i in 0..2 {
            assert!(b.check_call("bot-1", t + i).is_empty());
            b.add_call("bot-1", t + i);
        }
        let f = b.check_call("bot-1", t + 3);
        assert_eq!(f[0].rule, "budget.tool-calls");
        // Rate limit: 4th call within a minute.
        let f = b.check_call("bot-1", t + 4);
        assert!(f.iter().any(|f| f.rule == "ratelimit.tool-calls"));
        assert!(b.check_call("bot-1", t + 70_000).iter().all(|f| f.rule != "ratelimit.tool-calls"));
    }
}
