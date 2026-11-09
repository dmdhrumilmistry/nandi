//! Per-agent behaviour models over tool-call sequences.
//!
//! - **Transition model**: a first-order Markov chain over `server/tool`
//!   states learned from the agent's own allowed traffic. A transition whose
//!   smoothed probability is very low is "surprising" (Behavioral Firewall,
//!   TraceAegis). A tool the agent has never used is reported separately.
//! - **Unsafe-reach lookahead** (Pro2Guard): each state also counts how often
//!   it was flagged. The probability of reaching a flagged state within a
//!   few steps is computed by bounded value iteration over the learned
//!   transitions.
//!
//! Models are plain counters, serialized as JSON into the [`StateStore`].

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use nandi_core::config::{BehaviorConfig, BehaviorMode};
use nandi_core::{Category, Finding, Severity, StateStore};

/// Pseudo-state before the first tool call of a session.
pub const START: &str = "^";
const ALPHA: f64 = 0.1;
const LOOKAHEAD: usize = 3;
const MAX_BRANCH: usize = 16;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AgentModel {
    pub observations: u64,
    /// prev -> next -> count
    pub transitions: BTreeMap<String, BTreeMap<String, u32>>,
    /// state -> (flagged, total)
    pub outcomes: BTreeMap<String, (u32, u32)>,
}

impl AgentModel {
    fn out_total(&self, prev: &str) -> u32 {
        self.transitions.get(prev).map(|m| m.values().sum()).unwrap_or(0)
    }

    fn knows(&self, state: &str) -> bool {
        self.outcomes.contains_key(state)
    }

    /// Smoothed transition probability.
    pub fn probability(&self, prev: &str, next: &str) -> f64 {
        let c = self.transitions.get(prev).and_then(|m| m.get(next)).copied().unwrap_or(0) as f64;
        let total = self.out_total(prev) as f64;
        let vocab = self.outcomes.len() as f64 + 1.0;
        (c + ALPHA) / (total + ALPHA * vocab)
    }

    fn flag_rate(&self, state: &str) -> f64 {
        match self.outcomes.get(state) {
            Some(&(flagged, total)) if total > 0 => flagged as f64 / total as f64,
            _ => 0.0,
        }
    }

    /// Probability of hitting a flagged state within `depth` steps after
    /// entering `state` (including `state` itself).
    pub fn unsafe_reach(&self, state: &str, depth: usize) -> f64 {
        let mut memo = HashMap::new();
        self.reach(state, depth, &mut memo)
    }

    fn reach(&self, state: &str, depth: usize, memo: &mut HashMap<(String, usize), f64>) -> f64 {
        if let Some(v) = memo.get(&(state.to_string(), depth)) {
            return *v;
        }
        let f = self.flag_rate(state);
        let mut v = f;
        if depth > 0
            && let Some(next) = self.transitions.get(state)
        {
            let total: u32 = next.values().sum();
            if total > 0 {
                let mut branches: Vec<(&String, &u32)> = next.iter().collect();
                branches.sort_by(|a, b| b.1.cmp(a.1));
                let mut acc = 0.0;
                for (s, c) in branches.into_iter().take(MAX_BRANCH) {
                    acc += (*c as f64 / total as f64) * self.reach(s, depth - 1, memo);
                }
                v = f + (1.0 - f) * acc;
            }
        }
        memo.insert((state.to_string(), depth), v);
        v
    }

    pub fn learn(&mut self, prev: &str, next: &str, flagged: bool) {
        self.observations += 1;
        *self.transitions.entry(prev.to_string()).or_default().entry(next.to_string()).or_insert(0) += 1;
        let e = self.outcomes.entry(next.to_string()).or_insert((0, 0));
        e.1 += 1;
        if flagged {
            e.0 += 1;
        }
    }
}

/// Behaviour engine shared by all sessions.
pub struct Behavior {
    cfg: BehaviorConfig,
    models: RwLock<HashMap<String, AgentModel>>,
    dirty: RwLock<Vec<String>>,
    store: Arc<dyn StateStore>,
}

impl Behavior {
    pub fn new(cfg: BehaviorConfig, store: Arc<dyn StateStore>) -> Self {
        let mut models = HashMap::new();
        for key in store.keys("behavior/") {
            if let Some(bytes) = store.get(&key)
                && let Ok(m) = serde_json::from_slice::<AgentModel>(&bytes)
            {
                models.insert(key.trim_start_matches("behavior/").to_string(), m);
            }
        }
        Self { cfg, models: RwLock::new(models), dirty: RwLock::new(Vec::new()), store }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    /// Score a transition before it happens.
    pub fn assess(&self, agent: &str, prev: &str, next: &str) -> Vec<Finding> {
        if !self.cfg.enabled || self.cfg.mode == BehaviorMode::Learn {
            return Vec::new();
        }
        let models = self.models.read();
        let Some(model) = models.get(agent) else { return Vec::new() };
        if model.observations < self.cfg.min_observations {
            return Vec::new();
        }
        let mut out = Vec::new();
        if !model.knows(next) {
            out.push(
                Finding::new(
                    "behavior.new-tool",
                    Category::Behavior,
                    Severity::Medium,
                    self.cfg.on_anomaly,
                    format!("agent has never used {next} before"),
                )
                .with_evidence(next.to_string()),
            );
        } else if model.out_total(prev) > 0 {
            let p = model.probability(prev, next);
            let bits = -p.log2();
            if bits >= self.cfg.surprise_bits {
                out.push(
                    Finding::new(
                        "behavior.unusual-sequence",
                        Category::Behavior,
                        Severity::Medium,
                        self.cfg.on_anomaly,
                        format!("transition {prev} -> {next} is unusual for this agent ({bits:.1} bits)"),
                    )
                    .with_evidence(format!("p={p:.5}")),
                );
            }
        }
        let reach = model.unsafe_reach(next, LOOKAHEAD);
        if reach >= self.cfg.unsafe_reach_threshold {
            out.push(
                Finding::new(
                    "behavior.unsafe-trajectory",
                    Category::Behavior,
                    Severity::High,
                    self.cfg.on_anomaly.max(nandi_core::Verdict::Alert),
                    format!("{:.0}% chance of reaching a flagged action within {LOOKAHEAD} steps", reach * 100.0),
                )
                .with_evidence(next.to_string()),
            );
        }
        out
    }

    /// Record a transition after the decision was made.
    pub fn observe(&self, agent: &str, prev: &str, next: &str, flagged: bool) {
        if !self.cfg.enabled || self.cfg.mode == BehaviorMode::Frozen {
            return;
        }
        self.models.write().entry(agent.to_string()).or_default().learn(prev, next, flagged);
        let mut dirty = self.dirty.write();
        if !dirty.iter().any(|a| a == agent) {
            dirty.push(agent.to_string());
        }
    }

    /// Persist models changed since the last flush.
    pub fn flush(&self) {
        let agents: Vec<String> = std::mem::take(&mut *self.dirty.write());
        let models = self.models.read();
        for agent in agents {
            if let Some(m) = models.get(&agent)
                && let Ok(bytes) = serde_json::to_vec(m)
            {
                self.store.put(&format!("behavior/{agent}"), &bytes);
            }
        }
    }

    pub fn model(&self, agent: &str) -> Option<AgentModel> {
        self.models.read().get(agent).cloned()
    }

    pub fn reset(&self, agent: &str) {
        self.models.write().remove(agent);
        self.store.delete(&format!("behavior/{agent}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::MemoryStore;

    fn trained() -> Behavior {
        let cfg = BehaviorConfig { min_observations: 10, ..BehaviorConfig::default() };
        let b = Behavior::new(cfg, Arc::new(MemoryStore::new()));
        for _ in 0..50 {
            b.observe("a", START, "crm/search", false);
            b.observe("a", "crm/search", "crm/get_contact", false);
            b.observe("a", "crm/get_contact", "mail/draft", false);
        }
        b
    }

    #[test]
    fn known_transitions_are_quiet() {
        let b = trained();
        assert!(b.assess("a", "crm/search", "crm/get_contact").is_empty());
    }

    #[test]
    fn new_tool_and_unusual_sequence_are_flagged() {
        let b = trained();
        let f = b.assess("a", "crm/search", "shell/exec");
        assert_eq!(f[0].rule, "behavior.new-tool");
        let f = b.assess("a", START, "mail/draft");
        assert!(f.iter().any(|f| f.rule == "behavior.unusual-sequence"), "{f:?}");
    }

    #[test]
    fn not_enough_data_means_no_alerts() {
        let b = Behavior::new(BehaviorConfig::default(), Arc::new(MemoryStore::new()));
        b.observe("a", START, "x/y", false);
        assert!(b.assess("a", START, "z/w").is_empty());
    }

    #[test]
    fn unsafe_reach_propagates_through_transitions() {
        let mut m = AgentModel::default();
        for _ in 0..10 {
            m.learn("^", "fs/read", false);
            m.learn("fs/read", "http/post", true);
        }
        assert!((m.unsafe_reach("http/post", 0) - 1.0).abs() < 1e-9);
        assert!(m.unsafe_reach("fs/read", 1) > 0.99);
        assert!(m.unsafe_reach("fs/read", 0) < 1e-9);
    }

    #[test]
    fn models_persist_through_store() {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStore::new());
        let b = Behavior::new(BehaviorConfig::default(), store.clone());
        b.observe("agent-x", START, "a/b", false);
        b.flush();
        let b2 = Behavior::new(BehaviorConfig::default(), store);
        assert_eq!(b2.model("agent-x").unwrap().observations, 1);
    }
}
