//! Per-session state: taint, value-flow index, call history, plan, loops.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use nandi_policy::{HistoryEntry, PlanTracker};

use crate::behavior::START;
use crate::flow::FlowIndex;

const MAX_HISTORY: usize = 256;
const MAX_SOURCES: usize = 16;
const MAX_SEEN_MESSAGES: usize = 4096;

#[derive(Debug)]
pub struct SessionState {
    pub agent: String,
    pub session: String,
    /// Untrusted content has entered this session's context.
    pub tainted: bool,
    /// Where the untrusted content came from (bounded, oldest first).
    pub taint_sources: Vec<String>,
    pub flow: FlowIndex,
    /// Tool calls so far, oldest first.
    pub history: Vec<HistoryEntry>,
    /// Call ids parallel to `history`.
    pub call_ids: Vec<Option<String>>,
    pub plan: Option<PlanTracker>,
    /// Behaviour state of the last call (`server/tool` or `^`).
    pub last_state: String,
    pub calls: u64,
    pub risk: f32,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    /// (timestamp, hash of tool + canonical args) for loop detection.
    pub recent_calls: VecDeque<(u64, u64)>,
    /// Digests of LLM conversation messages already inspected; providers
    /// resend the whole conversation on every turn.
    pub seen_messages: HashSet<u64>,
    pub findings: u64,
}

impl SessionState {
    pub fn new(agent: &str, session: &str, min_flow_len: usize, now_ms: u64) -> Self {
        Self {
            agent: agent.to_string(),
            session: session.to_string(),
            tainted: false,
            taint_sources: Vec::new(),
            flow: FlowIndex::new(min_flow_len),
            history: Vec::new(),
            call_ids: Vec::new(),
            plan: None,
            last_state: START.to_string(),
            calls: 0,
            risk: 0.0,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            recent_calls: VecDeque::new(),
            seen_messages: HashSet::new(),
            findings: 0,
        }
    }

    pub fn taint(&mut self, source: &str) {
        self.tainted = true;
        if !self.taint_sources.iter().any(|s| s == source) {
            if self.taint_sources.len() >= MAX_SOURCES {
                self.taint_sources.remove(0);
            }
            self.taint_sources.push(source.to_string());
        }
    }

    pub fn push_history(&mut self, entry: HistoryEntry, call_id: Option<String>) {
        if self.history.len() >= MAX_HISTORY {
            let cut = MAX_HISTORY / 4;
            self.history.drain(..cut);
            self.call_ids.drain(..cut);
        }
        self.history.push(entry);
        self.call_ids.push(call_id);
    }

    /// Mark the matching call as failed or succeeded once its result arrives.
    pub fn complete_call(&mut self, call_id: Option<&str>, server: &str, tool: &str, ok: bool) {
        let idx = match call_id {
            Some(id) => self.call_ids.iter().rposition(|c| c.as_deref() == Some(id)),
            None => None,
        }
        .or_else(|| self.history.iter().rposition(|h| h.server == server && h.tool == tool));
        if let Some(i) = idx {
            self.history[i].ok = ok;
        }
    }

    /// Returns true the first time a message digest is seen.
    pub fn first_sight(&mut self, digest: u64) -> bool {
        if self.seen_messages.len() >= MAX_SEEN_MESSAGES {
            self.seen_messages.clear();
        }
        self.seen_messages.insert(digest)
    }

    /// Count identical calls within `window_ms`, recording this one.
    pub fn repeat_count(&mut self, hash: u64, now_ms: u64, window_ms: u64) -> u32 {
        while self.recent_calls.front().is_some_and(|&(t, _)| t + window_ms <= now_ms) {
            self.recent_calls.pop_front();
        }
        let n = self.recent_calls.iter().filter(|&&(_, h)| h == hash).count() as u32;
        self.recent_calls.push_back((now_ms, hash));
        if self.recent_calls.len() > 1024 {
            self.recent_calls.pop_front();
        }
        n + 1
    }
}

/// Summary for the admin API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionSummary {
    pub agent: String,
    pub session: String,
    pub tainted: bool,
    pub taint_sources: Vec<String>,
    pub calls: u64,
    pub risk: f32,
    pub findings: u64,
    pub plan_remaining: Option<Vec<String>>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

/// Concurrent session table with idle eviction and a size cap. Each
/// session has its own lock, so events in different sessions never contend.
pub struct Sessions {
    map: RwLock<HashMap<String, Arc<Mutex<SessionState>>>>,
    max: usize,
    idle_ms: u64,
    min_flow_len: usize,
}

impl Sessions {
    pub fn new(max: usize, idle_ms: u64, min_flow_len: usize) -> Self {
        Self { map: RwLock::new(HashMap::new()), max, idle_ms, min_flow_len }
    }

    fn key(agent: &str, session: &str) -> String {
        format!("{agent}\u{1f}{session}")
    }

    pub fn get(&self, agent: &str, session: &str, now_ms: u64) -> Arc<Mutex<SessionState>> {
        let key = Self::key(agent, session);
        if let Some(s) = self.map.read().get(&key) {
            return s.clone();
        }
        let mut map = self.map.write();
        if map.len() >= self.max {
            self.evict(&mut map, now_ms);
        }
        map.entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(SessionState::new(agent, session, self.min_flow_len, now_ms))))
            .clone()
    }

    fn evict(&self, map: &mut HashMap<String, Arc<Mutex<SessionState>>>, now_ms: u64) {
        map.retain(|_, s| s.try_lock().is_none_or(|s| s.last_seen_ms + self.idle_ms > now_ms));
        if map.len() >= self.max {
            // Still full: drop the least recently seen quarter.
            let mut ages: Vec<(String, u64)> = map
                .iter()
                .map(|(k, s)| (k.clone(), s.try_lock().map(|s| s.last_seen_ms).unwrap_or(u64::MAX)))
                .collect();
            ages.sort_by_key(|a| a.1);
            for (k, _) in ages.into_iter().take(self.max / 4 + 1) {
                map.remove(&k);
            }
        }
    }

    /// Drop sessions idle for longer than the idle timeout.
    pub fn sweep(&self, now_ms: u64) {
        let mut map = self.map.write();
        map.retain(|_, s| s.try_lock().is_none_or(|s| s.last_seen_ms + self.idle_ms > now_ms));
    }

    pub fn len(&self) -> usize {
        self.map.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn summaries(&self) -> Vec<SessionSummary> {
        let map = self.map.read();
        let mut out: Vec<SessionSummary> = map
            .values()
            .map(|s| {
                let s = s.lock();
                SessionSummary {
                    agent: s.agent.clone(),
                    session: s.session.clone(),
                    tainted: s.tainted,
                    taint_sources: s.taint_sources.clone(),
                    calls: s.calls,
                    risk: s.risk,
                    findings: s.findings,
                    plan_remaining: s.plan.as_ref().map(|p| p.remaining()),
                    first_seen_ms: s.first_seen_ms,
                    last_seen_ms: s.last_seen_ms,
                }
            })
            .collect();
        out.sort_by_key(|s| std::cmp::Reverse(s.last_seen_ms));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(tool: &str) -> HistoryEntry {
        HistoryEntry { ts_ms: 0, server: "s".into(), tool: tool.into(), args: json!({}), ok: true }
    }

    #[test]
    fn history_is_bounded_and_completion_matches_ids() {
        let mut s = SessionState::new("a", "s", 12, 0);
        for i in 0..300 {
            s.push_history(entry(&format!("t{i}")), Some(i.to_string()));
        }
        assert!(s.history.len() <= MAX_HISTORY);
        assert_eq!(s.history.len(), s.call_ids.len());
        s.complete_call(Some("299"), "s", "t299", false);
        assert!(!s.history.last().unwrap().ok);
        s.complete_call(None, "s", "t298", false);
        assert!(!s.history[s.history.len() - 2].ok);
    }

    #[test]
    fn repeat_counting_uses_window() {
        let mut s = SessionState::new("a", "s", 12, 0);
        assert_eq!(s.repeat_count(7, 0, 1000), 1);
        assert_eq!(s.repeat_count(7, 10, 1000), 2);
        assert_eq!(s.repeat_count(8, 20, 1000), 1);
        assert_eq!(s.repeat_count(7, 2000, 1000), 1);
    }

    #[test]
    fn sessions_evict_idle_when_full() {
        let sessions = Sessions::new(4, 1000, 12);
        for i in 0..4 {
            sessions.get("a", &i.to_string(), 0);
        }
        sessions.get("a", "new", 5000);
        assert!(sessions.len() <= 4);
        sessions.sweep(10_000);
        assert!(sessions.len() <= 1);
    }
}
