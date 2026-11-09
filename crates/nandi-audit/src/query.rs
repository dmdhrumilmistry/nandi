//! Filters for reading the audit log.

use nandi_core::Verdict;
use serde::{Deserialize, Serialize};

use crate::record::Record;

/// Selection of records for [`AuditLog::query`](crate::AuditLog::query).
///
/// All set filters must match. Without `since_seq` / `since_ts_ms` the
/// newest records are returned first; with either set, results are in
/// ascending order starting at that point, which suits tailing the log.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Query {
    /// Exact agent identity.
    pub agent: Option<String>,
    /// Exact session id.
    pub session: Option<String>,
    /// Only decisions at least this restrictive.
    pub min_verdict: Option<Verdict>,
    /// Event kind name, e.g. `tool_call` (see `EventKind::name`).
    pub kind: Option<String>,
    /// Only records with `seq` strictly greater than this (the last seq the
    /// caller has already seen).
    pub since_seq: Option<u64>,
    /// Only records appended at or after this Unix time in milliseconds.
    pub since_ts_ms: Option<u64>,
    /// Maximum number of records to return; 0 means no limit.
    pub limit: usize,
}

impl Query {
    /// Whether results are returned oldest first.
    pub fn ascending(&self) -> bool {
        self.since_seq.is_some() || self.since_ts_ms.is_some()
    }

    /// Effective limit, mapping 0 to unlimited.
    pub(crate) fn max_results(&self) -> usize {
        if self.limit == 0 { usize::MAX } else { self.limit }
    }

    /// Whether `record` passes every filter.
    pub fn matches(&self, record: &Record) -> bool {
        self.since_seq.is_none_or(|s| record.seq > s)
            && self.since_ts_ms.is_none_or(|t| record.ts_ms >= t)
            && self.agent.as_deref().is_none_or(|a| record.event.agent == a)
            && self.session.as_deref().is_none_or(|s| record.event.session == s)
            && self.min_verdict.is_none_or(|v| record.decision.verdict >= v)
            && self.kind.as_deref().is_none_or(|k| record.event.kind_name() == k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{GENESIS_HASH, tests::sample_event};
    use ed25519_dalek::SigningKey;
    use nandi_core::Decision;

    fn rec(seq: u64, ts_ms: u64, verdict: Verdict) -> Record {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let d = Decision { verdict, ..Decision::allow() };
        Record::seal(&key, seq, ts_ms, &sample_event("bot", "s1"), &d, GENESIS_HASH).unwrap()
    }

    #[test]
    fn filters_combine() {
        let r = rec(5, 100, Verdict::Ask);
        assert!(Query::default().matches(&r));
        assert!(Query { agent: Some("bot".into()), kind: Some("tool_call".into()), ..Default::default() }.matches(&r));
        assert!(!Query { agent: Some("other".into()), ..Default::default() }.matches(&r));
        assert!(!Query { session: Some("s2".into()), ..Default::default() }.matches(&r));
        assert!(Query { min_verdict: Some(Verdict::Ask), ..Default::default() }.matches(&r));
        assert!(!Query { min_verdict: Some(Verdict::Deny), ..Default::default() }.matches(&r));
        assert!(!Query { kind: Some("tool_result".into()), ..Default::default() }.matches(&r));
        assert!(Query { since_seq: Some(4), ..Default::default() }.matches(&r));
        assert!(!Query { since_seq: Some(5), ..Default::default() }.matches(&r));
        assert!(Query { since_ts_ms: Some(100), ..Default::default() }.matches(&r));
        assert!(!Query { since_ts_ms: Some(101), ..Default::default() }.matches(&r));
    }

    #[test]
    fn order_and_limit() {
        assert!(!Query::default().ascending());
        assert!(Query { since_seq: Some(0), ..Default::default() }.ascending());
        assert_eq!(Query::default().max_results(), usize::MAX);
        assert_eq!(Query { limit: 3, ..Default::default() }.max_results(), 3);
    }

    #[test]
    fn deserializes_with_defaults() {
        let q: Query = serde_json::from_str(r#"{"min_verdict":"deny","limit":10}"#).unwrap();
        assert_eq!(q.min_verdict, Some(Verdict::Deny));
        assert_eq!(q.limit, 10);
        assert!(q.agent.is_none());
    }
}
