//! The redb-backed [`AuditLog`].

use std::fmt;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::SigningKey;
use nandi_core::util::now_ms;
use nandi_core::{Decision, Event, Result};
use parking_lot::Mutex;
use redb::backends::InMemoryBackend;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::audit_err;
use crate::query::Query;
use crate::record::{GENESIS_HASH, Record, check_sig};
use crate::verify::{ChainVerifier, VerifyReport};
use crate::{keys, verify};

/// Audit records keyed by `seq`, values are the JSON of [`Record`].
pub(crate) const RECORDS: TableDefinition<u64, &[u8]> = TableDefinition::new("records");
/// Bookkeeping: log head and prune anchor, JSON values.
pub(crate) const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
/// Engine state exposed through [`nandi_core::StateStore`].
pub(crate) const STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("state");

const META_HEAD: &str = "head";
const META_ANCHOR: &str = "anchor";

/// The last appended record, cached so appends never read the database.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Head {
    seq: u64,
    hash: String,
    ts_ms: u64,
}

/// Where the chain starts after a prune: the first retained seq and the
/// hash and signature of the last pruned record, so the start of the
/// remaining chain is still bound to a signed hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Anchor {
    seq: u64,
    prev_hash: String,
    prev_sig: String,
    pruned_at_ms: u64,
}

/// The fields prune needs, decoded without the full event.
#[derive(Deserialize)]
struct PruneView {
    ts_ms: u64,
    hash: String,
    sig: String,
}

/// Map redb (and other) errors into [`nandi_core::Error::Audit`].
pub(crate) trait OrAudit<T> {
    fn audit(self) -> Result<T>;
}

impl<T, E: fmt::Display> OrAudit<T> for std::result::Result<T, E> {
    fn audit(self) -> Result<T> {
        self.map_err(audit_err)
    }
}

fn read_json<T: DeserializeOwned>(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<T>> {
    match table.get(key).audit()? {
        Some(v) => Ok(Some(serde_json::from_slice(v.value())?)),
        None => Ok(None),
    }
}

/// Tamper-evident, signed, append-only audit log on redb.
///
/// `Send + Sync`; share it with `Arc`. Appends are serialized internally and
/// each append (or batch) is one write transaction.
pub struct AuditLog {
    pub(crate) db: Database,
    key: SigningKey,
    head: Mutex<Head>,
}

impl fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let head = self.head.lock();
        f.debug_struct("AuditLog")
            .field("public_key", &self.public_key_hex())
            .field("head_seq", &head.seq)
            .finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Open (or create) the database at `db_path`, signing with the Ed25519
    /// key at `key_path` (generated with mode 0600 when missing).
    pub fn open(db_path: &Path, key_path: &Path) -> Result<Self> {
        let key = keys::load_or_create(key_path)?;
        if let Some(dir) = db_path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let db = Database::create(db_path).map_err(|e| audit_err(format!("opening {}: {e}", db_path.display())))?;
        Self::init(db, key)
    }

    /// Ephemeral log in memory with a fresh random key, for tests and runs
    /// that do not need persistence.
    pub fn open_in_memory() -> Result<Self> {
        let db = redb::Builder::new().create_with_backend(InMemoryBackend::new()).audit()?;
        Self::init(db, keys::generate()?)
    }

    fn init(db: Database, key: SigningKey) -> Result<Self> {
        let txn = db.begin_write().audit()?;
        let head = {
            let records = txn.open_table(RECORDS).audit()?;
            let meta = txn.open_table(META).audit()?;
            txn.open_table(STATE).audit()?;
            match read_json::<Head>(&meta, META_HEAD)? {
                Some(h) => h,
                None => match records.last().audit()? {
                    // Head missing but records present: recover from the tail.
                    Some((_, v)) => {
                        let r = Record::from_bytes(v.value())?;
                        Head { seq: r.seq, hash: r.hash, ts_ms: r.ts_ms }
                    }
                    None => match read_json::<Anchor>(&meta, META_ANCHOR)? {
                        Some(a) => Head { seq: a.seq.saturating_sub(1), hash: a.prev_hash, ts_ms: 0 },
                        None => Head { seq: 0, hash: GENESIS_HASH.to_string(), ts_ms: 0 },
                    },
                },
            }
        };
        txn.commit().audit()?;
        Ok(Self { db, key, head: Mutex::new(head) })
    }

    /// Hex Ed25519 public key that verifies this log's signatures.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    /// `(seq, hash)` of the newest record; `(0, GENESIS_HASH)` when empty.
    /// Publishing this elsewhere lets auditors detect later truncation.
    pub fn head(&self) -> (u64, String) {
        let h = self.head.lock();
        (h.seq, h.hash.clone())
    }

    /// Append one record.
    pub fn append(&self, event: &Event, decision: &Decision) -> Result<Record> {
        let mut out = self.append_iter(std::iter::once((event, decision)))?;
        out.pop().ok_or_else(|| audit_err("append produced no record"))
    }

    /// Append several records in a single write transaction.
    pub fn append_batch(&self, items: &[(Event, Decision)]) -> Result<Vec<Record>> {
        self.append_iter(items.iter().map(|(e, d)| (e, d)))
    }

    fn append_iter<'a>(&self, items: impl Iterator<Item = (&'a Event, &'a Decision)>) -> Result<Vec<Record>> {
        let mut head = self.head.lock();
        let mut next = head.clone();
        let mut out = Vec::new();
        for (event, decision) in items {
            // Keep record time monotonic so prune and time queries can rely
            // on ascending order.
            let ts_ms = now_ms().max(next.ts_ms);
            let rec = Record::seal(&self.key, next.seq + 1, ts_ms, event, decision, &next.hash)?;
            next = Head { seq: rec.seq, hash: rec.hash.clone(), ts_ms };
            out.push(rec);
        }
        if out.is_empty() {
            return Ok(out);
        }
        let txn = self.db.begin_write().audit()?;
        {
            let mut records = txn.open_table(RECORDS).audit()?;
            for rec in &out {
                records.insert(rec.seq, rec.to_bytes()?.as_slice()).audit()?;
            }
            let mut meta = txn.open_table(META).audit()?;
            meta.insert(META_HEAD, serde_json::to_vec(&next)?.as_slice()).audit()?;
        }
        txn.commit().audit()?;
        *head = next;
        Ok(out)
    }

    /// Record with the given sequence number, if present.
    pub fn get(&self, seq: u64) -> Result<Option<Record>> {
        let txn = self.db.begin_read().audit()?;
        let records = txn.open_table(RECORDS).audit()?;
        records.get(seq).audit()?.map(|v| Record::from_bytes(v.value())).transpose()
    }

    /// Number of records currently stored.
    pub fn len(&self) -> Result<u64> {
        let txn = self.db.begin_read().audit()?;
        txn.open_table(RECORDS).audit()?.len().audit()
    }

    /// Whether the log holds no records.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Records matching `q`: newest first, or ascending when `since_seq` or
    /// `since_ts_ms` is set. Unreadable records are skipped (and reported by
    /// [`AuditLog::verify`]).
    pub fn query(&self, q: &Query) -> Result<Vec<Record>> {
        let txn = self.db.begin_read().audit()?;
        let records = txn.open_table(RECORDS).audit()?;
        let limit = q.max_results();
        let mut out = Vec::new();
        let mut take = |bytes: &[u8]| -> bool {
            match Record::from_bytes(bytes) {
                Ok(rec) if q.matches(&rec) => out.push(rec),
                Ok(_) => {}
                Err(e) => tracing::warn!("audit: skipping unreadable record: {e}"),
            }
            out.len() < limit
        };
        if q.ascending() {
            let mut start = q.since_seq.map_or(0, |s| s.saturating_add(1));
            if let Some(ts) = q.since_ts_ms {
                start = start.max(first_seq_at_or_after(&records, ts)?);
            }
            for item in records.range(start..).audit()? {
                if !take(item.audit()?.1.value()) {
                    break;
                }
            }
        } else {
            for item in records.iter().audit()?.rev() {
                if !take(item.audit()?.1.value()) {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Recompute every hash, check chain links, signatures, the prune anchor
    /// and that the chain ends at the recorded head.
    pub fn verify(&self) -> Result<VerifyReport> {
        let txn = self.db.begin_read().audit()?;
        let records = txn.open_table(RECORDS).audit()?;
        let meta = txn.open_table(META).audit()?;
        let anchor = read_json::<Anchor>(&meta, META_ANCHOR)?;
        let head = read_json::<Head>(&meta, META_HEAD)?;
        let vk = self.key.verifying_key();
        let start = anchor.as_ref().map_or((1, GENESIS_HASH.to_string()), |a| (a.seq, a.prev_hash.clone()));
        let mut v = ChainVerifier::new(&vk, Some(start));
        if let Some(a) = &anchor
            && let Err(e) = check_sig(&vk, &a.prev_hash, &a.prev_sig)
        {
            v.problem(format!("prune anchor: {e}"));
        }
        for item in records.iter().audit()? {
            let (k, val) = item.audit()?;
            let key = k.value();
            match Record::from_bytes(val.value()) {
                Ok(rec) => {
                    if rec.seq != key {
                        v.problem(format!("key {key} holds record seq {}", rec.seq));
                    }
                    v.check(&rec);
                }
                Err(e) => v.unreadable(Some(key), &format!("seq {key}"), e),
            }
        }
        match head {
            Some(h) => v.expect_end(h.seq, &h.hash),
            None if !records.is_empty().audit()? => v.problem("log head is missing"),
            None => {}
        }
        Ok(v.finish())
    }

    /// Delete the oldest records appended before `ts_ms`, keeping the chain
    /// verifiable through a signed anchor. Returns how many were removed.
    pub fn prune_older_than(&self, ts_ms: u64) -> Result<u64> {
        // Hold the head lock so no append interleaves with the prune.
        let _head = self.head.lock();
        let txn = self.db.begin_write().audit()?;
        let removed = {
            let mut records = txn.open_table(RECORDS).audit()?;
            let mut last: Option<(u64, PruneView)> = None;
            let mut count = 0u64;
            for item in records.iter().audit()? {
                let (k, v) = item.audit()?;
                let view: PruneView = serde_json::from_slice(v.value())?;
                if view.ts_ms >= ts_ms {
                    break;
                }
                last = Some((k.value(), view));
                count += 1;
            }
            if let Some((last_seq, view)) = last {
                records.retain_in(..=last_seq, |_, _| false).audit()?;
                let anchor =
                    Anchor { seq: last_seq + 1, prev_hash: view.hash, prev_sig: view.sig, pruned_at_ms: now_ms() };
                let mut meta = txn.open_table(META).audit()?;
                meta.insert(META_ANCHOR, serde_json::to_vec(&anchor)?.as_slice()).audit()?;
            }
            count
        };
        if removed == 0 {
            txn.abort().audit()?;
        } else {
            txn.commit().audit()?;
        }
        Ok(removed)
    }

    /// Write all records, oldest first, one JSON [`Record`] per line.
    /// Returns the number of lines written.
    pub fn export_jsonl(&self, w: &mut dyn Write) -> Result<u64> {
        let txn = self.db.begin_read().audit()?;
        let records = txn.open_table(RECORDS).audit()?;
        let mut n = 0u64;
        for item in records.iter().audit()? {
            let (_, v) = item.audit()?;
            w.write_all(v.value())?;
            w.write_all(b"\n")?;
            n += 1;
        }
        w.flush()?;
        Ok(n)
    }

    /// Verify an export of this log with its own public key.
    pub fn verify_export(&self, r: &mut dyn std::io::BufRead) -> Result<VerifyReport> {
        verify::verify_jsonl(r, &self.public_key_hex())
    }
}

/// Smallest seq whose record was appended at or after `ts_ms`. Record times
/// never decrease along the chain, so this is a binary search over seqs.
fn first_seq_at_or_after(records: &impl ReadableTable<u64, &'static [u8]>, ts_ms: u64) -> Result<u64> {
    #[derive(Deserialize)]
    struct TsView {
        ts_ms: u64,
    }
    let (Some(first), Some(last)) =
        (records.first().audit()?.map(|(k, _)| k.value()), records.last().audit()?.map(|(k, _)| k.value()))
    else {
        return Ok(0);
    };
    let (mut lo, mut hi) = (first, last.saturating_add(1));
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let Some(v) = records.get(mid).audit()? else {
            // A gap means the chain is damaged; fall back to a full scan.
            return Ok(first);
        };
        let Ok(view) = serde_json::from_slice::<TsView>(v.value()) else {
            return Ok(first);
        };
        if view.ts_ms < ts_ms {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::sample_event;
    use nandi_core::{Category, EventKind, Finding, Severity, Source, ToolResult, Verdict};

    fn decision(verdict: Verdict) -> Decision {
        let mut d = Decision::allow();
        if verdict != Verdict::Allow {
            d.push(Finding::new("test.rule", Category::Policy, Severity::Medium, verdict, "m"));
        }
        d
    }

    fn open(dir: &Path) -> AuditLog {
        AuditLog::open(&dir.join("audit.redb"), &dir.join("audit.key")).unwrap()
    }

    #[test]
    fn append_and_get() {
        let log = AuditLog::open_in_memory().unwrap();
        assert!(log.is_empty().unwrap());
        let ev = sample_event("a", "s");
        let r1 = log.append(&ev, &decision(Verdict::Alert)).unwrap();
        let r2 = log.append(&ev, &Decision::allow()).unwrap();
        assert_eq!((r1.seq, r2.seq), (1, 2));
        assert_eq!(r1.prev_hash, GENESIS_HASH);
        assert_eq!(r2.prev_hash, r1.hash);
        assert!(r2.ts_ms >= r1.ts_ms);
        assert_eq!(log.get(1).unwrap().unwrap(), r1);
        assert!(log.get(3).unwrap().is_none());
        assert_eq!(log.len().unwrap(), 2);
        assert_eq!(log.head(), (2, r2.hash));
    }

    #[test]
    fn batch_and_chain_verify() {
        let log = AuditLog::open_in_memory().unwrap();
        let items: Vec<_> = (0..5).map(|i| (sample_event(&format!("a{i}"), "s"), Decision::allow())).collect();
        let recs = log.append_batch(&items).unwrap();
        assert_eq!(recs.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5]);
        assert!(log.append_batch(&[]).unwrap().is_empty());
        log.append(&sample_event("b", "s"), &Decision::allow()).unwrap();
        let rep = log.verify().unwrap();
        assert!(rep.ok, "{:?}", rep.problems);
        assert_eq!((rep.records, rep.first_seq, rep.last_seq), (6, Some(1), Some(6)));
    }

    #[test]
    fn empty_log_verifies() {
        let log = AuditLog::open_in_memory().unwrap();
        let rep = log.verify().unwrap();
        assert!(rep.ok);
        assert_eq!(rep.records, 0);
    }

    fn rewrite(log: &AuditLog, seq: u64, f: impl FnOnce(&mut Record)) {
        let mut rec = log.get(seq).unwrap().unwrap();
        f(&mut rec);
        let txn = log.db.begin_write().unwrap();
        {
            let mut t = txn.open_table(RECORDS).unwrap();
            t.insert(seq, rec.to_bytes().unwrap().as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }

    #[test]
    fn tampered_record_is_detected() {
        let log = AuditLog::open_in_memory().unwrap();
        for _ in 0..3 {
            log.append(&sample_event("a", "s"), &decision(Verdict::Deny)).unwrap();
        }
        rewrite(&log, 2, |r| r.decision.verdict = Verdict::Allow);
        let rep = log.verify().unwrap();
        assert!(!rep.ok);
        assert!(rep.problems.iter().any(|p| p.contains("seq 2: content does not match")), "{:?}", rep.problems);
    }

    #[test]
    fn rehashed_tamper_breaks_signature_and_link() {
        let log = AuditLog::open_in_memory().unwrap();
        for _ in 0..3 {
            log.append(&sample_event("a", "s"), &Decision::allow()).unwrap();
        }
        // An attacker without the key recomputes the hash but cannot sign it.
        rewrite(&log, 2, |r| {
            r.event.agent = "someone-else".into();
            r.hash = r.compute_hash().unwrap();
        });
        let rep = log.verify().unwrap();
        assert!(rep.problems.iter().any(|p| p.contains("seq 2: bad signature")), "{:?}", rep.problems);
        assert!(rep.problems.iter().any(|p| p.contains("seq 3: prev_hash")), "{:?}", rep.problems);
    }

    #[test]
    fn garbage_bytes_and_deleted_tail_are_detected() {
        let log = AuditLog::open_in_memory().unwrap();
        for _ in 0..4 {
            log.append(&sample_event("a", "s"), &Decision::allow()).unwrap();
        }
        let txn = log.db.begin_write().unwrap();
        {
            let mut t = txn.open_table(RECORDS).unwrap();
            t.insert(2u64, b"garbage".as_slice()).unwrap();
            t.remove(4u64).unwrap();
        }
        txn.commit().unwrap();
        let rep = log.verify().unwrap();
        assert!(rep.problems.iter().any(|p| p.contains("seq 2: unreadable")), "{:?}", rep.problems);
        assert!(rep.problems.iter().any(|p| p.contains("log head is seq 4")), "{:?}", rep.problems);
        // Queries skip the unreadable record.
        assert_eq!(log.query(&Query::default()).unwrap().len(), 2);
    }

    #[test]
    fn wrong_key_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        {
            let log = open(dir.path());
            log.append(&sample_event("a", "s"), &Decision::allow()).unwrap();
        }
        let other = dir.path().join("other.key");
        let log = AuditLog::open(&dir.path().join("audit.redb"), &other).unwrap();
        let rep = log.verify().unwrap();
        assert!(!rep.ok);
        assert!(rep.problems.iter().any(|p| p.contains("bad signature")));
    }

    #[test]
    fn prune_keeps_chain_verifiable() {
        let log = AuditLog::open_in_memory().unwrap();
        for _ in 0..3 {
            log.append(&sample_event("old", "s"), &Decision::allow()).unwrap();
        }
        let cutoff = log.get(3).unwrap().unwrap().ts_ms + 1;
        // Make sure later records are strictly newer than the cutoff.
        while now_ms() < cutoff {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        for _ in 0..2 {
            log.append(&sample_event("new", "s"), &Decision::allow()).unwrap();
        }
        assert_eq!(log.prune_older_than(0).unwrap(), 0);
        assert_eq!(log.prune_older_than(cutoff).unwrap(), 3);
        assert_eq!(log.len().unwrap(), 2);
        assert!(log.get(3).unwrap().is_none());
        let rep = log.verify().unwrap();
        assert!(rep.ok, "{:?}", rep.problems);
        assert_eq!(rep.first_seq, Some(4));
        // Appends continue after a prune and everything can be pruned.
        log.append(&sample_event("new", "s"), &Decision::allow()).unwrap();
        assert_eq!(log.prune_older_than(u64::MAX).unwrap(), 3);
        let rep = log.verify().unwrap();
        assert!(rep.ok, "{:?}", rep.problems);
        assert_eq!(rep.records, 0);
        assert_eq!(log.append(&sample_event("x", "s"), &Decision::allow()).unwrap().seq, 7);
        assert!(log.verify().unwrap().ok);
    }

    #[test]
    fn forged_anchor_is_detected() {
        let log = AuditLog::open_in_memory().unwrap();
        for _ in 0..3 {
            log.append(&sample_event("a", "s"), &Decision::allow()).unwrap();
        }
        // Silently drop record 1 and fake an anchor without the key.
        let rec2 = log.get(2).unwrap().unwrap();
        let txn = log.db.begin_write().unwrap();
        {
            txn.open_table(RECORDS).unwrap().remove(1u64).unwrap();
            let anchor = Anchor { seq: 2, prev_hash: rec2.prev_hash, prev_sig: "00".repeat(64), pruned_at_ms: 0 };
            let mut meta = txn.open_table(META).unwrap();
            meta.insert(META_ANCHOR, serde_json::to_vec(&anchor).unwrap().as_slice()).unwrap();
        }
        txn.commit().unwrap();
        let rep = log.verify().unwrap();
        assert!(rep.problems.iter().any(|p| p.contains("prune anchor")), "{:?}", rep.problems);
    }

    #[test]
    fn query_filters_and_order() {
        let log = AuditLog::open_in_memory().unwrap();
        let result = Event::new(
            Source::Stdio,
            "b",
            "s2",
            EventKind::ToolResult(ToolResult {
                server: "fs".into(),
                tool: "read_file".into(),
                call_id: None,
                content: serde_json::json!("x"),
                is_error: false,
            }),
        );
        log.append(&sample_event("a", "s1"), &decision(Verdict::Allow)).unwrap(); // 1
        log.append(&sample_event("a", "s1"), &decision(Verdict::Deny)).unwrap(); // 2
        log.append(&result, &decision(Verdict::Alert)).unwrap(); // 3
        log.append(&sample_event("b", "s2"), &decision(Verdict::Ask)).unwrap(); // 4
        log.append(&sample_event("a", "s3"), &decision(Verdict::Redact)).unwrap(); // 5

        let seqs = |q: Query| log.query(&q).unwrap().iter().map(|r| r.seq).collect::<Vec<_>>();
        assert_eq!(seqs(Query::default()), vec![5, 4, 3, 2, 1]);
        assert_eq!(seqs(Query { limit: 2, ..Default::default() }), vec![5, 4]);
        assert_eq!(seqs(Query { agent: Some("a".into()), ..Default::default() }), vec![5, 2, 1]);
        assert_eq!(seqs(Query { session: Some("s2".into()), ..Default::default() }), vec![4, 3]);
        assert_eq!(seqs(Query { min_verdict: Some(Verdict::Ask), ..Default::default() }), vec![4, 2]);
        assert_eq!(seqs(Query { kind: Some("tool_result".into()), ..Default::default() }), vec![3]);
        assert_eq!(seqs(Query { since_seq: Some(2), ..Default::default() }), vec![3, 4, 5]);
        assert_eq!(seqs(Query { since_seq: Some(2), limit: 1, ..Default::default() }), vec![3]);
        assert_eq!(
            seqs(Query {
                since_seq: Some(0),
                agent: Some("a".into()),
                min_verdict: Some(Verdict::Alert),
                limit: 0,
                ..Default::default()
            }),
            vec![2, 5]
        );
        let ts4 = log.get(4).unwrap().unwrap().ts_ms;
        let got = seqs(Query { since_ts_ms: Some(ts4), ..Default::default() });
        assert!(got.ends_with(&[4, 5]) && got.windows(2).all(|w| w[0] < w[1]), "{got:?}");
        assert!(seqs(Query { since_ts_ms: Some(u64::MAX), ..Default::default() }).is_empty());
        assert_eq!(seqs(Query { since_ts_ms: Some(0), ..Default::default() }), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn time_search_finds_first_match() {
        let log = AuditLog::open_in_memory().unwrap();
        log.append(&sample_event("a", "s"), &Decision::allow()).unwrap();
        let ts1 = log.get(1).unwrap().unwrap().ts_ms;
        while now_ms() <= ts1 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        for _ in 0..4 {
            log.append(&sample_event("a", "s"), &Decision::allow()).unwrap();
        }
        let got: Vec<u64> = log
            .query(&Query { since_ts_ms: Some(ts1 + 1), ..Default::default() })
            .unwrap()
            .iter()
            .map(|r| r.seq)
            .collect();
        assert_eq!(got, vec![2, 3, 4, 5]);
    }

    #[test]
    fn reopen_continues_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (pk, last) = {
            let log = open(dir.path());
            log.append(&sample_event("a", "s"), &Decision::allow()).unwrap();
            let last = log.append(&sample_event("a", "s"), &Decision::allow()).unwrap();
            (log.public_key_hex(), last)
        };
        let log = open(dir.path());
        assert_eq!(log.public_key_hex(), pk);
        assert_eq!(log.head(), (2, last.hash.clone()));
        let r3 = log.append(&sample_event("a", "s"), &Decision::allow()).unwrap();
        assert_eq!(r3.seq, 3);
        assert_eq!(r3.prev_hash, last.hash);
        assert!(r3.ts_ms >= last.ts_ms);
        let rep = log.verify().unwrap();
        assert!(rep.ok, "{:?}", rep.problems);
        assert_eq!(rep.records, 3);
    }

    #[test]
    fn export_and_verify_jsonl_round_trip() {
        let log = AuditLog::open_in_memory().unwrap();
        for i in 0..4 {
            log.append(&sample_event(&format!("a{i}"), "s"), &decision(Verdict::Alert)).unwrap();
        }
        let mut buf = Vec::new();
        assert_eq!(log.export_jsonl(&mut buf).unwrap(), 4);
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 4);
        let rep = verify::verify_jsonl(&mut buf.as_slice(), &log.public_key_hex()).unwrap();
        assert!(rep.ok, "{:?}", rep.problems);
        assert_eq!((rep.records, rep.first_seq, rep.last_seq), (4, Some(1), Some(4)));
        assert!(log.verify_export(&mut buf.as_slice()).unwrap().ok);

        // Wrong public key.
        let other = AuditLog::open_in_memory().unwrap();
        let rep = verify::verify_jsonl(&mut buf.as_slice(), &other.public_key_hex()).unwrap();
        assert!(!rep.ok);
        assert_eq!(rep.problems.iter().filter(|p| p.contains("bad signature")).count(), 4);

        // Edited line.
        let text = String::from_utf8(buf).unwrap().replacen("\"a2\"", "\"zz\"", 1);
        let rep = verify::verify_jsonl(&mut text.as_bytes(), &log.public_key_hex()).unwrap();
        assert!(rep.problems.iter().any(|p| p.contains("seq 3: content does not match")), "{:?}", rep.problems);
    }

    #[test]
    fn concurrent_appends_keep_chain() {
        let log = std::sync::Arc::new(AuditLog::open_in_memory().unwrap());
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let log = log.clone();
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        log.append(&sample_event(&format!("t{t}"), "s"), &Decision::allow()).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let rep = log.verify().unwrap();
        assert!(rep.ok, "{:?}", rep.problems);
        assert_eq!(rep.records, 40);
    }
}
