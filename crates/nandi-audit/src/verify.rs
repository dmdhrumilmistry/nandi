//! Chain verification shared by the database and exported JSONL files.

use std::io::BufRead;

use ed25519_dalek::VerifyingKey;
use nandi_core::Result;
use serde::{Deserialize, Serialize};

use crate::audit_err;
use crate::record::{GENESIS_HASH, Record, check_sig};

/// Problems beyond this many are summarized in a single line.
const MAX_PROBLEMS: usize = 100;

/// Outcome of verifying an audit chain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Number of records examined (including unreadable ones).
    pub records: u64,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    /// `true` when no problem was found.
    pub ok: bool,
    /// Human-readable descriptions of every problem found.
    pub problems: Vec<String>,
}

/// Incremental verifier: feed records in ascending order, then `finish`.
pub(crate) struct ChainVerifier<'k> {
    key: &'k VerifyingKey,
    /// Next expected `(seq, prev_hash)`; `None` accepts whatever comes next
    /// (start of an export, or after an unreadable record).
    expect: Option<(u64, String)>,
    report: VerifyReport,
    suppressed: usize,
}

impl<'k> ChainVerifier<'k> {
    pub(crate) fn new(key: &'k VerifyingKey, start: Option<(u64, String)>) -> Self {
        Self { key, expect: start, report: VerifyReport::default(), suppressed: 0 }
    }

    pub(crate) fn problem(&mut self, msg: impl Into<String>) {
        if self.report.problems.len() < MAX_PROBLEMS {
            self.report.problems.push(msg.into());
        } else {
            self.suppressed += 1;
        }
    }

    fn count(&mut self, seq: Option<u64>) {
        self.report.records += 1;
        if let Some(seq) = seq {
            self.report.first_seq.get_or_insert(seq);
            self.report.last_seq = Some(seq);
        }
    }

    /// Check one record against its own content, signature and the chain.
    pub(crate) fn check(&mut self, rec: &Record) {
        let first = self.report.records == 0;
        self.count(Some(rec.seq));
        match self.expect.take() {
            Some((seq, prev)) => {
                if rec.seq != seq {
                    self.problem(format!("seq {}: expected seq {seq} (records missing or reordered)", rec.seq));
                }
                if rec.prev_hash != prev {
                    self.problem(format!("seq {}: prev_hash does not link to the previous record", rec.seq));
                }
            }
            None if first && rec.seq == 1 && rec.prev_hash != GENESIS_HASH => {
                self.problem("seq 1: prev_hash is not the genesis hash");
            }
            None => {}
        }
        match rec.compute_hash() {
            Ok(h) if h == rec.hash => {}
            Ok(_) => self.problem(format!("seq {}: content does not match its hash (record modified)", rec.seq)),
            Err(e) => self.problem(format!("seq {}: cannot hash record: {e}", rec.seq)),
        }
        if let Err(e) = check_sig(self.key, &rec.hash, &rec.sig) {
            self.problem(format!("seq {}: {e}", rec.seq));
        }
        self.expect = Some((rec.seq.saturating_add(1), rec.hash.clone()));
    }

    /// Record an entry that could not be decoded; the chain cannot be
    /// followed across it.
    pub(crate) fn unreadable(&mut self, seq: Option<u64>, what: &str, err: impl std::fmt::Display) {
        self.count(seq);
        self.problem(format!("{what}: unreadable record: {err}"));
        self.expect = None;
    }

    /// Check that the chain ends where the log head says it does.
    pub(crate) fn expect_end(&mut self, head_seq: u64, head_hash: &str) {
        if let Some((next, prev)) = self.expect.clone() {
            let last = next.saturating_sub(1);
            if last != head_seq {
                self.problem(format!(
                    "chain ends at seq {last} but the log head is seq {head_seq} (records removed or head rewritten)"
                ));
            } else if prev != head_hash {
                self.problem(format!("seq {last}: hash does not match the log head"));
            }
        }
    }

    pub(crate) fn finish(mut self) -> VerifyReport {
        if self.suppressed > 0 {
            self.report.problems.push(format!("... and {} more problems", self.suppressed));
        }
        self.report.ok = self.report.problems.is_empty();
        self.report
    }
}

/// Parse a hex Ed25519 public key.
pub(crate) fn parse_public_key(public_key_hex: &str) -> Result<VerifyingKey> {
    let raw = hex::decode(public_key_hex.trim()).map_err(|e| audit_err(format!("public key is not hex: {e}")))?;
    let raw: [u8; 32] = raw.try_into().map_err(|_| audit_err("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&raw).map_err(audit_err)
}

/// Verify an exported JSONL audit log (one [`Record`] per line, ascending)
/// against the log's hex public key.
///
/// The first record's `prev_hash` is taken as the starting point unless it
/// is seq 1, which must link to the genesis hash, so exports of pruned logs
/// verify too. Removing records from the start of an export cannot be
/// detected this way; compare `first_seq` against what you expect.
pub fn verify_jsonl(r: &mut dyn BufRead, public_key_hex: &str) -> Result<VerifyReport> {
    let key = parse_public_key(public_key_hex)?;
    let mut v = ChainVerifier::new(&key, None);
    let mut line = String::new();
    let mut lineno = 0u64;
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            break;
        }
        lineno += 1;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Record>(&line) {
            Ok(rec) => v.check(&rec),
            Err(e) => v.unreadable(None, &format!("line {lineno}"), e),
        }
    }
    Ok(v.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::sample_event;
    use ed25519_dalek::SigningKey;
    use nandi_core::Decision;

    fn chain(key: &SigningKey, n: u64) -> Vec<Record> {
        let mut prev = GENESIS_HASH.to_string();
        (1..=n)
            .map(|seq| {
                let r = Record::seal(key, seq, seq * 10, &sample_event("a", "s"), &Decision::allow(), &prev).unwrap();
                prev = r.hash.clone();
                r
            })
            .collect()
    }

    fn to_jsonl(recs: &[Record]) -> String {
        recs.iter().map(|r| serde_json::to_string(r).unwrap() + "\n").collect()
    }

    #[test]
    fn valid_chain_verifies() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let text = to_jsonl(&chain(&key, 4));
        let rep = verify_jsonl(&mut text.as_bytes(), &pk).unwrap();
        assert!(rep.ok, "{:?}", rep.problems);
        assert_eq!((rep.records, rep.first_seq, rep.last_seq), (4, Some(1), Some(4)));
    }

    #[test]
    fn detects_gap_bad_genesis_and_garbage() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let mut recs = chain(&key, 4);
        recs.remove(2);
        let rep = verify_jsonl(&mut to_jsonl(&recs).as_bytes(), &pk).unwrap();
        assert!(!rep.ok);
        assert!(rep.problems.iter().any(|p| p.contains("expected seq 3")));

        let bad = Record::seal(&key, 1, 1, &sample_event("a", "s"), &Decision::allow(), &"f".repeat(64)).unwrap();
        let rep = verify_jsonl(&mut to_jsonl(&[bad]).as_bytes(), &pk).unwrap();
        assert!(rep.problems.iter().any(|p| p.contains("genesis")));

        let rep = verify_jsonl(&mut "{not json}\n".as_bytes(), &pk).unwrap();
        assert!(!rep.ok);
        assert_eq!(rep.records, 1);
    }

    #[test]
    fn rejects_bad_public_key() {
        assert!(verify_jsonl(&mut "".as_bytes(), "zz").is_err());
        assert!(verify_jsonl(&mut "".as_bytes(), "abcd").is_err());
    }

    #[test]
    fn problems_are_capped() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let vk = key.verifying_key();
        let mut v = ChainVerifier::new(&vk, None);
        for i in 0..MAX_PROBLEMS + 5 {
            v.problem(format!("p{i}"));
        }
        let rep = v.finish();
        assert_eq!(rep.problems.len(), MAX_PROBLEMS + 1);
        assert!(rep.problems.last().unwrap().contains("5 more"));
    }
}
