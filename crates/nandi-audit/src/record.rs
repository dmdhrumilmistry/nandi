//! The [`Record`] type, its canonical hash and its signature.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nandi_core::util::{canonical_json, sha256_hex};
use nandi_core::{Decision, Event, Result};
use serde::{Deserialize, Serialize};

use crate::audit_err;

/// `prev_hash` of the first record of a fresh log.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One entry of the audit log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// Position in the chain, starting at 1 and increasing by one.
    pub seq: u64,
    /// Unix epoch milliseconds when the record was appended. Never decreases
    /// along the chain, even if the wall clock steps back.
    pub ts_ms: u64,
    pub event: Event,
    pub decision: Decision,
    /// `hash` of the previous record, or [`GENESIS_HASH`].
    pub prev_hash: String,
    /// Hex SHA-256 over the canonical JSON of
    /// `{seq, ts_ms, event, decision, prev_hash}`.
    pub hash: String,
    /// Hex Ed25519 signature over the 32 raw bytes of `hash`.
    pub sig: String,
}

/// The hashed part of a record.
#[derive(Serialize)]
struct HashBody<'a> {
    seq: u64,
    ts_ms: u64,
    event: &'a Event,
    decision: &'a Decision,
    prev_hash: &'a str,
}

/// Hex SHA-256 of the canonical JSON of the hashed fields.
pub(crate) fn compute_hash(
    seq: u64,
    ts_ms: u64,
    event: &Event,
    decision: &Decision,
    prev_hash: &str,
) -> Result<String> {
    let body = serde_json::to_value(HashBody { seq, ts_ms, event, decision, prev_hash })?;
    Ok(sha256_hex(canonical_json(&body)))
}

/// Hex Ed25519 signature over the raw bytes of a hex hash.
pub(crate) fn sign_hash(key: &SigningKey, hash_hex: &str) -> Result<String> {
    let bytes = hex::decode(hash_hex).map_err(audit_err)?;
    Ok(hex::encode(key.sign(&bytes).to_bytes()))
}

/// Check a hex signature over the raw bytes of a hex hash.
pub(crate) fn check_sig(key: &VerifyingKey, hash_hex: &str, sig_hex: &str) -> std::result::Result<(), String> {
    let hash = hex::decode(hash_hex).map_err(|e| format!("hash is not hex: {e}"))?;
    let sig = hex::decode(sig_hex).map_err(|e| format!("signature is not hex: {e}"))?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| "signature is not 64 bytes".to_string())?;
    key.verify_strict(&hash, &Signature::from_bytes(&sig)).map_err(|_| "bad signature".to_string())
}

impl Record {
    /// Build, hash and sign a record.
    pub(crate) fn seal(
        key: &SigningKey,
        seq: u64,
        ts_ms: u64,
        event: &Event,
        decision: &Decision,
        prev_hash: &str,
    ) -> Result<Self> {
        let mut decision = decision.clone();
        // serde_json turns non-finite floats into `null`, which would not
        // deserialize back into `f32`; keep stored records readable.
        if !decision.risk.is_finite() {
            decision.risk = 0.0;
        }
        let hash = compute_hash(seq, ts_ms, event, &decision, prev_hash)?;
        let sig = sign_hash(key, &hash)?;
        Ok(Self { seq, ts_ms, event: event.clone(), decision, prev_hash: prev_hash.to_string(), hash, sig })
    }

    /// Recompute the hash from the record's content.
    pub fn compute_hash(&self) -> Result<String> {
        compute_hash(self.seq, self.ts_ms, &self.event, &self.decision, &self.prev_hash)
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nandi_core::{EventKind, Source, ToolCall, Verdict};

    pub(crate) fn sample_event(agent: &str, session: &str) -> Event {
        Event::new(
            Source::Stdio,
            agent,
            session,
            EventKind::ToolCall(ToolCall {
                server: "fs".into(),
                tool: "read_file".into(),
                call_id: None,
                args: serde_json::json!({"path": "/tmp/x", "n": 1.5}),
            }),
        )
    }

    #[test]
    fn seal_hash_and_sig_round_trip() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut d = Decision::allow();
        d.verdict = Verdict::Alert;
        d.risk = 0.3;
        let rec = Record::seal(&key, 1, 42, &sample_event("a", "s"), &d, GENESIS_HASH).unwrap();
        assert_eq!(rec.hash.len(), 64);
        let back = Record::from_bytes(&rec.to_bytes().unwrap()).unwrap();
        assert_eq!(back.compute_hash().unwrap(), rec.hash);
        assert!(check_sig(&key.verifying_key(), &rec.hash, &rec.sig).is_ok());
        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert!(check_sig(&other.verifying_key(), &rec.hash, &rec.sig).is_err());
    }

    #[test]
    fn non_finite_risk_is_stored_as_zero() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let d = Decision { risk: f32::NAN, ..Decision::allow() };
        let rec = Record::seal(&key, 1, 1, &sample_event("a", "s"), &d, GENESIS_HASH).unwrap();
        assert_eq!(rec.decision.risk, 0.0);
        assert!(Record::from_bytes(&rec.to_bytes().unwrap()).is_ok());
    }

    #[test]
    fn hash_covers_prev_hash() {
        let ev = sample_event("a", "s");
        let d = Decision::allow();
        let h1 = compute_hash(1, 1, &ev, &d, GENESIS_HASH).unwrap();
        let h2 = compute_hash(1, 1, &ev, &d, &"1".repeat(64)).unwrap();
        assert_ne!(h1, h2);
    }
}
