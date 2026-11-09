//! Tamper-evident audit log and persistent state store for nandi.
//!
//! Every recorded [`Event`](nandi_core::Event) and its
//! [`Decision`](nandi_core::Decision) becomes a [`Record`] in a redb table.
//! Records form a hash chain: each one carries the SHA-256 of its canonical
//! content including the previous record's hash, and an Ed25519 signature
//! over that hash. [`AuditLog::verify`] recomputes the chain and checks every
//! signature; [`verify_jsonl`] does the same for an exported log with only
//! the public key, for offline auditors.
//!
//! The same database also backs the engine's [`StateStore`](nandi_core::StateStore)
//! (tool pins, behaviour models, budget counters) in a separate table.

mod keys;
mod log;
mod query;
mod record;
mod state;
mod verify;

pub use log::AuditLog;
pub use query::Query;
pub use record::{GENESIS_HASH, Record};
pub use verify::{VerifyReport, verify_jsonl};

/// Map any displayable storage or crypto error into the audit error variant.
pub(crate) fn audit_err(e: impl std::fmt::Display) -> nandi_core::Error {
    nandi_core::Error::Audit(e.to_string())
}
