//! [`StateStore`] implementation on the audit database's `state` table.
//!
//! The trait is infallible, so storage errors are logged and reads fall
//! back to "absent". Use the `try_*` methods when errors matter.

use nandi_core::{Result, StateStore};
use redb::ReadableDatabase;

use crate::log::{AuditLog, OrAudit, STATE};

impl AuditLog {
    /// Read a state value.
    pub fn try_state_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read().audit()?;
        let table = txn.open_table(STATE).audit()?;
        Ok(table.get(key).audit()?.map(|v| v.value().to_vec()))
    }

    /// Write a state value (one durable write transaction).
    pub fn try_state_put(&self, key: &str, value: &[u8]) -> Result<()> {
        let txn = self.db.begin_write().audit()?;
        txn.open_table(STATE).audit()?.insert(key, value).audit()?;
        txn.commit().audit()
    }

    /// Delete a state value; missing keys are not an error.
    pub fn try_state_delete(&self, key: &str) -> Result<()> {
        let txn = self.db.begin_write().audit()?;
        txn.open_table(STATE).audit()?.remove(key).audit()?;
        txn.commit().audit()
    }

    /// State keys starting with `prefix`, in order.
    pub fn try_state_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let txn = self.db.begin_read().audit()?;
        let table = txn.open_table(STATE).audit()?;
        let mut out = Vec::new();
        for item in table.range(prefix..).audit()? {
            let (k, _) = item.audit()?;
            let k = k.value();
            if !k.starts_with(prefix) {
                break;
            }
            out.push(k.to_string());
        }
        Ok(out)
    }
}

impl StateStore for AuditLog {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.try_state_get(key).unwrap_or_else(|e| {
            tracing::warn!("state get {key}: {e}");
            None
        })
    }

    fn put(&self, key: &str, value: &[u8]) {
        if let Err(e) = self.try_state_put(key, value) {
            tracing::warn!("state put {key}: {e}");
        }
    }

    fn delete(&self, key: &str) {
        if let Err(e) = self.try_state_delete(key) {
            tracing::warn!("state delete {key}: {e}");
        }
    }

    fn keys(&self, prefix: &str) -> Vec<String> {
        self.try_state_keys(prefix).unwrap_or_else(|e| {
            tracing::warn!("state keys {prefix}: {e}");
            Vec::new()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_put_delete_keys() {
        let log = AuditLog::open_in_memory().unwrap();
        let s: &dyn StateStore = &log;
        assert!(s.get("pin/a").is_none());
        s.put("pin/a", b"1");
        s.put("pin/b", b"2");
        s.put("pio", b"x");
        s.put("model/x", b"3");
        s.put("pin/a", b"1b");
        assert_eq!(s.get("pin/a").unwrap(), b"1b");
        assert_eq!(s.keys("pin/"), vec!["pin/a", "pin/b"]);
        assert_eq!(s.keys(""), vec!["model/x", "pin/a", "pin/b", "pio"]);
        s.delete("pin/a");
        s.delete("missing");
        assert_eq!(s.keys("pin/"), vec!["pin/b"]);
        assert!(s.keys("zzz").is_empty());
        // State does not touch the audit chain.
        assert_eq!(log.len().unwrap(), 0);
    }

    #[test]
    fn state_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (db, key) = (dir.path().join("a.redb"), dir.path().join("a.key"));
        AuditLog::open(&db, &key).unwrap().put("budget/x", b"42");
        let log = AuditLog::open(&db, &key).unwrap();
        assert_eq!(StateStore::get(&log, "budget/x").unwrap(), b"42");
    }
}
