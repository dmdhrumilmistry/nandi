//! Tiny key-value persistence interface.
//!
//! The engine persists tool pins, agent card pins, behaviour models and
//! budget counters through this trait. `nandi-audit` implements it on top of
//! redb; [`MemoryStore`] is used in tests and for ephemeral runs.

use std::collections::BTreeMap;

use parking_lot::RwLock;

pub trait StateStore: Send + Sync {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn put(&self, key: &str, value: &[u8]);
    fn delete(&self, key: &str);
    /// All keys starting with `prefix`, in order.
    fn keys(&self, prefix: &str) -> Vec<String>;
}

#[derive(Debug, Default)]
pub struct MemoryStore {
    map: RwLock<BTreeMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateStore for MemoryStore {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.map.read().get(key).cloned()
    }

    fn put(&self, key: &str, value: &[u8]) {
        self.map.write().insert(key.to_string(), value.to_vec());
    }

    fn delete(&self, key: &str) {
        self.map.write().remove(key);
    }

    fn keys(&self, prefix: &str) -> Vec<String> {
        self.map
            .read()
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, _)| k.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_prefix_keys() {
        let s = MemoryStore::new();
        s.put("pin/a", b"1");
        s.put("pin/b", b"2");
        s.put("model/x", b"3");
        assert_eq!(s.keys("pin/"), vec!["pin/a", "pin/b"]);
        assert_eq!(s.get("pin/b").unwrap(), b"2");
        s.delete("pin/a");
        assert_eq!(s.keys("pin/"), vec!["pin/b"]);
    }
}
