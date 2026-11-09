//! API key helpers.

use base64::Engine;

/// Hex SHA-256 of an API key, as stored in `identity.api_keys[].sha256`.
pub fn hash_key(key: &str) -> String {
    nandi_core::util::sha256_hex(key.as_bytes())
}

/// A new random API key: 32 bytes from the OS RNG, base64url without
/// padding, prefixed with `nandi_`.
pub fn generate_api_key() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("operating system random number generator is unavailable");
    format!("nandi_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Constant-time equality for equal-length secrets (hex digests).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_generates() {
        assert_eq!(hash_key("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let k = generate_api_key();
        assert!(k.starts_with("nandi_"));
        assert_eq!(k.len(), "nandi_".len() + 43);
        assert_ne!(k, generate_api_key());
    }

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abcd", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abce"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }
}
