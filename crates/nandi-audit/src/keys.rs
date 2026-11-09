//! Loading and creating the Ed25519 signing key file.

use std::fs;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::SigningKey;
use nandi_core::Result;

use crate::audit_err;

/// Generate a fresh signing key from the OS random source.
pub(crate) fn generate() -> Result<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(audit_err)?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    Ok(key)
}

/// Parse a key file: 64 hex characters (surrounding whitespace ignored) or
/// exactly 32 raw bytes.
pub(crate) fn parse(bytes: &[u8]) -> Result<SigningKey> {
    if bytes.len() == 32 {
        let seed: [u8; 32] = bytes.try_into().map_err(audit_err)?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| audit_err("signing key is neither hex nor 32 raw bytes"))?;
    let raw = hex::decode(text.trim()).map_err(|e| audit_err(format!("signing key is not hex: {e}")))?;
    let seed: [u8; 32] = raw.try_into().map_err(|_| audit_err("signing key must be 32 bytes (64 hex characters)"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Load the key at `path`, creating it (hex, mode 0600 on unix) if missing.
pub(crate) fn load_or_create(path: &Path) -> Result<SigningKey> {
    match fs::read(path) {
        Ok(bytes) => return parse(&bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(audit_err(format!("reading signing key {}: {e}", path.display()))),
    }
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let key = generate()?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => {
            f.write_all(format!("{}\n", hex::encode(key.to_bytes())).as_bytes())?;
            f.sync_all()?;
            Ok(key)
        }
        // Another process created it first: use theirs.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => parse(&fs::read(path)?),
        Err(e) => Err(audit_err(format!("creating signing key {}: {e}", path.display()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_then_reloads_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/audit.key");
        let k1 = load_or_create(&path).unwrap();
        let k2 = load_or_create(&path).unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text.trim().len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn parses_hex_and_raw() {
        let seed = [3u8; 32];
        assert_eq!(parse(&seed).unwrap().to_bytes(), seed);
        let hex_text = format!("  {}\n", hex::encode(seed));
        assert_eq!(parse(hex_text.as_bytes()).unwrap().to_bytes(), seed);
        assert!(parse(b"nope").is_err());
        assert!(parse(hex::encode([1u8; 20]).as_bytes()).is_err());
    }
}
