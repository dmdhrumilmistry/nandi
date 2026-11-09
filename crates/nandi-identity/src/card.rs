//! A2A Agent Card signature verification.
//!
//! An Agent Card carries detached JWS signatures (RFC 7515 Appendix F) in
//! its `signatures` array. Each entry has a base64url `protected` header
//! (`alg`, `kid`, `typ`, optional `jku`) and a base64url `signature`. The
//! signing input is `<protected>.<base64url(payload)>` where the payload is
//! the canonical JSON of the card without `signatures`
//! ([`nandi_proto::a2a::card_signing_payload`]).
//!
//! Only locally configured keys are trusted: `jku` / `jwk` header
//! parameters are never followed, and symmetric (`HS*`) algorithms are
//! refused.

use std::path::PathBuf;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, AlgorithmFamily};
use nandi_core::util::sha256_hex;
use nandi_core::{Error, Result};
use nandi_proto::a2a::{CardSignature, card_signing_payload, parse_card};
use serde_json::Value;

use crate::jwk::{VerifyKey, parse_jwks, pem_key};

/// Keys trusted to sign Agent Cards.
#[derive(Debug, Clone, Default)]
pub struct TrustedKeys {
    keys: Vec<VerifyKey>,
}

impl TrustedKeys {
    /// Load JWKS JSON files and PEM public keys. A PEM key's kid is its file
    /// stem (`partner-a.pem` has kid `partner-a`).
    pub fn load(paths: &[PathBuf]) -> Result<Self> {
        let mut keys = Vec::new();
        for path in paths {
            let text =
                std::fs::read_to_string(path).map_err(|e| Error::Config(format!("reading {}: {e}", path.display())))?;
            let loaded = if text.trim_start().starts_with('{') {
                let v: Value = serde_json::from_str(&text)?;
                parse_jwks(&v)
            } else {
                let kid = path.file_stem().map(|s| s.to_string_lossy().into_owned());
                pem_key(&text, kid).map(|k| vec![k])
            };
            keys.extend(loaded.map_err(|e| Error::Config(format!("{}: {e}", path.display())))?);
        }
        Ok(Self { keys })
    }

    /// Trusted keys parsed from an in-memory JWKS document.
    pub fn from_jwks(jwks: &Value) -> Result<Self> {
        parse_jwks(jwks).map(|keys| Self { keys }).map_err(Error::Config)
    }

    /// Add a PEM public key with an explicit kid.
    pub fn add_pem(&mut self, pem: &str, kid: Option<String>) -> Result<()> {
        self.keys.push(pem_key(pem, kid).map_err(Error::Config)?);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Outcome of verifying an Agent Card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardVerification {
    /// Hex SHA-256 of the signing payload (stable card digest for pinning).
    pub digest: String,
    /// `None` when the card has no signatures.
    pub signature_valid: Option<bool>,
    /// Key id of the trusted key that verified the card.
    pub signer: Option<String>,
    /// Why verification failed, when it did.
    pub error: Option<String>,
}

fn check_signature(
    sig: &CardSignature,
    payload_b64: &str,
    keys: &TrustedKeys,
) -> std::result::Result<Option<String>, String> {
    let header_bytes = URL_SAFE_NO_PAD
        .decode(sig.protected.trim_end_matches('='))
        .map_err(|e| format!("protected header is not base64url: {e}"))?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("protected header is not JSON: {e}"))?;
    let alg_name = header.get("alg").and_then(Value::as_str).ok_or("protected header has no alg")?;
    let alg = Algorithm::from_str(alg_name).map_err(|_| format!("unsupported alg {alg_name:?}"))?;
    if alg.family() == AlgorithmFamily::Hmac {
        return Err(format!("symmetric alg {alg_name} is not allowed for Agent Cards"));
    }
    if header.get("b64").and_then(Value::as_bool) == Some(false) {
        return Err("unencoded payload (b64: false) is not supported".into());
    }
    let kid = header.get("kid").or_else(|| sig.header.as_ref().and_then(|h| h.get("kid"))).and_then(Value::as_str);
    let input = format!("{}.{payload_b64}", sig.protected);
    let candidates: Vec<&VerifyKey> = keys.keys.iter().filter(|k| k.matches(kid, alg)).collect();
    if candidates.is_empty() {
        return Err(match kid {
            Some(k) => format!("no trusted key with kid {k:?} for {alg_name}"),
            None => format!("no trusted key for {alg_name}"),
        });
    }
    for k in candidates {
        if jsonwebtoken::crypto::verify(&sig.signature, input.as_bytes(), &k.key, alg).unwrap_or(false) {
            return Ok(k.kid.clone().or_else(|| kid.map(str::to_string)));
        }
    }
    Err("signature does not verify".into())
}

/// Verify an Agent Card's signatures against trusted keys. Valid when any
/// signature verifies with a trusted key whose kid matches the signature's
/// kid (any key with a compatible algorithm when the signature has none).
pub fn verify_card(card: &Value, keys: &TrustedKeys) -> CardVerification {
    let payload = card_signing_payload(card);
    let digest = sha256_hex(payload.as_bytes());
    let has_field = card.get("signatures").is_some_and(|s| s.as_array().is_some_and(|a| !a.is_empty()));
    let sigs = parse_card(card).signatures;
    if !has_field {
        return CardVerification { digest, signature_valid: None, signer: None, error: None };
    }
    if sigs.is_empty() {
        return CardVerification {
            digest,
            signature_valid: Some(false),
            signer: None,
            error: Some("malformed signatures".into()),
        };
    }
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let mut errors = Vec::new();
    for sig in &sigs {
        match check_signature(sig, &payload_b64, keys) {
            Ok(signer) => return CardVerification { digest, signature_valid: Some(true), signer, error: None },
            Err(e) => errors.push(e),
        }
    }
    CardVerification { digest, signature_valid: Some(false), signer: None, error: Some(errors.join("; ")) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::test_keys::*;
    use jsonwebtoken::EncodingKey;
    use serde_json::json;

    fn card() -> Value {
        json!({
            "name": "Travel Agent",
            "description": "Books trips",
            "version": "1.0.0",
            "supportedInterfaces": [{"url": "https://travel.example/a2a", "protocolBinding": "JSONRPC"}],
            "skills": [{"id": "book_flight", "name": "Book flight"}]
        })
    }

    fn sign(card: &Value, key: &EncodingKey, alg: Algorithm, header: Value) -> Value {
        let protected = URL_SAFE_NO_PAD.encode(header.to_string());
        let payload = URL_SAFE_NO_PAD.encode(card_signing_payload(card));
        let signature = jsonwebtoken::crypto::sign(format!("{protected}.{payload}").as_bytes(), key, alg).unwrap();
        let mut signed = card.clone();
        signed["signatures"] = json!([{"protected": protected, "signature": signature}]);
        signed
    }

    fn ed_keys() -> TrustedKeys {
        TrustedKeys::from_jwks(&json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": ED_X, "kid": "travel-2026"}]}))
            .unwrap()
    }

    #[test]
    fn ed25519_signature_verifies() {
        let key = EncodingKey::from_ed_pem(ED_PRIVATE.as_bytes()).unwrap();
        let signed =
            sign(&card(), &key, Algorithm::EdDSA, json!({"alg": "EdDSA", "kid": "travel-2026", "typ": "JOSE"}));
        let v = verify_card(&signed, &ed_keys());
        assert_eq!(v.signature_valid, Some(true), "{:?}", v.error);
        assert_eq!(v.signer.as_deref(), Some("travel-2026"));
        assert_eq!(v.digest, verify_card(&card(), &ed_keys()).digest);
    }

    #[test]
    fn tampered_card_is_invalid() {
        let key = EncodingKey::from_ed_pem(ED_PRIVATE.as_bytes()).unwrap();
        let mut signed = sign(&card(), &key, Algorithm::EdDSA, json!({"alg": "EdDSA", "kid": "travel-2026"}));
        signed["supportedInterfaces"][0]["url"] = json!("https://evil.example/a2a");
        let v = verify_card(&signed, &ed_keys());
        assert_eq!(v.signature_valid, Some(false));
        assert!(v.error.unwrap().contains("does not verify"));
    }

    #[test]
    fn unknown_kid_and_wrong_key_are_invalid() {
        let key = EncodingKey::from_ed_pem(ED_PRIVATE.as_bytes()).unwrap();
        let signed = sign(&card(), &key, Algorithm::EdDSA, json!({"alg": "EdDSA", "kid": "someone-else"}));
        let v = verify_card(&signed, &ed_keys());
        assert_eq!(v.signature_valid, Some(false));
        assert!(v.error.unwrap().contains("someone-else"));

        let other = EncodingKey::from_ed_pem(ED2_PRIVATE.as_bytes()).unwrap();
        let forged = sign(&card(), &other, Algorithm::EdDSA, json!({"alg": "EdDSA", "kid": "travel-2026"}));
        assert_eq!(verify_card(&forged, &ed_keys()).signature_valid, Some(false));
    }

    #[test]
    fn unsigned_card_has_no_verdict() {
        let v = verify_card(&card(), &ed_keys());
        assert_eq!(v.signature_valid, None);
        assert_eq!(v.digest.len(), 64);
        let mut empty = card();
        empty["signatures"] = json!([]);
        assert_eq!(verify_card(&empty, &ed_keys()).signature_valid, None);
        let mut junk = card();
        junk["signatures"] = json!([{"x": 1}]);
        assert_eq!(verify_card(&junk, &ed_keys()).signature_valid, Some(false));
    }

    #[test]
    fn es256_with_pem_file_and_no_kid() {
        let dir = std::env::temp_dir().join(format!("nandi-card-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pem = dir.join("partner.pem");
        std::fs::write(&pem, EC_PUBLIC).unwrap();
        let keys = TrustedKeys::load(&[pem]).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(keys.len(), 1);

        let key = EncodingKey::from_ec_pem(EC_PRIVATE.as_bytes()).unwrap();
        let signed = sign(&card(), &key, Algorithm::ES256, json!({"alg": "ES256"}));
        let v = verify_card(&signed, &keys);
        assert_eq!(v.signature_valid, Some(true), "{:?}", v.error);
        assert_eq!(v.signer.as_deref(), Some("partner"));
        let by_kid = sign(&card(), &key, Algorithm::ES256, json!({"alg": "ES256", "kid": "partner"}));
        assert_eq!(verify_card(&by_kid, &keys).signature_valid, Some(true));
    }

    #[test]
    fn symmetric_algs_rejected() {
        let key = EncodingKey::from_secret(b"shared");
        let signed = sign(&card(), &key, Algorithm::HS256, json!({"alg": "HS256"}));
        let keys = TrustedKeys::from_jwks(&json!({"keys": [{"kty": "oct", "k": "c2hhcmVk"}]})).unwrap();
        let v = verify_card(&signed, &keys);
        assert_eq!(v.signature_valid, Some(false));
        assert!(v.error.unwrap().contains("symmetric"));
    }
}
