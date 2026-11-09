//! Public verification keys from JWKS documents and PEM files, shared by
//! JWT authentication and Agent Card verification.

use std::str::FromStr;

use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;

/// One verification key and the JWS algorithms it may be used with.
#[derive(Clone)]
pub(crate) struct VerifyKey {
    pub kid: Option<String>,
    pub key: DecodingKey,
    pub algs: Vec<Algorithm>,
}

impl std::fmt::Debug for VerifyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyKey").field("kid", &self.kid).field("algs", &self.algs).finish_non_exhaustive()
    }
}

impl VerifyKey {
    /// True when this key may verify a signature with `kid` and `alg`. A
    /// signature that names a kid only matches keys with that kid.
    pub fn matches(&self, kid: Option<&str>, alg: Algorithm) -> bool {
        let kid_ok = match kid {
            Some(k) => self.kid.as_deref() == Some(k),
            None => true,
        };
        kid_ok && self.algs.contains(&alg)
    }
}

const RSA_ALGS: [Algorithm; 6] =
    [Algorithm::RS256, Algorithm::RS384, Algorithm::RS512, Algorithm::PS256, Algorithm::PS384, Algorithm::PS512];

fn jwk_key(v: &Value) -> Result<Option<VerifyKey>, String> {
    if v.get("use").and_then(Value::as_str) == Some("enc") {
        return Ok(None);
    }
    let kid = v.get("kid").and_then(Value::as_str).map(str::to_string);
    let kty = v.get("kty").and_then(Value::as_str).unwrap_or_default();
    let crv = v.get("crv").and_then(Value::as_str).unwrap_or_default();
    let family: Vec<Algorithm> = match (kty, crv) {
        ("RSA", _) => RSA_ALGS.to_vec(),
        ("EC", "P-256") => vec![Algorithm::ES256],
        ("EC", "P-384") => vec![Algorithm::ES384],
        ("OKP", "Ed25519") => vec![Algorithm::EdDSA],
        ("oct", _) => vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512],
        _ => return Err(format!("unsupported key type {kty:?} {crv:?}")),
    };
    let algs = match v.get("alg").and_then(Value::as_str) {
        Some(a) => {
            let alg = Algorithm::from_str(a).map_err(|e| format!("key alg {a:?}: {e}"))?;
            if !family.contains(&alg) {
                return Err(format!("key alg {a} does not fit key type {kty}"));
            }
            vec![alg]
        }
        None => family,
    };
    let jwk: Jwk = serde_json::from_value(v.clone()).map_err(|e| format!("invalid JWK: {e}"))?;
    let key = DecodingKey::from_jwk(&jwk).map_err(|e| format!("invalid JWK: {e}"))?;
    Ok(Some(VerifyKey { kid, key, algs }))
}

/// Keys of a JWKS document (`{"keys": [...]}`) or a single JWK. Encryption
/// keys are skipped; any malformed signing key is an error.
pub(crate) fn parse_jwks(v: &Value) -> Result<Vec<VerifyKey>, String> {
    let keys: Vec<&Value> = match v.get("keys").and_then(Value::as_array) {
        Some(keys) => keys.iter().collect(),
        None if v.get("kty").is_some() => vec![v],
        None => return Err("not a JWKS document".into()),
    };
    let mut out = Vec::new();
    for k in keys {
        if let Some(key) = jwk_key(k)? {
            out.push(key);
        }
    }
    Ok(out)
}

/// A PEM public key (SubjectPublicKeyInfo or PKCS#1 RSA).
pub(crate) fn pem_key(pem: &str, kid: Option<String>) -> Result<VerifyKey, String> {
    let bytes = pem.as_bytes();
    if let Ok(key) = DecodingKey::from_ed_pem(bytes) {
        return Ok(VerifyKey { kid, key, algs: vec![Algorithm::EdDSA] });
    }
    if let Ok(key) = DecodingKey::from_ec_pem(bytes) {
        return Ok(VerifyKey { kid, key, algs: vec![Algorithm::ES256, Algorithm::ES384] });
    }
    if let Ok(key) = DecodingKey::from_rsa_pem(bytes) {
        return Ok(VerifyKey { kid, key, algs: RSA_ALGS.to_vec() });
    }
    Err("unsupported or malformed PEM public key".into())
}

#[cfg(test)]
pub(crate) mod test_keys {
    //! Fixed test keys (generated with openssl for these tests only).

    pub const ED_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAdEduVIWl7YXt34vt5dOSjwR4ieAR8w2yByWiQuNO70\n-----END PRIVATE KEY-----\n";
    pub const ED_PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAxbpT1nzsD669o5wdWSOCHSsE9ktomd0NONX5cczaTHE=\n-----END PUBLIC KEY-----\n";
    pub const ED_X: &str = "xbpT1nzsD669o5wdWSOCHSsE9ktomd0NONX5cczaTHE";
    pub const ED2_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIF1xPiteLFOB3DOX6tUcqbm29xzMHSyKX1Yd1zRMpBf6\n-----END PRIVATE KEY-----\n";
    pub const EC_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglLesA7gqvipWcCzH\n6MHeWA7faAn5JFEBdRVF8obSEa+hRANCAASmMOqspo/To5P7JJvWqTXxvAbz3t/v\nCTHIBuAZbJY15qLKRfU+aYXVgPCqoT4F2i4z/vF5BUVw1Hff7d8Mnfqh\n-----END PRIVATE KEY-----\n";
    pub const EC_PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpjDqrKaP06OT+ySb1qk18bwG897f\n7wkxyAbgGWyWNeaiykX1PmmF1YDwqqE+BdouM/7xeQVFcNR33+3fDJ36oQ==\n-----END PUBLIC KEY-----\n";
    pub const EC_X: &str = "pjDqrKaP06OT-ySb1qk18bwG897f7wkxyAbgGWyWNeY";
    pub const EC_Y: &str = "ospF9T5phdWA8KqhPgXaLjP-8XkFRXDUd9_t3wyd-qE";
}

#[cfg(test)]
mod tests {
    use super::test_keys::*;
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_jwks_families() {
        let jwks = json!({"keys": [
            {"kty": "OKP", "crv": "Ed25519", "x": ED_X, "kid": "ed", "use": "sig"},
            {"kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "kid": "ec", "alg": "ES256"},
            {"kty": "RSA", "n": "x", "e": "AQAB", "use": "enc"}
        ]});
        let keys = parse_jwks(&jwks).unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys[0].matches(Some("ed"), Algorithm::EdDSA));
        assert!(!keys[0].matches(Some("ec"), Algorithm::EdDSA));
        assert!(keys[1].matches(None, Algorithm::ES256));
        assert!(!keys[1].matches(None, Algorithm::HS256));
        assert!(
            parse_jwks(&json!({"keys": [{"kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "alg": "RS256"}]}))
                .is_err()
        );
        assert!(parse_jwks(&json!({"nope": 1})).is_err());
    }

    #[test]
    fn parses_pem_keys() {
        assert_eq!(pem_key(ED_PUBLIC, None).unwrap().algs, vec![Algorithm::EdDSA]);
        assert!(pem_key(EC_PUBLIC, None).unwrap().algs.contains(&Algorithm::ES256));
        assert!(pem_key("garbage", None).is_err());
    }
}
