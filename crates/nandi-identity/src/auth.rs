//! Request authentication.
//!
//! Credentials are tried in this order and the first one present names the
//! agent: mTLS identity, Biscuit token header, `Authorization: Bearer <jwt>`
//! (only when JWT is configured and the value is JWT-shaped, so provider API
//! keys passing through to an upstream are left alone), API key header.
//! Every credential that is present is validated: a present but invalid
//! credential is always an error, never a silent fallback to anonymous.

use std::path::Path;

use biscuit_auth::PublicKey;
use http::HeaderMap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use nandi_core::config::{IdentityConfig, JwtConfig, resolve_secret};
use nandi_core::util::sha256_hex;
use nandi_core::{Error, Result};
use serde_json::Value;

use crate::biscuit::{self, BiscuitGrant};
use crate::error::AuthError;
use crate::jwk::{VerifyKey, parse_jwks};
use crate::keys::ct_eq;

/// How the principal was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    Anonymous,
    ApiKey,
    Jwt,
    Mtls,
    Biscuit,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::Anonymous => "anonymous",
            AuthMethod::ApiKey => "api_key",
            AuthMethod::Jwt => "jwt",
            AuthMethod::Mtls => "mtls",
            AuthMethod::Biscuit => "biscuit",
        }
    }
}

/// An authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Agent id (`anonymous` when unauthenticated).
    pub agent: String,
    pub groups: Vec<String>,
    pub method: AuthMethod,
    /// Human or agent this caller acts for (JWT delegation claim).
    pub delegator: Option<String>,
    /// Biscuit capability presented with the request, if any.
    pub grant: Option<BiscuitGrant>,
}

impl Principal {
    /// The anonymous principal.
    pub fn anonymous() -> Self {
        Self {
            agent: "anonymous".into(),
            groups: Vec::new(),
            method: AuthMethod::Anonymous,
            delegator: None,
            grant: None,
        }
    }

    fn new(agent: String, method: AuthMethod) -> Self {
        Self { agent, groups: Vec::new(), method, delegator: None, grant: None }
    }
}

#[derive(Debug)]
struct ApiKeyEntry {
    agent: String,
    sha256: String,
    groups: Vec<String>,
}

#[derive(Debug)]
struct JwtVerifier {
    cfg: JwtConfig,
    hs256: Option<Vec<u8>>,
    keys: Vec<VerifyKey>,
}

/// Turns request headers (and a TLS-verified client identity) into a
/// [`Principal`].
#[derive(Debug)]
pub struct Authenticator {
    allow_anonymous: bool,
    api_key_header: String,
    api_keys: Vec<ApiKeyEntry>,
    jwt: Option<JwtVerifier>,
    biscuit: Option<(String, PublicKey)>,
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
    method: &'static str,
) -> std::result::Result<Option<&'a str>, AuthError> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else { return Ok(None) };
    if values.next().is_some() {
        return Err(AuthError::invalid(method, format!("multiple {name} headers")));
    }
    let v = first.to_str().map_err(|_| AuthError::invalid(method, format!("{name} header is not ASCII")))?.trim();
    Ok(if v.is_empty() { None } else { Some(v) })
}

/// Value at a dotted claim path (`act.sub`). An exact top-level key wins
/// over the dotted interpretation (claims such as `https://x/roles`).
fn claim<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(v) = claims.get(path) {
        return Some(v);
    }
    path.split('.').try_fold(claims, |cur, k| cur.get(k))
}

fn looks_like_jwt(token: &str) -> bool {
    token.starts_with("eyJ")
        && token.split('.').count() == 3
        && token.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl Authenticator {
    /// Build from config. Relative key file paths resolve against `base_dir`.
    pub fn new(cfg: &IdentityConfig, base_dir: &Path) -> Result<Self> {
        let mut api_keys = Vec::new();
        for k in &cfg.api_keys {
            let h = k.sha256.trim().to_ascii_lowercase();
            if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Config(format!("api key for agent {}: sha256 must be 64 hex characters", k.agent)));
            }
            api_keys.push(ApiKeyEntry { agent: k.agent.clone(), sha256: h, groups: k.groups.clone() });
        }
        let jwt = match &cfg.jwt {
            None => None,
            Some(j) => {
                let hs256 = j.hs256_secret.as_deref().map(resolve_secret).transpose()?.map(String::into_bytes);
                let mut keys = Vec::new();
                if let Some(file) = &j.jwks_file {
                    let path = if file.is_absolute() { file.clone() } else { base_dir.join(file) };
                    let text = std::fs::read_to_string(&path)
                        .map_err(|e| Error::Config(format!("reading JWKS {}: {e}", path.display())))?;
                    let v: Value = serde_json::from_str(&text)?;
                    keys = parse_jwks(&v).map_err(|e| Error::Config(format!("JWKS {}: {e}", path.display())))?;
                    // Symmetric keys come only from hs256_secret.
                    keys.retain(|k| {
                        !k.algs.iter().any(|a| matches!(a, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512))
                    });
                }
                if hs256.is_none() && keys.is_empty() {
                    return Err(Error::Config("identity.jwt needs jwks_file or hs256_secret".into()));
                }
                Some(JwtVerifier { cfg: j.clone(), hs256, keys })
            }
        };
        let biscuit = match &cfg.biscuit {
            None => None,
            Some(b) => {
                let raw = resolve_secret(&b.root_public_key)?;
                let pk = biscuit::parse_public_key(&raw)
                    .map_err(|e| Error::Config(format!("identity.biscuit.root_public_key: {e}")))?;
                Some((b.header.to_ascii_lowercase(), pk))
            }
        };
        Ok(Self {
            allow_anonymous: cfg.allow_anonymous,
            api_key_header: cfg.api_key_header.to_ascii_lowercase(),
            api_keys,
            jwt,
            biscuit,
        })
    }

    /// Authenticate a request. `mtls_identity` is the client identity the
    /// TLS layer already verified (SPIFFE id or certificate CN).
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        mtls_identity: Option<&str>,
    ) -> std::result::Result<Principal, AuthError> {
        let mut found: Option<Principal> = None;

        if let Some(id) = mtls_identity.map(str::trim).filter(|s| !s.is_empty()) {
            found = Some(Principal::new(id.to_string(), AuthMethod::Mtls));
        }

        let mut grant = None;
        if let Some((header, root)) = &self.biscuit
            && let Some(tok) = single_header(headers, header, "biscuit")?
        {
            let g = biscuit::verify_at(tok, root, std::time::SystemTime::now())?;
            if found.is_none() {
                found = Some(Principal::new(g.agent.clone(), AuthMethod::Biscuit));
            }
            grant = Some(g);
        }

        if let Some(jwt) = &self.jwt
            && let Some(auth) = single_header(headers, "authorization", "jwt")?
        {
            let token =
                auth.split_once(' ').filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer")).map(|(_, t)| t.trim());
            if let Some(token) = token.filter(|t| looks_like_jwt(t)) {
                let p = jwt.verify(token)?;
                if found.is_none() {
                    found = Some(p);
                }
            }
        }

        if let Some(key) = single_header(headers, &self.api_key_header, "api_key")? {
            let p = self.check_api_key(key)?;
            if found.is_none() {
                found = Some(p);
            }
        }

        let mut principal = match found {
            Some(p) => p,
            None if self.allow_anonymous => Principal::anonymous(),
            None => return Err(AuthError::Missing),
        };
        principal.grant = grant;
        Ok(principal)
    }

    /// Check a tool call against the Biscuit the principal presented. A
    /// principal without a grant is not restricted here (policy decides).
    pub fn authorize_tool(
        &self,
        principal: &Principal,
        server: &str,
        tool: &str,
    ) -> std::result::Result<(), AuthError> {
        match (&principal.grant, &self.biscuit) {
            (None, _) => Ok(()),
            (Some(g), Some((_, root))) => {
                biscuit::authorize_at(&g.token, root, server, tool, std::time::SystemTime::now()).map(|_| ())
            }
            (Some(_), None) => Err(AuthError::invalid("biscuit", "biscuit authentication is not configured")),
        }
    }

    fn check_api_key(&self, key: &str) -> std::result::Result<Principal, AuthError> {
        let digest = sha256_hex(key.as_bytes());
        let mut hit: Option<&ApiKeyEntry> = None;
        // Compare against every entry so timing does not reveal which matched.
        for entry in &self.api_keys {
            if ct_eq(entry.sha256.as_bytes(), digest.as_bytes()) && hit.is_none() {
                hit = Some(entry);
            }
        }
        let entry = hit.ok_or_else(|| AuthError::invalid("api_key", "unknown API key"))?;
        let mut p = Principal::new(entry.agent.clone(), AuthMethod::ApiKey);
        p.groups = entry.groups.clone();
        Ok(p)
    }
}

impl JwtVerifier {
    fn verify(&self, token: &str) -> std::result::Result<Principal, AuthError> {
        let bad = |r: String| AuthError::invalid("jwt", r);
        let header = jsonwebtoken::decode_header(token).map_err(|e| bad(e.to_string()))?;
        let alg = header.alg;
        let key: DecodingKey = if alg == Algorithm::HS256 {
            DecodingKey::from_secret(self.hs256.as_deref().ok_or_else(|| bad("HS256 tokens are not accepted".into()))?)
        } else {
            let kid = header.kid.as_deref();
            let matching: Vec<&VerifyKey> = self.keys.iter().filter(|k| k.matches(kid, alg)).collect();
            match (matching.as_slice(), kid) {
                ([one], _) => one.key.clone(),
                ([], Some(k)) => return Err(bad(format!("no key with kid {k:?} for {alg:?}"))),
                ([], None) => return Err(bad(format!("no key for {alg:?}"))),
                (_, _) => return Err(bad("token has no kid and several keys match".into())),
            }
        };
        let mut v = Validation::new(alg);
        v.algorithms = vec![alg];
        v.validate_nbf = true;
        match &self.cfg.issuer {
            Some(iss) => {
                v.set_issuer(&[iss]);
                v.set_required_spec_claims(&["exp", "iss"]);
            }
            None => v.set_required_spec_claims(&["exp"]),
        }
        match &self.cfg.audience {
            Some(aud) => {
                v.set_audience(&[aud]);
                v.required_spec_claims.insert("aud".into());
            }
            None => v.validate_aud = false,
        }
        let data = jsonwebtoken::decode::<Value>(token, &key, &v).map_err(|e| bad(e.to_string()))?;
        let claims = data.claims;
        let agent = claim(&claims, &self.cfg.agent_claim)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| bad(format!("missing {} claim", self.cfg.agent_claim)))?;
        let mut p = Principal::new(agent.to_string(), AuthMethod::Jwt);
        p.groups = match claim(&claims, &self.cfg.groups_claim) {
            Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).map(str::to_string).collect(),
            Some(Value::String(s)) => s.split_whitespace().map(str::to_string).collect(),
            _ => Vec::new(),
        };
        p.delegator = self
            .cfg
            .delegator_claim
            .as_deref()
            .and_then(|c| claim(&claims, c))
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::test_keys::*;
    use crate::keys::hash_key;
    use jsonwebtoken::{EncodingKey, Header, encode, get_current_timestamp};
    use nandi_core::config::{ApiKey, BiscuitConfig};
    use serde_json::json;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    }

    fn jwt_cfg() -> JwtConfig {
        JwtConfig {
            issuer: Some("https://idp.example".into()),
            audience: Some("nandi".into()),
            jwks_file: None,
            hs256_secret: Some("test-secret".into()),
            agent_claim: "sub".into(),
            groups_claim: "groups".into(),
            delegator_claim: Some("act.sub".into()),
        }
    }

    fn cfg() -> IdentityConfig {
        IdentityConfig {
            allow_anonymous: false,
            api_keys: vec![ApiKey {
                agent: "ci-bot".into(),
                sha256: hash_key("nandi_secret"),
                groups: vec!["ci".into()],
            }],
            jwt: Some(jwt_cfg()),
            ..IdentityConfig::default()
        }
    }

    fn hs_token(claims: Value) -> String {
        encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(b"test-secret")).unwrap()
    }

    fn good_claims() -> Value {
        json!({"sub": "planner", "iss": "https://idp.example", "aud": "nandi", "exp": get_current_timestamp() + 600,
               "groups": "ops admins", "act": {"sub": "alice@example.com"}})
    }

    #[test]
    fn api_key_auth() {
        let a = Authenticator::new(&cfg(), Path::new(".")).unwrap();
        let p = a.authenticate(&headers(&[("X-Nandi-Key", "nandi_secret")]), None).unwrap();
        assert_eq!((p.agent.as_str(), p.method), ("ci-bot", AuthMethod::ApiKey));
        assert_eq!(p.groups, vec!["ci"]);
        assert!(matches!(a.authenticate(&headers(&[("x-nandi-key", "wrong")]), None), Err(AuthError::Invalid { .. })));
        assert_eq!(a.authenticate(&HeaderMap::new(), None), Err(AuthError::Missing));
        assert!(a.authenticate(&headers(&[("x-nandi-key", "nandi_secret"), ("x-nandi-key", "x")]), None).is_err());
    }

    #[test]
    fn anonymous_only_without_credentials() {
        let mut c = cfg();
        c.allow_anonymous = true;
        let a = Authenticator::new(&c, Path::new(".")).unwrap();
        assert_eq!(a.authenticate(&HeaderMap::new(), None).unwrap(), Principal::anonymous());
        assert!(a.authenticate(&headers(&[("x-nandi-key", "bad")]), None).is_err());
        let bad_jwt = format!("Bearer {}", hs_token(json!({"sub": "x", "exp": 1})));
        assert!(a.authenticate(&headers(&[("authorization", &bad_jwt)]), None).is_err());
        // A provider API key in Authorization is not a JWT and is ignored.
        let p = a.authenticate(&headers(&[("authorization", "Bearer sk-proj-abc123")]), None).unwrap();
        assert_eq!(p.method, AuthMethod::Anonymous);
    }

    #[test]
    fn jwt_hs256_claims() {
        let a = Authenticator::new(&cfg(), Path::new(".")).unwrap();
        let auth = format!("Bearer {}", hs_token(good_claims()));
        let p = a.authenticate(&headers(&[("authorization", &auth)]), None).unwrap();
        assert_eq!(p.agent, "planner");
        assert_eq!(p.method, AuthMethod::Jwt);
        assert_eq!(p.groups, vec!["ops", "admins"]);
        assert_eq!(p.delegator.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn jwt_validation_failures() {
        let a = Authenticator::new(&cfg(), Path::new(".")).unwrap();
        let check = |claims: Value| {
            let auth = format!("Bearer {}", hs_token(claims));
            a.authenticate(&headers(&[("authorization", &auth)]), None)
        };
        let mut c = good_claims();
        c["iss"] = json!("https://evil.example");
        assert!(check(c).is_err());
        let mut c = good_claims();
        c["aud"] = json!("other");
        assert!(check(c).is_err());
        let mut c = good_claims();
        c["exp"] = json!(get_current_timestamp() - 3600);
        assert!(check(c).is_err());
        let mut c = good_claims();
        c["nbf"] = json!(get_current_timestamp() + 3600);
        assert!(check(c).is_err());
        let mut c = good_claims();
        c.as_object_mut().unwrap().remove("sub");
        assert!(check(c).is_err());
        let forged =
            encode(&Header::new(Algorithm::HS256), &good_claims(), &EncodingKey::from_secret(b"guess")).unwrap();
        assert!(a.authenticate(&headers(&[("authorization", &format!("Bearer {forged}"))]), None).is_err());
    }

    #[test]
    fn jwt_with_jwks_file() {
        let dir = std::env::temp_dir().join(format!("nandi-jwks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let jwks = json!({"keys": [
            {"kty": "OKP", "crv": "Ed25519", "x": ED_X, "kid": "ed1"},
            {"kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "kid": "ec1"}
        ]});
        std::fs::write(dir.join("jwks.json"), jwks.to_string()).unwrap();
        let mut c = cfg();
        let mut j = jwt_cfg();
        j.hs256_secret = None;
        j.jwks_file = Some("jwks.json".into());
        j.groups_claim = "roles".into();
        c.jwt = Some(j);
        let a = Authenticator::new(&c, &dir).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        let mut claims = good_claims();
        claims["roles"] = json!(["reader"]);
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some("ed1".into());
        let tok = encode(&h, &claims, &EncodingKey::from_ed_pem(ED_PRIVATE.as_bytes()).unwrap()).unwrap();
        let p = a.authenticate(&headers(&[("authorization", &format!("Bearer {tok}"))]), None).unwrap();
        assert_eq!(p.groups, vec!["reader"]);

        let mut h = Header::new(Algorithm::ES256);
        h.kid = Some("ec1".into());
        let tok = encode(&h, &claims, &EncodingKey::from_ec_pem(EC_PRIVATE.as_bytes()).unwrap()).unwrap();
        assert!(a.authenticate(&headers(&[("authorization", &format!("Bearer {tok}"))]), None).is_ok());

        // Wrong kid, unsigned-by-trusted-key and HS256 confusion all fail.
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some("ec1".into());
        let tok = encode(&h, &claims, &EncodingKey::from_ed_pem(ED_PRIVATE.as_bytes()).unwrap()).unwrap();
        assert!(a.authenticate(&headers(&[("authorization", &format!("Bearer {tok}"))]), None).is_err());
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some("ed1".into());
        let tok = encode(&h, &claims, &EncodingKey::from_ed_pem(ED2_PRIVATE.as_bytes()).unwrap()).unwrap();
        assert!(a.authenticate(&headers(&[("authorization", &format!("Bearer {tok}"))]), None).is_err());
        let tok = encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(ED_X.as_bytes())).unwrap();
        assert!(a.authenticate(&headers(&[("authorization", &format!("Bearer {tok}"))]), None).is_err());
    }

    #[test]
    fn mtls_and_biscuit() {
        let (sk, pk) = biscuit::generate_root_keypair();
        let mut c = cfg();
        c.biscuit = Some(BiscuitConfig { root_public_key: pk.clone(), header: "x-nandi-biscuit".into() });
        let a = Authenticator::new(&c, Path::new(".")).unwrap();

        let p = a.authenticate(&HeaderMap::new(), Some("spiffe://corp/agents/planner")).unwrap();
        assert_eq!((p.agent.as_str(), p.method), ("spiffe://corp/agents/planner", AuthMethod::Mtls));

        let tok = biscuit::mint(&sk, "researcher", &["search/*".to_string()], 600).unwrap();
        let p = a.authenticate(&headers(&[("x-nandi-biscuit", &tok)]), None).unwrap();
        assert_eq!((p.agent.as_str(), p.method), ("researcher", AuthMethod::Biscuit));
        assert_eq!(p.grant.as_ref().unwrap().chain_len, 1);
        assert!(a.authorize_tool(&p, "search", "web").is_ok());
        assert!(a.authorize_tool(&p, "github", "delete_repo").is_err());

        // mTLS names the agent; the presented Biscuit still restricts tools.
        let p = a.authenticate(&headers(&[("x-nandi-biscuit", &tok)]), Some("spiffe://corp/agents/planner")).unwrap();
        assert_eq!(p.method, AuthMethod::Mtls);
        assert!(a.authorize_tool(&p, "github", "delete_repo").is_err());

        // A bad Biscuit is an error even with a valid API key.
        let (other_sk, _) = biscuit::generate_root_keypair();
        let forged = biscuit::mint(&other_sk, "researcher", &["*".to_string()], 600).unwrap();
        assert!(
            a.authenticate(&headers(&[("x-nandi-biscuit", &forged), ("x-nandi-key", "nandi_secret")]), None).is_err()
        );
    }

    #[test]
    fn config_errors() {
        let mut c = cfg();
        c.api_keys[0].sha256 = "abc".into();
        assert!(Authenticator::new(&c, Path::new(".")).is_err());
        let mut c = cfg();
        let mut j = jwt_cfg();
        j.hs256_secret = None;
        c.jwt = Some(j);
        assert!(Authenticator::new(&c, Path::new(".")).is_err());
        let mut c = cfg();
        c.biscuit = Some(BiscuitConfig { root_public_key: "zz".into(), header: "x".into() });
        assert!(Authenticator::new(&c, Path::new(".")).is_err());
    }

    #[test]
    fn dotted_claims() {
        let c = json!({"act": {"sub": "bob"}, "https://x/roles": ["a"]});
        assert_eq!(claim(&c, "act.sub"), Some(&json!("bob")));
        assert_eq!(claim(&c, "https://x/roles"), Some(&json!(["a"])));
        assert_eq!(claim(&c, "act.missing"), None);
    }
}
