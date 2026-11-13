//! Biscuit capability tokens for agent delegation.
//!
//! A root key mints a token for an agent with a set of `server/tool`
//! rights. Any holder can attenuate it offline (append a block that narrows
//! the tools or shortens the lifetime) before handing it to a sub-agent; no
//! block can widen access, because the authorizer only trusts rights from
//! the authority block while every block's checks must pass.
//!
//! Tool patterns: `*` (everything), `server/*` or `server/prefix*` (prefix
//! match) and exact `server/tool`. Datalog has no globs, so prefix patterns
//! are stored as `right_prefix("server/")` facts and checked with
//! `.starts_with()`. Other wildcard positions are rejected.
//!
//! Authority block written by [`mint`]:
//!
//! ```text
//! agent("planner");
//! right("github/create_issue");
//! right_prefix("search/");
//! check if time($t), $t <= 2026-01-01T00:00:00Z;
//! ```
//!
//! Attenuation block written by [`attenuate`]:
//!
//! ```text
//! check if operation("authenticate") or tool($t), $t == "github/create_issue" || $t.starts_with("search/");
//! check if time($t), $t <= 2025-12-01T00:00:00Z;
//! ```
//!
//! The `operation("authenticate")` alternative lets [`verify`] check
//! signatures and expiry when a request arrives, before any tool is known;
//! that fact is only ever added by nandi's own authorizer.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use biscuit_auth::builder::{Algorithm, Term};
use biscuit_auth::{
    AuthorizerBuilder, AuthorizerLimits, Biscuit, BlockBuilder, KeyPair, PrivateKey, PublicKey, UnverifiedBiscuit,
};

use crate::error::AuthError;

const METHOD: &str = "biscuit";

/// What a verified Biscuit grants.
#[derive(Clone, PartialEq, Eq)]
pub struct BiscuitGrant {
    /// Agent named in the authority block.
    pub agent: String,
    /// Number of blocks (1 = not attenuated).
    pub chain_len: usize,
    /// The token itself, so later tool calls can be authorized against it.
    pub token: String,
    /// Hex revocation identifiers of every block, authority first. Revoking
    /// a block's identifier invalidates that token and everything
    /// attenuated from it.
    pub revocation_ids: Vec<String>,
}

impl std::fmt::Debug for BiscuitGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BiscuitGrant")
            .field("agent", &self.agent)
            .field("chain_len", &self.chain_len)
            .field("revocation_ids", &self.revocation_ids)
            .finish_non_exhaustive()
    }
}

fn err(e: impl std::fmt::Display) -> AuthError {
    AuthError::invalid(METHOD, e.to_string())
}

/// New Ed25519 root key pair as `(private_hex, public_hex)`.
pub fn generate_root_keypair() -> (String, String) {
    let kp = KeyPair::new();
    (kp.private().to_bytes_hex(), kp.public().to_bytes_hex())
}

/// Parse a root public key: bare hex (Ed25519) or biscuit's prefixed form
/// (`ed25519/<hex>`, `secp256r1/<hex>`).
pub fn parse_public_key(s: &str) -> Result<PublicKey, AuthError> {
    let s = s.trim();
    if s.contains('/') {
        s.parse::<PublicKey>().map_err(err)
    } else {
        PublicKey::from_bytes_hex(s, Algorithm::Ed25519).map_err(err)
    }
}

fn parse_private_key(s: &str) -> Result<PrivateKey, AuthError> {
    let s = s.trim();
    if s.contains('/') {
        s.parse::<PrivateKey>().map_err(err)
    } else {
        PrivateKey::from_bytes_hex(s, Algorithm::Ed25519).map_err(err)
    }
}

/// A tool pattern translated for Datalog.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pattern {
    Any,
    Exact(String),
    Prefix(String),
}

fn pattern(p: &str) -> Result<Pattern, AuthError> {
    let p = p.trim();
    if p == "*" {
        return Ok(Pattern::Any);
    }
    if !p.contains('/') {
        return Err(err(format!("tool pattern {p:?} must be \"*\" or \"server/tool\"")));
    }
    let (body, prefix) = match p.strip_suffix('*') {
        Some(b) => (b, true),
        None => (p, false),
    };
    if body.contains(['*', '?']) || body.is_empty() {
        return Err(err(format!("tool pattern {p:?}: only a trailing * is supported")));
    }
    Ok(if prefix { Pattern::Prefix(body.into()) } else { Pattern::Exact(body.into()) })
}

fn date(t: SystemTime) -> Term {
    Term::Date(t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
}

fn expiry_check(t: SystemTime) -> Result<(String, HashMap<String, Term>), AuthError> {
    let mut params = HashMap::new();
    params.insert("expiry".to_string(), date(t));
    Ok(("check if time($t), $t <= {expiry};".to_string(), params))
}

/// Mint a token for `agent` allowed to call `tools`, valid for `ttl_secs`.
pub fn mint(root_private_hex: &str, agent: &str, tools: &[String], ttl_secs: u64) -> Result<String, AuthError> {
    mint_at(root_private_hex, agent, tools, SystemTime::now() + Duration::from_secs(ttl_secs))
}

fn mint_at(root_private_hex: &str, agent: &str, tools: &[String], expires: SystemTime) -> Result<String, AuthError> {
    if agent.is_empty() {
        return Err(err("agent must not be empty"));
    }
    let root = KeyPair::from(&parse_private_key(root_private_hex)?);
    let mut b = Biscuit::builder();
    let mut params = HashMap::new();
    params.insert("agent".to_string(), Term::Str(agent.into()));
    b = b.code_with_params("agent({agent});", params, HashMap::new()).map_err(err)?;
    for t in tools {
        let mut params = HashMap::new();
        let code = match pattern(t)? {
            Pattern::Any => {
                params.insert("p".to_string(), Term::Str(String::new()));
                "right_prefix({p});"
            }
            Pattern::Exact(e) => {
                params.insert("p".to_string(), Term::Str(e));
                "right({p});"
            }
            Pattern::Prefix(pre) => {
                params.insert("p".to_string(), Term::Str(pre));
                "right_prefix({p});"
            }
        };
        b = b.code_with_params(code, params, HashMap::new()).map_err(err)?;
    }
    let (code, params) = expiry_check(expires)?;
    b = b.code_with_params(code, params, HashMap::new()).map_err(err)?;
    b.build(&root).map_err(err)?.to_base64().map_err(err)
}

/// Append a block that restricts the token to `tools` (and optionally a
/// shorter lifetime). The token's signature chain is verified first.
pub fn attenuate(
    token_b64: &str,
    root_public_hex: &str,
    tools: &[String],
    ttl_secs: Option<u64>,
) -> Result<String, AuthError> {
    attenuate_at(token_b64, root_public_hex, tools, ttl_secs.map(|s| SystemTime::now() + Duration::from_secs(s)))
}

fn attenuate_at(
    token_b64: &str,
    root_public_hex: &str,
    tools: &[String],
    expires: Option<SystemTime>,
) -> Result<String, AuthError> {
    let token = Biscuit::from_base64(token_b64.trim(), parse_public_key(root_public_hex)?).map_err(err)?;
    let mut block = BlockBuilder::new();
    let patterns = tools.iter().map(|t| pattern(t)).collect::<Result<Vec<_>, _>>()?;
    if !patterns.contains(&Pattern::Any) {
        // An empty list means "no tools at all".
        let mut exprs = Vec::new();
        let mut params = HashMap::new();
        for (i, p) in patterns.iter().enumerate() {
            let name = format!("p{i}");
            match p {
                Pattern::Exact(e) => {
                    exprs.push(format!("$t == {{{name}}}"));
                    params.insert(name, Term::Str(e.clone()));
                }
                Pattern::Prefix(pre) => {
                    exprs.push(format!("$t.starts_with({{{name}}})"));
                    params.insert(name, Term::Str(pre.clone()));
                }
                Pattern::Any => unreachable!("handled above"),
            }
        }
        let expr = if exprs.is_empty() { "false".to_string() } else { exprs.join(" || ") };
        let code = format!("check if operation(\"authenticate\") or tool($t), {expr};");
        block = block.code_with_params(code, params, HashMap::new()).map_err(err)?;
    }
    if let Some(t) = expires {
        let (code, params) = expiry_check(t)?;
        block = block.code_with_params(code, params, HashMap::new()).map_err(err)?;
    }
    token.append(block).map_err(err)?.to_base64().map_err(err)
}

/// Datalog limits for authorization. biscuit-auth's default time limit is
/// 1 ms, which a loaded host can exceed for perfectly valid tokens and turn
/// into spurious denials. The fact and iteration caps (the real guard
/// against degenerate tokens) keep their defaults; the time cap only
/// protects against a stalled machine.
fn limits() -> AuthorizerLimits {
    AuthorizerLimits { max_time: std::time::Duration::from_millis(50), ..AuthorizerLimits::default() }
}

fn run(token: &Biscuit, code: &str, params: HashMap<String, Term>, now: SystemTime) -> Result<BiscuitGrant, AuthError> {
    let mut time = HashMap::new();
    time.insert("now".to_string(), date(now));
    let mut authorizer = AuthorizerBuilder::new()
        .set_limits(limits())
        .code_with_params("time({now});", time, HashMap::new())
        .and_then(|a| a.code_with_params(code, params, HashMap::new()))
        .and_then(|a| a.build(token))
        .map_err(err)?;
    authorizer.authorize().map_err(|e| AuthError::Forbidden(format!("biscuit authorization failed: {e}")))?;
    let mut agents: Vec<(String,)> = authorizer.query("agent_name($a) <- agent($a)").map_err(err)?;
    agents.sort();
    let agent = agents.into_iter().next().map(|(a,)| a).ok_or_else(|| err("token names no agent"))?;
    Ok(BiscuitGrant {
        agent,
        chain_len: token.block_count(),
        token: token.to_base64().map_err(err)?,
        revocation_ids: token.revocation_identifiers().iter().map(hex::encode).collect(),
    })
}

/// Verify signatures and expiry, without a tool. Used to authenticate a
/// request carrying a token; tool calls are checked with [`authorize`].
pub fn verify(token_b64: &str, root_public_hex: &str) -> Result<BiscuitGrant, AuthError> {
    verify_at(token_b64, &parse_public_key(root_public_hex)?, SystemTime::now())
}

pub(crate) fn verify_at(token_b64: &str, root: &PublicKey, now: SystemTime) -> Result<BiscuitGrant, AuthError> {
    let token = Biscuit::from_base64(token_b64.trim(), *root).map_err(err)?;
    let grant = run(&token, "operation(\"authenticate\"); allow if agent($a);", HashMap::new(), now)?;
    Ok(BiscuitGrant { token: token_b64.trim().to_string(), ..grant })
}

/// Authorize a call of `tool` on `server`: the signature chain must verify
/// with the root key, every block's checks must pass, and an authority
/// right must cover `server/tool`.
pub fn authorize(token_b64: &str, root_public_hex: &str, server: &str, tool: &str) -> Result<BiscuitGrant, AuthError> {
    authorize_at(token_b64, &parse_public_key(root_public_hex)?, server, tool, SystemTime::now())
}

pub(crate) fn authorize_at(
    token_b64: &str,
    root: &PublicKey,
    server: &str,
    tool: &str,
    now: SystemTime,
) -> Result<BiscuitGrant, AuthError> {
    let token = Biscuit::from_base64(token_b64.trim(), *root).map_err(err)?;
    let mut params = HashMap::new();
    params.insert("tool".to_string(), Term::Str(format!("{server}/{tool}")));
    let code = "tool({tool});\n\
                allow if tool($t), right($t);\n\
                allow if tool($t), right_prefix($p), $t.starts_with($p);";
    let grant = run(&token, code, params, now)?;
    Ok(BiscuitGrant { token: token_b64.trim().to_string(), ..grant })
}

/// Hex revocation identifiers of every block, authority first. Signatures
/// are not verified.
pub fn revocation_ids(token_b64: &str) -> Result<Vec<String>, AuthError> {
    let token = UnverifiedBiscuit::from_base64(token_b64.trim()).map_err(err)?;
    Ok(token.revocation_identifiers().iter().map(hex::encode).collect())
}

/// Datalog source of every block, for `nandi token inspect`, each with its
/// revocation identifier. Signatures are not verified.
pub fn inspect(token_b64: &str) -> Result<String, AuthError> {
    let token = UnverifiedBiscuit::from_base64(token_b64.trim()).map_err(err)?;
    let ids: Vec<String> = token.revocation_identifiers().iter().map(hex::encode).collect();
    let mut out = String::new();
    for i in 0..token.block_count() {
        let src = token.print_block_source(i).map_err(err)?;
        let name = if i == 0 { "authority".to_string() } else { format!("block {i}") };
        let title = match ids.get(i) {
            Some(id) => format!("{name}, revocation id {id}"),
            None => name,
        };
        out.push_str(&format!("// {title}\n{}\n", src.trim_end()));
        if i + 1 < token.block_count() {
            out.push('\n');
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools(t: &[&str]) -> Vec<String> {
        t.iter().map(|s| s.to_string()).collect()
    }

    fn pk(hex: &str) -> PublicKey {
        parse_public_key(hex).unwrap()
    }

    #[test]
    fn mint_then_authorize() {
        let (sk, pubk) = generate_root_keypair();
        let tok = mint(&sk, "planner", &tools(&["github/*", "search/web"]), 3600).unwrap();
        let g = authorize(&tok, &pubk, "github", "create_issue").unwrap();
        assert_eq!(g.agent, "planner");
        assert_eq!(g.chain_len, 1);
        assert!(authorize(&tok, &pubk, "search", "web").is_ok());
        assert!(matches!(authorize(&tok, &pubk, "search", "web2"), Err(AuthError::Forbidden(_))));
        assert!(authorize(&tok, &pubk, "gitlab", "create_issue").is_err());
        assert_eq!(verify(&tok, &pubk).unwrap().agent, "planner");
    }

    #[test]
    fn wildcard_right() {
        let (sk, pubk) = generate_root_keypair();
        let tok = mint(&sk, "admin", &tools(&["*"]), 60).unwrap();
        assert!(authorize(&tok, &pubk, "any", "thing").is_ok());
        let none = mint(&sk, "nobody", &[], 60).unwrap();
        assert!(authorize(&none, &pubk, "any", "thing").is_err());
        assert!(verify(&none, &pubk).is_ok());
    }

    #[test]
    fn attenuation_narrows_and_cannot_widen() {
        let (sk, pubk) = generate_root_keypair();
        let tok = mint(&sk, "planner", &tools(&["github/*"]), 3600).unwrap();
        let narrow = attenuate(&tok, &pubk, &tools(&["github/list_*"]), None).unwrap();
        let g = authorize(&narrow, &pubk, "github", "list_issues").unwrap();
        assert_eq!(g.chain_len, 2);
        assert!(authorize(&narrow, &pubk, "github", "delete_repo").is_err());
        assert!(verify(&narrow, &pubk).is_ok());

        // A block asking for more than the authority granted gains nothing.
        let wider = attenuate(&tok, &pubk, &tools(&["*"]), None).unwrap();
        assert!(authorize(&wider, &pubk, "slack", "post").is_err());
        let wider2 = attenuate(&narrow, &pubk, &tools(&["github/*", "slack/post"]), None).unwrap();
        assert!(authorize(&wider2, &pubk, "github", "delete_repo").is_err());
        assert!(authorize(&wider2, &pubk, "slack", "post").is_err());
        assert!(authorize(&wider2, &pubk, "github", "list_prs").is_ok());

        let nothing = attenuate(&tok, &pubk, &[], None).unwrap();
        assert!(authorize(&nothing, &pubk, "github", "list_issues").is_err());
    }

    #[test]
    fn expiry_is_enforced() {
        let (sk, pubk) = generate_root_keypair();
        let tok = mint(&sk, "a", &tools(&["*"]), 10).unwrap();
        let later = SystemTime::now() + Duration::from_secs(60);
        assert!(authorize_at(&tok, &pk(&pubk), "s", "t", later).is_err());
        assert!(verify_at(&tok, &pk(&pubk), later).is_err());
        let short =
            attenuate_at(&tok, &pubk, &tools(&["*"]), Some(SystemTime::now() - Duration::from_secs(1))).unwrap();
        assert!(authorize(&short, &pubk, "s", "t").is_err());
        assert!(verify(&short, &pubk).is_err());
        let past = mint_at(&sk, "a", &tools(&["*"]), SystemTime::now() - Duration::from_secs(5)).unwrap();
        assert!(authorize(&past, &pubk, "s", "t").is_err());
    }

    #[test]
    fn other_root_key_rejected() {
        let (sk, _) = generate_root_keypair();
        let (_, other_pub) = generate_root_keypair();
        let tok = mint(&sk, "a", &tools(&["*"]), 60).unwrap();
        assert!(matches!(authorize(&tok, &other_pub, "s", "t"), Err(AuthError::Invalid { .. })));
        assert!(verify(&tok, &other_pub).is_err());
        assert!(attenuate(&tok, &other_pub, &tools(&["s/t"]), None).is_err());
        assert!(verify("not-a-token", &other_pub).is_err());
    }

    #[test]
    fn rejects_unsupported_patterns_and_quotes_safely() {
        let (sk, pubk) = generate_root_keypair();
        assert!(mint(&sk, "a", &tools(&["*/read"]), 60).is_err());
        assert!(mint(&sk, "a", &tools(&["read_file"]), 60).is_err());
        assert!(mint(&sk, "a", &tools(&["gh/a?c"]), 60).is_err());
        // Quotes in names are data, not Datalog.
        let tok = mint(&sk, "x\"); right_prefix(\"", &tools(&["s/t\"); right_prefix(\""]), 60).unwrap();
        assert!(authorize(&tok, &pubk, "other", "tool").is_err());
    }

    #[test]
    fn inspect_prints_blocks() {
        let (sk, pubk) = generate_root_keypair();
        let tok = mint(&sk, "planner", &tools(&["github/*"]), 60).unwrap();
        let tok = attenuate(&tok, &pubk, &tools(&["github/list"]), Some(30)).unwrap();
        let out = inspect(&tok).unwrap();
        assert!(out.contains("// authority"));
        assert!(out.contains("agent(\"planner\")"));
        assert!(out.contains("right_prefix(\"github/\")"));
        assert!(out.contains("// block 1"));
        assert!(out.contains("\"github/list\""));
        assert!(inspect("%%%").is_err());
    }
}
