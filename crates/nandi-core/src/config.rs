//! `nandi.yaml` configuration model.
//!
//! Everything has a safe default so an empty file is a valid config: monitor
//! mode, localhost listeners, all detectors on, tool pinning on.
//!
//! String values that hold credentials may be written as `env:NAME` or
//! `file:/path` and are resolved with [`resolve_secret`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::decision::Verdict;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Record and alert only. Nothing is blocked or rewritten.
    #[default]
    Monitor,
    /// Apply verdicts.
    Enforce,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Block when an internal component (approval broker, ML model,
    /// external guardrail) is unavailable.
    #[default]
    Closed,
    /// Let traffic through when an internal component is unavailable.
    Open,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub fail_mode: FailMode,
    /// Directory for state (audit log, tool pins, behaviour models, keys).
    pub data_dir: Option<PathBuf>,
    pub listen: Listen,
    pub admin: AdminConfig,
    pub routes: Vec<Route>,
    pub identity: IdentityConfig,
    pub policy: PolicyConfig,
    pub tools: ToolsConfig,
    pub taint: TaintConfig,
    pub detect: DetectConfig,
    pub behavior: BehaviorConfig,
    pub plan: PlanConfig,
    pub budgets: Vec<Budget>,
    pub approvals: ApprovalConfig,
    pub audit: AuditConfig,
    pub telemetry: TelemetryConfig,
    pub a2a: A2aConfig,
    pub sensor: SensorConfig,
    pub ml: MlConfig,
}

impl Config {
    /// Parse a YAML document.
    pub fn from_yaml(text: &str) -> Result<Self> {
        if text.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_yaml_ng::from_str(text).map_err(|e| Error::Config(e.to_string()))
    }

    /// Load and parse a YAML file. Relative paths inside the config are
    /// resolved against the file's directory by the callers that use them,
    /// via [`Config::base_dir`].
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).map_err(|e| Error::Config(format!("reading {}: {e}", path.display())))?;
        let mut cfg = Self::from_yaml(&text)?;
        if cfg.data_dir.is_none() {
            cfg.data_dir = Some(path.parent().unwrap_or(Path::new(".")).join("nandi-data"));
        }
        Ok(cfg)
    }

    pub fn data_dir(&self) -> PathBuf {
        self.data_dir.clone().unwrap_or_else(|| PathBuf::from("nandi-data"))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listen {
    /// Data-plane proxy address.
    pub proxy: String,
    /// Optional TLS for the proxy listener.
    pub tls: Option<TlsConfig>,
}

impl Default for Listen {
    fn default() -> Self {
        Self { proxy: "127.0.0.1:8787".into(), tls: None }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// CA bundle for verifying client certificates (mTLS). When set, client
    /// certificates are required and the SPIFFE ID / CN becomes the agent id.
    #[serde(default)]
    pub client_ca: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Admin API + dashboard address. Keep on localhost unless fronted by auth.
    pub listen: String,
    /// Bearer token for the admin API (`env:` / `file:` allowed). When unset
    /// the admin API only accepts loopback connections.
    pub token: Option<String>,
    pub ui: bool,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self { listen: "127.0.0.1:8788".into(), token: None, ui: true }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    /// LLM provider API (OpenAI, Anthropic, Gemini, compatible).
    Llm,
    /// MCP server over Streamable HTTP (or legacy SSE).
    Mcp,
    /// A2A agent.
    A2a,
}

/// A path prefix on the proxy listener mapped to an upstream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub name: String,
    /// Path prefix, e.g. `/openai`. Stripped before forwarding.
    pub prefix: String,
    pub upstream: String,
    pub kind: RouteKind,
    /// For `llm` routes: `openai`, `anthropic`, `gemini`. Inferred from the
    /// upstream host when omitted.
    #[serde(default)]
    pub provider: Option<String>,
    /// Headers added to upstream requests (credential injection). Values may
    /// use `env:` / `file:`. Agents never see these values.
    #[serde(default)]
    pub inject_headers: BTreeMap<String, String>,
    /// Request headers removed before forwarding (e.g. the agent's own key).
    #[serde(default)]
    pub strip_headers: Vec<String>,
    /// Upstream request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    300
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityConfig {
    /// Accept requests without credentials as agent `anonymous`.
    pub allow_anonymous: bool,
    /// Header carrying the agent API key.
    pub api_key_header: String,
    pub api_keys: Vec<ApiKey>,
    pub jwt: Option<JwtConfig>,
    pub biscuit: Option<BiscuitConfig>,
    /// Header an agent may use to name its session (otherwise derived).
    pub session_header: String,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            allow_anonymous: true,
            api_key_header: "x-nandi-key".into(),
            api_keys: Vec::new(),
            jwt: None,
            biscuit: None,
            session_header: "x-nandi-session".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKey {
    /// Agent id this key authenticates as.
    pub agent: String,
    /// Hex SHA-256 of the key. Generate with `nandi key hash`.
    pub sha256: String,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    /// Local JWKS file with the issuer's public keys.
    #[serde(default)]
    pub jwks_file: Option<PathBuf>,
    /// Shared secret for HS256 (`env:` / `file:` allowed).
    #[serde(default)]
    pub hs256_secret: Option<String>,
    /// Claim holding the agent id (default `sub`).
    #[serde(default = "default_sub")]
    pub agent_claim: String,
    /// Claim holding groups / roles.
    #[serde(default = "default_groups")]
    pub groups_claim: String,
    /// Claim naming the human or agent the caller acts for (`act.sub`).
    #[serde(default)]
    pub delegator_claim: Option<String>,
}

fn default_sub() -> String {
    "sub".into()
}
fn default_groups() -> String {
    "groups".into()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BiscuitConfig {
    /// Hex Ed25519 root public key that signed the authority block.
    pub root_public_key: String,
    /// Header carrying the token (default `x-nandi-biscuit`).
    #[serde(default = "default_biscuit_header")]
    pub header: String,
}

fn default_biscuit_header() -> String {
    "x-nandi-biscuit".into()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    /// Allow when no policy matches (monitor-friendly default).
    #[default]
    Allow,
    /// Zero trust: deny anything not explicitly permitted.
    Deny,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// What happens to a tool call that no rule or Cedar policy permits.
    pub default: DefaultAction,
    /// Cedar policy files (`.cedar`).
    pub cedar: Vec<PathBuf>,
    /// Optional Cedar entities file (agents, groups, tools as JSON).
    pub cedar_entities: Option<PathBuf>,
    /// YAML rule files (argument predicates, sequences, budgets).
    pub rules: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolsConfig {
    /// Pin tool definitions (name + description + schema hash) on first sight.
    pub pin: bool,
    /// Verdict for a tool whose definition changed after pinning.
    pub on_drift: Verdict,
    /// Verdict for a tool never seen in `tools/list` (possible shadowing).
    pub on_unlisted: Verdict,
    /// Scan descriptions for poisoning (hidden instructions, cross-tool
    /// references, exfil hints).
    pub scan_descriptions: bool,
    /// Hide tools the caller is not allowed to call from `tools/list`.
    pub filter_list: bool,
}

impl Default for ToolsConfig {
    fn default() -> Self {
        Self {
            pin: true,
            on_drift: Verdict::Deny,
            on_unlisted: Verdict::Alert,
            scan_descriptions: true,
            filter_list: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Spotlight {
    #[default]
    Off,
    /// Wrap untrusted tool output in random delimiters.
    Delimit,
    /// Interleave a per-session marker between words of untrusted output.
    Datamark,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TaintConfig {
    pub enabled: bool,
    /// Tool globs (`server/tool` or `tool`) whose output is trusted. All other
    /// tool output and inbound A2A messages are untrusted.
    pub trusted_sources: Vec<String>,
    /// Tool globs that cause external side effects (send, write, pay, exec).
    pub consequential: Vec<String>,
    /// Verdict when a consequential tool runs in a tainted session.
    pub on_tainted_call: Verdict,
    /// Stronger verdict when the arguments carry values copied from
    /// untrusted output (value-flow match).
    pub on_tainted_flow: Verdict,
    /// Minimum length of a copied value to count as a flow.
    pub min_flow_len: usize,
    pub spotlight: Spotlight,
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_sources: Vec::new(),
            consequential: vec![
                "*send*".into(),
                "*email*".into(),
                "*post*".into(),
                "*write*".into(),
                "*delete*".into(),
                "*exec*".into(),
                "*shell*".into(),
                "*bash*".into(),
                "*run*".into(),
                "*pay*".into(),
                "*transfer*".into(),
                "*upload*".into(),
                "*push*".into(),
                "*http*".into(),
                "*fetch*".into(),
            ],
            on_tainted_call: Verdict::Alert,
            on_tainted_flow: Verdict::Ask,
            min_flow_len: 12,
            spotlight: Spotlight::Off,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectConfig {
    pub secrets: bool,
    pub pii: bool,
    pub injection: bool,
    pub ssrf: bool,
    /// Exact strings planted as canaries. Any appearance in egress is
    /// treated as exfiltration.
    pub honeytokens: Vec<String>,
    /// Decode base64 / hex / URL-encoded substrings this many levels deep
    /// before scanning.
    pub decode_depth: u8,
    /// Verdict for secrets leaving through tool args, LLM prompts or A2A.
    pub on_secret: Verdict,
    pub on_pii: Verdict,
    pub on_injection: Verdict,
    pub on_ssrf: Verdict,
    pub on_honeytoken: Verdict,
    /// Extra hosts/CIDRs to treat as internal for SSRF checks.
    pub internal_hosts: Vec<String>,
    /// Hosts allowed even if internal (e.g. a local MCP server).
    pub allow_hosts: Vec<String>,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            secrets: true,
            pii: true,
            injection: true,
            ssrf: true,
            honeytokens: Vec::new(),
            decode_depth: 2,
            on_secret: Verdict::Redact,
            on_pii: Verdict::Alert,
            on_injection: Verdict::Alert,
            on_ssrf: Verdict::Deny,
            on_honeytoken: Verdict::Deny,
            internal_hosts: Vec::new(),
            allow_hosts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorMode {
    /// Update the per-agent model from observed traffic, never alert.
    Learn,
    /// Score against the model and alert on anomalies; keep learning from
    /// allowed traffic.
    #[default]
    Detect,
    /// Score against a frozen model.
    Frozen,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BehaviorConfig {
    pub enabled: bool,
    pub mode: BehaviorMode,
    /// Observations per agent before anomaly alerts start.
    pub min_observations: u64,
    /// Surprise threshold in bits (-log2 p) for a tool transition.
    pub surprise_bits: f64,
    /// Verdict for an anomalous transition.
    pub on_anomaly: Verdict,
    /// Identical calls (same tool + args) within `loop_window_secs` that count
    /// as a runaway loop.
    pub loop_threshold: u32,
    pub loop_window_secs: u64,
    /// Max tool calls per agent per minute (0 = unlimited).
    pub max_calls_per_minute: u32,
    /// Probability of reaching an unsafe state (Pro2Guard-style lookahead)
    /// above which the call is escalated.
    pub unsafe_reach_threshold: f64,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: BehaviorMode::Detect,
            min_observations: 200,
            surprise_bits: 8.0,
            on_anomaly: Verdict::Alert,
            loop_threshold: 8,
            loop_window_secs: 60,
            max_calls_per_minute: 0,
            unsafe_reach_threshold: 0.5,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanMode {
    /// Plans are ignored.
    #[default]
    Off,
    /// Deviations from a declared plan are alerts.
    Observe,
    /// Deviations from a declared plan are denied; sessions without a
    /// plan are unaffected.
    Enforce,
    /// Every session must declare a plan before calling tools.
    Required,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlanConfig {
    pub mode: PlanMode,
}

/// Token / cost budget for agents matching a glob.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub agent: String,
    #[serde(default)]
    pub tokens_per_day: Option<u64>,
    #[serde(default)]
    pub tool_calls_per_day: Option<u64>,
    #[serde(default = "default_budget_verdict")]
    pub verdict: Verdict,
}

fn default_budget_verdict() -> Verdict {
    Verdict::Deny
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalConfig {
    pub timeout_secs: u64,
    /// Verdict applied when nobody answers in time.
    pub on_timeout: Verdict,
    /// Webhook notified when an approval is pending (Slack-compatible JSON).
    pub webhook: Option<String>,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self { timeout_secs: 300, on_timeout: Verdict::Deny, webhook: None }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    pub enabled: bool,
    /// Defaults to `<data_dir>/audit.redb`.
    pub path: Option<PathBuf>,
    /// Ed25519 signing key; generated on first start when missing.
    /// Defaults to `<data_dir>/audit.key`.
    pub signing_key: Option<PathBuf>,
    /// Drop records older than this many days (0 = keep forever).
    pub retention_days: u32,
    /// Record allowed events with no findings (high volume).
    pub record_clean: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { enabled: true, path: None, signing_key: None, retention_days: 30, record_clean: true }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// OTLP/HTTP endpoint base, e.g. `http://localhost:4318`.
    pub otlp_endpoint: Option<String>,
    pub otlp_headers: BTreeMap<String, String>,
    pub service_name: String,
    /// Expose Prometheus metrics on the admin listener at `/metrics`.
    pub prometheus: bool,
    /// Generic webhooks receiving findings at or above `webhook_min_severity`.
    pub webhooks: Vec<String>,
    pub webhook_min_severity: crate::decision::Severity,
    /// Log format: `text` or `json`.
    pub log_format: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            otlp_headers: BTreeMap::new(),
            service_name: "nandi".into(),
            prometheus: true,
            webhooks: Vec::new(),
            webhook_min_severity: crate::decision::Severity::High,
            log_format: "text".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct A2aConfig {
    /// Deny Agent Cards without a valid signature.
    pub require_signed_cards: bool,
    /// Trusted signer keys: JWKS files or PEM public keys.
    pub trusted_keys: Vec<PathBuf>,
    /// Pin card digests and alert / deny when a card changes.
    pub pin_cards: bool,
    pub on_card_drift: Verdict,
    /// Bind each `contextId` to the first authenticated caller that used it.
    pub bind_context: bool,
}

impl Default for A2aConfig {
    fn default() -> Self {
        Self {
            require_signed_cards: false,
            trusted_keys: Vec::new(),
            pin_cards: true,
            on_card_drift: Verdict::Alert,
            bind_context: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SensorConfig {
    pub enabled: bool,
    /// Process names treated as agents (their process trees are watched).
    pub agent_comms: Vec<String>,
    /// Path globs whose access by an agent tree is sensitive.
    pub sensitive_paths: Vec<String>,
    /// LLM provider hosts; direct connections that bypass the proxy are
    /// reported as shadow AI.
    pub llm_hosts: Vec<String>,
    /// Capture TLS plaintext with uprobes on libssl.
    pub ssl_uprobes: bool,
    /// Seconds within which an observed effect must match a declared tool
    /// call (intent / effect correlation).
    pub correlation_window_secs: u64,
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            agent_comms: vec![
                "claude".into(),
                "codex".into(),
                "cursor".into(),
                "gemini".into(),
                "aider".into(),
                "goose".into(),
                "opencode".into(),
            ],
            sensitive_paths: vec![
                "*/.ssh/*".into(),
                "*/.aws/credentials".into(),
                "*/.aws/config".into(),
                "*/.config/gcloud/*".into(),
                "*/.kube/config".into(),
                "*/.docker/config.json".into(),
                "*/.netrc".into(),
                "*/.git-credentials".into(),
                "*/.env".into(),
                "*/.env.*".into(),
                "/etc/shadow".into(),
            ],
            llm_hosts: vec![
                "api.openai.com".into(),
                "api.anthropic.com".into(),
                "generativelanguage.googleapis.com".into(),
                "api.mistral.ai".into(),
                "api.groq.com".into(),
                "api.deepseek.com".into(),
                "openrouter.ai".into(),
            ],
            ssl_uprobes: false,
            correlation_window_secs: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MlConfig {
    pub enabled: bool,
    /// ONNX model (e.g. Llama Prompt Guard 2 22M exported to ONNX).
    pub model: Option<PathBuf>,
    /// HuggingFace `tokenizer.json` for the model.
    pub tokenizer: Option<PathBuf>,
    /// Path to `libonnxruntime` (loaded at runtime).
    pub onnxruntime: Option<PathBuf>,
    /// Malicious-class probability threshold.
    pub threshold: f32,
    pub on_detect: Verdict,
    /// Max tokens per chunk fed to the model.
    pub max_tokens: usize,
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model: None,
            tokenizer: None,
            onnxruntime: None,
            threshold: 0.9,
            on_detect: Verdict::Alert,
            max_tokens: 512,
        }
    }
}

/// Resolve `env:NAME`, `file:/path` or a literal value.
pub fn resolve_secret(value: &str) -> Result<String> {
    if let Some(name) = value.strip_prefix("env:") {
        std::env::var(name).map_err(|_| Error::Config(format!("environment variable {name} is not set")))
    } else if let Some(path) = value.strip_prefix("file:") {
        std::fs::read_to_string(path)
            .map(|s| s.trim_end().to_string())
            .map_err(|e| Error::Config(format!("reading {path}: {e}")))
    } else {
        Ok(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_valid_monitor_mode() {
        let c = Config::from_yaml("").unwrap();
        assert_eq!(c.mode, Mode::Monitor);
        assert!(c.tools.pin);
        assert_eq!(c.listen.proxy, "127.0.0.1:8787");
    }

    #[test]
    fn parses_routes_and_rejects_typos() {
        let c = Config::from_yaml(
            r#"
mode: enforce
routes:
  - name: openai
    prefix: /openai
    upstream: https://api.openai.com
    kind: llm
    inject_headers: { authorization: "env:OPENAI_KEY" }
taint:
  on_tainted_flow: deny
"#,
        )
        .unwrap();
        assert_eq!(c.mode, Mode::Enforce);
        assert_eq!(c.routes[0].kind, RouteKind::Llm);
        assert_eq!(c.routes[0].timeout_secs, 300);
        assert_eq!(c.taint.on_tainted_flow, Verdict::Deny);
        assert!(Config::from_yaml("mdoe: enforce").is_err());
    }

    #[test]
    fn resolves_secrets() {
        assert_eq!(resolve_secret("literal").unwrap(), "literal");
        // SAFETY: tests in this module do not read this variable concurrently.
        unsafe { std::env::set_var("NANDI_TEST_SECRET", "s3cret") };
        assert_eq!(resolve_secret("env:NANDI_TEST_SECRET").unwrap(), "s3cret");
        assert!(resolve_secret("env:NANDI_DOES_NOT_EXIST").is_err());
    }
}
