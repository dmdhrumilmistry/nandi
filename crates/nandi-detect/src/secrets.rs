//! Secret detection.
//!
//! Gitleaks style: every rule carries a few lowercase keywords. One
//! Aho-Corasick pass over the text finds which keywords occur and only the
//! regexes of those rules run. Rules without keywords always run, so they
//! must be cheap and specific.

use aho_corasick::{AhoCorasick, MatchKind};
use nandi_core::Severity;
use regex::Regex;

/// Extra validation applied to the extracted secret.
#[derive(Debug, Clone, Copy)]
enum Check {
    None,
    /// Shannon entropy (bits per char) of at least this value, and a mix of
    /// letters and digits. Used for generic, keyword-anchored rules.
    Entropy(f64),
}

/// Static description of one secret rule.
struct RuleDef {
    rule: &'static str,
    desc: &'static str,
    severity: Severity,
    keywords: &'static [&'static str],
    /// Rust regex. If it has a named group `s`, that group is the secret
    /// (and the span that gets redacted); otherwise the whole match is.
    regex: &'static str,
    check: Check,
}

const fn def(
    rule: &'static str,
    severity: Severity,
    desc: &'static str,
    keywords: &'static [&'static str],
    regex: &'static str,
) -> RuleDef {
    RuleDef { rule, desc, severity, keywords, regex, check: Check::None }
}

const fn def_entropy(
    rule: &'static str,
    severity: Severity,
    desc: &'static str,
    keywords: &'static [&'static str],
    regex: &'static str,
    min: f64,
) -> RuleDef {
    RuleDef { rule, desc, severity, keywords, regex, check: Check::Entropy(min) }
}

use Severity::{Critical, High, Medium};

/// Trailing boundary for token alphabets that include `-` and `_`.
macro_rules! tb {
    () => {
        r"(?:[^0-9A-Za-z_\-]|$)"
    };
}

/// The rule table. Order matters: when two rules match overlapping text the
/// earlier (more specific) one wins.
const RULES: &[RuleDef] = &[
    def(
        "secret.aws-access-key",
        Critical,
        "AWS access key id",
        &["akia", "asia", "abia", "acca", "a3t"],
        r"\b(?P<s>(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z2-7]{16})\b",
    ),
    def_entropy(
        "secret.aws-secret-key",
        Critical,
        "AWS secret access key",
        &["aws"],
        concat!(
            r#"(?i)aws[a-z0-9_.\-]{0,32}["']?\s{0,3}(?::=|=>|=|:)\s{0,3}["']?(?P<s>[A-Za-z0-9/+]{40})"#,
            r"(?:[^A-Za-z0-9/+=]|$)"
        ),
        3.5,
    ),
    def(
        "secret.gcp-api-key",
        High,
        "Google Cloud API key",
        &["aiza"],
        concat!(r"\b(?P<s>AIza[0-9A-Za-z_\-]{35})", tb!()),
    ),
    def(
        "secret.gcp-service-account",
        Critical,
        "Google Cloud service account private key",
        &["private_key"],
        r#""private_key"\s*:\s*"(?P<s>-----BEGIN[A-Z ]{0,20}PRIVATE KEY-----[^"]{16,})""#,
    ),
    def(
        "secret.private-key",
        Critical,
        "Private key (PEM)",
        &["private key"],
        r"(?s)-----BEGIN[A-Z ]{0,20}PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END[A-Z ]{0,20}PRIVATE KEY(?: BLOCK)?-----|\z)",
    ),
    def("secret.github-pat", High, "GitHub personal access token", &["ghp_"], r"\b(?P<s>ghp_[A-Za-z0-9]{36,255})\b"),
    def("secret.github-oauth", High, "GitHub OAuth access token", &["gho_"], r"\b(?P<s>gho_[A-Za-z0-9]{36,255})\b"),
    def(
        "secret.github-app-token",
        High,
        "GitHub app token",
        &["ghu_", "ghs_"],
        r"\b(?P<s>(?:ghu|ghs)_[A-Za-z0-9]{36,255})\b",
    ),
    def("secret.github-refresh-token", High, "GitHub refresh token", &["ghr_"], r"\b(?P<s>ghr_[A-Za-z0-9]{36,255})\b"),
    def(
        "secret.github-fine-grained-pat",
        High,
        "GitHub fine-grained personal access token",
        &["github_pat_"],
        r"\b(?P<s>github_pat_[A-Za-z0-9_]{60,255})\b",
    ),
    def(
        "secret.gitlab-pat",
        High,
        "GitLab personal access token",
        &["glpat-"],
        concat!(r"\b(?P<s>glpat-[A-Za-z0-9_\-]{20,})", tb!()),
    ),
    def(
        "secret.gitlab-trigger-token",
        High,
        "GitLab pipeline trigger or runner token",
        &["glptt-", "glrt-"],
        concat!(r"\b(?P<s>(?:glptt|glrt)-[A-Za-z0-9_\-]{20,})", tb!()),
    ),
    def(
        "secret.slack-token",
        High,
        "Slack token",
        &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xoxe"],
        concat!(r"\b(?P<s>xox(?:[baprs]|e\.xox[bp]|e)-[0-9A-Za-z\-]{10,250})", tb!()),
    ),
    def(
        "secret.slack-webhook",
        High,
        "Slack incoming webhook URL",
        &["hooks.slack.com"],
        r"(?P<s>https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9_/+\-]{20,})",
    ),
    def(
        "secret.stripe-key",
        Critical,
        "Stripe live secret or restricted key",
        &["sk_live_", "rk_live_"],
        r"\b(?P<s>(?:sk|rk)_live_[0-9A-Za-z]{20,247})\b",
    ),
    def(
        "secret.stripe-webhook-secret",
        High,
        "Stripe webhook signing secret",
        &["whsec_"],
        r"\b(?P<s>whsec_[A-Za-z0-9]{32,})\b",
    ),
    def(
        "secret.anthropic-api-key",
        Critical,
        "Anthropic API key",
        &["sk-ant-"],
        concat!(r"\b(?P<s>sk-ant-[A-Za-z0-9_\-]{32,})", tb!()),
    ),
    def(
        "secret.openai-api-key",
        Critical,
        "OpenAI API key",
        &["t3blbkfj"],
        concat!(r"\b(?P<s>sk-(?:[A-Za-z0-9_\-]{0,40}-)?[A-Za-z0-9_\-]{16,80}T3BlbkFJ[A-Za-z0-9_\-]{16,80})", tb!()),
    ),
    def(
        "secret.openai-project-key",
        Critical,
        "OpenAI project or service account key",
        &["sk-proj-", "sk-svcacct-", "sk-admin-"],
        concat!(r"\b(?P<s>sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,})", tb!()),
    ),
    def(
        "secret.google-oauth-secret",
        High,
        "Google OAuth client secret",
        &["gocspx-"],
        concat!(r"\b(?P<s>GOCSPX-[A-Za-z0-9_\-]{28})", tb!()),
    ),
    def(
        "secret.azure-storage-key",
        Critical,
        "Azure storage account key",
        &["accountkey="],
        r"(?i)AccountKey=(?P<s>[A-Za-z0-9+/]{86,88}={0,2})",
    ),
    def(
        "secret.azure-client-secret",
        High,
        "Azure AD client secret",
        &["q~"],
        r"(?:^|[^A-Za-z0-9_~.\-])(?P<s>[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.\-]{31,34})(?:[^A-Za-z0-9_~.\-]|$)",
    ),
    def("secret.twilio-api-key", High, "Twilio API key", &["sk"], r"\b(?P<s>SK[0-9a-fA-F]{32})\b"),
    def(
        "secret.sendgrid-api-key",
        High,
        "SendGrid API key",
        &["sg."],
        concat!(r"\b(?P<s>SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})", tb!()),
    ),
    def("secret.mailgun-api-key", High, "Mailgun API key", &["key-"], r"\b(?P<s>key-[0-9a-f]{32})\b"),
    def("secret.mailchimp-api-key", High, "Mailchimp API key", &["-us"], r"\b(?P<s>[0-9a-f]{32}-us[0-9]{1,2})\b"),
    def("secret.npm-token", High, "npm access token", &["npm_"], r"\b(?P<s>npm_[A-Za-z0-9]{36})\b"),
    def(
        "secret.pypi-token",
        High,
        "PyPI upload token",
        &["pypi-ageichlwas5vcmc"],
        concat!(r"\b(?P<s>pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})", tb!()),
    ),
    def(
        "secret.dockerhub-token",
        High,
        "Docker Hub personal access token",
        &["dckr_pat_"],
        concat!(r"\b(?P<s>dckr_pat_[A-Za-z0-9_\-]{27,})", tb!()),
    ),
    def("secret.huggingface-token", High, "Hugging Face access token", &["hf_"], r"\b(?P<s>hf_[A-Za-z]{34})\b"),
    def(
        "secret.shopify-token",
        High,
        "Shopify access token or shared secret",
        &["shpat_", "shpss_", "shpca_", "shppa_"],
        r"\b(?P<s>shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32})\b",
    ),
    def(
        "secret.datadog-api-key",
        High,
        "Datadog API or application key",
        &["datadog", "dd_api", "dd_app", "dd-api", "dd-app"],
        concat!(
            r#"(?i)(?:datadog|dd)[a-z0-9_.\-]{0,20}(?:api|app|application)[_\-]?key["']?\s{0,3}(?::=|=>|=|:)\s{0,3}["']?"#,
            r"(?P<s>[a-f0-9]{40}|[a-f0-9]{32})\b"
        ),
    ),
    def(
        "secret.heroku-api-key",
        High,
        "Heroku API key",
        &["heroku"],
        concat!(
            r#"(?i)heroku[a-z0-9_.\-]{0,20}["']?\s{0,3}(?::=|=>|=|:)\s{0,3}["']?"#,
            r"(?P<s>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"
        ),
    ),
    def(
        "secret.heroku-api-key-v2",
        High,
        "Heroku platform API key",
        &["hrku-"],
        concat!(r"\b(?P<s>HRKU-[A-Za-z0-9_\-]{60})", tb!()),
    ),
    def(
        "secret.digitalocean-token",
        High,
        "DigitalOcean token",
        &["dop_v1_", "doo_v1_", "dor_v1_"],
        r"\b(?P<s>do[opr]_v1_[a-f0-9]{64})\b",
    ),
    def(
        "secret.discord-bot-token",
        High,
        "Discord bot token",
        &[],
        r"\b(?P<s>[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38})\b",
    ),
    def(
        "secret.telegram-bot-token",
        High,
        "Telegram bot token",
        &[":aa"],
        concat!(r"\b(?P<s>[0-9]{8,10}:AA[A-Za-z0-9_\-]{33})", tb!()),
    ),
    def("secret.linear-api-key", High, "Linear API key", &["lin_api_"], r"\b(?P<s>lin_api_[A-Za-z0-9]{40})\b"),
    def("secret.postman-api-key", High, "Postman API key", &["pmak-"], r"\b(?P<s>PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b"),
    def(
        "secret.grafana-token",
        High,
        "Grafana cloud or service account token",
        &["glc_", "glsa_"],
        r"\b(?P<s>glc_[A-Za-z0-9+/]{32,400}={0,2}|glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})",
    ),
    def(
        "secret.vault-token",
        High,
        "HashiCorp Vault token",
        &["hvs.", "hvb."],
        concat!(r"\b(?P<s>hv[sb]\.[A-Za-z0-9_\-]{90,})", tb!()),
    ),
    def("secret.databricks-token", High, "Databricks API token", &["dapi"], r"\b(?P<s>dapi[a-f0-9]{32}(?:-[0-9])?)\b"),
    def("secret.groq-api-key", High, "Groq API key", &["gsk_"], r"\b(?P<s>gsk_[A-Za-z0-9]{52})\b"),
    def(
        "secret.age-secret-key",
        Critical,
        "age encryption secret key",
        &["age-secret-key-1"],
        r"(?P<s>AGE-SECRET-KEY-1[0-9A-Z]{58})",
    ),
    def(
        "secret.jwt",
        Medium,
        "JSON web token",
        &["eyj"],
        concat!(r"\b(?P<s>eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})", tb!()),
    ),
    def(
        "secret.database-url",
        High,
        "Database URL with inline credentials",
        &["postgres", "mysql", "mariadb", "mongodb", "redis", "amqp", "mssql", "sqlserver"],
        concat!(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://",
            r#"[^\s:/@"'`]{1,128}:(?P<s>[^\s@/"'`]{3,128})@[^\s/"'`]+"#
        ),
    ),
    def_entropy(
        "secret.generic-assignment",
        Medium,
        "High-entropy value assigned to a credential-like name",
        &[
            "password",
            "passwd",
            "pwd",
            "secret",
            "api_key",
            "api-key",
            "apikey",
            "access_token",
            "access-token",
            "auth_token",
            "auth-token",
        ],
        concat!(
            r"(?i)(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token)[a-z0-9_\-]{0,20}",
            r#"["']?\s{0,3}(?::=|=>|=|:)\s{0,3}["']?(?P<s>[^\s"'`,;<>{}()$\\]{16,256})"#
        ),
        3.5,
    ),
];

/// Rule id for secrets found through the name of the JSON key that holds them.
pub(crate) const GENERIC_RULE: &str = "secret.generic-assignment";
const GENERIC_DESC: &str = "High-entropy value assigned to a credential-like name";

/// Number of secret rules (including the key-context generic check, which
/// shares its id with the generic assignment regex).
pub(crate) fn rule_count() -> usize {
    RULES.len()
}

/// A secret found in a text.
#[derive(Debug, Clone)]
pub(crate) struct SecretHit {
    pub start: usize,
    pub end: usize,
    pub rule: &'static str,
    pub desc: &'static str,
    pub severity: Severity,
}

struct Compiled {
    def: &'static RuleDef,
    re: Regex,
    has_s: bool,
}

/// Compiled secret rules plus the keyword prefilter.
pub(crate) struct SecretScanner {
    rules: Vec<Compiled>,
    ac: AhoCorasick,
    /// Keyword pattern index to rule indices.
    kw_rules: Vec<Vec<usize>>,
    always: Vec<usize>,
}

impl SecretScanner {
    pub fn new() -> Self {
        let mut rules = Vec::with_capacity(RULES.len());
        let mut keywords: Vec<&'static str> = Vec::new();
        let mut kw_rules: Vec<Vec<usize>> = Vec::new();
        let mut always = Vec::new();
        for (i, d) in RULES.iter().enumerate() {
            let re = crate::compile(d.regex);
            let has_s = re.capture_names().any(|n| n == Some("s"));
            rules.push(Compiled { def: d, re, has_s });
            if d.keywords.is_empty() {
                always.push(i);
            }
            for kw in d.keywords {
                match keywords.iter().position(|k| k == kw) {
                    Some(p) => kw_rules[p].push(i),
                    None => {
                        keywords.push(kw);
                        kw_rules.push(vec![i]);
                    }
                }
            }
        }
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&keywords)
            .expect("secret keyword automaton");
        Self { rules, ac, kw_rules, always }
    }

    /// Append secrets found in `text` to `out`. Matches overlapping an
    /// earlier hit in `out` are dropped.
    pub fn scan(&self, text: &str, out: &mut Vec<SecretHit>) {
        let mut selected = vec![false; self.rules.len()];
        let mut any = false;
        for m in self.ac.find_overlapping_iter(text) {
            for &r in &self.kw_rules[m.pattern().as_usize()] {
                selected[r] = true;
                any = true;
            }
        }
        for &r in &self.always {
            selected[r] = true;
        }
        if !any && self.always.is_empty() {
            return;
        }
        for (i, rule) in self.rules.iter().enumerate() {
            if !selected[i] {
                continue;
            }
            for caps in rule.re.captures_iter(text) {
                let m = if rule.has_s { caps.name("s") } else { caps.get(0) };
                let Some(m) = m else { continue };
                let secret = m.as_str();
                if is_placeholder(secret) || !passes(rule.def.check, secret) {
                    continue;
                }
                if out.iter().any(|h| h.start < m.end() && m.start() < h.end) {
                    continue;
                }
                out.push(SecretHit {
                    start: m.start(),
                    end: m.end(),
                    rule: rule.def.rule,
                    desc: rule.def.desc,
                    severity: rule.def.severity,
                });
            }
        }
    }
}

/// A secret identified by the name of the JSON key holding it, e.g.
/// `{"password": "..."}` or `{"Authorization": "Bearer ..."}`. Returns the
/// span of the secret inside `value`.
pub(crate) fn from_key(key: &str, value: &str) -> Option<SecretHit> {
    if !is_sensitive_key(key) {
        return None;
    }
    let trimmed_start = value.len() - value.trim_start().len();
    let mut v = value.trim();
    let mut start = trimmed_start;
    for prefix in ["Bearer ", "bearer ", "Basic ", "basic ", "token ", "Token "] {
        if let Some(rest) = v.strip_prefix(prefix) {
            start += prefix.len();
            v = rest.trim_start();
            start += rest.len() - v.len();
            break;
        }
    }
    if v.len() < 16 || v.len() > 512 || v.contains(char::is_whitespace) {
        return None;
    }
    if is_placeholder(v) || !passes(Check::Entropy(3.5), v) {
        return None;
    }
    Some(SecretHit { start, end: start + v.len(), rule: GENERIC_RULE, desc: GENERIC_DESC, severity: Severity::Medium })
}

fn is_sensitive_key(key: &str) -> bool {
    let k: String = key.chars().filter(|c| *c != '_' && *c != '-').flat_map(char::to_lowercase).collect();
    if matches!(k.as_str(), "token" | "auth" | "authorization" | "pass" | "proxyauthorization") {
        return true;
    }
    const SUFFIXES: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "apikey",
        "accesskey",
        "secretkey",
        "privatekey",
        "accesstoken",
        "authtoken",
        "refreshtoken",
        "apitoken",
        "sessiontoken",
        "bearertoken",
        "credentials",
        "credential",
    ];
    SUFFIXES.iter().any(|s| k.ends_with(s))
}

fn passes(check: Check, s: &str) -> bool {
    match check {
        Check::None => true,
        Check::Entropy(min) => {
            let has_digit = s.bytes().any(|b| b.is_ascii_digit());
            let has_alpha = s.bytes().any(|b| b.is_ascii_alphabetic());
            has_digit && has_alpha && shannon_entropy(s) >= min
        }
    }
}

/// Obvious placeholders and documentation values that are not real secrets.
pub(crate) fn is_placeholder(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    const MARKERS: &[&str] =
        &["example", "xxxxx", "*****", "your_", "your-", "<your", "redacted", "changeme", "placeholder", "dummy"];
    if MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    if matches!(lower.as_str(), "password" | "pass" | "passwd" | "secret" | "pwd" | "root" | "admin" | "user") {
        return true;
    }
    let first = s.as_bytes().first().copied().unwrap_or(b' ');
    if matches!(first, b'$' | b'<' | b'{' | b'%') {
        return true;
    }
    // A single repeated character.
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => chars.all(|d| d == c),
        None => true,
    }
}

/// Shannon entropy in bits per character.
pub(crate) fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let mut n = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    let n = n as f64;
    counts.iter().filter(|c| **c > 0).map(|&c| c as f64 / n).map(|p| -p * p.log2()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    static SCANNER: LazyLock<SecretScanner> = LazyLock::new(SecretScanner::new);

    fn rules_for(text: &str) -> Vec<&'static str> {
        let mut out = Vec::new();
        SCANNER.scan(text, &mut out);
        out.iter().map(|h| h.rule).collect()
    }

    fn first(text: &str) -> Option<String> {
        let mut out = Vec::new();
        SCANNER.scan(text, &mut out);
        out.first().map(|h| text[h.start..h.end].to_string())
    }

    #[test]
    fn all_rules_compile() {
        assert_eq!(SCANNER.rules.len(), RULES.len());
        assert!(RULES.len() >= 40);
    }

    #[test]
    fn positives() {
        let cases: &[(&str, &str)] = &[
            (concat!("key AKIA", "QYLPMN5HHHFPZAM2 here"), "secret.aws-access-key"),
            (concat!("aws_secret_access_key = wJalrXUtnFEMI", "/K7MDENG/bPxRfiCYzQ8a2Ld91x"), "secret.aws-secret-key"),
            (concat!("AIza", "SyD3x9Kq2Lm8Np4Rs6Tu8Vw0Xy2Za4Bc6De"), "secret.gcp-api-key"),
            (
                concat!("-----BEGIN RSA PRIVATE KEY-----\nMI", "IEow\n-----END RSA PRIVATE KEY-----"),
                "secret.private-key",
            ),
            (concat!("-----BEGIN OPENSSH PRI", "VATE KEY-----\nb3BlbnNz"), "secret.private-key"),
            (concat!("token ghp_", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A"), "secret.github-pat"),
            (concat!("gho_", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A"), "secret.github-oauth"),
            (concat!("ghs_", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A"), "secret.github-app-token"),
            (concat!("ghr_", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A"), "secret.github-refresh-token"),
            (
                concat!(
                    "github_pat_",
                    concat!("11ABCDEFG0aB3dE5fG7hJ9_kL1mN3pQ5rS7tU9vW1", "xY3z5AaB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A")
                ),
                "secret.github-fine-grained-pat",
            ),
            (concat!("glpat-", "aB3dE5fG7hJ9kL1mN3pQ"), "secret.gitlab-pat"),
            (concat!("xoxb-", "2611112222-3611112222-aB3dE5fG7hJ9kL1mN3pQ5rS7"), "secret.slack-token"),
            (
                concat!("https://hooks.slack.com/services/", "T02ABCDEF/B03GHIJKL/aB3dE5fG7hJ9kL1mN3pQ5rS7"),
                "secret.slack-webhook",
            ),
            (concat!("sk_live_", "51HaB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW"), "secret.stripe-key"),
            (concat!("rk_live_", "51HaB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW"), "secret.stripe-key"),
            (
                concat!("sk-ant-", "api03-aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5AaB3dE5fG7hJ9kL1mN3p"),
                "secret.anthropic-api-key",
            ),
            (concat!("sk-aB3dE5fG7hJ9kL1mN3pQT3", "BlbkFJaB3dE5fG7hJ9kL1mN3pQ"), "secret.openai-api-key"),
            (concat!("sk-proj-", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A"), "secret.openai-project-key"),
            (concat!("GOCSPX-", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9v"), "secret.google-oauth-secret"),
            (concat!("SK0123456789abcde", "f0123456789abcdef"), "secret.twilio-api-key"),
            (
                concat!("SG.", "aB3dE5fG7hJ9kL1mN3pQ5r.aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5AaB3dE5f"),
                "secret.sendgrid-api-key",
            ),
            (concat!("key-0123456789abcd", "ef0123456789abcdef"), "secret.mailgun-api-key"),
            (concat!("npm_", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A"), "secret.npm-token"),
            (concat!("dckr_pat_", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9"), "secret.dockerhub-token"),
            (concat!("hf_", "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgH"), "secret.huggingface-token"),
            (concat!("shpat_", "0123456789abcdef0123456789abcdef"), "secret.shopify-token"),
            (concat!("DATADOG_API_KEY=01234567", "89abcdef0123456789abcdef"), "secret.datadog-api-key"),
            (concat!("HEROKU_API_KEY: 01234567-8", "9ab-cdef-0123-456789abcdef"), "secret.heroku-api-key"),
            (
                concat!("dop_v1_", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                "secret.digitalocean-token",
            ),
            (
                concat!("MTA4OTkyODc2NTQzMjEwOTg3.GaB3dE.a", "B3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5"),
                "secret.discord-bot-token",
            ),
            (concat!("123456789:AAaB3dE5fG7h", "J9kL1mN3pQ5rS7tU9vW1xY3"), "secret.telegram-bot-token"),
            (
                concat!(
                    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw",
                    "In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                ),
                "secret.jwt",
            ),
            (concat!("postgres://admin:s3cr3tP", "4ss@db.prod.corp:5432/app"), "secret.database-url"),
            (concat!("mongodb+srv://svc:Zq8wPl2x", "K@cluster0.mongodb.net/test"), "secret.database-url"),
            (concat!("api_key = 'Zq8wP", "l2xKr5TbN7mVc4H'"), "secret.generic-assignment"),
            (
                concat!(
                    "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=aB3dE5fG7hJ9kL1mN3pQ",
                    "5rS7tU9vW1xY3z5AaB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5AaB3dE5fG7hJ9kL1mN3pQ5rS7t=="
                ),
                "secret.azure-storage-key",
            ),
            (concat!("client secret: abc8Q~aB3dE5", "fG7hJ9kL1mN3pQ5rS7tU9vW1xY3"), "secret.azure-client-secret"),
            (concat!("lin_api_aB3dE5fG7hJ9kL1m", "N3pQ5rS7tU9vW1xY3z5AaB3d"), "secret.linear-api-key"),
            (concat!("gsk_aB3dE5fG7hJ9kL1mN3pQ5rS7", "tU9vW1xY3z5AaB3dE5fG7hJ9kL1m"), "secret.groq-api-key"),
        ];
        for (text, rule) in cases {
            let got = rules_for(text);
            assert!(got.contains(rule), "{rule} not found in {text:?}: {got:?}");
        }
    }

    #[test]
    fn negatives() {
        let cases = [
            concat!("AKIA", "IOSFODNN7EXAMPLE"),
            "ghp_short",
            "the sk_test_ key is for testing",
            "password = hunter2",
            "password = ${DB_PASSWORD}",
            "api_key = settings.OPENAI_API_KEY_VALUE",
            "postgres://user:password@localhost/db",
            "sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "id 550e8400-e29b-41d4-a716-446655440000",
            "Ask the task desk about skills",
            concat!("visit Asia and the AIza", " conference"),
        ];
        for text in cases {
            assert!(rules_for(text).is_empty(), "false positive in {text:?}: {:?}", rules_for(text));
        }
    }

    #[test]
    fn named_group_is_the_span() {
        assert_eq!(first("DB=postgres://admin:s3cr3tP4ss@db:5432/x").as_deref(), Some("s3cr3tP4ss"));
        assert_eq!(first(concat!("x AKIA", "QYLPMN5HHHFPZAM2.")).as_deref(), Some(concat!("AKIA", "QYLPMN5HHHFPZAM2")));
    }

    #[test]
    fn key_context() {
        assert!(from_key("password", "Zq8wPl2xKr5TbN7mVc4H").is_some());
        assert!(from_key("clientSecret", "Zq8wPl2xKr5TbN7mVc4H").is_some());
        let h = from_key("Authorization", "Bearer Zq8wPl2xKr5TbN7mVc4H").unwrap();
        assert_eq!(h.start, 7);
        assert!(from_key("nextPageToken", "Zq8wPl2xKr5TbN7mVc4H").is_none());
        assert!(from_key("password", "short").is_none());
        assert!(from_key("description", "Zq8wPl2xKr5TbN7mVc4H").is_none());
    }

    #[test]
    fn entropy() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!((shannon_entropy("ab") - 1.0).abs() < 1e-9);
        assert!(shannon_entropy("Zq8wPl2xKr5TbN7mVc4H") > 4.0);
    }
}
