//! Fast, deterministic content scanners for the nandi request path.
//!
//! A [`Detector`] is built once from [`DetectConfig`] (all automata and
//! regexes are compiled up front) and shared across threads. It scans JSON
//! values flowing across the agent boundary:
//!
//! - [`Detector::scan_egress`]: content leaving the agent (tool-call
//!   arguments, LLM prompts, outbound A2A): secrets, PII, honeytokens and
//!   SSRF destinations.
//! - [`Detector::scan_ingress`]: content entering the agent context (tool
//!   results, LLM responses, inbound A2A): prompt injection, hidden unicode,
//!   exfiltration links, plus secrets (alert only) and honeytokens.
//! - [`Detector::scan_tool_definition`]: tool poisoning and shadowing checks
//!   for MCP tool definitions.
//! - [`Detector::redact`]: rewrite secrets, PII and honeytokens.
//!
//! Every scan does one keyword pass per string and only runs the regexes of
//! rules whose keywords occurred. Encoded substrings (base64, hex, percent)
//! are decoded and rescanned up to `decode_depth` levels, within a fixed
//! work budget. Evidence in findings is always masked.

mod encoding;
mod injection;
mod pii;
mod secrets;
mod ssrf;
mod tooldef;

use aho_corasick::AhoCorasick;
use nandi_core::config::DetectConfig;
use nandi_core::util::{mask, truncate, walk_strings};
use nandi_core::{Category, Finding, Severity, ToolDef, Verdict};
use serde::Serialize;
use serde_json::Value;

use encoding::{Budget, Decoder};
use injection::InjectionScanner;
use pii::PiiScanner;
use secrets::SecretScanner;
use ssrf::SsrfChecker;

/// Rule id for honeytoken matches.
pub const HONEYTOKEN_RULE: &str = "honeytoken";
/// Rule id for invisible or direction-changing characters.
pub const HIDDEN_UNICODE_RULE: &str = "injection.hidden-unicode";

/// Upper bound on recorded matches per scan.
const MAX_MATCHES: usize = 1000;

/// What kind of content a [`Match`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Secret,
    Pii,
    Honeytoken,
    Injection,
    Ssrf,
    Unicode,
    /// A link or image whose URL can carry data out.
    Exfil,
}

/// One located match inside a string of the scanned value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Match {
    /// Path of the string, as produced by [`nandi_core::util::walk_strings`].
    pub path: String,
    /// Byte range in that string. For matches found after decoding, the
    /// range of the whole encoded run.
    pub start: usize,
    pub end: usize,
    /// Finding rule id this match contributes to.
    pub rule: String,
    pub kind: MatchKind,
    /// `base64`, `hex` or `url` when the match was found after decoding.
    pub decoded_from: Option<&'static str>,
}

/// Result of a content scan.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Scan {
    /// One finding per rule, with masked evidence and a match count.
    pub findings: Vec<Finding>,
    pub matches: Vec<Match>,
}

impl Scan {
    /// Most restrictive verdict among the findings.
    pub fn verdict(&self) -> Verdict {
        self.findings.iter().map(|f| f.verdict).max().unwrap_or_default()
    }

    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

/// Number of rules per family, for documentation and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RuleCounts {
    pub secrets: usize,
    pub pii: usize,
    pub injection: usize,
    pub ssrf: usize,
    pub tool: usize,
}

/// Which checks a scan runs.
#[derive(Debug, Clone, Copy)]
struct Mode {
    ingress: bool,
    secrets: bool,
    honey: bool,
    pii: bool,
    ssrf: bool,
    injection: bool,
}

/// One hit before aggregation.
struct Hit<'a> {
    path: &'a str,
    start: usize,
    end: usize,
    rule: &'static str,
    kind: MatchKind,
    category: Category,
    severity: Severity,
    message: &'static str,
    evidence: String,
    decoded_from: Option<&'static str>,
}

/// Findings aggregated per rule.
struct Group {
    rule: &'static str,
    kind: MatchKind,
    category: Category,
    severity: Severity,
    message: &'static str,
    evidence: String,
    path: String,
    decoded_from: Option<&'static str>,
    count: usize,
}

#[derive(Default)]
struct Acc {
    groups: Vec<Group>,
    matches: Vec<Match>,
    budget: Budget,
}

impl Acc {
    fn add(&mut self, h: Hit<'_>) {
        if self.matches.len() < MAX_MATCHES {
            self.matches.push(Match {
                path: h.path.to_string(),
                start: h.start,
                end: h.end,
                rule: h.rule.to_string(),
                kind: h.kind,
                decoded_from: h.decoded_from,
            });
        }
        match self.groups.iter_mut().find(|g| g.rule == h.rule) {
            Some(g) => {
                g.count += 1;
                g.severity = g.severity.max(h.severity);
            }
            None => self.groups.push(Group {
                rule: h.rule,
                kind: h.kind,
                category: h.category,
                severity: h.severity,
                message: h.message,
                evidence: h.evidence,
                path: h.path.to_string(),
                decoded_from: h.decoded_from,
                count: 1,
            }),
        }
    }
}

/// The content scanner. Cheap to share (`Send + Sync`), expensive to build.
pub struct Detector {
    cfg: DetectConfig,
    secrets: SecretScanner,
    pii: PiiScanner,
    honey: Option<AhoCorasick>,
    decoder: Decoder,
    pub(crate) injection: InjectionScanner,
    ssrf: SsrfChecker,
    pub(crate) tools: tooldef::ToolChecks,
}

impl std::fmt::Debug for Detector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detector").field("cfg", &self.cfg).finish_non_exhaustive()
    }
}

impl Detector {
    /// Compile all scanners for `cfg`.
    pub fn new(cfg: &DetectConfig) -> Self {
        let tokens: Vec<&str> = cfg.honeytokens.iter().map(|s| s.as_str()).filter(|s| !s.is_empty()).collect();
        let honey = (!tokens.is_empty()).then(|| {
            AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                .build(&tokens)
                .expect("honeytoken automaton")
        });
        Self {
            cfg: cfg.clone(),
            secrets: SecretScanner::new(),
            pii: PiiScanner::new(),
            honey,
            decoder: Decoder::new(),
            injection: InjectionScanner::new(),
            ssrf: SsrfChecker::new(&cfg.internal_hosts, &cfg.allow_hosts),
            tools: tooldef::ToolChecks::new(),
        }
    }

    /// Rule counts per family.
    pub fn rule_counts() -> RuleCounts {
        RuleCounts {
            secrets: secrets::rule_count(),
            pii: pii::RULE_COUNT,
            injection: injection::rule_count() + 1,
            ssrf: ssrf::RULE_COUNT,
            tool: tooldef::RULE_COUNT,
        }
    }

    /// Scan content leaving the agent boundary: tool-call arguments, LLM
    /// prompts, outbound A2A messages.
    pub fn scan_egress(&self, value: &Value) -> Scan {
        let mode = Mode {
            ingress: false,
            secrets: self.cfg.secrets,
            honey: self.honey.is_some(),
            pii: self.cfg.pii,
            ssrf: self.cfg.ssrf,
            injection: false,
        };
        self.scan_value(value, mode)
    }

    /// Scan content entering the agent context: tool results, LLM
    /// responses, inbound A2A messages. Secrets found here are alerted on,
    /// never redacted, unless they are honeytokens.
    pub fn scan_ingress(&self, value: &Value) -> Scan {
        let mode = Mode {
            ingress: true,
            secrets: self.cfg.secrets,
            honey: self.honey.is_some(),
            pii: false,
            ssrf: false,
            injection: self.cfg.injection,
        };
        self.scan_value(value, mode)
    }

    /// Tool poisoning checks for one MCP tool definition. `all_tools` lists
    /// `(server, tool)` for every tool visible to the agent and is used to
    /// detect descriptions that reference tools of other servers.
    pub fn scan_tool_definition(&self, server: &str, tool: &ToolDef, all_tools: &[(String, String)]) -> Vec<Finding> {
        tooldef::scan(self, server, tool, all_tools)
    }

    /// Replace every secret, PII and honeytoken match in string values with
    /// `[REDACTED:<rule>]`. Returns `None` if nothing changed. Object keys
    /// are left untouched.
    pub fn redact(&self, value: &Value) -> Option<Value> {
        let mode = Mode {
            ingress: false,
            secrets: self.cfg.secrets,
            honey: self.honey.is_some(),
            pii: self.cfg.pii,
            ssrf: false,
            injection: false,
        };
        let mut out = value.clone();
        let mut acc = Acc::default();
        self.redact_value(&mut out, None, mode, &mut acc).then_some(out)
    }

    fn redact_value(&self, v: &mut Value, key: Option<&str>, mode: Mode, acc: &mut Acc) -> bool {
        match v {
            Value::String(s) => {
                acc.matches.clear();
                self.scan_layer(acc, "", key, s, mode, self.cfg.decode_depth, None);
                match apply_redactions(s, &acc.matches) {
                    Some(new) => {
                        *s = new;
                        true
                    }
                    None => false,
                }
            }
            Value::Array(items) => {
                let mut changed = false;
                for item in items {
                    changed |= self.redact_value(item, None, mode, acc);
                }
                changed
            }
            Value::Object(map) => {
                let mut changed = false;
                for (k, item) in map.iter_mut() {
                    changed |= self.redact_value(item, Some(k), mode, acc);
                }
                changed
            }
            _ => false,
        }
    }

    fn scan_value(&self, value: &Value, mode: Mode) -> Scan {
        let mut acc = Acc::default();
        walk_strings(value, &mut |path, s| {
            let key = if path.ends_with("#key") { None } else { path.rsplit('/').next() };
            self.scan_layer(&mut acc, path, key, s, mode, self.cfg.decode_depth, None);
        });
        self.finish(acc, mode.ingress)
    }

    /// Scan one string. `outer` is set when `text` is the decoding of an
    /// encoded run: hits then point at that run in the original string.
    #[allow(clippy::too_many_arguments)]
    fn scan_layer(
        &self,
        acc: &mut Acc,
        path: &str,
        key: Option<&str>,
        text: &str,
        mode: Mode,
        depth: u8,
        outer: Option<(usize, usize, &'static str)>,
    ) {
        let span = |s: usize, e: usize| outer.map(|(a, b, _)| (a, b)).unwrap_or((s, e));
        let decoded_from = outer.map(|o| o.2);
        let top = outer.is_none();

        if mode.secrets {
            let mut hits = Vec::new();
            if top && let Some(h) = key.and_then(|k| secrets::from_key(k, text)) {
                hits.push(h);
            }
            self.secrets.scan(text, &mut hits);
            for h in hits {
                let (start, end) = span(h.start, h.end);
                acc.add(Hit {
                    path,
                    start,
                    end,
                    rule: h.rule,
                    kind: MatchKind::Secret,
                    category: Category::Secret,
                    severity: h.severity,
                    message: h.desc,
                    evidence: mask(&text[h.start..h.end]),
                    decoded_from,
                });
            }
        }

        if mode.honey
            && let Some(ac) = &self.honey
        {
            for m in ac.find_iter(text) {
                let (start, end) = span(m.start(), m.end());
                acc.add(Hit {
                    path,
                    start,
                    end,
                    rule: HONEYTOKEN_RULE,
                    kind: MatchKind::Honeytoken,
                    category: Category::Exfiltration,
                    severity: Severity::Critical,
                    message: "Honeytoken (canary) observed",
                    evidence: mask(&text[m.start()..m.end()]),
                    decoded_from,
                });
            }
        }

        if mode.pii && top {
            let mut hits = Vec::new();
            self.pii.scan(text, &mut hits);
            for h in hits {
                acc.add(Hit {
                    path,
                    start: h.start,
                    end: h.end,
                    rule: h.rule,
                    kind: MatchKind::Pii,
                    category: Category::Pii,
                    severity: h.severity,
                    message: h.desc,
                    evidence: mask(&text[h.start..h.end]),
                    decoded_from: None,
                });
            }
        }

        if mode.ssrf && top {
            let mut hits = Vec::new();
            self.ssrf.scan(text, &mut hits);
            for h in hits {
                let severity = if h.rule == ssrf::RULE_METADATA { Severity::Critical } else { Severity::High };
                acc.add(Hit {
                    path,
                    start: h.start,
                    end: h.end,
                    rule: h.rule,
                    kind: MatchKind::Ssrf,
                    category: Category::Ssrf,
                    severity,
                    message: "Request to an internal or metadata address",
                    evidence: format!("{}: {}", h.reason, truncate(&h.host, 80)),
                    decoded_from: None,
                });
            }
        }

        if mode.injection {
            let hidden = injection::hidden_unicode(text);
            let mut assessment = self.injection.assess(text);
            if let Some(h) = &hidden {
                let severity = if h.tags > 0 || h.bidi > 0 { Severity::High } else { Severity::Medium };
                let summary = h.summary();
                for &(s, e) in &h.spans {
                    let (start, end) = span(s, e);
                    acc.add(Hit {
                        path,
                        start,
                        end,
                        rule: HIDDEN_UNICODE_RULE,
                        kind: MatchKind::Unicode,
                        category: Category::Injection,
                        severity,
                        message: "Invisible or direction-changing unicode characters",
                        evidence: summary.clone(),
                        decoded_from,
                    });
                }
                if !h.tag_text.is_empty() {
                    let mut smuggled = self.injection.assess(&h.tag_text);
                    for ind in &mut smuggled.indicators {
                        (ind.start, ind.end) = h.spans[0];
                    }
                    assessment.merge(smuggled);
                }
            }
            if assessment.triggered()
                && let Some(family) = assessment.top_family()
            {
                let summary = assessment.summary();
                for ind in &assessment.indicators {
                    let (start, end) = span(ind.start, ind.end);
                    acc.add(Hit {
                        path,
                        start,
                        end,
                        rule: family.rule(),
                        kind: MatchKind::Injection,
                        category: Category::Injection,
                        severity: Severity::High,
                        message: family.describe(),
                        evidence: summary.clone(),
                        decoded_from,
                    });
                }
            }
            if top {
                let mut links = Vec::new();
                self.injection.exfil_links(text, &mut links);
                for l in links {
                    let image = l.rule == "exfil.markdown-image";
                    acc.add(Hit {
                        path,
                        start: l.start,
                        end: l.end,
                        rule: l.rule,
                        kind: MatchKind::Exfil,
                        category: Category::Exfiltration,
                        severity: if image { Severity::High } else { Severity::Medium },
                        message: if image {
                            "Image URL carrying data in its query (renders without a click)"
                        } else {
                            "Link URL carrying data in its query"
                        },
                        evidence: format!("link to {}", truncate(&l.host, 80)),
                        decoded_from: None,
                    });
                }
            }
        }

        if depth > 0 && (mode.secrets || mode.honey || mode.injection) {
            let mut decoded = Vec::new();
            self.decoder.decode_all(text, &mut acc.budget, &mut decoded);
            let inner = Mode { pii: false, ssrf: false, ..mode };
            for d in decoded {
                let o = outer.or(Some((d.start, d.end, d.encoding)));
                self.scan_layer(acc, path, None, &d.text, inner, depth - 1, o);
            }
        }
    }

    fn verdict_for(&self, kind: MatchKind, ingress: bool) -> Verdict {
        match kind {
            MatchKind::Secret if ingress => self.cfg.on_secret.min(Verdict::Alert),
            MatchKind::Secret => self.cfg.on_secret,
            MatchKind::Pii => self.cfg.on_pii,
            MatchKind::Honeytoken => self.cfg.on_honeytoken,
            MatchKind::Injection | MatchKind::Unicode | MatchKind::Exfil => self.cfg.on_injection,
            MatchKind::Ssrf => self.cfg.on_ssrf,
        }
    }

    fn finish(&self, acc: Acc, ingress: bool) -> Scan {
        let findings = acc
            .groups
            .into_iter()
            .map(|g| {
                let mut evidence = format!("{} at {}", g.evidence, if g.path.is_empty() { "/" } else { &g.path });
                if let Some(enc) = g.decoded_from {
                    evidence.push_str(&format!(" (decoded from {enc})"));
                }
                if g.count > 1 {
                    evidence.push_str(&format!("; {} matches", g.count));
                }
                Finding::new(g.rule, g.category, g.severity, self.verdict_for(g.kind, ingress), g.message)
                    .with_evidence(evidence)
            })
            .collect();
        Scan { findings, matches: acc.matches }
    }
}

/// Compile a pattern with ASCII word boundaries. Unicode `\b` stops the
/// lazy DFA on non-ASCII input; ASCII boundaries keep every scan on the fast
/// path, and all tokens these rules look for are ASCII anyway.
pub(crate) fn compile(pattern: &str) -> regex::Regex {
    regex::Regex::new(&pattern.replace(r"\b", r"(?-u:\b)")).unwrap_or_else(|e| panic!("invalid pattern {pattern}: {e}"))
}

/// Placeholder label for a redacted rule: `secret.aws-access-key` becomes
/// `aws-access-key`.
fn redaction_label(rule: &str) -> &str {
    rule.strip_prefix("secret.").or_else(|| rule.strip_prefix("pii.")).unwrap_or(rule)
}

/// Replace the (merged) spans of redactable matches in `s`.
fn apply_redactions(s: &str, matches: &[Match]) -> Option<String> {
    let mut spans: Vec<(usize, usize, &str)> = matches
        .iter()
        .filter(|m| matches!(m.kind, MatchKind::Secret | MatchKind::Pii | MatchKind::Honeytoken))
        .filter(|m| m.start < m.end && m.end <= s.len() && s.is_char_boundary(m.start) && s.is_char_boundary(m.end))
        .map(|m| (m.start, m.end, redaction_label(&m.rule)))
        .collect();
    if spans.is_empty() {
        return None;
    }
    spans.sort_by_key(|x| (x.0, std::cmp::Reverse(x.1)));
    let mut merged: Vec<(usize, usize, &str)> = Vec::new();
    for sp in spans {
        match merged.last_mut() {
            Some(last) if sp.0 < last.1 => last.1 = last.1.max(sp.1),
            _ => merged.push(sp),
        }
    }
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    for (start, end, label) in merged {
        out.push_str(&s[pos..start]);
        out.push_str("[REDACTED:");
        out.push_str(label);
        out.push(']');
        pos = end;
    }
    out.push_str(&s[pos..]);
    Some(out)
}

#[cfg(test)]
mod tests;
