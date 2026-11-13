//! YAML rule language: argument-predicate rules and temporal sequence rules.
//!
//! Rules are indexed by exact tool name so evaluation only touches rules that
//! can apply to the tool being called; rules whose tool is a glob live in a
//! separate list. See the crate docs for the file format.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use serde_json::Value;

use nandi_core::util::glob_match;
use nandi_core::{Capability, Category, Error, Finding, Result, Severity, Verdict};

use crate::matcher::{ArgPath, ArgsMatcher};
use crate::{Action, HistoryEntry, Outcome, PolicyInput, SessionFacts};

/// Upper bound on compiled regexes across all rule files.
const MAX_REGEXES: usize = 2048;

/// What a rule does when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Explicit permit (satisfies default deny); produces no finding.
    Allow,
    Alert,
    Redact,
    Ask,
    Deny,
}

impl RuleAction {
    fn verdict(self) -> Option<Verdict> {
        match self {
            RuleAction::Allow => None,
            RuleAction::Alert => Some(Verdict::Alert),
            RuleAction::Redact => Some(Verdict::Redact),
            RuleAction::Ask => Some(Verdict::Ask),
            RuleAction::Deny => Some(Verdict::Deny),
        }
    }
}

fn default_action() -> RuleAction {
    RuleAction::Deny
}

/// Which kind of action a rule applies to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    #[default]
    ToolCall,
    ListTools,
    Llm,
    A2a,
}

impl RuleKind {
    fn as_str(self) -> &'static str {
        match self {
            RuleKind::ToolCall => "tool_call",
            RuleKind::ListTools => "list_tools",
            RuleKind::Llm => "llm",
            RuleKind::A2a => "a2a",
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    rules: Vec<RawRule>,
    #[serde(default)]
    sequences: Vec<RawSequence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, rename = "match")]
    matcher: RawMatch,
    #[serde(default = "default_action")]
    action: RuleAction,
    #[serde(default)]
    severity: Option<Severity>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMatch {
    #[serde(default)]
    kind: RuleKind,
    agent: Option<String>,
    group: Option<String>,
    server: Option<String>,
    tool: Option<String>,
    capability: Option<OneOrMany>,
    provider: Option<String>,
    model: Option<String>,
    peer: Option<String>,
    skill: Option<String>,
    method: Option<String>,
    #[serde(default)]
    args: Value,
    #[serde(default)]
    session: SessionCond,
}

/// A single string or a list of strings.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

/// Capability names or globs; matches when any of the tool's capabilities
/// matches any pattern.
#[derive(Debug, Clone, Default)]
struct CapabilityMatcher {
    patterns: Vec<String>,
}

impl CapabilityMatcher {
    /// Validate patterns: plain names must be known capabilities and globs
    /// must match at least one, so a typo can never disable a rule.
    fn parse(patterns: Vec<String>) -> std::result::Result<Self, String> {
        if patterns.is_empty() {
            return Err("`capability` needs at least one name".into());
        }
        for p in &patterns {
            let known = if p.contains(['*', '?']) {
                Capability::ALL.iter().any(|c| glob_match(p, c.as_str()))
            } else {
                p.parse::<Capability>().is_ok()
            };
            if !known {
                let names: Vec<&str> = Capability::ALL.iter().map(Capability::as_str).collect();
                return Err(format!("unknown capability `{p}` (one of {})", names.join(", ")));
            }
        }
        Ok(Self { patterns })
    }

    fn matches(&self, caps: &[Capability]) -> bool {
        caps.iter().any(|c| self.patterns.iter().any(|p| glob_match(p, c.as_str())))
    }
}

/// Conditions on the session's accumulated facts.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCond {
    pub tainted: Option<bool>,
    pub risk_gte: Option<f32>,
    pub risk_lt: Option<f32>,
    pub calls_gte: Option<u64>,
    pub calls_lt: Option<u64>,
}

impl SessionCond {
    fn is_empty(&self) -> bool {
        *self == SessionCond::default()
    }

    fn matches(&self, s: &SessionFacts) -> bool {
        self.tainted.is_none_or(|t| t == s.tainted)
            && self.risk_gte.is_none_or(|r| s.risk >= r)
            && self.risk_lt.is_none_or(|r| s.risk < r)
            && self.calls_gte.is_none_or(|c| s.calls >= c)
            && self.calls_lt.is_none_or(|c| s.calls < c)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSequence {
    id: String,
    #[serde(default)]
    description: Option<String>,
    tool: String,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    args: Value,
    #[serde(default)]
    requires_prior: Option<RawPrior>,
    #[serde(default)]
    forbid_after: Option<RawPrior>,
    #[serde(default = "default_action")]
    action: RuleAction,
    #[serde(default)]
    severity: Option<Severity>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrior {
    tool: String,
    #[serde(default)]
    args: Value,
    #[serde(default)]
    success: bool,
    #[serde(default)]
    same_args: Vec<String>,
    #[serde(default)]
    within_calls: Option<usize>,
}

/// A tool pattern split into an optional server glob and a tool glob.
#[derive(Debug, Clone)]
struct ToolPattern {
    server: Option<String>,
    tool: String,
}

impl ToolPattern {
    fn parse(pattern: &str) -> Self {
        match pattern.split_once('/') {
            Some((s, t)) => Self { server: Some(s.to_owned()), tool: t.to_owned() },
            None => Self { server: None, tool: pattern.to_owned() },
        }
    }

    fn matches(&self, server: &str, tool: &str) -> bool {
        self.server.as_deref().is_none_or(|s| glob_match(s, server)) && glob_match(&self.tool, tool)
    }

    /// Lowercased tool name when the tool part has no wildcards.
    fn exact_key(&self) -> Option<String> {
        (!self.tool.contains(['*', '?'])).then(|| self.tool.to_lowercase())
    }
}

/// Index of items by exact (case-insensitive) tool name plus a list of glob
/// items. Candidate iteration yields indices in declaration order.
#[derive(Debug, Default)]
struct ToolIndex {
    exact: HashMap<String, Vec<usize>>,
    glob: Vec<usize>,
}

impl ToolIndex {
    fn insert(&mut self, key: Option<String>, idx: usize) {
        match key {
            Some(k) => self.exact.entry(k).or_default().push(idx),
            None => self.glob.push(idx),
        }
    }

    /// Merge the exact and glob candidate lists (both ascending).
    fn candidates<'s>(&'s self, tool: &str) -> impl Iterator<Item = usize> + 's {
        let key: Cow<'_, str> =
            if tool.chars().any(char::is_uppercase) { Cow::Owned(tool.to_lowercase()) } else { Cow::Borrowed(tool) };
        let exact: &[usize] = self.exact.get(key.as_ref()).map_or(&[], Vec::as_slice);
        let (mut i, mut j) = (0usize, 0usize);
        let glob = &self.glob;
        std::iter::from_fn(move || {
            let next = match (exact.get(i), glob.get(j)) {
                (Some(&a), Some(&b)) if a < b => {
                    i += 1;
                    a
                }
                (_, Some(&b)) => {
                    j += 1;
                    b
                }
                (Some(&a), None) => {
                    i += 1;
                    a
                }
                (None, None) => return None,
            };
            Some(next)
        })
    }
}

/// A compiled rule.
#[derive(Debug)]
struct Rule {
    id: String,
    kind: RuleKind,
    agent: Option<String>,
    group: Option<String>,
    server: Option<String>,
    tool: Option<ToolPattern>,
    capability: Option<CapabilityMatcher>,
    provider: Option<String>,
    model: Option<String>,
    peer: Option<String>,
    skill: Option<String>,
    method: Option<String>,
    args: ArgsMatcher,
    session: SessionCond,
    action: RuleAction,
    severity: Severity,
    message: String,
}

fn opt_glob(pattern: &Option<String>, text: &str) -> bool {
    pattern.as_deref().is_none_or(|p| glob_match(p, text))
}

impl Rule {
    fn matches_principal(&self, agent: &str, groups: &[String]) -> bool {
        opt_glob(&self.agent, agent) && self.group.as_deref().is_none_or(|p| groups.iter().any(|g| glob_match(p, g)))
    }

    fn matches_tool(&self, server: &str, tool: &str, caps: &[Capability]) -> bool {
        opt_glob(&self.server, server)
            && self.tool.as_ref().is_none_or(|t| t.matches(server, tool))
            && self.capability.as_ref().is_none_or(|c| c.matches(caps))
    }

    fn matches(&self, input: &PolicyInput<'_>) -> bool {
        if !self.matches_principal(input.agent, input.groups) || !self.session.matches(&input.session) {
            return false;
        }
        match input.action {
            Action::CallTool { server, tool, args } => {
                self.matches_tool(server, tool, input.capabilities) && self.args.matches(args)
            }
            Action::ListTools { server } => opt_glob(&self.server, server),
            Action::LlmRequest { provider, model } => {
                opt_glob(&self.provider, provider) && opt_glob(&self.model, model)
            }
            Action::A2aSend { peer, skill, method } => {
                opt_glob(&self.peer, peer)
                    && opt_glob(&self.method, method)
                    && self.skill.as_deref().is_none_or(|p| skill.is_some_and(|s| glob_match(p, s)))
            }
        }
    }

    fn finding(&self, verdict: Verdict) -> Finding {
        Finding::new(format!("policy.{}", self.id), Category::Policy, self.severity, verdict, self.message.clone())
    }
}

#[derive(Debug)]
enum SeqKind {
    RequiresPrior,
    ForbidAfter,
}

#[derive(Debug)]
struct Prior {
    tool: ToolPattern,
    args: ArgsMatcher,
    success: bool,
    same_args: Vec<ArgPath>,
    within_calls: Option<usize>,
}

impl Prior {
    fn matches(&self, entry: &HistoryEntry, current: &Value) -> bool {
        (!self.success || entry.ok)
            && self.tool.matches(&entry.server, &entry.tool)
            && self.args.matches(&entry.args)
            && self.same_args.iter().all(|p| match (p.lookup(current), p.lookup(&entry.args)) {
                (Some(a), Some(b)) => crate::matcher::json_eq(a, b),
                _ => false,
            })
    }

    fn window<'h>(&self, history: &'h [HistoryEntry]) -> &'h [HistoryEntry] {
        match self.within_calls {
            Some(n) if n < history.len() => &history[history.len() - n..],
            _ => history,
        }
    }
}

/// A compiled temporal sequence rule.
#[derive(Debug)]
struct Sequence {
    id: String,
    tool: ToolPattern,
    agent: Option<String>,
    args: ArgsMatcher,
    kind: SeqKind,
    prior: Prior,
    verdict: Verdict,
    severity: Severity,
    message: String,
}

/// All YAML rules and sequences, compiled and indexed.
#[derive(Debug, Default)]
pub(crate) struct RuleBook {
    rules: Vec<Rule>,
    /// Indices of `tool_call` rules.
    tool_index: ToolIndex,
    /// Indices of rules for the other action kinds.
    list_rules: Vec<usize>,
    llm_rules: Vec<usize>,
    a2a_rules: Vec<usize>,
    sequences: Vec<Sequence>,
    seq_index: ToolIndex,
    warnings: Vec<String>,
}

fn policy_err(source: &str, msg: impl std::fmt::Display) -> Error {
    Error::Policy(format!("{source}: {msg}"))
}

impl RuleBook {
    /// Compile rule files given as `(name, yaml text)` pairs.
    pub(crate) fn load(files: &[(String, &str)]) -> Result<Self> {
        let mut book = RuleBook::default();
        let mut rule_ids = HashSet::new();
        let mut seq_ids = HashSet::new();
        let mut regexes = 0usize;
        for (name, text) in files {
            if text.trim().is_empty() {
                continue;
            }
            let raw: Option<RawFile> = serde_saphyr::from_str(text).map_err(|e| policy_err(name, e))?;
            let Some(raw) = raw else { continue };
            for r in raw.rules {
                let ctx = format!("{name}: rule `{}`", r.id);
                if !rule_ids.insert(r.id.clone()) {
                    return Err(Error::Policy(format!("{ctx}: duplicate rule id")));
                }
                let rule = compile_rule(r, &ctx, &mut book.warnings)?;
                regexes += rule.args.regex_count();
                let idx = book.rules.len();
                match rule.kind {
                    RuleKind::ToolCall => {
                        book.tool_index.insert(rule.tool.as_ref().and_then(ToolPattern::exact_key), idx)
                    }
                    RuleKind::ListTools => book.list_rules.push(idx),
                    RuleKind::Llm => book.llm_rules.push(idx),
                    RuleKind::A2a => book.a2a_rules.push(idx),
                }
                book.rules.push(rule);
            }
            for s in raw.sequences {
                let ctx = format!("{name}: sequence `{}`", s.id);
                if !seq_ids.insert(s.id.clone()) {
                    return Err(Error::Policy(format!("{ctx}: duplicate sequence id")));
                }
                let seq = compile_sequence(s, &ctx, &mut book.warnings)?;
                regexes += seq.args.regex_count() + seq.prior.args.regex_count();
                book.seq_index.insert(seq.tool.exact_key(), book.sequences.len());
                book.sequences.push(seq);
            }
        }
        if regexes > MAX_REGEXES {
            return Err(Error::Policy(format!(
                "rule files compile {regexes} regexes, more than the limit of {MAX_REGEXES}"
            )));
        }
        Ok(book)
    }

    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Apply matching rules and sequences to `input`, appending to `out`.
    pub(crate) fn evaluate(&self, input: &PolicyInput<'_>, history: &[HistoryEntry], out: &mut Outcome) {
        match input.action {
            Action::CallTool { server, tool, args } => {
                for idx in self.tool_index.candidates(tool) {
                    self.apply(idx, input, out);
                }
                for idx in self.seq_index.candidates(tool) {
                    let seq = &self.sequences[idx];
                    if let Some(f) = check_sequence(seq, input.agent, server, tool, args, history) {
                        out.findings.push(f);
                    }
                }
            }
            Action::ListTools { .. } => self.list_rules.iter().for_each(|&i| self.apply(i, input, out)),
            Action::LlmRequest { .. } => self.llm_rules.iter().for_each(|&i| self.apply(i, input, out)),
            Action::A2aSend { .. } => self.a2a_rules.iter().for_each(|&i| self.apply(i, input, out)),
        }
    }

    fn apply(&self, idx: usize, input: &PolicyInput<'_>, out: &mut Outcome) {
        let rule = &self.rules[idx];
        if rule.matches(input) {
            match rule.action.verdict() {
                Some(v) => out.findings.push(rule.finding(v)),
                None => out.permitted = true,
            }
        }
    }

    /// Static view of a tool for `tools/list` filtering.
    ///
    /// Returns `(always_denied, allow_possible)`: whether an unconditional
    /// deny rule covers the tool for this principal, and whether some allow
    /// rule could permit it for some arguments / session state.
    pub(crate) fn tool_status(
        &self,
        agent: &str,
        groups: &[String],
        server: &str,
        tool: &str,
        caps: &[Capability],
    ) -> (bool, bool) {
        let mut allow_possible = false;
        for idx in self.tool_index.candidates(tool) {
            let rule = &self.rules[idx];
            if !rule.matches_principal(agent, groups) || !rule.matches_tool(server, tool, caps) {
                continue;
            }
            match rule.action {
                RuleAction::Allow => allow_possible = true,
                RuleAction::Deny if rule.args.is_empty() && rule.session.is_empty() => return (true, allow_possible),
                _ => {}
            }
        }
        (false, allow_possible)
    }
}

fn compile_rule(r: RawRule, ctx: &str, warnings: &mut Vec<String>) -> Result<Rule> {
    let m = r.matcher;
    use RuleKind::*;
    // Fields that only make sense for some kinds: (is set, name, kinds it applies to).
    let fields: [(bool, &str, &[RuleKind]); 9] = [
        (m.server.is_some(), "server", &[ToolCall, ListTools]),
        (m.tool.is_some(), "tool", &[ToolCall]),
        (m.capability.is_some(), "capability", &[ToolCall]),
        (!m.args.is_null(), "args", &[ToolCall]),
        (m.provider.is_some(), "provider", &[Llm]),
        (m.model.is_some(), "model", &[Llm]),
        (m.peer.is_some(), "peer", &[A2a]),
        (m.skill.is_some(), "skill", &[A2a]),
        (m.method.is_some(), "method", &[A2a]),
    ];
    for (set, name, kinds) in fields {
        if set && !kinds.contains(&m.kind) {
            warnings.push(format!("{ctx}: `{name}` is ignored for kind {}", m.kind.as_str()));
        }
    }
    if let Some(r) = m.session.risk_gte.into_iter().chain(m.session.risk_lt).find(|r| !(0.0..=1.0).contains(r)) {
        warnings.push(format!("{ctx}: session risk bound {r} is outside 0.0-1.0"));
    }
    let args = ArgsMatcher::parse(&m.args).map_err(|e| Error::Policy(format!("{ctx}: {e}")))?;
    let capability = m
        .capability
        .map(|c| CapabilityMatcher::parse(c.into_vec()))
        .transpose()
        .map_err(|e| Error::Policy(format!("{ctx}: {e}")))?;
    let message = r.message.or(r.description).unwrap_or_else(|| format!("matched policy rule {}", r.id));
    Ok(Rule {
        kind: m.kind,
        agent: m.agent,
        group: m.group,
        server: m.server,
        tool: m.tool.as_deref().map(ToolPattern::parse),
        capability,
        provider: m.provider,
        model: m.model,
        peer: m.peer,
        skill: m.skill,
        method: m.method,
        args,
        session: m.session,
        action: r.action,
        severity: r.severity.unwrap_or(Severity::Medium),
        message,
        id: r.id,
    })
}

fn compile_sequence(s: RawSequence, ctx: &str, warnings: &mut Vec<String>) -> Result<Sequence> {
    let err = |e: String| Error::Policy(format!("{ctx}: {e}"));
    let (kind, prior) = match (s.requires_prior, s.forbid_after) {
        (Some(p), None) => (SeqKind::RequiresPrior, p),
        (None, Some(p)) => (SeqKind::ForbidAfter, p),
        _ => return Err(err("exactly one of `requires_prior` or `forbid_after` is required".into())),
    };
    let verdict = s.action.verdict().ok_or_else(|| err("`allow` is not a valid sequence action".into()))?;
    if prior.within_calls == Some(0) {
        warnings.push(format!("{ctx}: `within_calls: 0` looks at no history"));
    }
    if matches!(kind, SeqKind::ForbidAfter) && !prior.same_args.is_empty() {
        warnings.push(format!("{ctx}: `same_args` narrows `forbid_after` to calls with equal arguments"));
    }
    let same_args = prior.same_args.iter().map(|p| ArgPath::parse(p)).collect::<Result<Vec<_>, _>>().map_err(err)?;
    let default_msg = match kind {
        SeqKind::RequiresPrior => {
            let ok = if prior.success { "successful " } else { "" };
            format!("`{}` requires a prior {ok}call to `{}`", s.tool, prior.tool)
        }
        SeqKind::ForbidAfter => format!("`{}` is not allowed after `{}`", s.tool, prior.tool),
    };
    Ok(Sequence {
        tool: ToolPattern::parse(&s.tool),
        agent: s.agent,
        args: ArgsMatcher::parse(&s.args).map_err(err)?,
        kind,
        prior: Prior {
            tool: ToolPattern::parse(&prior.tool),
            args: ArgsMatcher::parse(&prior.args).map_err(err)?,
            success: prior.success,
            same_args,
            within_calls: prior.within_calls,
        },
        verdict,
        severity: s.severity.unwrap_or(Severity::Medium),
        message: s.message.or(s.description).unwrap_or(default_msg),
        id: s.id,
    })
}

fn check_sequence(
    seq: &Sequence,
    agent: &str,
    server: &str,
    tool: &str,
    args: &Value,
    history: &[HistoryEntry],
) -> Option<Finding> {
    if !opt_glob(&seq.agent, agent) || !seq.tool.matches(server, tool) || !seq.args.matches(args) {
        return None;
    }
    let mut window = seq.prior.window(history).iter().rev();
    let violated = match seq.kind {
        SeqKind::RequiresPrior => !window.any(|e| seq.prior.matches(e, args)),
        SeqKind::ForbidAfter => window.any(|e| seq.prior.matches(e, args)),
    };
    violated.then(|| {
        Finding::new(format!("sequence.{}", seq.id), Category::Temporal, seq.severity, seq.verdict, seq.message.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn book(yaml: &str) -> RuleBook {
        RuleBook::load(&[("test.yaml".into(), yaml)]).unwrap()
    }

    fn call<'a>(
        agent: &'a str,
        groups: &'a [String],
        server: &'a str,
        tool: &'a str,
        args: &'a Value,
    ) -> PolicyInput<'a> {
        PolicyInput::new(agent, groups, SessionFacts::default(), Action::CallTool { server, tool, args })
    }

    fn run(book: &RuleBook, input: &PolicyInput<'_>, history: &[HistoryEntry]) -> Outcome {
        let mut out = Outcome::default();
        book.evaluate(input, history, &mut out);
        out
    }

    fn hist(server: &str, tool: &str, args: Value, ok: bool) -> HistoryEntry {
        HistoryEntry { ts_ms: 0, server: server.into(), tool: tool.into(), args, ok }
    }

    #[test]
    fn index_merges_exact_and_glob_in_order() {
        let mut idx = ToolIndex::default();
        idx.insert(None, 0);
        idx.insert(Some("read_file".into()), 1);
        idx.insert(Some("other".into()), 2);
        idx.insert(None, 3);
        idx.insert(Some("read_file".into()), 4);
        assert_eq!(idx.candidates("READ_FILE").collect::<Vec<_>>(), vec![0, 1, 3, 4]);
        assert_eq!(idx.candidates("nothing").collect::<Vec<_>>(), vec![0, 3]);
        assert_eq!(ToolIndex::default().candidates("x").count(), 0);
    }

    #[test]
    fn exact_and_glob_rules() {
        let b = book(
            r#"
rules:
  - id: no-prod-delete
    match: { server: "db*", tool: "delete_*", args: { table: { in: [users, payments] } } }
    action: deny
    severity: high
  - id: shell
    match: { tool: "run_shell" }
    action: ask
  - id: gh-issues
    match: { tool: "github/create_issue" }
    action: alert
"#,
        );
        assert_eq!(b.tool_index.glob, vec![0]);
        assert_eq!(b.tool_index.exact["run_shell"], vec![1]);
        assert_eq!(b.tool_index.exact["create_issue"], vec![2]);
        let args = json!({"table": "users"});
        let out = run(&b, &call("a", &[], "db-prod", "delete_rows", &args), &[]);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule, "policy.no-prod-delete");
        assert_eq!(out.findings[0].severity, Severity::High);
        assert_eq!(out.findings[0].verdict, Verdict::Deny);
        let other = json!({"table": "logs"});
        assert!(run(&b, &call("a", &[], "db-prod", "delete_rows", &other), &[]).findings.is_empty());
        assert!(run(&b, &call("a", &[], "fs", "delete_rows", &args), &[]).findings.is_empty());
        let none = json!({});
        let out = run(&b, &call("a", &[], "local", "Run_Shell", &none), &[]);
        assert_eq!(out.findings[0].verdict, Verdict::Ask);
        assert_eq!(out.findings[0].severity, Severity::Medium);
        assert_eq!(run(&b, &call("a", &[], "github", "create_issue", &none), &[]).findings.len(), 1);
        assert!(run(&b, &call("a", &[], "gitlab", "create_issue", &none), &[]).findings.is_empty());
    }

    #[test]
    fn principal_and_session_conditions() {
        let b = book(
            r#"
rules:
  - id: finance-only
    match: { agent: "bot-*", group: "fin*", tool: "pay" }
    action: allow
  - id: tainted-net
    match: { tool: "http_*", session: { tainted: true, risk_gte: 0.5 } }
    action: deny
    message: no network once tainted
  - id: chatty
    match: { session: { calls_gte: 100, calls_lt: 200 } }
    action: alert
"#,
        );
        let none = json!({});
        let fin = vec!["finance".to_string()];
        assert!(run(&b, &call("bot-1", &fin, "s", "pay", &none), &[]).permitted);
        assert!(!run(&b, &call("bot-1", &[], "s", "pay", &none), &[]).permitted);
        assert!(!run(&b, &call("human", &fin, "s", "pay", &none), &[]).permitted);

        let mut input = call("a", &[], "s", "http_get", &none);
        assert!(run(&b, &input, &[]).findings.is_empty());
        input.session = SessionFacts { tainted: true, risk: 0.7, calls: 0 };
        let out = run(&b, &input, &[]);
        assert_eq!(out.findings[0].rule, "policy.tainted-net");
        assert_eq!(out.findings[0].message, "no network once tainted");
        input.session.risk = 0.2;
        assert!(run(&b, &input, &[]).findings.is_empty());
        input.session.calls = 150;
        assert_eq!(run(&b, &input, &[]).findings[0].rule, "policy.chatty");
        input.session.calls = 250;
        assert!(run(&b, &input, &[]).findings.is_empty());
    }

    #[test]
    fn non_tool_kinds() {
        let b = book(
            r#"
rules:
  - id: no-gpt3
    match: { kind: llm, provider: openai, model: "gpt-3*" }
  - id: list-secret
    match: { kind: list_tools, server: "vault" }
    action: alert
  - id: a2a-pay
    match: { kind: a2a, peer: "*.partner.com", skill: "pay*", method: "message/*" }
    action: ask
"#,
        );
        let mk = |action| PolicyInput::new("a", &[], SessionFacts::default(), action);
        let out = run(&b, &mk(Action::LlmRequest { provider: "openai", model: "gpt-3.5-turbo" }), &[]);
        assert_eq!(out.findings[0].verdict, Verdict::Deny);
        assert!(run(&b, &mk(Action::LlmRequest { provider: "openai", model: "gpt-4o" }), &[]).findings.is_empty());
        assert_eq!(run(&b, &mk(Action::ListTools { server: "vault" }), &[]).findings[0].verdict, Verdict::Alert);
        let a2a = Action::A2aSend { peer: "x.partner.com", skill: Some("payments"), method: "message/send" };
        assert_eq!(run(&b, &mk(a2a), &[]).findings[0].verdict, Verdict::Ask);
        let a2a = Action::A2aSend { peer: "x.partner.com", skill: None, method: "message/send" };
        assert!(run(&b, &mk(a2a), &[]).findings.is_empty());
        let args = json!({});
        assert!(run(&b, &call("a", &[], "vault", "x", &args), &[]).findings.is_empty());
    }

    #[test]
    fn requires_prior_with_same_args_success_and_window() {
        let b = book(
            r#"
sequences:
  - id: refund-needs-verification
    tool: "refund*"
    requires_prior:
      tool: "verify_identity"
      success: true
      same_args: [user_id]
      within_calls: 3
    action: deny
"#,
        );
        let args = json!({"user_id": "u1", "amount": 10});
        let input = call("a", &[], "shop", "refund_order", &args);
        let out = run(&b, &input, &[]);
        assert_eq!(out.findings[0].rule, "sequence.refund-needs-verification");
        assert_eq!(out.findings[0].category, Category::Temporal);

        let good = hist("crm", "verify_identity", json!({"user_id": "u1"}), true);
        assert!(run(&b, &input, std::slice::from_ref(&good)).findings.is_empty());
        let failed = hist("crm", "verify_identity", json!({"user_id": "u1"}), false);
        assert_eq!(run(&b, &input, &[failed]).findings.len(), 1);
        let other_user = hist("crm", "verify_identity", json!({"user_id": "u2"}), true);
        assert_eq!(run(&b, &input, &[other_user]).findings.len(), 1);

        let filler = hist("x", "noop", json!({}), true);
        let old = vec![good.clone(), filler.clone(), filler.clone(), filler.clone()];
        assert_eq!(run(&b, &input, &old).findings.len(), 1);
        let recent = vec![filler.clone(), good, filler.clone(), filler];
        assert!(run(&b, &input, &recent).findings.is_empty());

        let no_user = json!({"amount": 10});
        let h = [hist("crm", "verify_identity", json!({}), true)];
        assert_eq!(run(&b, &call("a", &[], "shop", "refund_order", &no_user), &h).findings.len(), 1);
    }

    #[test]
    fn forbid_after() {
        let b = book(
            r#"
sequences:
  - id: no-net-after-secret-read
    tool: "http_*"
    forbid_after:
      tool: "fs/read_file"
      args: { path: { regex: "(\\.env|id_rsa|credentials)" } }
    action: ask
    severity: high
"#,
        );
        let args = json!({"url": "https://x"});
        let input = call("a", &[], "net", "http_post", &args);
        let benign = hist("fs", "read_file", json!({"path": "README.md"}), true);
        assert!(run(&b, &input, std::slice::from_ref(&benign)).findings.is_empty());
        let secret = hist("fs", "read_file", json!({"path": "/home/u/.ssh/id_rsa"}), false);
        let out = run(&b, &input, &[secret.clone(), benign]);
        assert_eq!(out.findings[0].verdict, Verdict::Ask);
        assert_eq!(out.findings[0].severity, Severity::High);
        let wrong_server = hist("other", "read_file", json!({"path": ".env"}), true);
        assert!(run(&b, &input, &[wrong_server]).findings.is_empty());
        assert!(run(&b, &call("a", &[], "net", "dns_lookup", &args), &[secret]).findings.is_empty());
    }

    #[test]
    fn tool_status_is_static() {
        let b = book(
            r#"
rules:
  - id: block-shell
    match: { tool: "run_shell", agent: "untrusted-*" }
  - id: block-conditional
    match: { tool: "write_file", args: { path: { prefix: "/etc" } } }
  - id: allow-read
    match: { tool: "read_*" }
    action: allow
"#,
        );
        assert_eq!(b.tool_status("untrusted-1", &[], "s", "run_shell", &[]), (true, false));
        assert_eq!(b.tool_status("trusted", &[], "s", "run_shell", &[]), (false, false));
        assert_eq!(b.tool_status("x", &[], "s", "write_file", &[]), (false, false));
        assert_eq!(b.tool_status("x", &[], "s", "read_file", &[]), (false, true));
    }

    #[test]
    fn capability_rules() {
        let b = book(
            r#"
rules:
  - id: payments-need-approval
    match: { capability: payment }
    action: ask
  - id: no-destruction
    match: { capability: ["data_deletion", "file_*"], server: "prod*" }
  - id: watch-admin
    match: { tool: "*", capability: "identity_*" }
    action: alert
"#,
        );
        let none = json!({});
        let pay = [Capability::Payment, Capability::ExternalSend];
        let out = run(&b, &call("a", &[], "stripe", "create_refund", &none).with_capabilities(&pay), &[]);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule, "policy.payments-need-approval");
        assert_eq!(out.findings[0].verdict, Verdict::Ask);
        // Without capabilities a capability rule never matches.
        assert!(run(&b, &call("a", &[], "stripe", "create_refund", &none), &[]).findings.is_empty());
        let fw = [Capability::FileWrite];
        let out = run(&b, &call("a", &[], "prod-fs", "write", &none).with_capabilities(&fw), &[]);
        assert_eq!(out.findings[0].rule, "policy.no-destruction");
        assert!(run(&b, &call("a", &[], "dev-fs", "write", &none).with_capabilities(&fw), &[]).findings.is_empty());
        let admin = [Capability::IdentityAdmin];
        let out = run(&b, &call("a", &[], "gh", "add_member", &none).with_capabilities(&admin), &[]);
        assert_eq!(out.findings[0].verdict, Verdict::Alert);

        // Capabilities are static, so unconditional capability denies hide tools.
        let del = [Capability::DataDeletion];
        assert_eq!(b.tool_status("a", &[], "prod-db", "drop_table", &del), (true, false));
        assert_eq!(b.tool_status("a", &[], "prod-db", "drop_table", &[]), (false, false));

        let load = |y: &str| RuleBook::load(&[("f.yaml".into(), y)]);
        let err = load("rules:\n  - id: a\n    match: { capability: paymnet }\n").unwrap_err().to_string();
        assert!(err.contains("unknown capability `paymnet`"), "{err}");
        assert!(load("rules:\n  - id: a\n    match: { capability: \"zz*\" }\n").is_err());
        assert!(load("rules:\n  - id: a\n    match: { capability: [] }\n").is_err());
        let w = load("rules:\n  - id: a\n    match: { kind: llm, capability: payment }\n").unwrap();
        assert_eq!(w.warnings().len(), 1, "{:?}", w.warnings());
    }

    #[test]
    fn load_errors_and_warnings() {
        let load = |y: &str| RuleBook::load(&[("f.yaml".into(), y)]);
        assert!(load("rules:\n  - id: a\n    match: { tool: x, toool: y }\n").is_err());
        assert!(load("rule: []\n").is_err());
        assert!(load("rules:\n  - id: a\n    action: maybe\n").is_err());
        assert!(load("rules:\n  - id: a\n  - id: a\n").is_err());
        assert!(load("rules:\n  - id: a\n    match: { args: { p: { regex: '(' } } }\n").is_err());
        assert!(load("sequences:\n  - id: s\n    tool: x\n").is_err());
        assert!(
            load("sequences:\n  - id: s\n    tool: x\n    action: allow\n    forbid_after: { tool: y }\n").is_err()
        );
        let both =
            "sequences:\n  - id: s\n    tool: x\n    forbid_after: { tool: y }\n    requires_prior: { tool: z }\n";
        assert!(load(both).is_err());
        let err = load("rules:\n  - id: a\n    match: { tool: x, toool: y }\n").unwrap_err().to_string();
        assert!(err.contains("f.yaml"), "{err}");

        assert!(load("").unwrap().rules.is_empty());
        assert!(load("# only a comment\n").unwrap().rules.is_empty());
        let b = load("rules:\n  - id: a\n    match: { kind: llm, tool: x, args: { a: 1 } }\n").unwrap();
        assert_eq!(b.warnings().len(), 2, "{:?}", b.warnings());
    }
}
