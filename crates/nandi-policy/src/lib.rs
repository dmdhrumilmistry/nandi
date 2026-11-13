//! Deterministic authorization for agent actions.
//!
//! A [`PolicySet`] combines three sources, all evaluated on every action:
//!
//! - YAML rules: argument predicates with graded actions (`allow`, `alert`,
//!   `redact`, `ask`, `deny`), indexed by tool name so evaluation cost does
//!   not grow with the number of unrelated rules.
//! - YAML sequences: temporal rules over the session's call history
//!   (`requires_prior`, `forbid_after`).
//! - Cedar policies, evaluated schema-less over per-request entities.
//!
//! [`PlanTracker`] implements plan-locked execution for sessions that declare
//! a plan up front.
//!
//! # Rule file format
//!
//! ```yaml
//! rules:
//!   - id: no-prod-delete
//!     description: optional, used as the message when `message` is absent
//!     match:
//!       kind: tool_call          # tool_call (default) | list_tools | llm | a2a
//!       agent: "*"               # globs, case-insensitive
//!       group: "finance"         # agent must be in a matching group
//!       server: "db*"
//!       tool: "delete_*"         # may be "server/tool"
//!       capability: payment      # name, glob or list; any of the tool's capabilities
//!       provider: "openai"       # llm
//!       model: "gpt-*"           # llm
//!       peer: "*.example.com"    # a2a
//!       skill: "pay*"            # a2a
//!       method: "message/*"      # a2a
//!       args:
//!         table: { in: [users, payments] }
//!         "options.force": true
//!       session: { tainted: true, risk_gte: 0.5, risk_lt: 1.0, calls_gte: 100, calls_lt: 500 }
//!     action: deny               # allow | alert | redact | ask | deny (default deny)
//!     severity: high             # default medium
//!     message: "..."
//! sequences:
//!   - id: refund-needs-verification
//!     tool: "refund*"
//!     agent: "*"                 # optional
//!     args: {}                   # optional matcher on the current call
//!     requires_prior:            # or forbid_after, exactly one
//!       tool: verify_identity
//!       args: {}                 # optional matcher on the prior call
//!       success: true            # only count calls with ok = true
//!       same_args: [user_id]     # must be present and equal in both calls
//!       within_calls: 50         # only the last N history entries
//!     action: deny
//! ```
//!
//! Unknown fields are load errors so a typo can never silently disable a
//! rule. Matcher operators are documented in [`matcher`].

mod cedar;
pub mod matcher;
pub mod packs;
mod plan;
mod rules;

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use nandi_core::config::{DefaultAction, PolicyConfig};
use nandi_core::{Capability, Category, Error, Finding, Result, Severity, Verdict};

pub use plan::PlanTracker;
pub use rules::{RuleAction, RuleKind, SessionCond};

use cedar::CedarEngine;
use rules::RuleBook;

/// The action being authorized.
#[derive(Debug, Clone, Copy)]
pub enum Action<'a> {
    /// A tool call on an MCP server (or a local tool namespace).
    CallTool { server: &'a str, tool: &'a str, args: &'a Value },
    /// Listing a server's tools.
    ListTools { server: &'a str },
    /// A request to an LLM provider.
    LlmRequest { provider: &'a str, model: &'a str },
    /// An outgoing agent-to-agent message.
    A2aSend { peer: &'a str, skill: Option<&'a str>, method: &'a str },
}

/// Facts about the session that rules may condition on.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SessionFacts {
    /// Untrusted content has entered the session's context.
    pub tainted: bool,
    /// Accumulated risk, 0.0 - 1.0.
    pub risk: f32,
    /// Tool calls made so far in the session.
    pub calls: u64,
}

/// Everything a policy decision needs, borrowed from the caller.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInput<'a> {
    pub agent: &'a str,
    pub groups: &'a [String],
    pub session: SessionFacts,
    pub action: Action<'a>,
    /// Capabilities of the called tool (`CallTool` only). Empty when
    /// unknown; rules with `match.capability` then do not match.
    pub capabilities: &'a [Capability],
}

impl<'a> PolicyInput<'a> {
    /// Input without capabilities.
    pub fn new(agent: &'a str, groups: &'a [String], session: SessionFacts, action: Action<'a>) -> Self {
        Self { agent, groups, session, action, capabilities: &[] }
    }

    /// The same input with the called tool's capabilities.
    pub fn with_capabilities(mut self, capabilities: &'a [Capability]) -> Self {
        self.capabilities = capabilities;
        self
    }
}

/// One past tool call in the session, oldest first in history slices.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub ts_ms: u64,
    pub server: String,
    pub tool: String,
    pub args: Value,
    /// The call completed without an error.
    pub ok: bool,
}

/// Result of evaluating one action.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Outcome {
    pub findings: Vec<Finding>,
    /// Some rule or Cedar policy explicitly permitted the action.
    pub permitted: bool,
}

impl Outcome {
    /// Most restrictive verdict among the findings.
    pub fn verdict(&self) -> Verdict {
        self.findings.iter().map(|f| f.verdict).max().unwrap_or_default()
    }
}

/// What an in-memory policy document contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// YAML rules, sequences and budgets.
    Rules,
    /// Cedar policies.
    Cedar,
}

/// An in-memory policy document, named for error messages.
#[derive(Debug, Clone)]
pub struct Source {
    pub name: String,
    pub kind: SourceKind,
    pub text: String,
}

/// Compiled, immutable policy state. Cheap to share across threads; hot
/// reload builds a new set and swaps it in.
#[derive(Debug)]
pub struct PolicySet {
    default: DefaultAction,
    rules: RuleBook,
    cedar: Option<CedarEngine>,
}

impl PolicySet {
    /// Load the files named in `cfg`, resolving relative paths against
    /// `base_dir`.
    pub fn load(cfg: &PolicyConfig, base_dir: &Path) -> Result<Self> {
        let read = |p: &Path| -> Result<(String, String)> {
            let path = base_dir.join(p);
            let text = std::fs::read_to_string(&path)
                .map_err(|e| Error::Policy(format!("cannot read {}: {e}", path.display())))?;
            Ok((path.display().to_string(), text))
        };
        let cedar = cfg.cedar.iter().map(|p| read(p)).collect::<Result<Vec<_>>>()?;
        let entities = cfg.cedar_entities.as_deref().map(read).transpose()?;
        let rules = cfg.rules.iter().map(|p| read(p)).collect::<Result<Vec<_>>>()?;
        Self::build(
            cfg.default,
            &cedar.iter().map(|(n, t)| (n.clone(), t.as_str())).collect::<Vec<_>>(),
            entities.as_ref().map(|(n, t)| (n.clone(), t.as_str())),
            &rules.iter().map(|(n, t)| (n.clone(), t.as_str())).collect::<Vec<_>>(),
        )
    }

    /// [`PolicySet::load`] plus in-memory documents (policies written in
    /// the dashboard), compiled together as one set.
    pub fn load_with(cfg: &PolicyConfig, base_dir: &Path, extra: &[Source]) -> Result<Self> {
        let read = |p: &Path| -> Result<(String, String)> {
            let path = base_dir.join(p);
            let text = std::fs::read_to_string(&path)
                .map_err(|e| Error::Policy(format!("cannot read {}: {e}", path.display())))?;
            Ok((path.display().to_string(), text))
        };
        let mut cedar = cfg.cedar.iter().map(|p| read(p)).collect::<Result<Vec<_>>>()?;
        let entities = cfg.cedar_entities.as_deref().map(read).transpose()?;
        let mut rules = cfg.rules.iter().map(|p| read(p)).collect::<Result<Vec<_>>>()?;
        for s in extra {
            let named = (s.name.clone(), s.text.clone());
            match s.kind {
                SourceKind::Rules => rules.push(named),
                SourceKind::Cedar => cedar.push(named),
            }
        }
        Self::build(
            cfg.default,
            &cedar.iter().map(|(n, t)| (n.clone(), t.as_str())).collect::<Vec<_>>(),
            entities.as_ref().map(|(n, t)| (n.clone(), t.as_str())),
            &rules.iter().map(|(n, t)| (n.clone(), t.as_str())).collect::<Vec<_>>(),
        )
    }

    /// Build from in-memory sources (tests, admin API, embedded configs).
    pub fn from_sources(
        default: DefaultAction,
        cedar: Option<&str>,
        entities_json: Option<&str>,
        rules_yaml: &[&str],
    ) -> Result<Self> {
        let cedar: Vec<(String, &str)> = cedar.map(|c| ("<cedar>".to_owned(), c)).into_iter().collect();
        let rules: Vec<(String, &str)> =
            rules_yaml.iter().enumerate().map(|(i, r)| (format!("<rules #{}>", i + 1), *r)).collect();
        Self::build(default, &cedar, entities_json.map(|e| ("<entities>".to_owned(), e)), &rules)
    }

    fn build(
        default: DefaultAction,
        cedar: &[(String, &str)],
        entities: Option<(String, &str)>,
        rules: &[(String, &str)],
    ) -> Result<Self> {
        let rules = RuleBook::load(rules)?;
        let cedar =
            if cedar.is_empty() && entities.is_none() { None } else { Some(CedarEngine::load(cedar, entities)?) };
        Ok(Self { default, rules, cedar })
    }

    /// The configured default action.
    pub fn default_action(&self) -> DefaultAction {
        self.default
    }

    /// Evaluate an action against rules, sequences and Cedar policies.
    /// `history` holds the session's earlier tool calls, oldest first, not
    /// including the current one.
    pub fn evaluate(&self, input: &PolicyInput<'_>, history: &[HistoryEntry]) -> Outcome {
        let mut out = Outcome::default();
        self.rules.evaluate(input, history, &mut out);
        if let Some(cedar) = &self.cedar {
            cedar.evaluate(input, &mut out);
        }
        let defaultable = !matches!(input.action, Action::ListTools { .. });
        if self.default == DefaultAction::Deny
            && defaultable
            && !out.permitted
            && !out.findings.iter().any(|f| f.verdict == Verdict::Deny)
        {
            out.findings.push(Finding::new(
                "policy.default-deny",
                Category::Policy,
                Severity::Medium,
                Verdict::Deny,
                "no rule or policy permits this action (default deny)",
            ));
        }
        out
    }

    /// Whether a tool should appear in `tools/list` for this principal.
    ///
    /// `false` only when the tool can never be called: an unconditional deny
    /// rule or argument-independent Cedar `forbid` covers it, or the default
    /// is deny and no rule or policy could permit it. Conditions on arguments
    /// and session state are assumed satisfiable, so this over-approximates
    /// visibility and never hides a usable tool. `capabilities` are the
    /// tool's capabilities; they are static, so capability conditions are
    /// decided here.
    pub fn tool_visible(
        &self,
        agent: &str,
        groups: &[String],
        server: &str,
        tool: &str,
        capabilities: &[Capability],
    ) -> bool {
        let (denied, mut allow_possible) = self.rules.tool_status(agent, groups, server, tool, capabilities);
        if denied {
            return false;
        }
        if let Some(cedar) = &self.cedar {
            let (denied, allowed) = cedar.tool_status(agent, groups, server, tool, capabilities);
            if denied {
                return false;
            }
            allow_possible |= allowed;
        }
        self.default == DefaultAction::Allow || allow_possible
    }

    /// Load-time warnings: fields ignored for a rule's kind, duplicate Cedar
    /// rule ids, unlinked templates and similar. Hard errors (unknown fields,
    /// bad regexes, duplicate ids) fail loading instead.
    pub fn validate(&self) -> Vec<String> {
        let mut out = self.rules.warnings().to_vec();
        if let Some(c) = &self.cedar {
            out.extend_from_slice(c.warnings());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn call<'a>(agent: &'a str, server: &'a str, tool: &'a str, args: &'a Value) -> PolicyInput<'a> {
        PolicyInput::new(agent, &[], SessionFacts::default(), Action::CallTool { server, tool, args })
    }

    const RULES: &str = r#"
rules:
  - id: allow-read
    match: { tool: "read_*" }
    action: allow
  - id: no-secrets
    match: { tool: "read_file", args: { path: { regex: "\\.env$" } } }
    action: deny
  - id: watch-search
    match: { tool: "search" }
    action: alert
"#;

    #[test]
    fn send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PolicySet>();
        assert_send_sync::<PlanTracker>();
    }

    #[test]
    fn explicit_allow_and_default_deny() {
        let p = PolicySet::from_sources(DefaultAction::Deny, None, None, &[RULES]).unwrap();
        let args = json!({"path": "README.md"});
        let out = p.evaluate(&call("a", "fs", "read_file", &args), &[]);
        assert!(out.permitted);
        assert!(out.findings.is_empty());

        let env = json!({"path": "/app/.env"});
        let out = p.evaluate(&call("a", "fs", "read_file", &env), &[]);
        assert!(out.permitted);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule, "policy.no-secrets");
        assert_eq!(out.verdict(), Verdict::Deny);

        let none = json!({});
        let out = p.evaluate(&call("a", "fs", "write_file", &none), &[]);
        assert!(!out.permitted);
        assert_eq!(out.findings[0].rule, "policy.default-deny");
        assert_eq!(out.findings[0].severity, Severity::Medium);

        // An alert does not permit, so default deny still applies.
        let out = p.evaluate(&call("a", "web", "search", &none), &[]);
        let rules: Vec<_> = out.findings.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(rules, vec!["policy.watch-search", "policy.default-deny"]);

        let list = PolicyInput { action: Action::ListTools { server: "fs" }, ..call("a", "fs", "x", &none) };
        assert!(p.evaluate(&list, &[]).findings.is_empty());
        let llm = PolicyInput { action: Action::LlmRequest { provider: "p", model: "m" }, ..list };
        assert_eq!(p.evaluate(&llm, &[]).findings[0].rule, "policy.default-deny");

        let open = PolicySet::from_sources(DefaultAction::Allow, None, None, &[RULES]).unwrap();
        assert!(open.evaluate(&call("a", "fs", "write_file", &none), &[]).findings.is_empty());
    }

    #[test]
    fn rules_and_cedar_combine() {
        let cedar = r#"
permit(principal in Group::"ops", action == Action::"call_tool", resource in Server::"k8s");
@id("no-exec")
forbid(principal, action, resource == Tool::"k8s/exec");
"#;
        let p = PolicySet::from_sources(DefaultAction::Deny, Some(cedar), None, &[RULES]).unwrap();
        let ops = vec!["ops".to_string()];
        let none = json!({});
        let input = |tool| {
            PolicyInput::new("a", &ops, SessionFacts::default(), Action::CallTool { server: "k8s", tool, args: &none })
        };
        let out = p.evaluate(&input("get_pods"), &[]);
        assert!(out.permitted && out.findings.is_empty());
        let out = p.evaluate(&input("exec"), &[]);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule, "cedar.no-exec");

        assert!(p.tool_visible("a", &ops, "k8s", "get_pods", &[]));
        assert!(!p.tool_visible("a", &ops, "k8s", "exec", &[]));
        assert!(!p.tool_visible("a", &[], "k8s", "get_pods", &[]));
        assert!(p.tool_visible("a", &[], "fs", "read_file", &[]));
        assert!(!p.tool_visible("a", &[], "fs", "write_file", &[]));
    }

    #[test]
    fn tool_visible_with_default_allow() {
        let rules = r#"
rules:
  - id: no-shell
    match: { tool: "run_shell", group: "untrusted" }
  - id: no-rm
    match: { tool: "run_shell", args: { cmd: { prefix: "rm " } } }
"#;
        let p = PolicySet::from_sources(DefaultAction::Allow, None, None, &[rules]).unwrap();
        let untrusted = vec!["untrusted".to_string()];
        assert!(!p.tool_visible("a", &untrusted, "local", "run_shell", &[]));
        assert!(p.tool_visible("a", &[], "local", "run_shell", &[]));
        assert!(p.tool_visible("a", &untrusted, "local", "ls", &[]));
    }

    #[test]
    fn load_from_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("policies")).unwrap();
        std::fs::write(dir.path().join("policies/a.yaml"), RULES).unwrap();
        std::fs::write(
            dir.path().join("policies/b.yaml"),
            "sequences:\n  - id: verify-first\n    tool: refund\n    requires_prior: { tool: verify }\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("main.cedar"), "permit(principal in Group::\"admins\", action, resource);")
            .unwrap();
        std::fs::write(
            dir.path().join("extra.cedar"),
            "@id(\"x\") forbid(principal, action, resource == Tool::\"s/x\");",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("entities.json"),
            r#"[{"uid": {"type": "Agent", "id": "root"}, "attrs": {}, "parents": [{"type": "Group", "id": "admins"}]}]"#,
        )
        .unwrap();
        let cfg = PolicyConfig {
            default: DefaultAction::Deny,
            cedar: vec!["main.cedar".into(), "extra.cedar".into()],
            cedar_entities: Some("entities.json".into()),
            rules: vec!["policies/a.yaml".into(), "policies/b.yaml".into()],
            ..PolicyConfig::default()
        };
        let p = PolicySet::load(&cfg, dir.path()).unwrap();
        // In-memory documents compile together with the files.
        let extra = [Source {
            name: "dashboard/extra".into(),
            kind: SourceKind::Rules,
            text: "rules:\n  - { id: from-dashboard, match: { tool: nope }, action: deny }\n".into(),
        }];
        assert!(PolicySet::load_with(&cfg, dir.path(), &extra).is_ok());
        let dup = [Source {
            name: "dashboard/dup".into(),
            kind: SourceKind::Rules,
            text: "rules: [{ id: from-dashboard, action: deny }, { id: from-dashboard, action: deny }]".into(),
        }];
        assert!(PolicySet::load_with(&cfg, dir.path(), &dup).is_err());
        assert!(p.validate().is_empty(), "{:?}", p.validate());
        let none = json!({});
        assert!(p.evaluate(&call("root", "s", "anything", &none), &[]).permitted);
        assert_eq!(p.evaluate(&call("root", "s", "x", &none), &[]).findings[0].rule, "cedar.x");
        let out = p.evaluate(&call("root", "shop", "refund", &none), &[]);
        assert_eq!(out.findings[0].rule, "sequence.verify-first");
        let h = HistoryEntry { ts_ms: 1, server: "shop".into(), tool: "verify".into(), args: none.clone(), ok: true };
        assert!(p.evaluate(&call("root", "shop", "refund", &none), &[h]).findings.is_empty());
        assert_eq!(p.evaluate(&call("guest", "s", "y", &none), &[]).findings[0].rule, "policy.default-deny");

        let missing = PolicyConfig { rules: vec!["nope.yaml".into()], ..cfg.clone() };
        let err = PolicySet::load(&missing, dir.path()).unwrap_err().to_string();
        assert!(err.contains("nope.yaml"), "{err}");
        std::fs::write(dir.path().join("bad.yaml"), "rules:\n  - id: x\n    match: { tol: y }\n").unwrap();
        let bad = PolicyConfig { rules: vec!["bad.yaml".into()], ..cfg };
        let err = PolicySet::load(&bad, dir.path()).unwrap_err().to_string();
        assert!(err.contains("bad.yaml"), "{err}");
    }

    #[test]
    fn empty_policy_set() {
        let p = PolicySet::from_sources(DefaultAction::Allow, None, None, &[]).unwrap();
        let none = json!({});
        assert_eq!(p.evaluate(&call("a", "s", "t", &none), &[]), Outcome::default());
        assert!(p.tool_visible("a", &[], "s", "t", &[]));
        assert_eq!(p.default_action(), DefaultAction::Allow);
        let deny = PolicySet::from_sources(DefaultAction::Deny, None, None, &[]).unwrap();
        assert!(!deny.tool_visible("a", &[], "s", "t", &[]));
    }
}
