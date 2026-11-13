//! Schema-less Cedar evaluation over generated per-request entities.
//!
//! Entities: the principal is `Agent::"<agent>"` with parents
//! `Group::"<group>"`; the resource is `Tool::"<server>/<tool>"` (parent
//! `Server::"<server>"`, attributes `name`, `server` and `capabilities`, a
//! set of capability names such as `"payment"`), `Server::"<server>"`,
//! `Model::"<provider>/<model>"`
//! or `Peer::"<peer>"`; the action is `Action::"call_tool"`,
//! `Action::"list_tools"`, `Action::"llm_request"` or `Action::"a2a_send"`.
//! Entities from an optional user file are merged in (user attributes win,
//! parents are unioned).
//!
//! Context: `{ args, session: { tainted, risk (0-100), calls }, method? }`.
//!
//! Annotations: `@id("...")` names the rule (`cedar.<id>`), `@message`,
//! `@severity` and, on `forbid` policies, `@action("ask" | "alert" |
//! "redact")` downgrades the verdict from deny. Downgraded forbids are
//! evaluated separately as permits so they never mask a real permit.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Effect, Entities, Entity, EntityId, EntityTypeName, EntityUid, Policy, PolicyId,
    PolicySet as CedarPolicySet, Request, RestrictedExpression,
};
use serde_json::{Map, Value, json};

use nandi_core::{Capability, Category, Error, Finding, Result, Severity, Verdict};

use crate::{Action, Outcome, PolicyInput, SessionFacts};

/// JSON nesting kept in `context.args`; deeper values are dropped.
const MAX_CONTEXT_DEPTH: usize = 8;

/// Per-policy metadata from annotations.
#[derive(Debug, Clone)]
struct Meta {
    rule: String,
    message: String,
    severity: Severity,
    verdict: Verdict,
}

/// Entity type names, parsed once.
#[derive(Debug)]
struct Types {
    agent: EntityTypeName,
    group: EntityTypeName,
    tool: EntityTypeName,
    server: EntityTypeName,
    model: EntityTypeName,
    peer: EntityTypeName,
    action: EntityTypeName,
}

impl Types {
    fn new() -> Result<Self> {
        let t = |s: &str| EntityTypeName::from_str(s).map_err(|e| Error::Policy(format!("cedar type {s}: {e}")));
        Ok(Self {
            agent: t("Agent")?,
            group: t("Group")?,
            tool: t("Tool")?,
            server: t("Server")?,
            model: t("Model")?,
            peer: t("Peer")?,
            action: t("Action")?,
        })
    }
}

fn uid(ty: &EntityTypeName, id: &str) -> EntityUid {
    EntityUid::from_type_name_and_id(ty.clone(), EntityId::new(id))
}

fn s(v: &str) -> RestrictedExpression {
    RestrictedExpression::new_string(v.to_owned())
}

/// A request's generated entity before merging with user entities.
struct GenEntity {
    uid: EntityUid,
    attrs: HashMap<String, RestrictedExpression>,
    parents: HashSet<EntityUid>,
}

/// Compiled Cedar policies plus static entities.
#[derive(Debug)]
pub(crate) struct CedarEngine {
    /// Permits and deny-verdict forbids.
    main: CedarPolicySet,
    /// Forbids with a downgraded `@action`, flipped to permits.
    advisory: CedarPolicySet,
    /// Context-free over-approximation used by `tool_visible`.
    visibility: CedarPolicySet,
    meta: HashMap<PolicyId, Meta>,
    entities: Option<Entities>,
    types: Types,
    warnings: Vec<String>,
}

fn cedar_err(msg: impl std::fmt::Display) -> Error {
    Error::Policy(msg.to_string())
}

/// Whether a policy's EST JSON references the `context` variable.
fn uses_context(est: &Value) -> bool {
    match est {
        Value::Object(map) => {
            map.get("Var").and_then(Value::as_str) == Some("context") || map.values().any(uses_context)
        }
        Value::Array(items) => items.iter().any(uses_context),
        _ => false,
    }
}

/// Rebuild `policy` from its EST after `edit`, keeping its id.
fn rebuild(policy: &Policy, edit: impl FnOnce(&mut Map<String, Value>)) -> Result<Policy> {
    let mut est = policy.to_json().map_err(|e| cedar_err(format!("cedar policy {}: {e}", policy.id())))?;
    if let Some(map) = est.as_object_mut() {
        edit(map);
    }
    Policy::from_json(Some(policy.id().clone()), est)
        .map_err(|e| cedar_err(format!("cedar policy {}: {e}", policy.id())))
}

fn parse_meta(p: &Policy) -> Result<Meta> {
    let rule = p.annotation("id").map_or_else(|| p.id().to_string(), str::to_owned);
    let severity = match p.annotation("severity") {
        None => Severity::Medium,
        Some(sev) => serde_json::from_value(Value::String(sev.to_ascii_lowercase()))
            .map_err(|_| cedar_err(format!("cedar policy {rule}: unknown @severity {sev:?}")))?,
    };
    let verdict = match p.annotation("action").map(str::to_ascii_lowercase).as_deref() {
        None | Some("deny") => Verdict::Deny,
        Some("ask") => Verdict::Ask,
        Some("alert") => Verdict::Alert,
        Some("redact") => Verdict::Redact,
        Some(other) => return Err(cedar_err(format!("cedar policy {rule}: unsupported @action {other:?}"))),
    };
    let message = p.annotation("message").map_or_else(|| format!("denied by Cedar policy {rule}"), str::to_owned);
    Ok(Meta { rule, message, severity, verdict })
}

/// Drop nulls, turn non-integer numbers into strings, cap nesting and strip
/// keys that Cedar's JSON format would treat as escapes (`__entity`, ...).
fn sanitize(v: &Value, depth: usize) -> Option<Value> {
    match v {
        Value::Null => None,
        Value::Bool(_) | Value::String(_) => Some(v.clone()),
        Value::Number(n) => Some(match n.as_i64() {
            Some(i) => Value::from(i),
            None => Value::String(n.to_string()),
        }),
        Value::Array(items) => (depth < MAX_CONTEXT_DEPTH)
            .then(|| Value::Array(items.iter().filter_map(|i| sanitize(i, depth + 1)).collect())),
        Value::Object(map) => (depth < MAX_CONTEXT_DEPTH).then(|| {
            Value::Object(
                map.iter()
                    .filter(|(k, _)| !k.starts_with("__"))
                    .filter_map(|(k, v)| sanitize(v, depth + 1).map(|v| (k.clone(), v)))
                    .collect(),
            )
        }),
    }
}

fn context_json(session: &SessionFacts, args: Option<&Value>, method: Option<&str>) -> Value {
    let risk = (session.risk.clamp(0.0, 1.0) * 100.0).round() as i64;
    let args = args.and_then(|a| sanitize(a, 0)).unwrap_or_else(|| Value::Object(Map::new()));
    let calls = i64::try_from(session.calls).unwrap_or(i64::MAX);
    let mut ctx = json!({
        "args": args,
        "session": { "tainted": session.tainted, "risk": risk, "calls": calls },
    });
    if let (Some(m), Some(obj)) = (method, ctx.as_object_mut()) {
        obj.insert("method".into(), Value::String(m.to_owned()));
    }
    ctx
}

impl CedarEngine {
    /// Parse policy sources `(name, text)` and an optional entities JSON.
    pub(crate) fn load(sources: &[(String, &str)], entities: Option<(String, &str)>) -> Result<Self> {
        let combined = sources.iter().map(|(_, t)| *t).collect::<Vec<_>>().join("\n");
        let parsed = CedarPolicySet::from_str(&combined).map_err(|e| {
            let culprit = sources.iter().find_map(|(name, text)| {
                CedarPolicySet::from_str(text).err().map(|fe| cedar_err(format!("{name}: {fe}")))
            });
            culprit.unwrap_or_else(|| cedar_err(format!("cedar policies: {e}")))
        })?;

        let mut warnings = Vec::new();
        if parsed.templates().next().is_some() {
            warnings.push("cedar: policy templates are not linked by nandi and are ignored".to_owned());
        }
        let mut main = CedarPolicySet::new();
        let mut advisory = CedarPolicySet::new();
        let mut visibility = CedarPolicySet::new();
        let mut meta = HashMap::new();
        let mut rule_ids = HashSet::new();
        let add = |set: &mut CedarPolicySet, p: Policy| set.add(p).map_err(cedar_err);
        for p in parsed.policies() {
            let m = parse_meta(p)?;
            if !rule_ids.insert(m.rule.clone()) {
                warnings.push(format!("cedar: rule id `{}` is used by more than one policy", m.rule));
            }
            let est = p.to_json().map_err(|e| cedar_err(format!("cedar policy {}: {e}", m.rule)))?;
            let ctx = uses_context(&est);
            match p.effect() {
                Effect::Permit => {
                    if p.annotation("action").is_some() {
                        warnings.push(format!("cedar: @action on permit policy `{}` is ignored", m.rule));
                    }
                    add(&mut main, p.clone())?;
                    let vis = if ctx {
                        rebuild(p, |est| drop(est.insert("conditions".into(), json!([]))))?
                    } else {
                        p.clone()
                    };
                    add(&mut visibility, vis)?;
                }
                Effect::Forbid if m.verdict == Verdict::Deny => {
                    add(&mut main, p.clone())?;
                    if !ctx {
                        add(&mut visibility, p.clone())?;
                    }
                }
                Effect::Forbid => {
                    add(&mut advisory, rebuild(p, |est| drop(est.insert("effect".into(), json!("permit"))))?)?;
                }
            }
            meta.insert(p.id().clone(), m);
        }

        let entities = match entities {
            Some((name, text)) => {
                Some(Entities::from_json_str(text, None).map_err(|e| cedar_err(format!("{name}: {e}")))?)
            }
            None => None,
        };
        Ok(Self { main, advisory, visibility, meta, entities, types: Types::new()?, warnings })
    }

    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Generated entities and request uids for an action.
    fn generate(
        &self,
        agent: &str,
        groups: &[String],
        action: &Action<'_>,
        caps: &[Capability],
    ) -> (Vec<GenEntity>, EntityUid, EntityUid) {
        let t = &self.types;
        let principal = GenEntity {
            uid: uid(&t.agent, agent),
            attrs: HashMap::from([("name".to_owned(), s(agent))]),
            parents: groups.iter().map(|g| uid(&t.group, g)).collect(),
        };
        let (action_id, resource) = match *action {
            Action::CallTool { server, tool, .. } => (
                "call_tool",
                GenEntity {
                    uid: uid(&t.tool, &format!("{server}/{tool}")),
                    attrs: HashMap::from([
                        ("name".to_owned(), s(tool)),
                        ("server".to_owned(), s(server)),
                        ("capabilities".to_owned(), RestrictedExpression::new_set(caps.iter().map(|c| s(c.as_str())))),
                    ]),
                    parents: HashSet::from([uid(&t.server, server)]),
                },
            ),
            Action::ListTools { server } => (
                "list_tools",
                GenEntity {
                    uid: uid(&t.server, server),
                    attrs: HashMap::from([("name".to_owned(), s(server))]),
                    parents: HashSet::new(),
                },
            ),
            Action::LlmRequest { provider, model } => (
                "llm_request",
                GenEntity {
                    uid: uid(&t.model, &format!("{provider}/{model}")),
                    attrs: HashMap::from([("provider".to_owned(), s(provider)), ("name".to_owned(), s(model))]),
                    parents: HashSet::new(),
                },
            ),
            Action::A2aSend { peer, skill, .. } => {
                let mut attrs = HashMap::from([("name".to_owned(), s(peer))]);
                if let Some(skill) = skill {
                    attrs.insert("skill".to_owned(), s(skill));
                }
                ("a2a_send", GenEntity { uid: uid(&t.peer, peer), attrs, parents: HashSet::new() })
            }
        };
        let action_uid = uid(&t.action, action_id);
        let resource_uid = resource.uid.clone();
        (vec![principal, resource], action_uid, resource_uid)
    }

    /// Build the request and entity store for one evaluation.
    fn request(
        &self,
        agent: &str,
        groups: &[String],
        action: &Action<'_>,
        caps: &[Capability],
        context: Value,
    ) -> std::result::Result<(Request, Entities), String> {
        let (generated, action_uid, resource_uid) = self.generate(agent, groups, action, caps);
        let principal_uid = generated[0].uid.clone();
        let mut list = Vec::with_capacity(generated.len());
        for g in generated {
            let (attrs, parents) = match self.entities.as_ref().and_then(|e| e.get(&g.uid)) {
                Some(existing) => {
                    let (_, mut attrs, mut parents) = existing.clone().into_inner();
                    for (k, v) in g.attrs {
                        attrs.entry(k).or_insert(v);
                    }
                    parents.extend(g.parents);
                    (attrs, parents)
                }
                None => (g.attrs, g.parents),
            };
            list.push(Entity::new(g.uid, attrs, parents).map_err(|e| e.to_string())?);
        }
        let entities = match &self.entities {
            Some(base) => base.clone().upsert_entities(list, None),
            None => Entities::from_entities(list, None),
        }
        .map_err(|e| e.to_string())?;
        let context = Context::from_json_value(context, None).map_err(|e| e.to_string())?;
        let request =
            Request::new(principal_uid, action_uid, resource_uid, context, None).map_err(|e| e.to_string())?;
        Ok((request, entities))
    }

    /// Evaluate `input`, appending findings and the permit flag to `out`.
    pub(crate) fn evaluate(&self, input: &PolicyInput<'_>, out: &mut Outcome) {
        let (args, method) = match input.action {
            Action::CallTool { args, .. } => (Some(args), None),
            Action::A2aSend { method, .. } => (None, Some(method)),
            _ => (None, None),
        };
        let ctx = context_json(&input.session, args, method);
        let (request, entities) = match self.request(input.agent, input.groups, &input.action, input.capabilities, ctx)
        {
            Ok(r) => r,
            Err(e) => {
                out.findings.push(error_finding(format!("could not build Cedar request: {e}")));
                return;
            }
        };
        let authorizer = Authorizer::new();
        let mut errors: Vec<String> = Vec::new();

        let resp = authorizer.is_authorized(&request, &self.main, &entities);
        match resp.decision() {
            Decision::Allow => out.permitted |= resp.diagnostics().reason().next().is_some(),
            Decision::Deny => {
                for id in resp.diagnostics().reason() {
                    if let Some(m) = self.meta.get(id) {
                        out.findings.push(self.finding(m, m.verdict));
                    }
                }
            }
        }
        errors.extend(resp.diagnostics().errors().map(ToString::to_string));

        if !self.advisory.is_empty() {
            let resp = authorizer.is_authorized(&request, &self.advisory, &entities);
            for id in resp.diagnostics().reason() {
                if let Some(m) = self.meta.get(id) {
                    out.findings.push(self.finding(m, m.verdict));
                }
            }
            errors.extend(resp.diagnostics().errors().map(ToString::to_string));
        }

        if !errors.is_empty() {
            errors.sort();
            out.findings.push(error_finding(errors.join("; ")));
        }
    }

    fn finding(&self, m: &Meta, verdict: Verdict) -> Finding {
        Finding::new(format!("cedar.{}", m.rule), Category::Policy, m.severity, verdict, m.message.clone())
    }

    /// Context-free view of a tool: `(always_denied, allow_possible)`.
    pub(crate) fn tool_status(
        &self,
        agent: &str,
        groups: &[String],
        server: &str,
        tool: &str,
        caps: &[Capability],
    ) -> (bool, bool) {
        let args = Value::Object(Map::new());
        let action = Action::CallTool { server, tool, args: &args };
        let ctx = context_json(&SessionFacts::default(), None, None);
        let Ok((request, entities)) = self.request(agent, groups, &action, caps, ctx) else {
            return (false, true);
        };
        let resp = Authorizer::new().is_authorized(&request, &self.visibility, &entities);
        let determined = resp.diagnostics().reason().next().is_some();
        match resp.decision() {
            Decision::Allow => (false, true),
            Decision::Deny => (determined, false),
        }
    }
}

fn error_finding(message: String) -> Finding {
    let message = nandi_core::util::truncate(&message, 500).to_owned();
    Finding::new("cedar.error", Category::Policy, Severity::Low, Verdict::Alert, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(policies: &str, entities: Option<&str>) -> CedarEngine {
        CedarEngine::load(&[("p.cedar".into(), policies)], entities.map(|e| ("e.json".to_owned(), e))).unwrap()
    }

    fn eval(e: &CedarEngine, agent: &str, groups: &[String], action: Action<'_>) -> Outcome {
        eval_caps(e, agent, groups, action, &[])
    }

    fn eval_caps(e: &CedarEngine, agent: &str, groups: &[String], action: Action<'_>, caps: &[Capability]) -> Outcome {
        let input = PolicyInput::new(agent, groups, SessionFacts::default(), action).with_capabilities(caps);
        let mut out = Outcome::default();
        e.evaluate(&input, &mut out);
        out
    }

    #[test]
    fn permit_forbid_and_no_match() {
        let e = engine(
            r#"
permit(principal == Agent::"alice", action == Action::"call_tool", resource in Server::"github");
@id("no-delete")
@message("deleting repos is not allowed")
@severity("critical")
forbid(principal, action, resource) when { resource.name like "delete_*" };
"#,
            None,
        );
        let args = json!({});
        let out = eval(&e, "alice", &[], Action::CallTool { server: "github", tool: "create_issue", args: &args });
        assert!(out.permitted);
        assert!(out.findings.is_empty());

        let out = eval(&e, "alice", &[], Action::CallTool { server: "github", tool: "delete_repo", args: &args });
        assert!(!out.permitted);
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.rule, "cedar.no-delete");
        assert_eq!(f.message, "deleting repos is not allowed");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.verdict, Verdict::Deny);

        let out = eval(&e, "bob", &[], Action::CallTool { server: "github", tool: "create_issue", args: &args });
        assert!(!out.permitted);
        assert!(out.findings.is_empty());
    }

    #[test]
    fn default_ids_and_context() {
        let e = engine(
            r#"
forbid(principal, action == Action::"call_tool", resource)
  when { context has args && context.args has path && context.args.path like "/etc/*" };
forbid(principal, action, resource) when { context.session.tainted && context.session.risk >= 50 };
permit(principal, action == Action::"a2a_send", resource == Peer::"partner")
  when { context.method == "message/send" && resource.skill == "quote" };
"#,
            None,
        );
        let args = json!({"path": "/etc/passwd", "ratio": 0.5, "n": null, "__entity": {"type": "Group", "id": "x"}});
        let out = eval(&e, "a", &[], Action::CallTool { server: "fs", tool: "read", args: &args });
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule, "cedar.policy0");
        assert_eq!(out.findings[0].message, "denied by Cedar policy policy0");

        let input = PolicyInput::new(
            "a",
            &[],
            SessionFacts { tainted: true, risk: 0.6, calls: 3 },
            Action::LlmRequest { provider: "openai", model: "gpt-4o" },
        );
        let mut out = Outcome::default();
        e.evaluate(&input, &mut out);
        assert_eq!(out.findings[0].rule, "cedar.policy1");

        let ok = Action::A2aSend { peer: "partner", skill: Some("quote"), method: "message/send" };
        assert!(eval(&e, "a", &[], ok).permitted);
        let other = Action::A2aSend { peer: "partner", skill: None, method: "message/send" };
        let out = eval(&e, "a", &[], other);
        assert!(!out.permitted);
        // `resource.skill` is missing: an evaluation error, reported as an alert.
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule, "cedar.error");
        assert_eq!(out.findings[0].verdict, Verdict::Alert);
    }

    #[test]
    fn groups_and_user_entities() {
        let entities = r#"[
            {"uid": {"type": "Group", "id": "finance"}, "attrs": {}, "parents": [{"type": "Group", "id": "staff"}]},
            {"uid": {"type": "Agent", "id": "carol"}, "attrs": {"level": 3}, "parents": [{"type": "Group", "id": "ops"}]},
            {"uid": {"type": "Server", "id": "payments"}, "attrs": {"tier": "prod"}, "parents": []}
        ]"#;
        let e = engine(
            r#"
permit(principal in Group::"staff", action == Action::"call_tool", resource in Server::"payments");
permit(principal in Group::"ops", action == Action::"list_tools", resource) when { principal.level >= 3 };
@id("prod-needs-finance")
forbid(principal, action == Action::"list_tools", resource)
  when { resource has tier && resource.tier == "prod" } unless { principal in Group::"finance" };
"#,
            Some(entities),
        );
        let args = json!({"amount": 1});
        let fin = vec!["finance".to_string()];
        let call = Action::CallTool { server: "payments", tool: "pay", args: &args };
        assert!(eval(&e, "dave", &fin, call).permitted);
        let call = Action::CallTool { server: "payments", tool: "pay", args: &args };
        assert!(!eval(&e, "dave", &[], call).permitted);
        // carol is in `ops` via the user entities file and keeps her attributes.
        assert!(eval(&e, "carol", &[], Action::ListTools { server: "github" }).permitted);
        let out = eval(&e, "carol", &[], Action::ListTools { server: "payments" });
        assert_eq!(out.findings[0].rule, "cedar.prod-needs-finance");
        // Groups from the request are merged with the file's parents.
        let out = eval(&e, "carol", &fin, Action::ListTools { server: "payments" });
        assert!(out.permitted && out.findings.is_empty());
    }

    #[test]
    fn action_annotation_downgrades() {
        let e = engine(
            r#"
permit(principal, action, resource);
@id("big-transfer")
@action("ask")
forbid(principal, action == Action::"call_tool", resource)
  when { context.args has amount && context.args.amount > 1000 };
@action("alert")
@severity("low")
forbid(principal, action, resource == Model::"openai/gpt-4o");
"#,
            None,
        );
        let big = json!({"amount": 5000});
        let out = eval(&e, "a", &[], Action::CallTool { server: "bank", tool: "transfer", args: &big });
        assert!(out.permitted, "a downgraded forbid must not mask the permit");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule, "cedar.big-transfer");
        assert_eq!(out.findings[0].verdict, Verdict::Ask);
        let small = json!({"amount": 5});
        let out = eval(&e, "a", &[], Action::CallTool { server: "bank", tool: "transfer", args: &small });
        assert!(out.permitted && out.findings.is_empty());
        let out = eval(&e, "a", &[], Action::LlmRequest { provider: "openai", model: "gpt-4o" });
        assert_eq!(out.findings[0].verdict, Verdict::Alert);
        assert_eq!(out.findings[0].severity, Severity::Low);
    }

    #[test]
    fn capabilities_attribute() {
        let e = engine(
            r#"
permit(principal, action, resource);
@id("payments-need-approval")
@action("ask")
forbid(principal, action == Action::"call_tool", resource)
  when { resource.capabilities.contains("payment") };
@id("no-shell-for-interns")
forbid(principal == Agent::"intern", action == Action::"call_tool", resource)
  when { resource.capabilities.containsAny(["command_execution", "credential_access"]) };
"#,
            None,
        );
        let args = json!({"amount": 5});
        let call = || Action::CallTool { server: "stripe", tool: "create_payout", args: &args };
        let out = eval_caps(&e, "a", &[], call(), &[Capability::Payment]);
        assert!(out.permitted);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule, "cedar.payments-need-approval");
        assert_eq!(out.findings[0].verdict, Verdict::Ask);
        let out = eval_caps(&e, "a", &[], call(), &[Capability::ReadOnly]);
        assert!(out.permitted && out.findings.is_empty());
        let out = eval(&e, "a", &[], call());
        assert!(out.findings.is_empty(), "an empty set never contains payment");

        let shell = [Capability::CommandExecution];
        assert_eq!(e.tool_status("intern", &[], "local", "Bash", &shell), (true, false));
        assert_eq!(e.tool_status("intern", &[], "local", "Read", &[Capability::ReadOnly]), (false, true));
        assert_eq!(e.tool_status("dev", &[], "local", "Bash", &shell), (false, true));
    }

    #[test]
    fn load_errors() {
        let load = |p: &str| CedarEngine::load(&[("bad.cedar".into(), p)], None);
        let err = load("permit(principal, action, resource").unwrap_err().to_string();
        assert!(err.contains("bad.cedar"), "{err}");
        assert!(load("@action(\"allow\") forbid(principal, action, resource);").is_err());
        assert!(load("@severity(\"extreme\") forbid(principal, action, resource);").is_err());
        let e = load("@action(\"ask\") permit(principal, action, resource);").unwrap();
        assert_eq!(e.warnings().len(), 1);
        let ents = CedarEngine::load(&[], Some(("e.json".into(), "{not json")));
        assert!(ents.unwrap_err().to_string().contains("e.json"));
    }

    #[test]
    fn sanitize_for_cedar() {
        let mut deep = json!("leaf");
        for _ in 0..12 {
            deep = json!({ "d": deep });
        }
        let v = json!({"f": 1.5, "i": -3, "u": u64::MAX, "n": null, "a": [1, null, "x"], "__extn": 1, "deep": deep});
        let out = sanitize(&v, 0).unwrap();
        assert_eq!(out["f"], json!("1.5"));
        assert_eq!(out["i"], json!(-3));
        assert_eq!(out["u"], json!(u64::MAX.to_string()));
        assert!(out.get("n").is_none());
        assert_eq!(out["a"], json!([1, "x"]));
        assert!(out.get("__extn").is_none());
        let mut depth = 0;
        let mut cur = &out["deep"];
        while let Some(next) = cur.get("d") {
            depth += 1;
            cur = next;
        }
        assert!(depth < MAX_CONTEXT_DEPTH, "{depth}");
    }

    #[test]
    fn tool_status_over_approximates() {
        let e = engine(
            r#"
permit(principal in Group::"dev", action == Action::"call_tool", resource in Server::"github");
permit(principal, action == Action::"call_tool", resource == Tool::"fs/read")
  when { context.args.path like "/tmp/*" };
forbid(principal == Agent::"intern", action, resource == Tool::"github/delete_repo");
forbid(principal, action, resource) when { context.args.force == true };
@action("ask") forbid(principal, action, resource == Tool::"github/merge");
"#,
            None,
        );
        let dev = vec!["dev".to_string()];
        assert_eq!(e.tool_status("x", &dev, "github", "create_issue", &[]), (false, true));
        assert_eq!(e.tool_status("x", &[], "github", "create_issue", &[]), (false, false));
        assert_eq!(e.tool_status("x", &[], "fs", "read", &[]), (false, true));
        assert_eq!(e.tool_status("intern", &dev, "github", "delete_repo", &[]), (true, false));
        assert_eq!(e.tool_status("x", &dev, "github", "delete_repo", &[]), (false, true));
        assert_eq!(e.tool_status("x", &dev, "github", "merge", &[]), (false, true));
    }
}
