//! Policies written in the dashboard, and the change process around them.
//!
//! Policy *documents* (YAML rules or Cedar) live in the state store, next to
//! the policy files named in the configuration, and compile together with
//! them into one policy set. Files stay read-only here.
//!
//! Documents only change through *change requests*. A change is a list of
//! operations (create or replace a document, delete, enable, disable). It
//! is validated when it is proposed, and its impact can be previewed by
//! replaying recorded events. A change is applied when it is approved:
//!
//! - with `policy.changes.require_review`, the author cannot approve their
//!   own change while someone else can (another user with the
//!   `policy_approver` or `admin` role, or the admin token); with nobody
//!   else, the author applies it and that is recorded;
//! - a change is refused as a conflict when a document it touches changed
//!   after it was proposed;
//! - every applied document gets a new version, and rolling back proposes a
//!   change that restores an old version.
//!
//! Everything people do here is also recorded in the audit trail by the
//! admin API.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use nandi_audit::{AuditLog, Query};
use nandi_core::util::{new_id, now_ms};
use nandi_core::{Config, EventKind, StateStore};
use nandi_engine::Engine;
use nandi_policy::{PolicySet, Source, SourceKind};

const DOC_PREFIX: &str = "policydoc/";
const VERSION_PREFIX: &str = "policyver/";
const CHANGE_PREFIX: &str = "policychange/";
/// Examples of changed decisions kept in a preview.
const MAX_EXAMPLES: usize = 50;

/// A policy document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Doc {
    pub name: String,
    pub kind: SourceKind,
    pub content: String,
    pub enabled: bool,
    pub version: u64,
    pub updated_ms: u64,
    pub updated_by: String,
    /// The change that produced this version.
    pub change: String,
}

impl Doc {
    fn source(&self) -> Source {
        Source { name: format!("dashboard/{}", self.name), kind: self.kind, text: self.content.clone() }
    }
}

/// One operation of a change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    /// Create a document or replace its content.
    Put {
        name: String,
        kind: SourceKind,
        content: String,
    },
    Delete {
        name: String,
    },
    Enable {
        name: String,
    },
    Disable {
        name: String,
    },
}

impl Op {
    pub fn name(&self) -> &str {
        match self {
            Op::Put { name, .. } | Op::Delete { name } | Op::Enable { name } | Op::Disable { name } => name,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Waiting for review.
    Pending,
    Applied,
    Rejected,
    /// Withdrawn by its author.
    Withdrawn,
    /// A document it touches changed after it was proposed.
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Validation {
    pub ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// One recorded event whose decision would change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImpactRow {
    pub seq: u64,
    pub ts_ms: u64,
    pub agent: String,
    pub kind: String,
    pub target: String,
    pub before: nandi_core::Verdict,
    pub after: nandi_core::Verdict,
    pub rules_before: Vec<String>,
    pub rules_after: Vec<String>,
}

/// What a change would have done to recent traffic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Impact {
    pub events: usize,
    pub changed: usize,
    pub stricter: usize,
    pub looser: usize,
    pub examples: Vec<ImpactRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Review {
    pub by: String,
    pub approved: bool,
    #[serde(default)]
    pub comment: String,
    pub ms: u64,
}

/// A change request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub author: String,
    pub created_ms: u64,
    pub status: Status,
    pub ops: Vec<Op>,
    /// Version of every touched document when the change was proposed
    /// (0: it did not exist).
    pub base: BTreeMap<String, u64>,
    /// Content before the change, per document, for diffs.
    #[serde(default)]
    pub before: BTreeMap<String, String>,
    pub validation: Validation,
    #[serde(default)]
    pub impact: Option<Impact>,
    #[serde(default)]
    pub reviews: Vec<Review>,
    #[serde(default)]
    pub closed_by: String,
    #[serde(default)]
    pub closed_ms: u64,
    /// Why it closed the way it did (e.g. applied without a second person).
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, PartialEq)]
pub enum ChangeError {
    Invalid(String),
    NotFound,
    /// Not pending any more.
    Closed(Status),
    /// The author cannot approve their own change while someone else can.
    SecondPersonRequired,
    Forbidden(String),
    Conflict(Vec<String>),
}

impl std::fmt::Display for ChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeError::Invalid(m) | ChangeError::Forbidden(m) => f.write_str(m),
            ChangeError::NotFound => f.write_str("no such change"),
            ChangeError::Closed(s) => write!(f, "the change is {s:?} and can no longer be reviewed"),
            ChangeError::SecondPersonRequired => {
                f.write_str("someone other than the author has to approve this change")
            }
            ChangeError::Conflict(docs) => {
                write!(f, "{} changed after this was proposed; propose it again", docs.join(", "))
            }
        }
    }
}

fn valid_name(name: &str) -> Result<(), ChangeError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        Err(ChangeError::Invalid(format!("'{name}': names are 1 to 64 of a-z, 0-9, '-', '_', '.'")))
    }
}

/// Documents, their versions and change requests.
pub struct Policies {
    store: Arc<dyn StateStore>,
    docs: RwLock<BTreeMap<String, Doc>>,
    changes: RwLock<BTreeMap<String, Change>>,
}

impl Policies {
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        let load = |prefix: &str| -> Vec<Vec<u8>> { store.keys(prefix).iter().filter_map(|k| store.get(k)).collect() };
        let docs = load(DOC_PREFIX)
            .iter()
            .filter_map(|b| serde_json::from_slice::<Doc>(b).ok())
            .map(|d| (d.name.clone(), d))
            .collect();
        let changes = load(CHANGE_PREFIX)
            .iter()
            .filter_map(|b| serde_json::from_slice::<Change>(b).ok())
            .map(|c| (c.id.clone(), c))
            .collect();
        Self { store, docs: RwLock::new(docs), changes: RwLock::new(changes) }
    }

    pub fn docs(&self) -> Vec<Doc> {
        self.docs.read().values().cloned().collect()
    }

    /// Enabled documents, as policy sources.
    pub fn sources(&self) -> Vec<Source> {
        self.docs.read().values().filter(|d| d.enabled).map(Doc::source).collect()
    }

    /// Versions of a document, newest first.
    pub fn versions(&self, name: &str) -> Vec<Doc> {
        let mut v: Vec<Doc> = self
            .store
            .keys(&format!("{VERSION_PREFIX}{name}/"))
            .iter()
            .filter_map(|k| self.store.get(k))
            .filter_map(|b| serde_json::from_slice::<Doc>(&b).ok())
            .collect();
        v.sort_by_key(|d| std::cmp::Reverse(d.version));
        v
    }

    pub fn changes(&self) -> Vec<Change> {
        let mut v: Vec<Change> = self.changes.read().values().cloned().collect();
        v.sort_by_key(|c| std::cmp::Reverse(c.created_ms));
        v
    }

    pub fn change(&self, id: &str) -> Option<Change> {
        self.changes.read().get(id).cloned()
    }

    fn save_change(&self, c: &Change) {
        if let Ok(b) = serde_json::to_vec(c) {
            self.store.put(&format!("{CHANGE_PREFIX}{}", c.id), &b);
        }
    }

    /// The documents as they would be after `ops`.
    pub fn apply_ops(&self, ops: &[Op]) -> Result<BTreeMap<String, Doc>, ChangeError> {
        if ops.is_empty() {
            return Err(ChangeError::Invalid("a change needs at least one operation".into()));
        }
        let mut docs = self.docs.read().clone();
        for op in ops {
            valid_name(op.name())?;
            let missing = || ChangeError::Invalid(format!("no policy document named '{}'", op.name()));
            match op {
                Op::Put { name, kind, content } => {
                    if content.trim().is_empty() {
                        return Err(ChangeError::Invalid(format!("'{name}' is empty; delete it instead")));
                    }
                    let d = docs.entry(name.clone()).or_insert_with(|| Doc {
                        name: name.clone(),
                        kind: *kind,
                        content: String::new(),
                        enabled: true,
                        version: 0,
                        updated_ms: 0,
                        updated_by: String::new(),
                        change: String::new(),
                    });
                    d.kind = *kind;
                    d.content = content.clone();
                }
                Op::Delete { name } => {
                    docs.remove(name).ok_or_else(missing)?;
                }
                Op::Enable { name } => docs.get_mut(name).ok_or_else(missing)?.enabled = true,
                Op::Disable { name } => docs.get_mut(name).ok_or_else(missing)?.enabled = false,
            }
        }
        Ok(docs)
    }

    /// Compile the policy files with the documents as they would be after
    /// `ops`.
    pub fn compile(&self, cfg: &Config, base_dir: &std::path::Path, ops: &[Op]) -> Result<PolicySet, Validation> {
        let fail = |e: String| Validation { ok: false, errors: vec![e], warnings: vec![] };
        let docs = self.apply_ops(ops).map_err(|e| fail(e.to_string()))?;
        let sources: Vec<Source> = docs.values().filter(|d| d.enabled).map(Doc::source).collect();
        PolicySet::load_with(&cfg.policy, base_dir, &sources).map_err(|e| fail(e.to_string()))
    }

    pub fn validate(&self, cfg: &Config, base_dir: &std::path::Path, ops: &[Op]) -> Validation {
        match self.compile(cfg, base_dir, ops) {
            Ok(set) => Validation { ok: true, errors: vec![], warnings: set.validate() },
            Err(v) => v,
        }
    }

    /// Record a new change. It must validate.
    pub fn propose(
        &self,
        author: &str,
        title: &str,
        description: &str,
        ops: Vec<Op>,
        validation: Validation,
        impact: Option<Impact>,
    ) -> Result<Change, ChangeError> {
        let title = title.trim();
        if title.is_empty() || title.len() > 200 {
            return Err(ChangeError::Invalid("give the change a title (up to 200 characters)".into()));
        }
        if !validation.ok {
            return Err(ChangeError::Invalid(format!("the policy does not compile: {}", validation.errors.join("; "))));
        }
        let docs = self.docs.read();
        let mut base = BTreeMap::new();
        let mut before = BTreeMap::new();
        for op in &ops {
            let cur = docs.get(op.name());
            base.insert(op.name().to_string(), cur.map_or(0, |d| d.version));
            before.insert(op.name().to_string(), cur.map(|d| d.content.clone()).unwrap_or_default());
        }
        drop(docs);
        let c = Change {
            id: new_id(),
            title: title.into(),
            description: description.trim().into(),
            author: author.into(),
            created_ms: now_ms(),
            status: Status::Pending,
            ops,
            base,
            before,
            validation,
            impact,
            reviews: vec![],
            closed_by: String::new(),
            closed_ms: 0,
            note: String::new(),
        };
        self.save_change(&c);
        self.changes.write().insert(c.id.clone(), c.clone());
        Ok(c)
    }

    fn close(&self, c: &mut Change, status: Status, by: &str, note: &str) {
        c.status = status;
        c.closed_by = by.into();
        c.closed_ms = now_ms();
        c.note = note.into();
        self.save_change(c);
        self.changes.write().insert(c.id.clone(), c.clone());
    }

    pub fn reject(&self, id: &str, by: &str, comment: &str) -> Result<Change, ChangeError> {
        let mut c = self.change(id).ok_or(ChangeError::NotFound)?;
        if c.status != Status::Pending {
            return Err(ChangeError::Closed(c.status));
        }
        c.reviews.push(Review { by: by.into(), approved: false, comment: comment.into(), ms: now_ms() });
        self.close(&mut c, Status::Rejected, by, comment);
        Ok(c)
    }

    pub fn withdraw(&self, id: &str, by: &str) -> Result<Change, ChangeError> {
        let mut c = self.change(id).ok_or(ChangeError::NotFound)?;
        if c.status != Status::Pending {
            return Err(ChangeError::Closed(c.status));
        }
        if c.author != by {
            return Err(ChangeError::Forbidden("only the author can withdraw a change".into()));
        }
        self.close(&mut c, Status::Withdrawn, by, "");
        Ok(c)
    }

    /// Approve and apply a pending change. `others_can_approve` says whether
    /// someone other than `by` could approve it. On success the documents
    /// are updated; the caller swaps the compiled `set` into the engine.
    pub fn approve(
        &self,
        id: &str,
        by: &str,
        comment: &str,
        require_review: bool,
        others_can_approve: bool,
        compile: impl FnOnce(&[Op]) -> Result<PolicySet, Validation>,
    ) -> Result<(Change, PolicySet), ChangeError> {
        let mut c = self.change(id).ok_or(ChangeError::NotFound)?;
        if c.status != Status::Pending {
            return Err(ChangeError::Closed(c.status));
        }
        let own = c.author == by;
        if own && require_review && others_can_approve {
            return Err(ChangeError::SecondPersonRequired);
        }
        let stale_in = |docs: &BTreeMap<String, Doc>| -> Vec<String> {
            c.base
                .iter()
                .filter(|(name, v)| docs.get(name.as_str()).map_or(0, |d| d.version) != **v)
                .map(|(n, _)| n.clone())
                .collect()
        };
        let stale = stale_in(&self.docs.read());
        if !stale.is_empty() {
            self.close(&mut c, Status::Conflict, by, &format!("changed since proposed: {}", stale.join(", ")));
            return Err(ChangeError::Conflict(stale));
        }
        // Compile without holding the lock (compiling reads the documents).
        let set = match compile(&c.ops) {
            Ok(set) => set,
            Err(v) => {
                return Err(ChangeError::Invalid(format!("the policy no longer compiles: {}", v.errors.join("; "))));
            }
        };
        let mut docs = self.docs.write();
        // Someone may have applied another change meanwhile.
        let stale = stale_in(&docs);
        if !stale.is_empty() {
            drop(docs);
            self.close(&mut c, Status::Conflict, by, &format!("changed since proposed: {}", stale.join(", ")));
            return Err(ChangeError::Conflict(stale));
        }
        // Apply the operations for real, with new versions.
        let now = now_ms();
        for op in &c.ops {
            let name = op.name().to_string();
            match op {
                Op::Delete { .. } => {
                    docs.remove(&name);
                    self.store.delete(&format!("{DOC_PREFIX}{name}"));
                    continue;
                }
                Op::Put { kind, content, .. } => {
                    let d = docs.entry(name.clone()).or_insert_with(|| Doc {
                        name: name.clone(),
                        kind: *kind,
                        content: String::new(),
                        enabled: true,
                        version: 0,
                        updated_ms: 0,
                        updated_by: String::new(),
                        change: String::new(),
                    });
                    d.kind = *kind;
                    d.content = content.clone();
                }
                Op::Enable { .. } => {
                    if let Some(d) = docs.get_mut(&name) {
                        d.enabled = true;
                    }
                }
                Op::Disable { .. } => {
                    if let Some(d) = docs.get_mut(&name) {
                        d.enabled = false;
                    }
                }
            }
            if let Some(d) = docs.get_mut(&name) {
                d.version += 1;
                d.updated_ms = now;
                d.updated_by = c.author.clone();
                d.change = c.id.clone();
                if let Ok(b) = serde_json::to_vec(&*d) {
                    self.store.put(&format!("{DOC_PREFIX}{name}"), &b);
                    self.store.put(&format!("{VERSION_PREFIX}{name}/{:010}", d.version), &b);
                }
            }
        }
        drop(docs);
        c.reviews.push(Review { by: by.into(), approved: true, comment: comment.into(), ms: now });
        let note = if own { "applied by its author: nobody else could approve it" } else { "" };
        self.close(&mut c, Status::Applied, by, note);
        Ok((c, set))
    }
}

/// Replay recently recorded events through the current and the candidate
/// policy, each in a fresh engine, and report what would change.
pub fn preview(cfg: &Config, log: &AuditLog, current: PolicySet, candidate: PolicySet, limit: usize) -> Impact {
    let q = Query { limit: limit.max(1), ..Query::default() };
    let mut records = log.query(&q).unwrap_or_default();
    records.reverse(); // oldest first, as they happened
    let (a, b) = (Engine::ephemeral(cfg.clone(), current), Engine::ephemeral(cfg.clone(), candidate));
    let mut out = Impact { events: 0, changed: 0, stricter: 0, looser: 0, examples: vec![] };
    let rules = |d: &nandi_core::Decision| d.findings.iter().map(|f| f.rule.clone()).collect::<Vec<_>>();
    for r in records {
        if matches!(r.event.kind, EventKind::Admin(_)) {
            continue;
        }
        out.events += 1;
        let (before, after) = (a.evaluate(&r.event, &[]), b.evaluate(&r.event, &[]));
        if before.verdict == after.verdict {
            continue;
        }
        out.changed += 1;
        if after.verdict > before.verdict {
            out.stricter += 1;
        } else {
            out.looser += 1;
        }
        if out.examples.len() < MAX_EXAMPLES {
            let ev = serde_json::to_value(&r.event).unwrap_or(Value::Null);
            out.examples.push(ImpactRow {
                seq: r.seq,
                ts_ms: r.event.ts_ms,
                agent: r.event.agent.clone(),
                kind: r.event.kind_name().into(),
                target: target_of(&ev),
                before: before.verdict,
                after: after.verdict,
                rules_before: rules(&before),
                rules_after: rules(&after),
            });
        }
    }
    out
}

/// `server/tool`, a model or a peer, for display.
fn target_of(ev: &Value) -> String {
    let k = &ev["kind"];
    let s = |key: &str| k[key].as_str().unwrap_or_default().to_string();
    match k["type"].as_str().unwrap_or_default() {
        "tool_call" | "tool_result" => format!("{}/{}", s("server"), s("tool")),
        "tool_list" => s("server"),
        "llm_request" | "llm_response" => format!("{}/{}", s("provider"), s("model")),
        "a2a_message" | "agent_card" => s("peer"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::MemoryStore;

    const DENY_RM: &str = "rules:\n  - { id: no-rm, match: { tool: rm }, action: deny }\n";

    fn put(name: &str, content: &str) -> Op {
        Op::Put { name: name.into(), kind: SourceKind::Rules, content: content.into() }
    }

    fn ok() -> Validation {
        Validation { ok: true, errors: vec![], warnings: vec![] }
    }

    fn compiled(_: &[Op]) -> Result<PolicySet, Validation> {
        Ok(PolicySet::from_sources(Default::default(), None, None, &[]).unwrap())
    }

    #[test]
    fn propose_review_apply_and_version() {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStore::new());
        let p = Policies::new(store.clone());
        let cfg = Config::default();
        // Validation compiles files and documents together.
        assert!(p.validate(&cfg, std::path::Path::new("."), &[put("guard", DENY_RM)]).ok);
        let bad = p.validate(&cfg, std::path::Path::new("."), &[put("guard", "rules: [{ id: x, action: maybe }]")]);
        assert!(!bad.ok && !bad.errors.is_empty());
        assert!(p.propose("asha", "x", "", vec![put("guard", "rules: [")], bad, None).is_err());
        assert!(matches!(p.apply_ops(&[put("Bad Name", DENY_RM)]), Err(ChangeError::Invalid(_))));

        let c = p.propose("asha", "Block rm", "", vec![put("guard", DENY_RM)], ok(), None).unwrap();
        // The author cannot approve while someone else can.
        assert_eq!(p.approve(&c.id, "asha", "", true, true, compiled).unwrap_err(), ChangeError::SecondPersonRequired);
        // The real compile reads the documents while approving.
        let (applied, _) = p
            .approve(&c.id, "vik", "looks right", true, true, |ops| p.compile(&cfg, std::path::Path::new("."), ops))
            .unwrap();
        assert_eq!(applied.status, Status::Applied);
        assert_eq!(applied.reviews[0].by, "vik");
        assert_eq!(p.docs()[0].version, 1);
        assert_eq!(p.sources()[0].name, "dashboard/guard");
        assert_eq!(
            p.approve(&c.id, "vik", "", true, true, compiled).unwrap_err(),
            ChangeError::Closed(Status::Applied)
        );

        // Alone, the author applies their own change, with a note.
        let c2 = p.propose("asha", "Disable", "", vec![Op::Disable { name: "guard".into() }], ok(), None).unwrap();
        let (applied, _) = p.approve(&c2.id, "asha", "", true, false, compiled).unwrap();
        assert!(applied.note.contains("author"));
        assert!(p.sources().is_empty() && p.docs()[0].version == 2);

        // Two changes from the same base: the second one conflicts.
        let a = p.propose("asha", "A", "", vec![put("guard", DENY_RM)], ok(), None).unwrap();
        let b = p.propose("asha", "B", "", vec![Op::Delete { name: "guard".into() }], ok(), None).unwrap();
        p.approve(&a.id, "vik", "", true, true, compiled).unwrap();
        assert!(matches!(p.approve(&b.id, "vik", "", true, true, compiled), Err(ChangeError::Conflict(_))));
        assert_eq!(p.change(&b.id).unwrap().status, Status::Conflict);

        // Versions are kept, newest first, and everything survives a restart.
        let again = Policies::new(store);
        assert_eq!(again.versions("guard").iter().map(|d| d.version).collect::<Vec<_>>(), [3, 2, 1]);
        assert_eq!(again.changes().len(), 4);
        assert_eq!(again.change(&a.id).unwrap().before["guard"], DENY_RM);

        // Reject and withdraw.
        let r = again.propose("asha", "R", "", vec![Op::Delete { name: "guard".into() }], ok(), None).unwrap();
        assert!(matches!(again.withdraw(&r.id, "vik"), Err(ChangeError::Forbidden(_))));
        assert_eq!(again.reject(&r.id, "vik", "not now").unwrap().status, Status::Rejected);
        let w = again.propose("asha", "W", "", vec![Op::Delete { name: "guard".into() }], ok(), None).unwrap();
        assert_eq!(again.withdraw(&w.id, "asha").unwrap().status, Status::Withdrawn);
    }

    #[test]
    fn preview_reports_changed_decisions() {
        let log = AuditLog::open_in_memory().unwrap();
        let call = |tool: &str| {
            nandi_core::Event::new(
                nandi_core::Source::Eval,
                "bot",
                "s",
                EventKind::ToolCall(nandi_core::ToolCall {
                    server: "sh".into(),
                    tool: tool.into(),
                    call_id: None,
                    args: serde_json::json!({}),
                }),
            )
        };
        for t in ["ls", "rm", "rm", "cat"] {
            log.append(&call(t), &nandi_core::Decision::allow()).unwrap();
        }
        let none = PolicySet::from_sources(Default::default(), None, None, &[]).unwrap();
        let deny = PolicySet::from_sources(Default::default(), None, None, &[DENY_RM]).unwrap();
        let i = preview(&Config::default(), &log, none, deny, 100);
        assert_eq!((i.events, i.changed, i.stricter, i.looser), (4, 2, 2, 0));
        assert_eq!(i.examples[0].target, "sh/rm");
        assert_eq!(i.examples[0].rules_after, ["policy.no-rm"]);
    }
}
