//! MCP server inventory: launch specs, approval, quarantine and risk.
//!
//! Every server the engine hears about gets a record: capture points
//! register how it is launched or reached ([`ServerSpec`]), tool listings
//! fill in its tools with their capabilities and risk scores, and calls of
//! tools never listed (coding-agent hooks, model-requested local tools) are
//! classified by name. Records are persisted under `server/<name>` so scores
//! and the first-seen binary hash survive restarts.
//!
//! Server-level findings, evaluated for tool lists and calls of the server:
//!
//! - `server.unapproved`: not in `servers.approved` (only when the list has
//!   entries). Verdict `servers.on_unknown`; with `deny` the server is
//!   quarantined.
//! - `server.spec-mismatch`: the name is approved but the package, URL or
//!   binary hash differs from the approved entry. Always `deny`.
//! - `server.unpinned`: a stdio server launched from a registry package
//!   without an exact version. Verdict `servers.on_unpinned`.
//! - `server.binary-changed`: a local server binary or script whose hash
//!   differs from the first one seen. Verdict `servers.on_binary_change`.
//!
//! A server with any `deny` finding is quarantined: its tools are hidden
//! from `tools/list` and every call is denied.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use nandi_core::capability::{RiskLevel, server_score};
use nandi_core::config::{ApprovedServer, ServersConfig};
use nandi_core::server::local_digest;
use nandi_core::util::{glob_match, truncate};
use nandi_core::{Capability, Category, Ecosystem, Finding, PackageRef, ServerSpec, Severity, StateStore, Verdict};

use crate::capability::classify_name;
use crate::engine::LOCAL_SERVER;

const PREFIX: &str = "server/";

/// Capabilities and risk of one tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRisk {
    pub name: String,
    pub capabilities: Vec<Capability>,
    /// 0 - 100.
    pub score: u8,
    pub level: RiskLevel,
    /// The description scan raised a high-severity finding.
    #[serde(default)]
    pub description_finding: bool,
    /// The definition drifted from its pin.
    #[serde(default)]
    pub drifted: bool,
    /// Why annotations were overridden, when they were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl ToolRisk {
    /// Risk of a tool with `capabilities`, scored with
    /// [`nandi_core::capability::tool_score`].
    pub fn new(name: &str, capabilities: Vec<Capability>, description_finding: bool, drifted: bool) -> Self {
        let score = nandi_core::capability::tool_score(&capabilities, description_finding, drifted);
        Self {
            name: name.to_string(),
            capabilities,
            score,
            level: RiskLevel::from_score(score),
            description_finding,
            drifted,
            note: None,
        }
    }
}

/// Where a server stands against `servers.approved`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    /// The allow-list is empty (gate off), or the server is the agent's own
    /// `local` tool namespace.
    NotRequired,
    /// An entry matches the name and the registered spec.
    Approved,
    /// No entry matches the name.
    Unapproved,
    /// An entry matches the name, but not the registered spec.
    Mismatch,
}

/// Persisted state of one server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Record {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spec: Option<ServerSpec>,
    /// SHA-256 of the local binary or script as last registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binary_sha256: Option<String>,
    /// SHA-256 first seen for this server name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binary_pin: Option<String>,
    first_seen_ms: u64,
    last_seen_ms: u64,
    #[serde(default)]
    tools: BTreeMap<String, ToolRisk>,
}

impl Record {
    fn package(&self) -> Option<PackageRef> {
        let pkg = self.spec.as_ref()?.package()?;
        Some(match &self.binary_sha256 {
            Some(h) if pkg.ecosystem == Ecosystem::Local => pkg.with_local_digest(h.clone()),
            _ => pkg,
        })
    }
}

/// One server as shown by `GET /v1/servers` and `nandi servers`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerSummary {
    pub name: String,
    /// How the server is launched or reached, when a capture point
    /// registered it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<ServerSpec>,
    /// The package a stdio server runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PackageRef>,
    /// Whether the package is pinned to one artifact; `None` when there is
    /// no package (HTTP servers, servers seen only through hooks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
    pub approval: Approval,
    /// Tools hidden and calls denied.
    pub quarantined: bool,
    /// The local binary differs from the first one seen.
    pub binary_changed: bool,
    /// 0 - 100: the highest tool score plus a small bonus for breadth.
    pub score: u8,
    pub level: RiskLevel,
    /// Union of the tools' capabilities, heaviest first.
    pub capabilities: Vec<Capability>,
    pub tools: Vec<ToolRisk>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

/// An allow-list entry with its package parsed once.
#[derive(Debug, Clone)]
struct Entry {
    cfg: ApprovedServer,
    /// `None` when no package is required; `Some(None)` when it does not
    /// parse (the entry then never matches a spec).
    package: Option<Option<PackageRef>>,
}

/// The server inventory.
pub struct Servers {
    cfg: ServersConfig,
    approved: Vec<Entry>,
    store: Arc<dyn StateStore>,
    records: RwLock<HashMap<String, Record>>,
    dirty: Mutex<HashSet<String>>,
    /// Servers whose alert-level findings were already reported on a call.
    reported: Mutex<HashSet<String>>,
}

fn urls_equal(a: &str, b: &str) -> bool {
    a.trim().trim_end_matches('/').eq_ignore_ascii_case(b.trim().trim_end_matches('/'))
}

impl Servers {
    pub fn new(cfg: ServersConfig, store: Arc<dyn StateStore>) -> Self {
        let approved = cfg
            .approved
            .iter()
            .map(|a| {
                let package = a.package.as_deref().map(|p| match PackageRef::parse_spec(p) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        tracing::warn!(server = %a.name, "servers.approved: {e}; the entry never matches a spec");
                        None
                    }
                });
                Entry { cfg: a.clone(), package }
            })
            .collect();
        let mut records = HashMap::new();
        for key in store.keys(PREFIX) {
            if let Some(bytes) = store.get(&key)
                && let Ok(rec) = serde_json::from_slice::<Record>(&bytes)
            {
                records.insert(key[PREFIX.len()..].to_string(), rec);
            }
        }
        Self {
            cfg,
            approved,
            store,
            records: RwLock::new(records),
            dirty: Mutex::new(HashSet::new()),
            reported: Mutex::new(HashSet::new()),
        }
    }

    fn save(&self, name: &str, rec: &Record) {
        if let Ok(bytes) = serde_json::to_vec(rec) {
            self.store.put(&format!("{PREFIX}{name}"), &bytes);
        }
        self.dirty.lock().remove(name);
    }

    /// Persist records whose last-seen time changed.
    pub fn flush(&self) {
        let names: Vec<String> = self.dirty.lock().drain().collect();
        let records = self.records.read();
        for name in names {
            if let Some(rec) = records.get(&name)
                && let Ok(bytes) = serde_json::to_vec(rec)
            {
                self.store.put(&format!("{PREFIX}{name}"), &bytes);
            }
        }
    }

    /// Record how `name` is launched or reached. For a local binary or
    /// script the file is hashed; the first hash seen is kept as the pin.
    pub fn register(&self, name: &str, spec: ServerSpec, now: u64) {
        let digest = spec.package().as_ref().and_then(local_digest);
        let mut records = self.records.write();
        let rec = records.entry(name.to_string()).or_insert_with(|| Record { first_seen_ms: now, ..Record::default() });
        rec.spec = Some(spec);
        rec.binary_sha256 = digest.clone();
        if rec.binary_pin.is_none() {
            rec.binary_pin = digest;
        }
        rec.last_seen_ms = now;
        let rec = rec.clone();
        drop(records);
        self.reported.lock().remove(name);
        self.save(name, &rec);
    }

    /// Replace the tools of `name` with a fresh listing.
    pub fn record_listing(&self, name: &str, tools: Vec<ToolRisk>, now: u64) {
        let mut records = self.records.write();
        let rec = records.entry(name.to_string()).or_insert_with(|| Record { first_seen_ms: now, ..Record::default() });
        rec.tools = tools.into_iter().map(|t| (t.name.clone(), t)).collect();
        rec.last_seen_ms = now;
        let rec = rec.clone();
        drop(records);
        self.save(name, &rec);
    }

    /// Capabilities of `server/tool` for a call: from the latest listing, or
    /// classified by name (and remembered) when the tool was never listed.
    pub fn observe_call(&self, server: &str, tool: &str, now: u64) -> Vec<Capability> {
        {
            let mut records = self.records.write();
            if let Some(rec) = records.get_mut(server)
                && let Some(t) = rec.tools.get(tool)
            {
                let caps = t.capabilities.clone();
                if rec.last_seen_ms != now {
                    rec.last_seen_ms = now;
                    self.dirty.lock().insert(server.to_string());
                }
                return caps;
            }
        }
        let caps = classify_name(server, tool);
        let mut records = self.records.write();
        let rec =
            records.entry(server.to_string()).or_insert_with(|| Record { first_seen_ms: now, ..Record::default() });
        rec.tools.insert(tool.to_string(), ToolRisk::new(tool, caps.clone(), false, false));
        rec.last_seen_ms = now;
        let rec = rec.clone();
        drop(records);
        self.save(server, &rec);
        caps
    }

    /// Capabilities of `server/tool` without recording anything.
    pub fn capabilities(&self, server: &str, tool: &str) -> Vec<Capability> {
        self.records
            .read()
            .get(server)
            .and_then(|r| r.tools.get(tool))
            .map_or_else(|| classify_name(server, tool), |t| t.capabilities.clone())
    }

    /// Risk of one tool, when the server listed it or it was called.
    pub fn tool_risk(&self, server: &str, tool: &str) -> Option<ToolRisk> {
        self.records.read().get(server)?.tools.get(tool).cloned()
    }

    /// Accept the current binary hash of `name` as its new pin. Returns
    /// false when there is no changed binary.
    pub fn accept_binary(&self, name: &str) -> bool {
        let mut records = self.records.write();
        let Some(rec) = records.get_mut(name) else { return false };
        if rec.binary_sha256.is_none() || rec.binary_pin == rec.binary_sha256 {
            return false;
        }
        rec.binary_pin = rec.binary_sha256.clone();
        let rec = rec.clone();
        drop(records);
        self.reported.lock().remove(name);
        self.save(name, &rec);
        true
    }

    fn approval_of(&self, name: &str, rec: Option<&Record>) -> Approval {
        if name == LOCAL_SERVER || self.approved.is_empty() {
            return Approval::NotRequired;
        }
        let entries: Vec<&Entry> = self.approved.iter().filter(|e| glob_match(&e.cfg.name, name)).collect();
        if entries.is_empty() {
            return Approval::Unapproved;
        }
        // Servers seen only through hooks have no spec: approved by name.
        let Some(spec) = rec.and_then(|r| r.spec.as_ref()) else { return Approval::Approved };
        let package = rec.and_then(Record::package);
        let binary = rec.and_then(|r| r.binary_sha256.as_deref());
        let admits = |e: &Entry| {
            let package_ok = match &e.package {
                None => true,
                Some(None) => false,
                Some(Some(want)) => package.as_ref().is_some_and(|seen| want.admits(seen)),
            };
            let url_ok = e.cfg.url.as_deref().is_none_or(|u| spec.url().is_some_and(|s| urls_equal(u, s)));
            let hash_ok =
                e.cfg.sha256.as_deref().is_none_or(|h| binary.is_some_and(|b| b.eq_ignore_ascii_case(h.trim())));
            package_ok && url_ok && hash_ok
        };
        if entries.into_iter().any(admits) { Approval::Approved } else { Approval::Mismatch }
    }

    /// Server-level findings for `name`.
    pub fn findings(&self, name: &str) -> Vec<Finding> {
        if name == LOCAL_SERVER {
            return Vec::new();
        }
        let records = self.records.read();
        let rec = records.get(name);
        let mut out = Vec::new();
        let shown = || {
            rec.and_then(|r| r.package().map(|p| p.to_string()).or_else(|| r.spec.as_ref().map(ServerSpec::display)))
                .map(|s| truncate(&s, 160).to_string())
        };
        match self.approval_of(name, rec) {
            Approval::Unapproved => {
                let mut f = Finding::new(
                    "server.unapproved",
                    Category::Integrity,
                    Severity::Medium,
                    self.cfg.on_unknown,
                    format!("MCP server {name} is not in servers.approved"),
                );
                if let Some(s) = shown() {
                    f = f.with_evidence(s);
                }
                out.push(f);
            }
            Approval::Mismatch => {
                let mut f = Finding::new(
                    "server.spec-mismatch",
                    Category::Integrity,
                    Severity::High,
                    Verdict::Deny,
                    format!(
                        "MCP server {name} is approved, but what runs under that name does not match the approved entry"
                    ),
                );
                if let Some(s) = shown() {
                    f = f.with_evidence(s);
                }
                out.push(f);
            }
            Approval::Approved | Approval::NotRequired => {}
        }
        if let Some(rec) = rec {
            if matches!(rec.spec, Some(ServerSpec::Stdio { .. }))
                && let Some(pkg) = rec.package()
                && pkg.ecosystem.is_registry()
                && !pkg.pinned
            {
                out.push(
                    Finding::new(
                        "server.unpinned",
                        Category::Integrity,
                        Severity::Low,
                        self.cfg.on_unpinned,
                        format!("MCP server {name} is launched from a package without an exact version"),
                    )
                    .with_evidence(truncate(&pkg.to_string(), 160).to_string()),
                );
            }
            if let (Some(pin), Some(seen)) = (&rec.binary_pin, &rec.binary_sha256)
                && pin != seen
            {
                out.push(
                    Finding::new(
                        "server.binary-changed",
                        Category::Integrity,
                        Severity::High,
                        self.cfg.on_binary_change,
                        format!("the local program of MCP server {name} changed since it was first seen"),
                    )
                    .with_evidence(format!(
                        "pinned {} now {}",
                        truncate(pin, 12),
                        truncate(seen, 12)
                    )),
                );
            }
        }
        out
    }

    /// Findings for a call of a tool on `name`. Blocking findings (`ask`,
    /// `deny`) apply to every call; alert-level ones are reported on tool
    /// listings, and on calls only once per server when it never listed its
    /// tools (servers seen through hooks).
    pub fn call_findings(&self, name: &str, listed: bool) -> Vec<Finding> {
        let mut out = self.findings(name);
        if out.iter().all(|f| f.verdict < Verdict::Ask) {
            let first = !listed && !out.is_empty() && self.reported.lock().insert(name.to_string());
            if !first {
                out.clear();
            }
        } else {
            out.retain(|f| f.verdict >= Verdict::Ask);
        }
        out
    }

    /// Approval status of `name`.
    pub fn approval(&self, name: &str) -> Approval {
        self.approval_of(name, self.records.read().get(name))
    }

    /// All known servers, riskiest first.
    pub fn summaries(&self) -> Vec<ServerSummary> {
        let names: Vec<String> = self.records.read().keys().cloned().collect();
        let mut out: Vec<ServerSummary> = names
            .into_iter()
            .filter_map(|name| {
                let findings = self.findings(&name);
                let records = self.records.read();
                let rec = records.get(&name)?;
                let package = rec.package();
                let tools: Vec<ToolRisk> = rec.tools.values().cloned().collect();
                let mut caps: Vec<Capability> = tools.iter().flat_map(|t| t.capabilities.iter().copied()).collect();
                caps.sort_unstable_by(|a, b| b.weight().cmp(&a.weight()).then(a.cmp(b)));
                caps.dedup();
                let scores: Vec<u8> = tools.iter().map(|t| t.score).collect();
                let score = server_score(&scores, &caps);
                Some(ServerSummary {
                    spec: rec.spec.clone(),
                    pinned: package.as_ref().map(|p| p.pinned),
                    package,
                    approval: self.approval_of(&name, Some(rec)),
                    quarantined: findings.iter().any(|f| f.verdict == Verdict::Deny),
                    binary_changed: findings.iter().any(|f| f.rule == "server.binary-changed"),
                    score,
                    level: RiskLevel::from_score(score),
                    capabilities: caps,
                    tools,
                    first_seen_ms: rec.first_seen_ms,
                    last_seen_ms: rec.last_seen_ms,
                    name,
                })
            })
            .collect();
        out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::MemoryStore;

    fn servers(yaml: &str) -> (Servers, Arc<dyn StateStore>) {
        let cfg = nandi_core::Config::from_yaml(yaml).unwrap().servers;
        let store: Arc<dyn StateStore> = Arc::new(MemoryStore::new());
        (Servers::new(cfg, store.clone()), store)
    }

    fn npx(pkg: &str) -> ServerSpec {
        ServerSpec::Stdio { command: "npx".into(), args: vec!["-y".into(), pkg.into()] }
    }

    fn rules(f: &[Finding]) -> Vec<(&str, Verdict)> {
        f.iter().map(|f| (f.rule.as_str(), f.verdict)).collect()
    }

    #[test]
    fn gate_is_off_without_an_allow_list() {
        let (s, _) = servers("");
        s.register("gh", npx("@modelcontextprotocol/server-github@2025.4.8"), 1);
        assert_eq!(s.approval("gh"), Approval::NotRequired);
        assert!(s.findings("gh").is_empty());
        s.register("fs", npx("@modelcontextprotocol/server-filesystem"), 1);
        assert_eq!(rules(&s.findings("fs")), [("server.unpinned", Verdict::Alert)]);
        assert!(s.findings("never-seen").is_empty());
    }

    #[test]
    fn approval_by_name_package_url_and_hash() {
        let (s, _) = servers(
            r#"
servers:
  on_unknown: deny
  approved:
    - { name: github, package: "npm:@modelcontextprotocol/server-github@2025.4.8" }
    - { name: web, url: "https://api.githubcopilot.com/mcp/" }
    - { name: hooked }
    - { name: tools, sha256: "00ff" }
    - { name: broken, package: "cargo:x" }
"#,
        );
        s.register("github", npx("@modelcontextprotocol/server-github@2025.4.8"), 1);
        assert_eq!(s.approval("github"), Approval::Approved);
        assert!(s.findings("github").is_empty());
        s.register("github", npx("@modelcontextprotocol/server-github@2025.5.1"), 2);
        assert_eq!(s.approval("github"), Approval::Mismatch);
        assert_eq!(rules(&s.findings("github")), [("server.spec-mismatch", Verdict::Deny)]);

        s.register("web", ServerSpec::Http { url: "https://API.githubcopilot.com/mcp".into() }, 1);
        assert_eq!(s.approval("web"), Approval::Approved);
        s.register("web", ServerSpec::Http { url: "https://evil.example/mcp".into() }, 1);
        assert_eq!(s.approval("web"), Approval::Mismatch);

        // Hook-only servers have no spec and match by name.
        assert_eq!(s.approval("hooked"), Approval::Approved);
        assert_eq!(s.approval("stranger"), Approval::Unapproved);
        assert_eq!(rules(&s.findings("stranger")), [("server.unapproved", Verdict::Deny)]);

        // No hash could be computed for a missing binary: mismatch.
        s.register("tools", ServerSpec::Stdio { command: "/does/not/exist".into(), args: vec![] }, 1);
        assert_eq!(s.approval("tools"), Approval::Mismatch);
        s.register("broken", npx("x@1.0.0"), 1);
        assert_eq!(s.approval("broken"), Approval::Mismatch);
        assert_eq!(s.approval(LOCAL_SERVER), Approval::NotRequired);
    }

    #[test]
    fn call_findings_report_alerts_once_and_blocks_always() {
        let (s, _) = servers("servers: { approved: [ { name: ok } ] }");
        assert_eq!(rules(&s.call_findings("other", false)), [("server.unapproved", Verdict::Alert)]);
        assert!(s.call_findings("other", false).is_empty());
        assert!(s.call_findings("listed", true).is_empty());
        let (s, _) = servers("servers: { on_unknown: ask, approved: [ { name: ok } ] }");
        assert_eq!(s.call_findings("other", true).len(), 1);
        assert_eq!(s.call_findings("other", true).len(), 1);
    }

    #[test]
    fn binary_changes_are_pinned_and_persisted() {
        let dir = std::env::temp_dir().join(format!("nandi-servers-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("server.js");
        std::fs::write(&bin, b"v1").unwrap();
        let spec = ServerSpec::Stdio { command: "node".into(), args: vec![bin.display().to_string()] };
        let (s, store) = servers("");
        s.register("local-srv", spec.clone(), 1);
        assert!(s.findings("local-srv").is_empty(), "a hashed local file is pinned");
        std::fs::write(&bin, b"v2").unwrap();
        s.register("local-srv", spec.clone(), 2);
        assert_eq!(rules(&s.findings("local-srv")), [("server.binary-changed", Verdict::Alert)]);
        let again = Servers::new(ServersConfig::default(), store);
        assert_eq!(again.findings("local-srv").len(), 1);
        assert!(again.summaries()[0].binary_changed);
        assert!(again.accept_binary("local-srv"));
        assert!(!again.accept_binary("local-srv"));
        assert!(again.findings("local-srv").is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn summaries_score_tools() {
        let (s, store) = servers("");
        s.record_listing(
            "shop",
            vec![
                ToolRisk::new("refund", vec![Capability::Payment], false, false),
                ToolRisk::new("list_orders", vec![Capability::ReadOnly], false, false),
                ToolRisk::new("email_customer", vec![Capability::ExternalSend], true, false),
            ],
            5,
        );
        assert_eq!(s.observe_call("shop", "refund", 6), [Capability::Payment]);
        assert_eq!(s.observe_call("hooked", "delete_repo", 7), [Capability::DataDeletion]);
        let all = s.summaries();
        assert_eq!(all[0].name, "shop");
        assert_eq!(all[0].capabilities, [Capability::Payment, Capability::ExternalSend, Capability::ReadOnly]);
        // max(40, 25 + 20) = 45, plus 2 for one extra capability.
        assert_eq!(all[0].score, 47);
        assert_eq!(all[0].level, RiskLevel::Medium);
        assert_eq!(all[1].tools[0].capabilities, [Capability::DataDeletion]);
        s.flush();
        let again = Servers::new(ServersConfig::default(), store);
        assert_eq!(again.tool_risk("shop", "refund").unwrap().score, 40);
        assert_eq!(again.summaries()[0].last_seen_ms, 6);
    }
}
