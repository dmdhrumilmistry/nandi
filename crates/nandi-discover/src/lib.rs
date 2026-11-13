//! AI footprint inventory: which AI agents, MCP servers, hooks, skills,
//! plugins and editor extensions are installed or configured on a machine,
//! and which of them bypass nandi.
//!
//! [`scan`] reads the configuration files of the common agents (Claude Code,
//! Claude Desktop, Cursor, Windsurf, VS Code, Codex, Gemini CLI, Zed and
//! Continue) under a home directory and a list of project directories. It
//! never touches the network and never fails: missing files are skipped and
//! files that cannot be parsed become warnings.
//!
//! Every [`Item`] carries [`Finding`]s:
//!
//! - `config.plaintext-secret`: a secret written into an MCP server's `env`,
//!   `headers`, arguments or URL (or a client's `env` settings). Only the
//!   masked evidence is kept; values are never stored in the inventory.
//! - `coverage.unwrapped-server`: an MCP server neither launched through
//!   `nandi wrap` nor routed through a nandi proxy URL.
//! - `coverage.no-hook`: a client with hook support but no `nandi hook`.
//! - `server.remote-http`: a remote MCP server over plain `http://`.
//! - `skill.*` and `hook.*`: risky commands in skills and hooks (downloads
//!   piped into a shell, credential reads, disabled safety checks), plus the
//!   detector's injection and secret findings for skill files.
//!
//! [`Inventory::coverage`] summarizes how many servers go through nandi and
//! lists the exact configuration changes that would bring the rest in.

mod coverage;
mod hooks;
mod jsonc;
mod mcp;
mod model;
mod render;
mod skills;
mod sources;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use nandi_core::config::DetectConfig;
use nandi_core::{Category, Finding, Severity, Verdict};
use nandi_detect::Detector;
use serde_json::{Value, json};

pub use model::*;
pub use render::{render_suggestions, render_text};

/// Proxy base URLs treated as nandi when no others are configured.
pub const DEFAULT_PROXY_URLS: &[&str] = &["http://127.0.0.1:8787", "http://localhost:8787"];

/// Client keys.
pub const CLAUDE_CODE: &str = "claude-code";
pub const CLAUDE_DESKTOP: &str = "claude-desktop";
pub const CURSOR: &str = "cursor";
pub const WINDSURF: &str = "windsurf";
pub const VSCODE: &str = "vscode";
pub const CODEX: &str = "codex";
pub const GEMINI: &str = "gemini-cli";
pub const ZED: &str = "zed";
pub const CONTINUE: &str = "continue";

/// Rule ids.
pub const RULE_PLAINTEXT_SECRET: &str = "config.plaintext-secret";
pub const RULE_UNWRAPPED: &str = "coverage.unwrapped-server";
pub const RULE_NO_HOOK: &str = "coverage.no-hook";
pub const RULE_REMOTE_HTTP: &str = "server.remote-http";

/// Display name of a client key.
pub fn client_name(client: &str) -> &str {
    match client {
        CLAUDE_CODE => "Claude Code",
        CLAUDE_DESKTOP => "Claude Desktop",
        CURSOR => "Cursor",
        WINDSURF => "Windsurf",
        VSCODE => "VS Code",
        CODEX => "Codex",
        GEMINI => "Gemini CLI",
        ZED => "Zed",
        CONTINUE => "Continue",
        other => other,
    }
}

/// Clients whose hooks can call `nandi hook`.
pub fn supports_hooks(client: &str) -> bool {
    matches!(client, CLAUDE_CODE | CURSOR)
}

/// What to scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Home directory whose user-level configuration is read.
    pub home: PathBuf,
    /// Project directories whose project-level configuration is read.
    pub projects: Vec<PathBuf>,
    /// Base URLs of nandi proxies. A remote MCP server whose URL starts with
    /// one of them is routed through nandi.
    pub proxy_urls: Vec<String>,
    /// nandi config path written into suggested `nandi wrap` commands.
    pub nandi_config: String,
    /// Host name to report (default: this machine's).
    pub host: Option<String>,
}

impl ScanOptions {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self {
            home: home.into(),
            projects: Vec::new(),
            proxy_urls: DEFAULT_PROXY_URLS.iter().map(|s| s.to_string()).collect(),
            nandi_config: "/path/to/nandi.yaml".into(),
            host: None,
        }
    }
}

/// Scan the machine described by `opts`.
pub fn scan(opts: &ScanOptions) -> Inventory {
    let mut sc = Scanner::new(opts);
    sources::scan_all(&mut sc);
    sc.finish()
}

/// Largest configuration file read (Claude Code's `~/.claude.json` keeps
/// project history and can grow to several megabytes).
const MAX_CONFIG_BYTES: u64 = 32 << 20;

/// Shared state of one scan.
pub(crate) struct Scanner<'a> {
    pub opts: &'a ScanOptions,
    pub detector: Detector,
    pub items: Vec<Item>,
    pub warnings: Vec<String>,
    /// Clients in discovery order with the configuration paths found.
    clients: Vec<(&'static str, Vec<String>)>,
    /// Findings about a client's own settings.
    client_findings: Vec<(&'static str, Finding)>,
    /// Canonical paths already read, so a project that is also the home
    /// directory is not reported twice.
    seen: HashSet<PathBuf>,
}

impl<'a> Scanner<'a> {
    fn new(opts: &'a ScanOptions) -> Self {
        let cfg = DetectConfig { pii: false, ssrf: false, ..DetectConfig::default() };
        Self {
            opts,
            detector: Detector::new(&cfg),
            items: Vec::new(),
            warnings: Vec::new(),
            clients: Vec::new(),
            client_findings: Vec::new(),
            seen: HashSet::new(),
        }
    }

    /// `~/...` for paths under the home directory, else the path itself.
    /// Paths under the home directory use `/` on every platform, so reports
    /// from Windows and Unix machines read the same.
    pub fn disp(&self, p: &Path) -> String {
        match p.strip_prefix(&self.opts.home) {
            Ok(rest) if rest.as_os_str().is_empty() => "~".into(),
            Ok(rest) => {
                let parts: Vec<String> =
                    rest.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
                format!("~/{}", parts.join("/"))
            }
            Err(_) => p.display().to_string(),
        }
    }

    pub fn home(&self, rel: &str) -> PathBuf {
        self.opts.home.join(rel)
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    /// Record that `client` has configuration at `p` (file or directory).
    pub fn found(&mut self, client: &'static str, p: &Path) {
        let shown = self.disp(p);
        match self.clients.iter_mut().find(|(c, _)| *c == client) {
            Some((_, paths)) => {
                if !paths.contains(&shown) {
                    paths.push(shown);
                }
            }
            None => self.clients.push((client, vec![shown])),
        }
    }

    /// Record `p` for `client` when it exists.
    pub fn found_if_exists(&mut self, client: &'static str, p: &Path) -> bool {
        let exists = p.exists();
        if exists {
            self.found(client, p);
        }
        exists
    }

    /// Mark a path as read. `false` when it was read before.
    pub fn first_visit(&mut self, p: &Path) -> bool {
        let key = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        self.seen.insert(key)
    }

    /// Read a configuration file of `client`. `None` when it does not exist,
    /// was already read, or cannot be read (a warning is recorded).
    pub fn read_text(&mut self, client: &'static str, p: &Path) -> Option<String> {
        self.read_text_as(Some(client), p)
    }

    /// Like [`Scanner::read_text`], without listing the file among the
    /// client's configuration paths (plugin internals).
    pub fn read_text_as(&mut self, client: Option<&'static str>, p: &Path) -> Option<String> {
        if !p.is_file() || !self.first_visit(p) {
            return None;
        }
        if let Some(client) = client {
            self.found(client, p);
        }
        match std::fs::metadata(p) {
            Ok(m) if m.len() > MAX_CONFIG_BYTES => {
                self.warn(format!("{}: skipped, larger than {} MiB", self.disp(p), MAX_CONFIG_BYTES >> 20));
                return None;
            }
            _ => {}
        }
        match std::fs::read(p) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => Some(s),
                Err(_) => {
                    self.warn(format!("{}: not UTF-8 text", self.disp(p)));
                    None
                }
            },
            Err(e) => {
                self.warn(format!("{}: {e}", self.disp(p)));
                None
            }
        }
    }

    /// Read a JSON (or JSON with comments) configuration file.
    pub fn read_json(&mut self, client: &'static str, p: &Path) -> Option<Value> {
        self.read_json_as(Some(client), p)
    }

    /// Read a JSON file without listing it as a client configuration path.
    pub fn read_json_as(&mut self, client: Option<&'static str>, p: &Path) -> Option<Value> {
        let text = self.read_text_as(client, p)?;
        match jsonc::parse(&text) {
            Ok(v) => Some(v),
            Err(e) => {
                self.warn(format!("{}: invalid JSON: {e}", self.disp(p)));
                None
            }
        }
    }

    /// Read a YAML configuration file.
    pub fn read_yaml(&mut self, client: &'static str, p: &Path) -> Option<Value> {
        let text = self.read_text(client, p)?;
        match serde_saphyr::from_str::<Value>(&text) {
            Ok(v) => Some(v),
            Err(e) => {
                self.warn(format!("{}: invalid YAML: {e}", self.disp(p)));
                None
            }
        }
    }

    /// Read a TOML configuration file.
    pub fn read_toml(&mut self, client: &'static str, p: &Path) -> Option<Value> {
        let text = self.read_text(client, p)?;
        match toml::from_str::<Value>(&text) {
            Ok(v) => Some(v),
            Err(e) => {
                self.warn(format!("{}: invalid TOML: {}", self.disp(p), e.to_string().trim()));
                None
            }
        }
    }

    /// Check one configuration value for a plaintext secret. `key` is the
    /// variable, header or flag name holding it, when there is one. Returns
    /// the value with secrets redacted and a finding per secret.
    pub fn check_secret(&self, what: &str, key: Option<&str>, value: &str) -> (String, Vec<Finding>) {
        // References such as `${GITHUB_TOKEN}`, `${env:X}` or `$X` are
        // resolved by the client and are the recommended practice.
        if value.trim_start().starts_with('$') {
            return (value.to_string(), Vec::new());
        }
        let wrapped = match key {
            Some(k) => json!({ k: value }),
            None => Value::String(value.to_string()),
        };
        let scan = self.detector.scan_egress(&wrapped);
        let findings: Vec<Finding> = scan
            .findings
            .into_iter()
            .filter(|f| matches!(f.category, Category::Secret | Category::Exfiltration))
            .map(|f| {
                let label = match key {
                    Some(k) => format!("{what} {k}"),
                    None => what.to_string(),
                };
                let evidence = f.evidence.as_deref().map(|e| e.split(" at /").next().unwrap_or(e).to_string());
                let mut out = Finding::new(
                    RULE_PLAINTEXT_SECRET,
                    Category::Secret,
                    Severity::High,
                    Verdict::Alert,
                    format!("Plaintext secret in {label} ({})", f.rule),
                );
                out.evidence = evidence;
                out
            })
            .collect();
        if findings.is_empty() {
            return (value.to_string(), findings);
        }
        let redacted = self
            .detector
            .redact(&wrapped)
            .and_then(|v| match key {
                Some(k) => v.get(k).and_then(Value::as_str).map(str::to_string),
                None => v.as_str().map(str::to_string),
            })
            .unwrap_or_else(|| "[REDACTED]".into());
        (redacted, findings)
    }

    pub fn push(&mut self, item: impl Into<Item>) {
        self.items.push(item.into());
    }

    /// Attach a finding to a client's own item.
    pub fn client_finding(&mut self, client: &'static str, finding: Finding) {
        self.client_findings.push((client, finding));
    }

    fn finish(mut self) -> Inventory {
        // Client items first, in discovery order.
        let mut items: Vec<Item> = Vec::with_capacity(self.items.len() + self.clients.len());
        for (client, paths) in std::mem::take(&mut self.clients) {
            let hooks = supports_hooks(client);
            let installed = hooks
                .then(|| self.items.iter().any(|i| matches!(i, Item::Hook(h) if h.client == client && h.is_nandi)));
            let mut c = Client {
                client: client.into(),
                name: client_name(client).into(),
                config_paths: paths,
                supports_hooks: hooks,
                nandi_hook: installed,
                findings: Vec::new(),
            };
            c.findings.extend(self.client_findings.iter().filter(|(k, _)| *k == client).map(|(_, f)| f.clone()));
            if installed == Some(false) {
                c.findings.push(Finding::new(
                    RULE_NO_HOOK,
                    Category::Policy,
                    Severity::Low,
                    Verdict::Alert,
                    format!("{} supports hooks but none runs `nandi hook`; its built-in tools bypass nandi", c.name),
                ));
            }
            items.push(Item::Client(c));
        }
        items.append(&mut self.items);
        let coverage = coverage::compute(&items, self.opts);
        Inventory {
            host: self.opts.host.clone().unwrap_or_else(hostname),
            scanned_at_ms: nandi_core::util::now_ms(),
            nandi_version: env!("CARGO_PKG_VERSION").into(),
            items,
            coverage,
            warnings: self.warnings,
        }
    }
}

macro_rules! into_item {
    ($($t:ident),*) => {$(
        impl From<$t> for Item {
            fn from(x: $t) -> Item {
                Item::$t(x)
            }
        }
    )*};
}
into_item!(Client, McpServer, Hook, Skill, Plugin, Extension);

/// This machine's host name, without any network lookup.
pub fn hostname() -> String {
    let from_file = |p: &str| std::fs::read_to_string(p).ok().map(|s| s.trim().to_string());
    std::env::var("NANDI_HOST")
        .ok()
        .or_else(|| from_file("/proc/sys/kernel/hostname"))
        .or_else(|| from_file("/etc/hostname"))
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown".into())
}
