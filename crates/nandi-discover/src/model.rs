//! The inventory data model. Serialized as JSON for `nandi discover --json`
//! and for `POST /v1/inventory`.
//!
//! Secret values never appear in an inventory: environment variables and
//! headers are recorded by name only, and commands, arguments and URLs are
//! redacted before they are stored.

use nandi_core::{Finding, Severity};
use serde::{Deserialize, Serialize};

/// Everything found on one machine.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    pub host: String,
    pub scanned_at_ms: u64,
    pub nandi_version: String,
    #[serde(default)]
    pub items: Vec<Item>,
    #[serde(default)]
    pub coverage: Coverage,
    /// Files that could not be read or parsed.
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl Inventory {
    /// All findings with the item they belong to.
    pub fn findings(&self) -> impl Iterator<Item = (&Item, &Finding)> {
        self.items.iter().flat_map(|i| i.findings().iter().map(move |f| (i, f)))
    }

    /// Highest severity of any finding.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings().map(|(_, f)| f.severity).max()
    }
}

/// One thing found on the machine, tagged by `type`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Item {
    Client(Client),
    McpServer(McpServer),
    Hook(Hook),
    Skill(Skill),
    Plugin(Plugin),
    Extension(Extension),
}

impl Item {
    pub fn kind(&self) -> &'static str {
        match self {
            Item::Client(_) => "client",
            Item::McpServer(_) => "mcp_server",
            Item::Hook(_) => "hook",
            Item::Skill(_) => "skill",
            Item::Plugin(_) => "plugin",
            Item::Extension(_) => "extension",
        }
    }

    /// Key of the client (agent) this item belongs to.
    pub fn client(&self) -> &str {
        match self {
            Item::Client(x) => &x.client,
            Item::McpServer(x) => &x.client,
            Item::Hook(x) => &x.client,
            Item::Skill(x) => &x.client,
            Item::Plugin(x) => &x.client,
            Item::Extension(x) => &x.client,
        }
    }

    /// Short display name of the item.
    pub fn name(&self) -> &str {
        match self {
            Item::Client(x) => &x.name,
            Item::McpServer(x) => &x.name,
            Item::Hook(x) => &x.event,
            Item::Skill(x) => &x.name,
            Item::Plugin(x) => &x.name,
            Item::Extension(x) => &x.id,
        }
    }

    pub fn findings(&self) -> &[Finding] {
        match self {
            Item::Client(x) => &x.findings,
            Item::McpServer(x) => &x.findings,
            Item::Hook(x) => &x.findings,
            Item::Skill(x) => &x.findings,
            Item::Plugin(x) => &x.findings,
            Item::Extension(x) => &x.findings,
        }
    }
}

/// An AI agent or editor with configuration on this machine.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Client {
    /// Stable key, e.g. `claude-code`.
    pub client: String,
    /// Display name, e.g. `Claude Code`.
    pub name: String,
    /// Configuration files and directories found.
    #[serde(default)]
    pub config_paths: Vec<String>,
    /// Whether the client supports command hooks.
    #[serde(default)]
    pub supports_hooks: bool,
    /// For clients with hooks: is a `nandi hook` installed anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nandi_hook: Option<bool>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// How an MCP client talks to a server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    #[default]
    Stdio,
    Http,
    Sse,
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Stdio => "stdio",
            Transport::Http => "http",
            Transport::Sse => "sse",
        }
    }
}

/// How a server's traffic reaches nandi.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Via {
    /// Launched through `nandi wrap`.
    Wrapped {
        /// `--server` name used in policies.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<String>,
        /// `-c/--config` given to the wrapper.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config: Option<String>,
        /// The real server command after `--` (redacted).
        #[serde(default)]
        inner_command: Vec<String>,
    },
    /// A remote server reached through a nandi proxy route.
    Routed { base_url: String },
}

/// An MCP server configured in a client.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct McpServer {
    pub client: String,
    /// `user`, `project:<path>` or `plugin:<name>`.
    pub scope: String,
    pub name: String,
    /// File the server is configured in.
    pub source: String,
    pub transport: Transport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Environment variable names. Values are never recorded.
    #[serde(default)]
    pub env: Vec<String>,
    /// HTTP header names. Values are never recorded.
    #[serde(default)]
    pub headers: Vec<String>,
    /// Turned off in the client's configuration.
    #[serde(default)]
    pub disabled: bool,
    /// `None` when the server bypasses nandi.
    #[serde(default)]
    pub via_nandi: Option<Via>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// A command hook configured in a client.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Hook {
    pub client: String,
    pub scope: String,
    pub source: String,
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    /// The hook command (redacted).
    pub command: String,
    /// Runs `nandi hook`.
    pub is_nandi: bool,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// An agent skill (a directory with `SKILL.md`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Skill {
    pub client: String,
    pub scope: String,
    pub name: String,
    pub path: String,
    pub files_scanned: usize,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// An installed client plugin.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Plugin {
    pub client: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub path: String,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// An installed editor extension.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Extension {
    pub client: String,
    /// `publisher.name`, lowercase.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// An AI assistant or agent extension.
    pub ai_related: bool,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// How much of the footprint nandi sees.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Coverage {
    /// Enabled MCP servers.
    pub servers_total: usize,
    /// Of those, wrapped or routed through nandi.
    pub servers_via_nandi: usize,
    pub servers_wrapped: usize,
    pub servers_routed: usize,
    /// Clients that support hooks.
    pub hook_clients: usize,
    /// Of those, clients with a nandi hook installed.
    pub hooks_installed: usize,
    #[serde(default)]
    pub clients: Vec<ClientCoverage>,
    #[serde(default)]
    pub suggestions: Vec<Suggestion>,
}

/// Coverage of one client.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientCoverage {
    pub client: String,
    pub name: String,
    pub servers_total: usize,
    pub servers_via_nandi: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nandi_hook: Option<bool>,
}

/// What a suggestion fixes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionKind {
    /// Launch a stdio server through `nandi wrap`.
    #[default]
    Wrap,
    /// Send a remote server through a nandi proxy route.
    Route,
    /// Install the nandi hook.
    Hook,
}

/// A configuration change that brings something under nandi.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Suggestion {
    pub client: String,
    pub kind: SuggestionKind,
    /// Server name, or `hooks` for a hook suggestion.
    pub target: String,
    /// Scope of the server (empty for hooks).
    #[serde(default)]
    pub scope: String,
    /// File to edit.
    pub file: String,
    pub message: String,
    /// Replacement or addition, in the file's own format.
    pub snippet: String,
}
