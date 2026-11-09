//! `nandi wrap`: interpose on a stdio MCP server.

use std::sync::Arc;

use crate::App;

/// Options for wrapping one stdio MCP server.
#[derive(Debug, Clone)]
pub struct WrapOptions {
    /// Logical server name used in policies (`server/tool`).
    pub server: String,
    /// Agent identity to attribute traffic to.
    pub agent: String,
    /// Session id; defaults to a fresh id per wrapper process.
    pub session: Option<String>,
    /// Command and arguments of the MCP server.
    pub command: Vec<String>,
}

/// Run the wrapped server until either side closes. Returns the child's
/// exit code.
pub async fn run(app: Arc<App>, opts: WrapOptions) -> anyhow::Result<i32> {
    let _ = (app, opts);
    anyhow::bail!("stdio wrapper not implemented yet")
}
