//! HTTP gateway in front of LLM APIs, MCP servers and A2A agents.

use std::future::Future;
use std::sync::Arc;

use crate::App;

/// Serve the proxy listener (`cfg.listen.proxy`) until `shutdown` resolves.
pub async fn serve(app: Arc<App>, shutdown: impl Future<Output = ()> + Send + 'static) -> anyhow::Result<()> {
    let _ = (app, shutdown);
    anyhow::bail!("proxy not implemented yet")
}
