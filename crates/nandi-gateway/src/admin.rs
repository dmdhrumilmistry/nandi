//! Admin API, dashboard and metrics endpoint.

use std::future::Future;
use std::sync::Arc;

use crate::App;

/// Serve the admin listener (`cfg.admin.listen`) until `shutdown` resolves.
pub async fn serve(app: Arc<App>, shutdown: impl Future<Output = ()> + Send + 'static) -> anyhow::Result<()> {
    let _ = (app, shutdown);
    anyhow::bail!("admin API not implemented yet")
}
