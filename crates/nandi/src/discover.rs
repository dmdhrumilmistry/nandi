//! `nandi discover`: inventory the AI agents, MCP servers, hooks and skills
//! on this machine and show which of them bypass nandi.

use std::path::{Path, PathBuf};

use nandi_core::Config;
use nandi_discover::{DEFAULT_PROXY_URLS, ScanOptions};

use crate::remote::{self, AdminOpts, Remote};

pub struct Args {
    pub home: Option<PathBuf>,
    pub projects: Vec<PathBuf>,
    pub json: bool,
    pub suggest: bool,
    pub nandi_config: Option<PathBuf>,
    pub proxy_urls: Vec<String>,
    pub report: bool,
    pub admin: Option<String>,
    pub token: Option<String>,
}

/// Proxy URL of a `listen.proxy` address (wildcard binds become loopback).
fn proxy_url_from_listen(listen: &str) -> Option<String> {
    let listen = listen.trim();
    if listen.is_empty() {
        return None;
    }
    let listen = listen.replacen("0.0.0.0", "127.0.0.1", 1).replacen("[::]", "[::1]", 1);
    Some(format!("http://{listen}"))
}

fn options(args: &Args, config: &Path) -> ScanOptions {
    let home = args
        .home
        .clone()
        .or_else(|| std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    let projects = if args.projects.is_empty() {
        std::env::current_dir().map(|d| vec![d]).unwrap_or_default()
    } else {
        args.projects.clone()
    };
    let mut proxy_urls: Vec<String> = if args.proxy_urls.is_empty() {
        DEFAULT_PROXY_URLS.iter().map(|s| s.to_string()).collect()
    } else {
        args.proxy_urls.clone()
    };
    let cfg = Config::load(config).ok();
    if let Some(url) = cfg.as_ref().and_then(|c| proxy_url_from_listen(&c.listen.proxy))
        && !proxy_urls.contains(&url)
    {
        proxy_urls.push(url);
    }
    let nandi_config = args.nandi_config.as_deref().unwrap_or(config);
    let nandi_config = std::path::absolute(nandi_config).unwrap_or_else(|_| nandi_config.to_path_buf());
    let mut opts = ScanOptions::new(home);
    opts.projects = projects;
    opts.proxy_urls = proxy_urls;
    opts.nandi_config = nandi_config.display().to_string();
    opts
}

/// Run the scan, print it and optionally report it. Never fails: problems
/// are printed to stderr so discovery can run from login scripts and MDM.
pub async fn run(args: Args, config: &Path) -> anyhow::Result<i32> {
    let opts = options(&args, config);
    let inv = tokio::task::spawn_blocking(move || nandi_discover::scan(&opts)).await?;
    for w in &inv.warnings {
        eprintln!("warning: {w}");
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&inv)?);
    } else {
        print!("{}", nandi_discover::render_text(&inv));
        if args.suggest {
            print!("{}", nandi_discover::render_suggestions(&inv));
        }
    }
    if args.report {
        let opts = AdminOpts { admin: args.admin.clone(), token: args.token.clone(), json: false };
        let (url, token) = remote::resolve_report_target(&opts, config);
        let body = serde_json::to_value(&inv)?;
        match Remote::new(url.clone(), token).post("/v1/inventory", Some(body)).await {
            Ok(_) => eprintln!("reported {} items for {} to {url}", inv.items.len(), inv.host),
            Err(e) => eprintln!("warning: reporting to {url} failed: {e:#}"),
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_to_proxy_url() {
        assert_eq!(proxy_url_from_listen("0.0.0.0:8787").as_deref(), Some("http://127.0.0.1:8787"));
        assert_eq!(proxy_url_from_listen(" "), None);
    }
}
