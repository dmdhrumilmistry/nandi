//! Malicious-package and vulnerability lookups in the OSV database
//! (<https://osv.dev>) for MCP servers started from npm or PyPI packages.
//!
//! A lookup sends the package name, and the version when it is pinned, to
//! `POST {servers.osv.url}/v1/query`. Results are cached in the state store
//! for `servers.osv.cache_hours`. A pinned version is checked for every
//! advisory; an unpinned one can resolve to any version, so only
//! malicious-package reports (which cover the whole package) count. Network
//! and parse errors are logged and the server starts as usual.

use std::time::Duration;

use http_body_util::{BodyExt, Limited};
use serde_json::{Value, json};

use nandi_core::util::now_ms;
use nandi_core::{Advisory, AdvisoryCheck, Ecosystem, PackageRef};

use crate::app::App;
use crate::client::full;

/// State store prefix for cached lookups.
const PREFIX: &str = "osv/";
/// Largest response read.
const MAX_BODY: usize = 4 << 20;
/// Advisories kept per lookup.
const MAX_ADVISORIES: usize = 50;

/// The OSV query for `pkg`, or `None` for packages OSV does not cover
/// (container images, local files, git or URL installs).
pub fn query_for(pkg: &PackageRef) -> Option<Value> {
    let ecosystem = match pkg.ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "PyPI",
        Ecosystem::Oci | Ecosystem::Local => return None,
    };
    if pkg.name.is_empty() || pkg.name.contains("://") || pkg.name.starts_with("git+") {
        return None;
    }
    let mut q = json!({ "package": { "name": pkg.name, "ecosystem": ecosystem } });
    if pkg.pinned
        && let Some(v) = pkg.version.as_deref().map(|v| v.trim_start_matches('=').trim()).filter(|v| !v.is_empty())
    {
        q["version"] = json!(v);
    }
    Some(q)
}

/// Advisories in an OSV query response. Without a pinned version only
/// malicious-package reports are kept.
pub fn parse_response(body: &Value, pinned: bool) -> Vec<Advisory> {
    let mut out: Vec<Advisory> = body["vulns"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| {
            let id = v["id"].as_str()?.to_string();
            let aliases = v["aliases"].as_array().into_iter().flatten().filter_map(Value::as_str);
            let malicious = id.starts_with("MAL-") || aliases.clone().any(|a| a.starts_with("MAL-"));
            let summary = v["summary"].as_str().unwrap_or_default().chars().take(200).collect();
            Some(Advisory { id, summary, malicious })
        })
        .filter(|a| pinned || a.malicious)
        .collect();
    // Malicious reports first, then by id, so the evidence is stable.
    out.sort_by(|a, b| b.malicious.cmp(&a.malicious).then_with(|| a.id.cmp(&b.id)));
    out.dedup_by(|a, b| a.id == b.id);
    out.truncate(MAX_ADVISORIES);
    out
}

/// Look up `pkg` (cached), store the result on server `server` and return
/// it. `None` when lookups are off, OSV does not cover the package, or the
/// lookup failed.
pub async fn check(app: &App, server: &str, pkg: &PackageRef) -> Option<AdvisoryCheck> {
    let cfg = &app.cfg.servers.osv;
    if !cfg.enabled {
        return None;
    }
    let query = query_for(pkg)?;
    let key = format!("{PREFIX}{pkg}");
    let now = now_ms();
    let store = app.engine.store();
    let cached = store
        .get(&key)
        .and_then(|b| serde_json::from_slice::<AdvisoryCheck>(&b).ok())
        .filter(|c| now.saturating_sub(c.checked_ms) < cfg.cache_hours.saturating_mul(3_600_000));
    let check = match cached {
        Some(c) => c,
        None => {
            let started = std::time::Instant::now();
            match lookup(app, &query).await {
                Ok(body) => {
                    let c = AdvisoryCheck {
                        package: pkg.to_string(),
                        checked_ms: now,
                        advisories: parse_response(&body, pkg.pinned),
                    };
                    if let Ok(bytes) = serde_json::to_vec(&c) {
                        store.put(&key, &bytes);
                    }
                    tracing::debug!(package = %pkg, advisories = c.advisories.len(), ms = started.elapsed().as_millis() as u64, "OSV lookup");
                    c
                }
                Err(e) => {
                    tracing::warn!(package = %pkg, error = %e, "OSV lookup failed; starting the server without it");
                    return None;
                }
            }
        }
    };
    app.engine.set_server_advisories(server, check.clone());
    Some(check)
}

async fn lookup(app: &App, query: &Value) -> anyhow::Result<Value> {
    let cfg = &app.cfg.servers.osv;
    let url = format!("{}/v1/query", cfg.url.trim_end_matches('/'));
    let req = http::Request::post(&url)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::USER_AGENT, concat!("nandi/", env!("CARGO_PKG_VERSION")))
        .body(full(serde_json::to_vec(query)?))?;
    let fetch = async {
        let resp = app.client.request(req).await?;
        let status = resp.status();
        let body = Limited::new(resp.into_body(), MAX_BODY).collect().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        anyhow::ensure!(status.is_success(), "OSV answered {status}");
        Ok::<_, anyhow::Error>(serde_json::from_slice::<Value>(&body.to_bytes())?)
    };
    tokio::time::timeout(Duration::from_millis(cfg.timeout_ms.max(100)), fetch)
        .await
        .map_err(|_| anyhow::anyhow!("timed out after {} ms", cfg.timeout_ms))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::ServerSpec;

    fn pkg(command: &str, args: &[&str]) -> PackageRef {
        ServerSpec::Stdio { command: command.into(), args: args.iter().map(|a| a.to_string()).collect() }
            .package()
            .unwrap()
    }

    #[test]
    fn queries_carry_the_version_only_when_pinned() {
        let q = query_for(&pkg("npx", &["-y", "@scope/srv@1.2.3"])).unwrap();
        assert_eq!(q, json!({ "package": { "name": "@scope/srv", "ecosystem": "npm" }, "version": "1.2.3" }));
        let q = query_for(&pkg("npx", &["-y", "@scope/srv"])).unwrap();
        assert!(q.get("version").is_none());
        let q = query_for(&pkg("uvx", &["--from", "mcp-x==2.0.1", "mcp-x"])).unwrap();
        assert_eq!(q["package"]["ecosystem"], "PyPI");
        assert_eq!(q["version"], "2.0.1");
        assert!(query_for(&pkg("docker", &["run", "-i", "ghcr.io/o/i:1"])).is_none());
        assert!(query_for(&pkg("node", &["./index.js"])).is_none());
    }

    #[test]
    fn responses_keep_malicious_reports_first() {
        let body = json!({ "vulns": [
            { "id": "GHSA-b", "summary": "prototype pollution" },
            { "id": "GHSA-m", "aliases": ["MAL-2025-7"], "summary": "steals tokens" },
            { "id": "MAL-2025-9" },
            { "id": "GHSA-b" },
            { "summary": "no id" },
        ]});
        let all = parse_response(&body, true);
        let ids: Vec<&str> = all.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["GHSA-m", "MAL-2025-9", "GHSA-b"]);
        assert!(all[0].malicious && !all[2].malicious);
        assert_eq!(all[0].summary, "steals tokens");
        // Unpinned: vulnerabilities of some version say nothing about the one that runs.
        assert_eq!(parse_response(&body, false).len(), 2);
        assert!(parse_response(&json!({}), true).is_empty());
    }
}
