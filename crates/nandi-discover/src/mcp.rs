//! MCP server entries: parsing the common configuration shapes, deciding
//! whether a server goes through nandi, and per-server findings.

use std::net::IpAddr;

use nandi_core::{Category, Finding, Severity, Verdict};
use serde_json::{Map, Value};

use crate::{McpServer, RULE_REMOTE_HTTP, RULE_UNWRAPPED, Scanner, Transport, Via};

/// Where a group of entries was found.
pub struct Origin {
    pub client: &'static str,
    pub scope: String,
    pub source: String,
}

/// Add every server of an `{"name": {...}}` map.
pub fn add_map(sc: &mut Scanner, origin: &Origin, map: Option<&Value>) {
    let Some(map) = map else { return };
    let Some(obj) = map.as_object() else {
        sc.warn(format!("{}: MCP server list is not an object", origin.source));
        return;
    };
    for (name, entry) in obj {
        add(sc, origin, name, entry);
    }
}

/// Add every server of a `[{"name": ..., ...}]` list (Continue).
pub fn add_list(sc: &mut Scanner, origin: &Origin, list: Option<&Value>) {
    let Some(list) = list else { return };
    let Some(items) = list.as_array() else {
        sc.warn(format!("{}: MCP server list is not an array", origin.source));
        return;
    };
    for (i, entry) in items.iter().enumerate() {
        // Continue's legacy shape nests the launch spec under `transport`.
        let flat = match entry.get("transport") {
            Some(t @ Value::Object(_)) => {
                let mut m = t.as_object().cloned().unwrap_or_default();
                if let Some(n) = entry.get("name") {
                    m.insert("name".into(), n.clone());
                }
                Value::Object(m)
            }
            _ => entry.clone(),
        };
        let name =
            flat.get("name").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| format!("server-{i}"));
        add(sc, origin, &name, &flat);
    }
}

/// Parse one server entry and record it.
pub fn add(sc: &mut Scanner, origin: &Origin, name: &str, entry: &Value) {
    let Some(obj) = entry.as_object() else {
        sc.warn(format!("{}: MCP server {name} is not an object", origin.source));
        return;
    };
    let server = parse(sc, origin, name, obj);
    sc.push(server);
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| match x {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn str_of<'a>(obj: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| obj.get(*k).and_then(Value::as_str)).filter(|s| !s.is_empty())
}

fn parse(sc: &Scanner, origin: &Origin, name: &str, obj: &Map<String, Value>) -> McpServer {
    // Zed's older shape: `"command": {"path": ..., "args": [...], "env": {...}}`.
    let (command, args, env) = match obj.get("command") {
        Some(Value::Object(c)) => (str_of(c, &["path", "command"]), strings(c.get("args")), c.get("env")),
        _ => (str_of(obj, &["command"]), strings(obj.get("args")), obj.get("env")),
    };
    let url_key = ["httpUrl", "url", "serverUrl"].into_iter().find(|k| obj.get(*k).and_then(Value::as_str).is_some());
    let url = url_key.and_then(|k| obj.get(k)).and_then(Value::as_str).filter(|s| !s.is_empty());
    let declared = str_of(obj, &["type", "transport"]).map(|t| t.to_ascii_lowercase().replace(['-', '_'], ""));
    let transport = match declared.as_deref() {
        Some("sse") => Transport::Sse,
        Some("http" | "streamablehttp" | "streamable") => Transport::Http,
        Some("stdio") => Transport::Stdio,
        _ if url_key == Some("httpUrl") => Transport::Http,
        _ => match url {
            Some(u) if u.split(['?', '#']).next().unwrap_or("").trim_end_matches('/').ends_with("/sse") => {
                Transport::Sse
            }
            Some(_) => Transport::Http,
            None => Transport::Stdio,
        },
    };
    let disabled = obj.get("disabled").and_then(Value::as_bool) == Some(true)
        || obj.get("enabled").and_then(Value::as_bool) == Some(false);

    let mut findings = Vec::new();
    let mut env_names = Vec::new();
    if let Some(Value::Object(env)) = env {
        for (k, v) in env {
            env_names.push(k.clone());
            if let Some(v) = v.as_str() {
                findings.extend(sc.check_secret("env", Some(k), v).1);
            }
        }
    }
    let mut header_names = Vec::new();
    for key in ["headers", "http_headers"] {
        if let Some(Value::Object(h)) = obj.get(key) {
            for (k, v) in h {
                header_names.push(k.clone());
                if let Some(v) = v.as_str() {
                    findings.extend(sc.check_secret("header", Some(k), v).1);
                }
            }
        }
    }
    let (command, mut f) = match command {
        Some(c) => {
            let (c, f) = sc.check_secret("command", None, c);
            (Some(c), f)
        }
        None => (None, Vec::new()),
    };
    findings.append(&mut f);
    let args = clean_args(sc, &args, &mut findings);
    let url = url.map(|u| {
        let (u, mut f) = sc.check_secret("url", None, u);
        findings.append(&mut f);
        u
    });

    let via_nandi = command
        .as_deref()
        .and_then(|c| wrapped(c, &args))
        .or_else(|| url.as_deref().and_then(|u| routed(u, &sc.opts.proxy_urls)));

    if let Some(u) = &url
        && let Some(host) = plain_http_host(u)
        && !is_loopback_host(&host)
    {
        findings.push(
            Finding::new(
                RULE_REMOTE_HTTP,
                Category::Exfiltration,
                Severity::Low,
                Verdict::Alert,
                "Remote MCP server over plain http://; traffic and credentials travel unencrypted",
            )
            .with_evidence(host),
        );
    }
    if via_nandi.is_none() && !disabled {
        let how = match transport {
            Transport::Stdio => "launch it through `nandi wrap`",
            Transport::Http | Transport::Sse => "route it through a nandi proxy route",
        };
        findings.push(Finding::new(
            RULE_UNWRAPPED,
            Category::Policy,
            Severity::Medium,
            Verdict::Alert,
            format!("MCP server {name} bypasses nandi; {how}"),
        ));
    }

    McpServer {
        client: origin.client.into(),
        scope: origin.scope.clone(),
        name: name.into(),
        source: origin.source.clone(),
        transport,
        command,
        args,
        url,
        env: env_names,
        headers: header_names,
        disabled,
        via_nandi,
        findings,
    }
}

/// Redact secrets in arguments. `--flag value` and `--flag=value` pairs are
/// checked with the flag as the key, so `--api-key <random>` is caught.
fn clean_args(sc: &Scanner, args: &[String], findings: &mut Vec<Finding>) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(flag) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) {
            if let Some((k, v)) = flag.split_once('=') {
                let (v, mut f) = sc.check_secret("argument", Some(k), v);
                findings.append(&mut f);
                out.push(format!("{}={v}", &arg[..arg.len() - flag.len() + k.len()]));
                i += 1;
                continue;
            }
            if let Some(next) = args.get(i + 1).filter(|n| !n.starts_with('-')) {
                let (v, mut f) = sc.check_secret("argument", Some(flag), next);
                if !f.is_empty() {
                    findings.append(&mut f);
                    out.push(arg.clone());
                    out.push(v);
                    i += 2;
                    continue;
                }
            }
        }
        let (v, mut f) = sc.check_secret("argument", None, arg);
        findings.append(&mut f);
        out.push(v);
        i += 1;
    }
    out
}

/// Last path component without a `.exe` suffix.
pub fn basename(cmd: &str) -> &str {
    let base = cmd.rsplit(['/', '\\']).next().unwrap_or(cmd);
    base.strip_suffix(".exe").unwrap_or(base)
}

/// `nandi [-c CFG] wrap [--server NAME] [-c CFG] ... -- CMD ARGS...`
pub fn wrapped(command: &str, args: &[String]) -> Option<Via> {
    if basename(command) != "nandi" || !args.iter().take_while(|a| *a != "--").any(|a| a == "wrap") {
        return None;
    }
    let (mut server, mut config, mut inner) = (None, None, Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--" => {
                inner = it.cloned().collect();
                break;
            }
            "--server" => server = it.next().cloned(),
            "-c" | "--config" => config = it.next().cloned(),
            _ => {
                if let Some(v) = a.strip_prefix("--server=") {
                    server = Some(v.into());
                } else if let Some(v) = a.strip_prefix("--config=") {
                    config = Some(v.into());
                }
            }
        }
    }
    Some(Via::Wrapped { server, config, inner_command: inner })
}

/// A URL under one of the nandi proxy base URLs.
pub fn routed(url: &str, proxies: &[String]) -> Option<Via> {
    let lower = url.to_ascii_lowercase();
    proxies.iter().find_map(|p| {
        let base = p.trim_end_matches('/').to_ascii_lowercase();
        let hit = !base.is_empty()
            && lower.strip_prefix(&base).is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?']));
        hit.then(|| Via::Routed { base_url: p.trim_end_matches('/').to_string() })
    })
}

/// Host of a plain `http://` URL.
fn plain_http_host(url: &str) -> Option<String> {
    let rest = url.get(..7).filter(|s| s.eq_ignore_ascii_case("http://")).map(|_| &url[7..])?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    Some(host.to_ascii_lowercase())
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn wrapped_parses_server_config_and_inner_command() {
        let via = wrapped(
            "/usr/local/bin/nandi",
            &s(&["wrap", "-c", "/etc/nandi.yaml", "--server", "github", "--", "npx", "-y", "srv"]),
        );
        assert_eq!(
            via,
            Some(Via::Wrapped {
                server: Some("github".into()),
                config: Some("/etc/nandi.yaml".into()),
                inner_command: s(&["npx", "-y", "srv"]),
            })
        );
        assert!(wrapped("nandi.exe", &s(&["--config=x", "wrap", "--server=a", "--", "x"])).is_some());
        assert!(wrapped("nandi", &s(&["status"])).is_none());
        assert!(wrapped("npx", &s(&["wrap"])).is_none());
        // `wrap` after `--` belongs to the inner command.
        assert!(wrapped("nandi", &s(&["hook", "--", "wrap"])).is_none());
    }

    #[test]
    fn routed_matches_prefix_only() {
        let proxies = s(&["http://127.0.0.1:8787/"]);
        assert!(routed("http://127.0.0.1:8787/mcp/github", &proxies).is_some());
        assert!(routed("HTTP://127.0.0.1:8787", &proxies).is_some());
        assert!(routed("http://127.0.0.1:87870/mcp", &proxies).is_none());
        assert!(routed("https://api.example.com/mcp", &proxies).is_none());
    }

    #[test]
    fn plain_http_hosts() {
        assert_eq!(plain_http_host("http://user@mcp.example.com:8080/x").as_deref(), Some("mcp.example.com"));
        assert_eq!(plain_http_host("https://mcp.example.com"), None);
        assert!(is_loopback_host(&plain_http_host("http://[::1]:3000/mcp").unwrap()));
        assert!(is_loopback_host("127.0.0.2"));
        assert!(!is_loopback_host("10.0.0.1"));
    }
}
