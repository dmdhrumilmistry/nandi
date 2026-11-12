//! Coverage summary and the configuration changes that close the gaps.

use serde_json::{Value, json};

use crate::{
    CLAUDE_CODE, CODEX, CURSOR, ClientCoverage, Coverage, Item, McpServer, ScanOptions, Suggestion, SuggestionKind,
    Transport, Via, client_name,
};

pub fn compute(items: &[Item], opts: &ScanOptions) -> Coverage {
    let mut cov = Coverage::default();
    for item in items {
        if let Item::Client(c) = item {
            cov.clients.push(ClientCoverage {
                client: c.client.clone(),
                name: c.name.clone(),
                servers_total: 0,
                servers_via_nandi: 0,
                nandi_hook: c.nandi_hook,
            });
            if let Some(installed) = c.nandi_hook {
                cov.hook_clients += 1;
                cov.hooks_installed += usize::from(installed);
                if !installed {
                    cov.suggestions.push(hook_suggestion(&c.client, &opts.nandi_config));
                }
            }
        }
    }
    for item in items {
        let Item::McpServer(s) = item else { continue };
        if s.disabled {
            continue;
        }
        cov.servers_total += 1;
        match &s.via_nandi {
            Some(Via::Wrapped { .. }) => cov.servers_wrapped += 1,
            Some(Via::Routed { .. }) => cov.servers_routed += 1,
            None => {}
        }
        let via = s.via_nandi.is_some();
        cov.servers_via_nandi += usize::from(via);
        if let Some(c) = cov.clients.iter_mut().find(|c| c.client == s.client) {
            c.servers_total += 1;
            c.servers_via_nandi += usize::from(via);
        }
        if !via && let Some(sugg) = server_suggestion(s, opts) {
            cov.suggestions.push(sugg);
        }
    }
    cov
}

/// Indented JSON that keeps short arrays and objects on one line, so a
/// snippet reads like hand-written configuration.
fn pretty(v: &Value) -> String {
    let mut out = String::new();
    write_pretty(v, 0, &mut out);
    out
}

/// Inline JSON with a space after `:` and `,`.
fn inline(v: &Value) -> String {
    match v {
        Value::Array(items) => format!("[{}]", items.iter().map(inline).collect::<Vec<_>>().join(", ")),
        Value::Object(map) => {
            let parts: Vec<String> =
                map.iter().map(|(k, v)| format!("{}: {}", Value::String(k.clone()), inline(v))).collect();
            format!("{{ {} }}", parts.join(", "))
        }
        other => other.to_string(),
    }
}

fn write_pretty(v: &Value, indent: usize, out: &mut String) {
    let flat = inline(v);
    let nested = match v {
        Value::Object(m) => m.values().any(|x| matches!(x, Value::Object(_))),
        _ => false,
    };
    if indent + flat.len() <= 100 && !nested {
        out.push_str(&flat);
        return;
    }
    let pad = "  ".repeat(indent + 1);
    let (open, close) = if v.is_array() { ('[', ']') } else { ('{', '}') };
    out.push(open);
    out.push('\n');
    let entries: Vec<(Option<&String>, &Value)> = match v {
        Value::Object(m) => m.iter().map(|(k, x)| (Some(k), x)).collect(),
        Value::Array(a) => a.iter().map(|x| (None, x)).collect(),
        _ => Vec::new(),
    };
    let n = entries.len();
    for (i, (k, x)) in entries.into_iter().enumerate() {
        out.push_str(&pad);
        if let Some(k) = k {
            out.push_str(&Value::String(k.clone()).to_string());
            out.push_str(": ");
        }
        write_pretty(x, indent + 1, out);
        if i + 1 < n {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(&"  ".repeat(indent));
    out.push(close);
}

/// TOML string literal (basic string, escaped).
fn toml_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

/// Bare TOML key when possible, quoted otherwise.
fn toml_key(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        s.to_string()
    } else {
        toml_str(s)
    }
}

fn server_suggestion(s: &McpServer, opts: &ScanOptions) -> Option<Suggestion> {
    match s.transport {
        Transport::Stdio => {
            let command = s.command.as_ref()?;
            let mut args: Vec<String> = vec!["wrap".into(), "-c".into(), opts.nandi_config.clone()];
            args.extend(["--server".into(), s.name.clone(), "--".into(), command.clone()]);
            args.extend(s.args.iter().cloned());
            let snippet = if s.client == CODEX {
                let list: Vec<String> = args.iter().map(|a| toml_str(a)).collect();
                format!("[mcp_servers.{}]\ncommand = \"nandi\"\nargs = [{}]", toml_key(&s.name), list.join(", "))
            } else {
                pretty(&json!({ &s.name: { "command": "nandi", "args": args } }))
            };
            let keep = if s.env.is_empty() { String::new() } else { format!(" Keep its env ({}).", s.env.join(", ")) };
            Some(Suggestion {
                client: s.client.clone(),
                kind: SuggestionKind::Wrap,
                target: s.name.clone(),
                scope: s.scope.clone(),
                file: s.source.clone(),
                message: format!(
                    "Launch {} through nandi wrap: replace its command and args in {}.{keep}",
                    s.name, s.source
                ),
                snippet,
            })
        }
        Transport::Http | Transport::Sse => {
            let url = s.url.as_ref()?;
            let base = opts.proxy_urls.first().map(|u| u.trim_end_matches('/')).unwrap_or("http://127.0.0.1:8787");
            let slug: String = s
                .name
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c.to_ascii_lowercase() } else { '-' })
                .collect();
            let snippet = format!(
                "# nandi.yaml\nroutes:\n  - name: {slug}\n    prefix: /mcp/{slug}\n    kind: mcp\n    upstream: {url}\n\n# {}: {}\n{}",
                client_name(&s.client),
                s.source,
                if s.client == CODEX {
                    format!("[mcp_servers.{}]\nurl = {}", toml_key(&s.name), toml_str(&format!("{base}/mcp/{slug}")))
                } else {
                    pretty(&json!({ &s.name: { "url": format!("{base}/mcp/{slug}") } }))
                }
            );
            Some(Suggestion {
                client: s.client.clone(),
                kind: SuggestionKind::Route,
                target: s.name.clone(),
                scope: s.scope.clone(),
                file: s.source.clone(),
                message: format!(
                    "Route {} through the nandi proxy: add an mcp route and point the client at it. Move any headers \
                     with credentials to the route's inject_headers.",
                    s.name
                ),
                snippet,
            })
        }
    }
}

fn hook_suggestion(client: &str, config: &str) -> Suggestion {
    let cmd = |format: &str| format!("nandi hook {format} -c {config}");
    let (file, snippet) = match client {
        CLAUDE_CODE => {
            let h = json!([{ "matcher": "*", "hooks": [{ "type": "command", "command": cmd("claude-code") }] }]);
            let p = json!([{ "hooks": [{ "type": "command", "command": cmd("claude-code") }] }]);
            (
                "~/.claude/settings.json",
                pretty(&json!({ "hooks": { "PreToolUse": h, "PostToolUse": h, "UserPromptSubmit": p } })),
            )
        }
        CURSOR => {
            let h = json!([{ "command": cmd("cursor") }]);
            let mut hooks = serde_json::Map::new();
            for event in [
                "beforeShellExecution",
                "beforeMCPExecution",
                "beforeReadFile",
                "beforeSubmitPrompt",
                "afterShellExecution",
                "afterMCPExecution",
                "afterFileEdit",
            ] {
                hooks.insert(event.into(), h.clone());
            }
            ("~/.cursor/hooks.json", pretty(&json!({ "version": 1, "hooks": hooks })))
        }
        _ => ("", String::new()),
    };
    Suggestion {
        client: client.into(),
        kind: SuggestionKind::Hook,
        target: "hooks".into(),
        scope: String::new(),
        file: file.into(),
        message: format!(
            "Install the nandi hook so {}'s built-in tools (shell, file edits, web fetches) are checked: merge into {file}.",
            client_name(client)
        ),
        snippet,
    }
}
