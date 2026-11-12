//! Plain-text rendering for the terminal.

use std::fmt::Write as _;

use nandi_core::util::truncate;

use crate::{Inventory, Item, Via, client_name};

/// Widest a free-text cell (commands, paths) is printed.
const MAX_CELL: usize = 72;

fn cell(s: &str) -> String {
    if s.chars().count() > MAX_CELL { format!("{}...", truncate(s, MAX_CELL - 3)) } else { s.to_string() }
}

/// Rows with aligned columns; the last column is not padded.
fn table(out: &mut String, rows: &[Vec<String>]) {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0; cols];
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }
    for r in rows {
        let mut line = String::from(" ");
        for (i, c) in r.iter().enumerate() {
            line.push(' ');
            if i + 1 == r.len() {
                line.push_str(c);
            } else {
                let _ = write!(line, "{c:<w$} ", w = widths[i]);
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
}

fn section(out: &mut String, title: &str, rows: Vec<Vec<String>>) {
    if rows.is_empty() {
        return;
    }
    let _ = writeln!(out, "\n{title}");
    table(out, &rows);
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Human-readable inventory with a coverage summary.
pub fn render_text(inv: &Inventory) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "AI footprint of {} (nandi {})", inv.host, inv.nandi_version);
    let cov = &inv.coverage;

    let clients: Vec<Vec<String>> = cov
        .clients
        .iter()
        .map(|c| {
            let paths = inv
                .items
                .iter()
                .find_map(|i| match i {
                    Item::Client(x) if x.client == c.client => Some(x.config_paths.join(", ")),
                    _ => None,
                })
                .unwrap_or_default();
            vec![
                c.name.clone(),
                format!("{} of {} via nandi", c.servers_via_nandi, plural(c.servers_total, "server", "servers")),
                match c.nandi_hook {
                    Some(true) => "nandi hook: yes".into(),
                    Some(false) => "nandi hook: no".into(),
                    None => String::new(),
                },
                cell(&paths),
            ]
        })
        .collect();
    if clients.is_empty() {
        out.push_str("\nNo AI agents or MCP configuration found.\n");
    }
    section(&mut out, "Clients", clients);

    let mut servers = Vec::new();
    let mut hooks = Vec::new();
    let mut skills = Vec::new();
    let mut plugins = Vec::new();
    let mut exts = Vec::new();
    let mut other_exts = 0;
    for item in &inv.items {
        match item {
            Item::McpServer(s) => {
                let status = match (&s.via_nandi, s.disabled) {
                    (Some(Via::Wrapped { .. }), _) => "wrapped",
                    (Some(Via::Routed { .. }), _) => "routed",
                    (None, true) => "disabled",
                    (None, false) => "BYPASS",
                };
                let target = match (&s.via_nandi, &s.command, &s.url) {
                    (Some(Via::Wrapped { inner_command, .. }), _, _) if !inner_command.is_empty() => {
                        inner_command.join(" ")
                    }
                    (_, Some(cmd), _) => std::iter::once(cmd.as_str())
                        .chain(s.args.iter().map(String::as_str))
                        .collect::<Vec<_>>()
                        .join(" "),
                    (_, None, Some(url)) => url.clone(),
                    _ => String::new(),
                };
                servers.push(vec![
                    client_name(&s.client).to_string(),
                    cell(&s.scope),
                    s.name.clone(),
                    s.transport.as_str().into(),
                    status.into(),
                    cell(&target),
                ]);
            }
            Item::Hook(h) => hooks.push(vec![
                client_name(&h.client).to_string(),
                cell(&h.scope),
                h.event.clone(),
                h.matcher.clone().unwrap_or_else(|| "-".into()),
                if h.is_nandi { "nandi".into() } else { String::new() },
                cell(&h.command),
            ]),
            Item::Skill(s) => skills.push(vec![
                client_name(&s.client).to_string(),
                cell(&s.scope),
                s.name.clone(),
                plural(s.files_scanned, "file", "files"),
                if s.findings.is_empty() { "clean".into() } else { plural(s.findings.len(), "finding", "findings") },
            ]),
            Item::Plugin(p) => plugins.push(vec![
                client_name(&p.client).to_string(),
                p.name.clone(),
                p.version.clone().unwrap_or_else(|| "-".into()),
                cell(&p.path),
            ]),
            Item::Extension(e) if e.ai_related => exts.push(vec![
                client_name(&e.client).to_string(),
                e.id.clone(),
                e.version.clone().unwrap_or_else(|| "-".into()),
            ]),
            Item::Extension(_) => other_exts += 1,
            Item::Client(_) => {}
        }
    }
    section(&mut out, "MCP servers", servers);
    section(&mut out, "Hooks", hooks);
    section(&mut out, "Skills", skills);
    section(&mut out, "Plugins", plugins);
    let ext_title = if other_exts > 0 {
        format!("AI extensions (and {} not AI related)", plural(other_exts, "other", "others"))
    } else {
        "AI extensions".into()
    };
    section(&mut out, &ext_title, exts);

    let mut findings: Vec<(&Item, &nandi_core::Finding)> = inv.findings().collect();
    findings.sort_by_key(|a| std::cmp::Reverse(a.1.severity));
    if !findings.is_empty() {
        let _ = writeln!(out, "\nFindings ({})", findings.len());
        let rows: Vec<Vec<String>> = findings
            .iter()
            .map(|(item, f)| {
                let sev = serde_json::to_value(f.severity).ok().and_then(|v| v.as_str().map(str::to_uppercase));
                let mut msg = f.message.clone();
                if let Some(e) = &f.evidence {
                    let _ = write!(msg, " [{}]", truncate(e, 100));
                }
                vec![
                    sev.unwrap_or_default(),
                    f.rule.clone(),
                    match item {
                        Item::Client(_) => client_name(item.client()).to_string(),
                        _ => format!("{} / {}", client_name(item.client()), item.name()),
                    },
                    msg,
                ]
            })
            .collect();
        table(&mut out, &rows);
    }

    let _ = writeln!(out, "\nCoverage");
    let _ = writeln!(
        out,
        "  MCP servers through nandi: {} of {} ({} wrapped, {} routed)",
        cov.servers_via_nandi, cov.servers_total, cov.servers_wrapped, cov.servers_routed
    );
    if cov.hook_clients > 0 {
        let _ = writeln!(out, "  Clients with the nandi hook: {} of {}", cov.hooks_installed, cov.hook_clients);
    }
    if !inv.warnings.is_empty() {
        let _ = writeln!(out, "  {} could not be read (see warnings)", plural(inv.warnings.len(), "file", "files"));
    }
    if !cov.suggestions.is_empty() {
        let _ = writeln!(
            out,
            "  {} would close the gaps: run `nandi discover --suggest`",
            plural(cov.suggestions.len(), "configuration change", "configuration changes")
        );
    }
    out
}

/// The suggested configuration changes, with snippets.
pub fn render_suggestions(inv: &Inventory) -> String {
    let list = &inv.coverage.suggestions;
    if list.is_empty() {
        return "\nNothing to change: every MCP server and hook-capable client goes through nandi.\n".into();
    }
    let mut out = format!("\nSuggested changes ({})\n", list.len());
    for (i, s) in list.iter().enumerate() {
        let _ = writeln!(out, "\n{}. {} / {} ({})", i + 1, client_name(&s.client), s.target, s.file);
        let _ = writeln!(out, "   {}\n", s.message);
        for line in s.snippet.lines() {
            let _ = writeln!(out, "     {line}");
        }
    }
    out
}
