//! Where each client keeps its configuration.

use std::path::{Path, PathBuf};

use nandi_core::util::glob_match;
use serde_json::Value;

use crate::mcp::{self, Origin};
use crate::{
    CLAUDE_CODE, CLAUDE_DESKTOP, CODEX, CONTINUE, CURSOR, Extension, GEMINI, Plugin, Scanner, VSCODE, WINDSURF, ZED,
    hooks, skills,
};

/// Editor extensions that are AI assistants or agents. `*` matches any run
/// of characters; ids are compared lowercase.
pub const AI_EXTENSIONS: &[&str] = &[
    "github.copilot",
    "github.copilot-chat",
    "continue.continue",
    "saoudrizwan.claude-dev",
    "rooveterinaryinc.roo-cline",
    "codeium.*",
    "anthropic.*",
    "openai.*",
    "amazonwebservices.amazon-q-vscode",
    "sourcegraph.cody-ai",
    "tabnine.*",
];

/// Whether an extension id is AI related.
pub fn is_ai_extension(id: &str) -> bool {
    AI_EXTENSIONS.iter().any(|p| glob_match(p, id))
}

pub fn scan_all(sc: &mut Scanner) {
    claude_code(sc);
    claude_desktop(sc);
    cursor(sc);
    windsurf(sc);
    vscode(sc);
    codex(sc);
    gemini(sc);
    zed(sc);
    continue_dev(sc);
}

fn projects(sc: &Scanner) -> Vec<PathBuf> {
    sc.opts.projects.clone()
}

fn project_scope(p: &Path) -> String {
    format!("project:{}", p.display())
}

fn origin(sc: &Scanner, client: &'static str, scope: &str, path: &Path) -> Origin {
    Origin { client, scope: scope.into(), source: sc.disp(path) }
}

/// Read a JSON file and add the servers under `key` (the whole file when
/// `key` is empty).
fn mcp_json(sc: &mut Scanner, client: &'static str, scope: &str, path: &Path, key: &str) {
    if let Some(v) = sc.read_json(client, path) {
        let o = origin(sc, client, scope, path);
        let map = if key.is_empty() { Some(&v) } else { v.get(key) };
        mcp::add_map(sc, &o, map);
    }
}

// ----- Claude Code ---------------------------------------------------------------

fn claude_code(sc: &mut Scanner) {
    let c = CLAUDE_CODE;
    sc.found_if_exists(c, &sc.home(".claude"));
    let state = sc.home(".claude.json");
    if let Some(v) = sc.read_json(c, &state) {
        let o = origin(sc, c, "user", &state);
        mcp::add_map(sc, &o, v.get("mcpServers"));
        if let Some(projects) = v.get("projects").and_then(Value::as_object) {
            for (path, p) in projects {
                let o = Origin { client: c, scope: format!("project:{path}"), source: o.source.clone() };
                mcp::add_map(sc, &o, p.get("mcpServers"));
            }
        }
    }
    claude_settings(sc, &sc.home(".claude/settings.json"), "user");
    skills::scan_dir(sc, c, "user", &sc.home(".claude/skills"));
    claude_plugins(sc);
    for p in projects(sc) {
        let scope = project_scope(&p);
        claude_settings(sc, &p.join(".claude/settings.json"), &scope);
        claude_settings(sc, &p.join(".claude/settings.local.json"), &scope);
        mcp_json(sc, c, &scope, &p.join(".mcp.json"), "mcpServers");
        skills::scan_dir(sc, c, &scope, &p.join(".claude/skills"));
    }
}

/// `settings.json`: hooks, and secrets written into the `env` block.
fn claude_settings(sc: &mut Scanner, path: &Path, scope: &str) {
    let Some(v) = sc.read_json(CLAUDE_CODE, path) else { return };
    let o = origin(sc, CLAUDE_CODE, scope, path);
    hooks::add_claude(sc, &o, v.get("hooks"));
    if let Some(env) = v.get("env").and_then(Value::as_object) {
        for (k, val) in env {
            let Some(val) = val.as_str() else { continue };
            for mut f in sc.check_secret("settings env", Some(k), val).1 {
                f.evidence = f.evidence.map(|e| format!("{}: {e}", o.source));
                sc.client_finding(CLAUDE_CODE, f);
            }
        }
    }
}

/// Installed plugins: `installed_plugins.json` when present, otherwise the
/// plugin manifests (`.claude-plugin/plugin.json`) on disk. Skills, MCP
/// servers and hooks shipped in a plugin are scanned too.
fn claude_plugins(sc: &mut Scanner) {
    let root = sc.home(".claude/plugins");
    if !root.is_dir() {
        return;
    }
    let mut found: Vec<(String, Option<String>, Option<PathBuf>)> = Vec::new();
    let installed = root.join("installed_plugins.json");
    if let Some(v) = sc.read_json(CLAUDE_CODE, &installed) {
        for (id, entry) in v.get("plugins").and_then(Value::as_object).into_iter().flatten() {
            let entries: Vec<&Value> = match entry {
                Value::Array(a) => a.iter().collect(),
                other => vec![other],
            };
            for e in entries {
                let dir = e.get("installPath").and_then(Value::as_str).map(PathBuf::from);
                let manifest = dir.as_deref().and_then(|d| plugin_manifest(sc, d));
                let name = manifest
                    .as_ref()
                    .and_then(|m| m.get("name").and_then(Value::as_str))
                    .map(str::to_string)
                    .unwrap_or_else(|| id.split('@').next().unwrap_or(id).to_string());
                let version = e
                    .get("version")
                    .and_then(Value::as_str)
                    .or_else(|| manifest.as_ref().and_then(|m| m.get("version").and_then(Value::as_str)))
                    .map(str::to_string);
                found.push((name, version, dir));
            }
        }
    } else {
        let mut manifests = Vec::new();
        find_manifests(&root, 0, &mut manifests);
        manifests.sort();
        for m in manifests {
            let Some(dir) = m.parent().and_then(Path::parent).map(Path::to_path_buf) else { continue };
            let manifest = plugin_manifest(sc, &dir);
            let field = |k: &str| manifest.as_ref().and_then(|m| m.get(k).and_then(Value::as_str)).map(str::to_string);
            let name = field("name").unwrap_or_else(|| dir.file_name().unwrap_or_default().to_string_lossy().into());
            found.push((name, field("version"), Some(dir)));
        }
    }
    for (name, version, dir) in found {
        let path = dir.as_deref().map(|d| sc.disp(d)).unwrap_or_else(|| sc.disp(&installed));
        sc.push(Plugin { client: CLAUDE_CODE.into(), name: name.clone(), version, path, findings: Vec::new() });
        if let Some(dir) = dir.filter(|d| d.is_dir()) {
            plugin_contents(sc, &name, &dir);
        }
    }
}

fn plugin_manifest(sc: &mut Scanner, dir: &Path) -> Option<Value> {
    sc.read_json_as(None, &dir.join(".claude-plugin/plugin.json"))
}

/// Manifests under the plugins directory, skipping marketplace checkouts
/// (plugins that are available, not installed).
fn find_manifests(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 5 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Ok(meta) = std::fs::symlink_metadata(e.path()) else { continue };
        if !meta.is_dir() || name == "marketplaces" || name == "node_modules" {
            continue;
        }
        if name == ".claude-plugin" {
            let m = e.path().join("plugin.json");
            if m.is_file() {
                out.push(m);
            }
        } else if !name.starts_with('.') {
            find_manifests(&e.path(), depth + 1, out);
        }
    }
}

fn plugin_contents(sc: &mut Scanner, name: &str, dir: &Path) {
    let c = CLAUDE_CODE;
    let scope = format!("plugin:{name}");
    skills::scan_dir(sc, c, &scope, &dir.join("skills"));
    let mcp_path = dir.join(".mcp.json");
    if let Some(v) = sc.read_json_as(None, &mcp_path) {
        let o = origin(sc, c, &scope, &mcp_path);
        mcp::add_map(sc, &o, Some(v.get("mcpServers").unwrap_or(&v)));
    }
    let hooks_path = dir.join("hooks/hooks.json");
    if let Some(v) = sc.read_json_as(None, &hooks_path) {
        let o = origin(sc, c, &scope, &hooks_path);
        hooks::add_claude(sc, &o, v.get("hooks"));
    }
}

// ----- other clients -----------------------------------------------------------------

fn claude_desktop(sc: &mut Scanner) {
    for rel in ["Library/Application Support/Claude", ".config/Claude", "AppData/Roaming/Claude"] {
        let dir = sc.home(rel);
        let file = dir.join("claude_desktop_config.json");
        if file.is_file() {
            mcp_json(sc, CLAUDE_DESKTOP, "user", &file, "mcpServers");
        } else {
            sc.found_if_exists(CLAUDE_DESKTOP, &dir);
        }
    }
}

fn cursor(sc: &mut Scanner) {
    let c = CURSOR;
    sc.found_if_exists(c, &sc.home(".cursor"));
    mcp_json(sc, c, "user", &sc.home(".cursor/mcp.json"), "mcpServers");
    cursor_hooks(sc, &sc.home(".cursor/hooks.json"), "user");
    for p in projects(sc) {
        let scope = project_scope(&p);
        mcp_json(sc, c, &scope, &p.join(".cursor/mcp.json"), "mcpServers");
        cursor_hooks(sc, &p.join(".cursor/hooks.json"), &scope);
    }
    extensions(sc, c, &sc.home(".cursor/extensions"));
}

fn cursor_hooks(sc: &mut Scanner, path: &Path, scope: &str) {
    if let Some(v) = sc.read_json(CURSOR, path) {
        let o = origin(sc, CURSOR, scope, path);
        hooks::add_cursor(sc, &o, &v);
    }
}

fn windsurf(sc: &mut Scanner) {
    let dir = sc.home(".codeium/windsurf");
    let file = dir.join("mcp_config.json");
    if file.is_file() {
        mcp_json(sc, WINDSURF, "user", &file, "mcpServers");
    } else {
        sc.found_if_exists(WINDSURF, &dir);
    }
}

fn vscode(sc: &mut Scanner) {
    let c = VSCODE;
    for rel in [".config/Code/User", "Library/Application Support/Code/User", "AppData/Roaming/Code/User"] {
        let dir = sc.home(rel);
        let settings = dir.join("settings.json");
        if let Some(v) = sc.read_json(c, &settings) {
            let o = origin(sc, c, "user", &settings);
            let servers = v.get("mcp").and_then(|m| m.get("servers")).or_else(|| v.get("mcp.servers"));
            mcp::add_map(sc, &o, servers);
        }
        mcp_json(sc, c, "user", &dir.join("mcp.json"), "servers");
    }
    for p in projects(sc) {
        mcp_json(sc, c, &project_scope(&p), &p.join(".vscode/mcp.json"), "servers");
    }
    extensions(sc, c, &sc.home(".vscode/extensions"));
}

fn codex(sc: &mut Scanner) {
    let dir = sc.home(".codex");
    let file = dir.join("config.toml");
    if let Some(v) = sc.read_toml(CODEX, &file) {
        let o = origin(sc, CODEX, "user", &file);
        mcp::add_map(sc, &o, v.get("mcp_servers"));
    } else {
        sc.found_if_exists(CODEX, &dir);
    }
}

fn gemini(sc: &mut Scanner) {
    let dir = sc.home(".gemini");
    let file = dir.join("settings.json");
    if file.is_file() {
        mcp_json(sc, GEMINI, "user", &file, "mcpServers");
    } else {
        sc.found_if_exists(GEMINI, &dir);
    }
    for p in projects(sc) {
        mcp_json(sc, GEMINI, &project_scope(&p), &p.join(".gemini/settings.json"), "mcpServers");
    }
}

fn zed(sc: &mut Scanner) {
    let file = sc.home(".config/zed/settings.json");
    mcp_json(sc, ZED, "user", &file, "context_servers");
}

fn continue_dev(sc: &mut Scanner) {
    let c = CONTINUE;
    let dir = sc.home(".continue");
    if !dir.is_dir() {
        return;
    }
    sc.found(c, &dir);
    let json_path = dir.join("config.json");
    if let Some(v) = sc.read_json(c, &json_path) {
        let o = origin(sc, c, "user", &json_path);
        mcp::add_list(sc, &o, v.get("experimental").and_then(|e| e.get("modelContextProtocolServers")));
        if v.get("mcpServers").is_some_and(Value::is_array) {
            mcp::add_list(sc, &o, v.get("mcpServers"));
        }
    }
    let mut yaml_files = vec![dir.join("config.yaml")];
    if let Ok(entries) = std::fs::read_dir(dir.join("mcpServers")) {
        let mut more: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "yaml" || x == "yml"))
            .collect();
        more.sort();
        yaml_files.extend(more);
    }
    for path in yaml_files {
        if let Some(v) = sc.read_yaml(c, &path) {
            let o = origin(sc, c, "user", &path);
            mcp::add_list(sc, &o, v.get("mcpServers"));
        }
    }
}

// ----- editor extensions ---------------------------------------------------------------

/// Installed extensions: the `extensions.json` index when present, else
/// each extension's `package.json`, else the directory name.
fn extensions(sc: &mut Scanner, client: &'static str, dir: &Path) {
    if !dir.is_dir() {
        return;
    }
    sc.found(client, dir);
    let mut list: Vec<(String, Option<String>)> = Vec::new();
    let index = std::fs::read_to_string(dir.join("extensions.json")).ok().and_then(|t| crate::jsonc::parse(&t).ok());
    if let Some(Value::Array(entries)) = index {
        for e in entries {
            let Some(id) = e.get("identifier").and_then(|i| i.get("id")).and_then(Value::as_str) else { continue };
            list.push((id.to_ascii_lowercase(), e.get("version").and_then(Value::as_str).map(str::to_string)));
        }
    } else if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || !e.path().is_dir() {
                continue;
            }
            let pkg = std::fs::read_to_string(e.path().join("package.json"))
                .ok()
                .and_then(|t| serde_json::from_str::<Value>(&t).ok());
            let from_pkg = pkg.as_ref().and_then(|p| {
                let publisher = p.get("publisher")?.as_str()?;
                let n = p.get("name")?.as_str()?;
                Some((
                    format!("{publisher}.{n}").to_ascii_lowercase(),
                    p.get("version").and_then(Value::as_str).map(str::to_string),
                ))
            });
            list.push(from_pkg.unwrap_or_else(|| split_dir_name(&name)));
        }
    }
    list.sort();
    list.dedup_by(|a, b| a.0 == b.0);
    for (id, version) in list {
        let ai_related = is_ai_extension(&id);
        sc.push(Extension { client: client.into(), id, version, ai_related, findings: Vec::new() });
    }
}

/// `publisher.name-1.2.3[-platform]` into id and version.
fn split_dir_name(name: &str) -> (String, Option<String>) {
    let cut = name.char_indices().find(|(i, c)| *c == '-' && name[i + 1..].starts_with(|n: char| n.is_ascii_digit()));
    match cut {
        Some((i, _)) => (name[..i].to_ascii_lowercase(), Some(name[i + 1..].to_string())),
        None => (name.to_ascii_lowercase(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_extensions() {
        assert!(is_ai_extension("github.copilot-chat"));
        assert!(is_ai_extension("codeium.windsurfpyright"));
        assert!(is_ai_extension("anthropic.claude-code"));
        assert!(!is_ai_extension("github.vscode-pull-request-github"));
        assert!(!is_ai_extension("ms-python.python"));
    }

    #[test]
    fn extension_dir_names() {
        assert_eq!(split_dir_name("GitHub.copilot-1.250.0"), ("github.copilot".into(), Some("1.250.0".into())));
        assert_eq!(split_dir_name("ms-python.python-2024.1.0-darwin-arm64").0, "ms-python.python");
        assert_eq!(split_dir_name("local.thing"), ("local.thing".into(), None));
    }
}
