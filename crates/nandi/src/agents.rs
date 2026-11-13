//! `nandi hook-config`: the hook configuration that puts nandi in front of
//! each coding agent's tools, for one user or (with `--managed`) system-wide
//! where the agent supports administrator-enforced hooks.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde_json::{Value, json};

/// Seconds a hook may run. Held calls wait for a person, so this is long;
/// agents treat a timed-out hook as allowed.
const TIMEOUT_SECS: u64 = 600;

/// Agents with a hook configuration.
pub const AGENTS: &[&str] = &["claude-code", "codex", "gemini-cli", "copilot-cli", "cursor", "windsurf", "devin"];

/// Where the configuration goes and what it contains.
pub struct HookConfig {
    pub path: PathBuf,
    pub content: Content,
    /// Things to know, printed with the configuration.
    pub notes: Vec<&'static str>,
}

pub enum Content {
    /// Merged into an existing JSON file.
    Json(Value),
    /// Written only when the file does not exist yet.
    Toml(String),
}

fn home() -> PathBuf {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from).unwrap_or_default()
}

/// `nandi` itself: the absolute path for system-wide hooks, which run in
/// environments without the user's PATH.
fn nandi_bin(managed: bool) -> String {
    if !managed {
        return "nandi".into();
    }
    if cfg!(windows) { r"C:\Program Files\nandi\nandi.exe".into() } else { "/usr/local/bin/nandi".into() }
}

/// Per-OS system path: (macOS, Linux, Windows).
fn system(paths: (&str, &str, &str)) -> PathBuf {
    PathBuf::from(if cfg!(target_os = "macos") {
        paths.0
    } else if cfg!(windows) {
        paths.2
    } else {
        paths.1
    })
}

/// The hook configuration of `agent`.
pub fn config(agent: &str, managed: bool) -> anyhow::Result<HookConfig> {
    let bin = nandi_bin(managed);
    let cmd = |format: &str| format!("{bin} hook {format}");
    let claude_style = |format: &str, timeout: Value| {
        let h = json!([{ "type": "command", "command": cmd(format), "timeout": timeout }]);
        json!({ "hooks": {
            "PreToolUse": [{ "matcher": "*", "hooks": h }],
            "PostToolUse": [{ "matcher": "*", "hooks": h }],
            "UserPromptSubmit": [{ "hooks": h }],
        }})
    };
    Ok(match (agent, managed) {
        ("claude-code" | "claude", false) => HookConfig {
            path: home().join(".claude/settings.json"),
            content: Content::Json(claude_style("claude-code", json!(TIMEOUT_SECS))),
            notes: vec![],
        },
        ("claude-code" | "claude", true) => HookConfig {
            path: system((
                "/Library/Application Support/ClaudeCode/managed-settings.json",
                "/etc/claude-code/managed-settings.json",
                r"C:\Program Files\ClaudeCode\managed-settings.json",
            )),
            content: Content::Json(claude_style("claude-code", json!(TIMEOUT_SECS))),
            notes: vec![
                "Managed settings cannot be overridden by users. Check the path against Claude Code's settings documentation for your version.",
            ],
        },
        ("codex", false) => HookConfig {
            path: home().join(".codex/hooks.json"),
            content: Content::Json(claude_style("codex", json!(TIMEOUT_SECS))),
            notes: vec!["Codex asks you to trust new hooks once, with /hooks.", "Needs Codex 0.131 or later."],
        },
        ("codex", true) => {
            let mut toml = String::from(
                "# nandi: enforced Codex hooks. Users cannot disable these.\n[features]\nhooks = true\n\n[hooks]\n",
            );
            for ev in ["PreToolUse", "PostToolUse", "UserPromptSubmit"] {
                toml.push_str(&format!(
                    "\n[[hooks.{ev}]]\n[[hooks.{ev}.hooks]]\ntype = \"command\"\ncommand = {}\ntimeout = {TIMEOUT_SECS}\n",
                    toml_str(&cmd("codex"))
                ));
            }
            HookConfig {
                path: system((
                    "/etc/codex/requirements.toml",
                    "/etc/codex/requirements.toml",
                    r"C:\ProgramData\OpenAI\Codex\requirements.toml",
                )),
                content: Content::Toml(toml),
                notes: vec![
                    "On macOS an MDM can deliver the same TOML base64-encoded as key requirements_toml_base64 of domain com.openai.codex.",
                    "Add allow_managed_hooks_only = true to ignore every other hook. Codex 0.148 or later refuses to start when a required hook cannot load.",
                ],
            }
        }
        ("gemini-cli" | "gemini", managed) => {
            let h = |name: &str| json!([{ "name": name, "type": "command", "command": cmd("gemini-cli"), "timeout": TIMEOUT_SECS * 1000 }]);
            HookConfig {
                path: if managed {
                    system((
                        "/Library/Application Support/GeminiCli/settings.json",
                        "/etc/gemini-cli/settings.json",
                        r"C:\ProgramData\gemini-cli\settings.json",
                    ))
                } else {
                    home().join(".gemini/settings.json")
                },
                content: Content::Json(json!({
                    "hooksConfig": { "enabled": true },
                    "hooks": {
                        "BeforeTool": [{ "matcher": "*", "hooks": h("nandi") }],
                        "AfterTool": [{ "matcher": "*", "hooks": h("nandi-after") }],
                        "BeforeAgent": [{ "hooks": h("nandi-prompt") }],
                    }
                })),
                notes: if managed {
                    vec![
                        "Gemini CLI lets users disable a hook by name, and skips settings hooks in folders it does not trust; nandi's footprint report shows the result per machine.",
                    ]
                } else {
                    vec![]
                },
            }
        }
        ("copilot-cli" | "copilot", managed) => {
            let entry = |extra: Value| {
                let mut e = json!({ "type": "command", "timeoutSec": TIMEOUT_SECS });
                if managed {
                    e["exec"] = json!(nandi_bin(true));
                    e["args"] = json!(["hook", "copilot-cli"]);
                } else {
                    e["bash"] = json!(cmd("copilot-cli"));
                    e["powershell"] = json!(cmd("copilot-cli"));
                }
                if let (Some(o), Some(x)) = (e.as_object_mut(), extra.as_object()) {
                    o.extend(x.clone());
                }
                e
            };
            HookConfig {
                path: if managed {
                    system((
                        "/etc/github-copilot/policy.d/nandi.json",
                        "/etc/github-copilot/policy.d/nandi.json",
                        r"C:\ProgramData\GitHub\Copilot\policy.d\nandi.json",
                    ))
                } else {
                    home().join(".copilot/hooks/nandi.json")
                },
                content: Content::Json(json!({ "version": 1, "hooks": {
                    "preToolUse": [entry(json!({}))],
                    "postToolUse": [entry(json!({}))],
                    "userPromptSubmitted": [entry(json!({}))],
                }})),
                notes: vec![
                    "Copilot CLI ignores the answer of prompt hooks, so prompts are recorded but not blocked.",
                    "Policy files must be owned by root and not writable by group or others.",
                ],
            }
        }
        ("cursor", false) => {
            let h = json!([{ "command": cmd("cursor") }]);
            HookConfig {
                path: home().join(".cursor/hooks.json"),
                content: Content::Json(json!({ "version": 1, "hooks": {
                    "beforeShellExecution": h, "beforeMCPExecution": h, "beforeReadFile": h, "beforeSubmitPrompt": h,
                    "afterShellExecution": h, "afterMCPExecution": h, "afterFileEdit": h,
                }})),
                notes: vec![],
            }
        }
        ("windsurf" | "cascade", managed) => {
            let h = json!([{ "command": cmd("windsurf"), "powershell": cmd("windsurf"), "show_output": false }]);
            HookConfig {
                path: if managed {
                    system((
                        "/Library/Application Support/Windsurf/hooks.json",
                        "/etc/windsurf/hooks.json",
                        r"C:\ProgramData\Windsurf\hooks.json",
                    ))
                } else {
                    home().join(".codeium/windsurf/hooks.json")
                },
                content: Content::Json(json!({ "hooks": {
                    "pre_run_command": h, "pre_read_code": h, "pre_write_code": h, "pre_mcp_tool_use": h,
                    "pre_user_prompt": h, "post_mcp_tool_use": h,
                }})),
                notes: vec![
                    "Windsurf hooks can only block, so calls nandi would ask about wait in its approval queue.",
                    "Devin Desktop reads /etc/devin (or the Devin folder) first when that file exists.",
                ],
            }
        }
        ("devin", false) => HookConfig {
            path: PathBuf::from(".devin/hooks.v1.json"),
            content: Content::Json(claude_style("devin", json!(TIMEOUT_SECS))["hooks"].clone()),
            notes: vec![
                "Devin also reads Claude Code's ~/.claude/settings.json hooks, so the claude-code setup may already cover it.",
            ],
        },
        (a @ ("cursor" | "devin"), true) => {
            bail!("{a} has no administrator-enforced hook file that nandi knows of; use the per-user setup")
        }
        (other, _) => bail!("unknown agent {other} (one of {})", AGENTS.join(", ")),
    })
}

fn toml_str(s: &str) -> String {
    if s.contains('\\') { format!("'{s}'") } else { format!("\"{s}\"") }
}

/// Merge nandi's hooks into an existing JSON document: keys that are maps
/// merge, hook lists get nandi's entries appended unless an entry already
/// runs `nandi hook`.
pub fn merge_json(existing: &mut Value, ours: &Value) {
    match (existing, ours) {
        (Value::Object(e), Value::Object(o)) => {
            for (k, v) in o {
                match e.get_mut(k) {
                    Some(cur) => merge_json(cur, v),
                    None => {
                        e.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (Value::Array(e), Value::Array(o)) => {
            if !e.iter().any(|x| x.to_string().contains("nandi")) {
                e.extend(o.iter().cloned());
            }
        }
        (e, o) => *e = o.clone(),
    }
}

/// `nandi hook-config`.
pub fn run(agent: &str, managed: bool, write: bool) -> anyhow::Result<()> {
    let agents: Vec<&str> = if agent == "all" { AGENTS.to_vec() } else { vec![agent] };
    for a in agents {
        let c = match config(a, managed) {
            Ok(c) => c,
            Err(e) if agent == "all" => {
                eprintln!("{a}: {e}");
                continue;
            }
            Err(e) => return Err(e),
        };
        let text = match &c.content {
            Content::Json(v) => serde_json::to_string_pretty(v)?,
            Content::Toml(t) => t.clone(),
        };
        if !write {
            println!("# {a}: {}", c.path.display());
            for n in &c.notes {
                println!("# {n}");
            }
            println!("{text}\n");
            continue;
        }
        install(a, &c, &text)?;
        for n in &c.notes {
            eprintln!("  note: {n}");
        }
    }
    Ok(())
}

fn install(agent: &str, c: &HookConfig, text: &str) -> anyhow::Result<()> {
    let path: &Path = &c.path;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    match (&c.content, path.exists()) {
        (_, false) => {
            std::fs::write(path, format!("{text}\n")).with_context(|| format!("writing {}", path.display()))?
        }
        (Content::Json(ours), true) => {
            let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            let mut existing: Value = if raw.trim().is_empty() {
                json!({})
            } else {
                serde_json::from_str(&raw)
                    .with_context(|| format!("{} is not plain JSON; add the hooks by hand", path.display()))?
            };
            if existing.to_string().contains("nandi") {
                println!("{agent}: {} already runs nandi; left as it is", path.display());
                return Ok(());
            }
            merge_json(&mut existing, ours);
            let backup = path.with_extension("json.bak-nandi");
            std::fs::copy(path, &backup).with_context(|| format!("backing up {}", path.display()))?;
            std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&existing)?))?;
            println!("{agent}: added nandi hooks to {} (previous version in {})", path.display(), backup.display());
            return Ok(());
        }
        (Content::Toml(_), true) => {
            bail!("{} exists; add this to it by hand:\n{text}", path.display());
        }
    }
    println!("{agent}: wrote {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_agent_has_a_user_config() {
        for a in AGENTS {
            let c = config(a, false).unwrap();
            let text = match &c.content {
                Content::Json(v) => v.to_string(),
                Content::Toml(t) => t.clone(),
            };
            assert!(text.contains("hook"), "{a}");
        }
        assert!(config("nope", false).is_err());
        assert!(config("cursor", true).is_err());
        let Content::Toml(t) = config("codex", true).unwrap().content else { panic!() };
        assert!(t.contains("[[hooks.PreToolUse.hooks]]") && t.contains("hooks = true"));
    }

    #[test]
    fn merging_keeps_existing_settings_and_is_idempotent() {
        let mut existing = json!({ "model": "opus", "hooks": { "PreToolUse": [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "lint.sh" }] }] } });
        let Content::Json(ours) = config("claude-code", false).unwrap().content else { panic!() };
        merge_json(&mut existing, &ours);
        assert_eq!(existing["model"], "opus");
        assert_eq!(existing["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);
        assert!(existing["hooks"]["UserPromptSubmit"].is_array());
        let once = existing.clone();
        merge_json(&mut existing, &ours);
        assert_eq!(existing, once);
    }

    #[test]
    fn write_merges_into_an_existing_file() {
        let dir = std::env::temp_dir().join(format!("nandi-hookcfg-{}", nandi_core::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, r#"{"theme": "dark"}"#).unwrap();
        let Content::Json(ours) = config("claude-code", false).unwrap().content else { panic!() };
        let c = HookConfig { path: path.clone(), content: Content::Json(ours), notes: vec![] };
        install("claude-code", &c, "").unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["theme"], "dark");
        assert!(v["hooks"]["PreToolUse"].to_string().contains("nandi hook claude-code"));
        assert!(path.with_extension("json.bak-nandi").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
