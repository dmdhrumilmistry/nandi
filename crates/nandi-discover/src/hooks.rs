//! Command hooks of Claude Code and Cursor.

use serde_json::Value;

use crate::mcp::{Origin, basename};
use crate::{Hook, Scanner, skills};

/// Claude Code: `{"Event": [{"matcher": "...", "hooks": [{"type": "command", "command": "..."}]}]}`.
pub fn add_claude(sc: &mut Scanner, origin: &Origin, hooks: Option<&Value>) {
    let Some(hooks) = hooks else { return };
    let Some(events) = hooks.as_object() else {
        sc.warn(format!("{}: `hooks` is not an object", origin.source));
        return;
    };
    for (event, groups) in events {
        for group in groups.as_array().into_iter().flatten() {
            let matcher = group.get("matcher").and_then(Value::as_str).map(str::to_string);
            for h in group.get("hooks").and_then(Value::as_array).into_iter().flatten() {
                if let Some(cmd) = h.get("command").and_then(Value::as_str) {
                    add(sc, origin, event, matcher.clone(), cmd);
                }
            }
        }
    }
}

/// Cursor: `{"version": 1, "hooks": {"event": [{"command": "..."}]}}`.
pub fn add_cursor(sc: &mut Scanner, origin: &Origin, file: &Value) {
    let Some(events) = file.get("hooks").and_then(Value::as_object) else {
        sc.warn(format!("{}: no `hooks` object", origin.source));
        return;
    };
    for (event, list) in events {
        for h in list.as_array().into_iter().flatten() {
            if let Some(cmd) = h.get("command").and_then(Value::as_str) {
                let matcher = h.get("matcher").and_then(Value::as_str).map(str::to_string);
                add(sc, origin, event, matcher, cmd);
            }
        }
    }
}

fn add(sc: &mut Scanner, origin: &Origin, event: &str, matcher: Option<String>, command: &str) {
    let (shown, mut findings) = sc.check_secret("hook command", None, command);
    findings.extend(skills::risky(&sc.detector, &shown, "hook").into_iter().map(|(f, _)| f));
    let hook = Hook {
        client: origin.client.into(),
        scope: origin.scope.clone(),
        source: origin.source.clone(),
        event: event.into(),
        matcher,
        is_nandi: is_nandi(command),
        command: shown,
        findings,
    };
    sc.push(hook);
}

/// A command that runs `nandi hook ...` (possibly with a path, quotes or
/// global flags before `hook`).
pub fn is_nandi(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().map(|t| t.trim_matches(['"', '\''])).collect();
    tokens.iter().enumerate().any(|(i, t)| {
        basename(t) == "nandi"
            && tokens[i + 1..].iter().take_while(|n| !matches!(**n, "&&" | "||" | ";" | "|")).any(|n| *n == "hook")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nandi_hook_commands() {
        assert!(is_nandi("nandi hook claude-code -c /etc/nandi.yaml"));
        assert!(is_nandi("\"/opt/nandi/bin/nandi\" -c x.yaml hook cursor --fail-open"));
        assert!(!is_nandi("nandi status && echo hook"));
        assert!(!is_nandi("./scripts/lint.sh"));
        assert!(!is_nandi("nandi-helper hook"));
    }
}
