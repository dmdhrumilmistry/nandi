//! Tool poisoning checks for MCP tool definitions.
//!
//! A malicious server can hide instructions for the model in a tool's
//! description or input schema: injected directives, hidden unicode,
//! requests to read credentials, instructions to keep the user in the dark,
//! or references to tools of other servers in order to change how those
//! are used (shadowing). These checks run when a tool list is observed.

use nandi_core::util::{truncate, walk_strings};
use nandi_core::{Category, Finding, Severity, ToolDef, Verdict};
use regex::Regex;
use serde_json::Value;

use crate::Detector;
use crate::injection::{self, Family};

/// Number of tool definition rules.
pub(crate) const RULE_COUNT: usize = 8;

/// Descriptions longer than this are reported (informational).
const LONG_DESCRIPTION: usize = 2000;

/// Parameter names that invite the model to pass along context or secrets.
const SUSPICIOUS_PARAMS: &[&str] = &[
    "sidenote",
    "notesformodel",
    "notetomodel",
    "context",
    "conversationhistory",
    "chathistory",
    "previousmessages",
    "fullcontext",
    "systemprompt",
    "secret",
];

/// Compiled tool-specific matchers.
pub(crate) struct ToolChecks {
    sensitive_file: Regex,
}

impl ToolChecks {
    pub fn new() -> Self {
        Self {
            sensitive_file: crate::compile(concat!(
                r"(?i)\b(?:read|cat|open|access|load|include|pass|send|upload|provide|attach|copy|fetch|get|extract)\b",
                r"[^\n]{0,80}?",
                r"(~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.ssh/|\bmcp\.json\b|~/\.aws|\.aws/credentials|~/\.cursor|",
                r"\.cursor/|(?:^|[\s`'\x22/])\.env\b|\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b|\.kube/config\b|",
                r"/etc/passwd\b|/etc/shadow\b|\bcredentials\.json\b|\.docker/config\.json\b|\.bash_history\b|",
                r"\.zsh_history\b|\bkeychain\b)"
            )),
        }
    }
}

fn finding(rule: &str, severity: Severity, verdict: Verdict, message: &str, evidence: String) -> Finding {
    Finding::new(rule, Category::Integrity, severity, verdict, message).with_evidence(evidence)
}

pub(crate) fn scan(det: &Detector, server: &str, tool: &ToolDef, all_tools: &[(String, String)]) -> Vec<Finding> {
    let strong = det.cfg.on_injection;
    let weak = det.cfg.on_injection.min(Verdict::Alert);
    let mut out = Vec::new();

    // Text the model reads: description plus schema descriptions, titles,
    // defaults and examples.
    let mut text = tool.description.clone();
    walk_strings(&tool.input_schema, &mut |path, s| {
        let last = path.rsplit('/').next().unwrap_or("");
        if !path.ends_with("#key") && !matches!(last, "type" | "format" | "pattern" | "$ref" | "$schema") {
            text.push('\n');
            text.push_str(s);
        }
    });

    // Hidden unicode anywhere, including names and schema keys.
    let mut hidden: Option<injection::HiddenUnicode> = None;
    let mut where_found = String::new();
    let mut check_hidden = |path: &str, s: &str| {
        if hidden.is_none()
            && let Some(h) = injection::hidden_unicode(s)
        {
            hidden = Some(h);
            where_found = path.to_string();
        }
    };
    check_hidden("name", &tool.name);
    check_hidden("description", &tool.description);
    walk_strings(&tool.input_schema, &mut |p, s| check_hidden(&format!("inputSchema{p}"), s));
    walk_strings(&tool.annotations, &mut |p, s| check_hidden(&format!("annotations{p}"), s));

    let mut assessment = det.injection.assess(&text);
    if let Some(h) = &hidden {
        out.push(finding(
            "tool.poisoning.hidden-unicode",
            Severity::High,
            strong,
            "Tool definition contains invisible or direction-changing characters",
            format!("{} in {where_found}", h.summary()),
        ));
        if !h.tag_text.is_empty() {
            assessment.merge(det.injection.assess(&h.tag_text));
        }
    }

    if assessment.triggered() {
        out.push(finding(
            "tool.poisoning.injection",
            Severity::High,
            strong,
            "Tool description contains instructions aimed at the model",
            assessment.summary(),
        ));
    }

    let conceal = assessment.family_score(Family::ConcealFromUser);
    if conceal >= 1.0 || (conceal > 0.0 && assessment.triggered()) {
        let labels: Vec<&str> =
            assessment.indicators.iter().filter(|i| i.family == Family::ConcealFromUser).map(|i| i.label).collect();
        out.push(finding(
            "tool.poisoning.conceal",
            Severity::High,
            strong,
            "Tool description asks the model to hide behavior from the user",
            labels.join(", "),
        ));
    }

    if let Some(c) = det.tools.sensitive_file.captures(&text) {
        let path = c[1].trim_start_matches(|ch: char| ch.is_whitespace() || "`'\"/".contains(ch));
        out.push(finding(
            "tool.poisoning.sensitive-file",
            Severity::High,
            strong,
            "Tool description asks the model to access sensitive files",
            format!("references {}", truncate(path, 60)),
        ));
    }

    let mut links = Vec::new();
    det.injection.exfil_links(&text, &mut links);
    if let Some(l) = links.first() {
        out.push(finding(
            "tool.poisoning.exfil-link",
            Severity::Medium,
            strong,
            "Tool description contains a link or image URL carrying data",
            format!("link to {}", truncate(&l.host, 80)),
        ));
    }

    let shadowed = shadowed_tools(&text, server, &tool.name, all_tools);
    if !shadowed.is_empty() {
        let n = shadowed.len();
        let list: Vec<String> = shadowed.into_iter().take(5).collect();
        out.push(finding(
            "tool.shadowing",
            Severity::High,
            strong,
            "Tool description references tools of another server",
            format!(
                "mentions {}{}",
                list.join(", "),
                if n > 5 { format!(" (+{} more)", n - 5) } else { String::new() }
            ),
        ));
    }

    let params = suspicious_params(&tool.input_schema);
    if !params.is_empty() {
        out.push(finding(
            "tool.poisoning.suspicious-param",
            Severity::Low,
            weak,
            "Tool schema has parameters that invite the model to pass context or secrets",
            truncate(&params.join(", "), 120).to_string(),
        ));
    }

    let len = tool.description.chars().count();
    if len > LONG_DESCRIPTION {
        out.push(finding(
            "tool.poisoning.long-description",
            Severity::Info,
            Verdict::Allow,
            "Unusually long tool description",
            format!("{len} chars"),
        ));
    }
    out
}

/// Names of other servers' tools mentioned as whole words in `text`.
fn shadowed_tools(text: &str, server: &str, own: &str, all_tools: &[(String, String)]) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut found = Vec::new();
    for (srv, name) in all_tools {
        if srv == server || name.eq_ignore_ascii_case(own) || !distinctive(name) {
            continue;
        }
        let needle = name.to_ascii_lowercase();
        if contains_word(&lower, &needle) {
            let label = format!("{srv}/{name}");
            if !found.contains(&label) {
                found.push(label);
            }
        }
    }
    found
}

/// Tool names that are unlikely to occur as ordinary words: they contain a
/// separator or an inner capital letter.
fn distinctive(name: &str) -> bool {
    name.len() >= 4 && (name.contains(['_', '-', '.']) || name.chars().skip(1).any(|c| c.is_ascii_uppercase()))
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let hb = haystack.as_bytes();
    let mut from = 0;
    while let Some(i) = haystack[from..].find(needle) {
        let s = from + i;
        let e = s + needle.len();
        if (s == 0 || !word(hb[s - 1])) && (e >= hb.len() || !word(hb[e])) {
            return true;
        }
        from = s + 1;
        while from < haystack.len() && !haystack.is_char_boundary(from) {
            from += 1;
        }
    }
    false
}

/// Property names anywhere in the schema that match [`SUSPICIOUS_PARAMS`].
fn suspicious_params(schema: &Value) -> Vec<String> {
    fn go(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                if let Some(Value::Object(props)) = map.get("properties") {
                    for (name, _) in props {
                        let norm: String =
                            name.chars().filter(|c| *c != '_' && *c != '-').flat_map(char::to_lowercase).collect();
                        if SUSPICIOUS_PARAMS.contains(&norm.as_str()) && !out.contains(name) {
                            out.push(name.clone());
                        }
                    }
                }
                for item in map.values() {
                    go(item, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|i| go(i, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    go(schema, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_matching() {
        assert!(contains_word("when using send_email, always", "send_email"));
        assert!(!contains_word("resend_email_now", "send_email"));
        assert!(contains_word("send_email", "send_email"));
    }

    #[test]
    fn distinctive_names() {
        assert!(distinctive("send_email"));
        assert!(distinctive("sendEmail"));
        assert!(!distinctive("search"));
        assert!(!distinctive("add"));
    }

    #[test]
    fn params_are_found_recursively() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "a": {"type": "number"},
                "side_note": {"type": "string"},
                "nested": {"type": "object", "properties": {"conversation_history": {"type": "string"}}}
            }
        });
        let mut p = suspicious_params(&schema);
        p.sort();
        assert_eq!(p, ["conversation_history", "side_note"]);
    }
}
