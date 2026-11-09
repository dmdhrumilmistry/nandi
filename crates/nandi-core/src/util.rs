//! Small helpers shared by all crates.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Time-ordered unique id (UUIDv7).
pub fn new_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Current Unix time in milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Hex SHA-256 of `data`.
pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(data.as_ref()))
}

/// Case-insensitive glob match supporting `*` (any run) and `?` (one char).
///
/// Used for tool, server and agent names throughout the config, so it is
/// deliberately simple and allocation free.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().flat_map(char::to_lowercase).collect();
    let t: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Match a `server/tool` style glob against a server and tool name. A
/// pattern without `/` matches the tool name on any server.
pub fn tool_glob_match(pattern: &str, server: &str, tool: &str) -> bool {
    match pattern.split_once('/') {
        Some((sp, tp)) => glob_match(sp, server) && glob_match(tp, tool),
        None => glob_match(pattern, tool),
    }
}

/// Canonical JSON: object keys sorted, no insignificant whitespace.
///
/// Independent of serde_json's `preserve_order` feature, so hashes are stable
/// regardless of what other crates in the build enable. Numbers use
/// serde_json's shortest representation; this is RFC 8785 compatible for the
/// integers and strings that tool definitions and agent cards contain.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            // RFC 8785 sorts by UTF-16 code units.
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Visit every string in a JSON value with its JSON-pointer-like path
/// (`/a/0/b`). Object keys are visited too (path ends with `#key`), because
/// injections and secrets hide in keys as well.
pub fn walk_strings<'a>(value: &'a Value, f: &mut dyn FnMut(&str, &'a str)) {
    fn go<'a>(v: &'a Value, path: &mut String, f: &mut dyn FnMut(&str, &'a str)) {
        match v {
            Value::String(s) => f(path, s),
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    let len = path.len();
                    path.push('/');
                    path.push_str(&i.to_string());
                    go(item, path, f);
                    path.truncate(len);
                }
            }
            Value::Object(map) => {
                for (k, item) in map {
                    let len = path.len();
                    path.push('/');
                    path.push_str(k);
                    let key_path = format!("{path}#key");
                    f(&key_path, k);
                    go(item, path, f);
                    path.truncate(len);
                }
            }
            _ => {}
        }
    }
    let mut path = String::new();
    go(value, &mut path, f);
}

/// Concatenate all strings in a JSON value (values only), separated by
/// newlines. Handy for scanners that work on text.
pub fn flatten_text(value: &Value) -> String {
    let mut out = String::new();
    walk_strings(value, &mut |path, s| {
        if !path.ends_with("#key") {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(s);
        }
    });
    out
}

/// Mask a sensitive value for evidence: keep a short prefix and the length.
pub fn mask(s: &str) -> String {
    let n = s.chars().count();
    let keep: String = s.chars().take(if n > 12 { 4 } else { 1 }).collect();
    format!("{keep}***({n} chars)")
}

/// Truncate to at most `max` characters on a char boundary.
pub fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn glob_basics() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*send*", "gmail_send_email"));
        assert!(glob_match("read_?ile", "READ_FILE"));
        assert!(!glob_match("read_*", "write_file"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn tool_glob() {
        assert!(tool_glob_match("github/*", "github", "create_issue"));
        assert!(!tool_glob_match("github/*", "gitlab", "create_issue"));
        assert!(tool_glob_match("create_*", "gitlab", "create_issue"));
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let v = json!({"b": 1, "a": {"d": [1, "x"], "c": null}});
        assert_eq!(canonical_json(&v), r#"{"a":{"c":null,"d":[1,"x"]},"b":1}"#);
    }

    #[test]
    fn walk_and_flatten() {
        let v = json!({"k": ["one", {"two": "2"}], "n": 3});
        let mut seen = Vec::new();
        walk_strings(&v, &mut |p, s| seen.push(format!("{p}={s}")));
        assert!(seen.contains(&"/k/0=one".to_string()));
        assert!(seen.contains(&"/k/1/two=2".to_string()));
        assert!(seen.contains(&"/k/1/two#key=two".to_string()));
        assert_eq!(flatten_text(&v), "one\n2");
    }

    #[test]
    fn masking_and_truncation() {
        assert_eq!(mask("AKIAABCDEFGHIJKLMNOP"), "AKIA***(20 chars)");
        assert_eq!(mask("abc"), "a***(3 chars)");
        assert_eq!(truncate("héllo", 2), "hé");
        assert_eq!(truncate("hi", 10), "hi");
    }
}
