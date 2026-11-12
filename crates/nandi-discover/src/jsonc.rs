//! Lenient JSON: editor settings files (VS Code, Zed, Cursor) allow
//! comments and trailing commas.

use serde_json::Value;

/// Parse strict JSON, falling back to JSON with comments and trailing
/// commas. The error of the strict parse is returned when both fail.
pub fn parse(text: &str) -> Result<Value, serde_json::Error> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    match serde_json::from_str(text) {
        Ok(v) => Ok(v),
        Err(e) => serde_json::from_str(&strip(text)).map_err(|_| e),
    }
}

/// Remove `//` and `/* */` comments and trailing commas outside strings.
pub fn strip(text: &str) -> String {
    let no_comments = strip_comments(text);
    strip_trailing_commas(&no_comments)
}

fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let (mut in_str, mut escaped) = (false, false);
    while let Some(c) = chars.next() {
        if in_str {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match (c, chars.peek()) {
            ('"', _) => {
                in_str = true;
                out.push(c);
            }
            ('/', Some('/')) => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut prev = '\0';
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                    }
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    out
}

fn strip_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let (mut in_str, mut escaped) = (false, false);
    for (i, &c) in chars.iter().enumerate() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            out.push(c);
            continue;
        }
        if c == '"' {
            in_str = true;
        } else if c == ',' {
            let next = chars[i + 1..].iter().find(|n| !n.is_whitespace());
            if matches!(next, Some('}') | Some(']')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_json_parses_unchanged() {
        assert_eq!(parse(r#"{"a": "//not a comment", "b": [1, 2]}"#).unwrap()["a"], "//not a comment");
    }

    #[test]
    fn comments_and_trailing_commas() {
        let text = "{\n  // user settings\n  \"a\": \"x/*y*/\", /* block */\n  \"b\": [1, 2,],\n}\n";
        let v = parse(text).unwrap();
        assert_eq!(v["a"], "x/*y*/");
        assert_eq!(v["b"][1], 2);
    }

    #[test]
    fn broken_json_reports_strict_error() {
        assert!(parse("{\"a\": ").is_err());
    }
}
