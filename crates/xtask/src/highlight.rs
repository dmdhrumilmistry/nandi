//! A small syntax highlighter for the code blocks in the documentation.
//!
//! It knows the languages the docs use (shell, YAML, JSON, Python, Cedar,
//! INI, cron) well enough to colour comments, strings, numbers, keywords,
//! keys and punctuation, and emits the short Pygments-style class names
//! (`c1`, `s2`, `mi`, `k`, `nt`, ...) that `website/assets/site.css` styles.
//! Anything else is escaped and left plain.

/// HTML-escape text for element content and attribute values.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lang {
    Shell,
    Yaml,
    Json,
    Python,
    Cedar,
    Ini,
    Cron,
    Plain,
}

impl Lang {
    fn of(name: &str) -> Self {
        match name {
            "sh" | "bash" | "shell" | "console" | "zsh" => Lang::Shell,
            "yaml" | "yml" => Lang::Yaml,
            "json" | "jsonc" => Lang::Json,
            "python" | "py" => Lang::Python,
            "cedar" => Lang::Cedar,
            "ini" | "toml" | "conf" => Lang::Ini,
            "cron" | "crontab" => Lang::Cron,
            _ => Lang::Plain,
        }
    }

    fn comment(self) -> &'static [&'static str] {
        match self {
            Lang::Shell | Lang::Yaml | Lang::Python | Lang::Cron => &["#"],
            Lang::Ini => &["#", ";"],
            Lang::Cedar => &["//"],
            Lang::Json | Lang::Plain => &[],
        }
    }

    fn keywords(self) -> &'static [&'static str] {
        match self {
            Lang::Shell => &[
                "if", "then", "else", "elif", "fi", "for", "in", "do", "done", "while", "until", "case", "esac",
                "function", "return", "local", "export",
            ],
            Lang::Python => &[
                "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else",
                "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "not", "or",
                "pass", "raise", "return", "try", "while", "with", "yield",
            ],
            Lang::Cedar => &[
                "permit",
                "forbid",
                "when",
                "unless",
                "principal",
                "action",
                "resource",
                "context",
                "in",
                "like",
                "has",
                "is",
                "if",
                "then",
                "else",
            ],
            _ => &[],
        }
    }

    fn builtins(self) -> &'static [&'static str] {
        match self {
            Lang::Shell => &[
                "echo", "cd", "printf", "read", "set", "unset", "source", "exit", "test", "sudo", "exec", "eval",
                "trap", "shift", "wait",
            ],
            Lang::Python => &["print", "len", "int", "str", "dict", "list", "abs", "open", "range", "bytes"],
            _ => &[],
        }
    }

    fn constants(self) -> &'static [&'static str] {
        match self {
            Lang::Yaml => &["true", "false", "null", "yes", "no", "on", "off", "~"],
            Lang::Json | Lang::Cedar => &["true", "false", "null"],
            Lang::Python => &["True", "False", "None"],
            _ => &[],
        }
    }

    /// Characters that continue a word (beyond letters, digits and `_`).
    fn word_extra(self) -> &'static [char] {
        match self {
            Lang::Shell => &['-', '.', '/', '+', '@', '%', ','],
            Lang::Yaml | Lang::Ini => &['-', '.', '/', '@', '+'],
            Lang::Cron => &['-', '/', ','],
            _ => &[],
        }
    }

    fn punctuation(self) -> &'static [char] {
        match self {
            Lang::Shell => &['|', '&', ';', '<', '>', '(', ')', '{', '}', '[', ']', '=', '!'],
            Lang::Plain => &[],
            _ => &[
                '{', '}', '[', ']', '(', ')', ',', ':', ';', '=', '<', '>', '!', '+', '*', '/', '%', '&', '|', '-',
                '.', '@',
            ],
        }
    }
}

struct Out {
    html: String,
}

impl Out {
    fn span(&mut self, class: &str, text: &str) {
        if text.is_empty() {
            return;
        }
        if class.is_empty() {
            self.html.push_str(&escape(text));
        } else {
            self.html.push_str(&format!("<span class=\"{class}\">{}</span>", escape(text)));
        }
    }
}

/// Highlight `code` written in `lang` (a fence info string).
pub fn highlight(lang: &str, code: &str) -> String {
    let lang = Lang::of(lang.split_whitespace().next().unwrap_or("").to_ascii_lowercase().as_str());
    let mut out = Out { html: String::with_capacity(code.len() * 2) };
    if lang == Lang::Plain {
        out.span("", code);
        return out.html;
    }
    for (i, line) in code.split('\n').enumerate() {
        if i > 0 {
            out.html.push('\n');
        }
        line_html(lang, line, &mut out);
    }
    out.html
}

fn line_html(lang: Lang, line: &str, out: &mut Out) {
    let mut rest = line;
    match lang {
        Lang::Yaml => {
            // Leading list markers, then a `key:`.
            let indent = rest.len() - rest.trim_start().len();
            out.span("", &rest[..indent]);
            rest = &rest[indent..];
            while let Some(r) = rest.strip_prefix("- ") {
                out.span("p", "-");
                out.span("", " ");
                rest = r;
            }
            if let Some(len) = yaml_key(rest) {
                out.span("nt", &rest[..len]);
                out.span("p", ":");
                rest = &rest[len + 1..];
            }
        }
        Lang::Ini => {
            let t = rest.trim();
            if t.starts_with('[') && t.ends_with(']') {
                out.span("nt", rest);
                return;
            }
            if let Some(eq) = rest.find('=')
                && !lang.comment().iter().any(|c| rest.trim_start().starts_with(c))
            {
                out.span("na", &rest[..eq]);
                out.span("o", "=");
                rest = &rest[eq + 1..];
            }
        }
        _ => {}
    }
    tokens(lang, rest, out);
}

/// Length of a YAML mapping key at the start of `s` (plain or quoted),
/// when it is followed by `:` and a space or the end of the line.
fn yaml_key(s: &str) -> Option<usize> {
    let first = s.chars().next()?;
    let end = if first == '"' || first == '\'' {
        s[1..].find(first)? + 2
    } else {
        if matches!(first, '#' | '-' | '[' | '{' | '&' | '*' | '!' | '|' | '>' | '%' | '@') {
            return None;
        }
        let colon = s.find(": ").or_else(|| s.strip_suffix(':').map(|t| t.len()))?;
        if s[..colon].contains(" #") {
            return None;
        }
        colon
    };
    let after = &s[end..];
    (after == ":" || after.starts_with(": ")).then_some(end)
}

fn tokens(lang: Lang, s: &str, out: &mut Out) {
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let at = |i: usize| chars.get(i).map(|c| c.0).unwrap_or(s.len());
    let is_word = |c: char| c.is_alphanumeric() || c == '_' || lang.word_extra().contains(&c);
    let mut i = 0;
    // The previous significant word (for `def name` in Python).
    let mut prev_word = String::new();
    while i < chars.len() {
        let (pos, c) = chars[i];
        let rest = &s[pos..];
        let boundary = i == 0 || chars[i - 1].1.is_whitespace();

        // Comments run to the end of the line.
        if let Some(marker) = lang.comment().iter().find(|m| rest.starts_with(**m))
            && (boundary || **marker == *"//")
        {
            out.span("c1", rest);
            return;
        }
        if c.is_whitespace() {
            let start = i;
            while i < chars.len() && chars[i].1.is_whitespace() {
                i += 1;
            }
            out.span("", &s[pos..at(i)]);
            let _ = start;
            continue;
        }
        // Strings.
        if c == '"' || (c == '\'' && lang != Lang::Json) {
            let mut j = i + 1;
            while j < chars.len() {
                let d = chars[j].1;
                if d == '\\' && (c == '"' || lang != Lang::Shell) {
                    j += 2;
                    continue;
                }
                if d == c {
                    j += 1;
                    break;
                }
                j += 1;
            }
            let text = &s[pos..at(j.min(chars.len()))];
            // A JSON string followed by `:` is a key.
            let key = lang == Lang::Json && s[at(j.min(chars.len()))..].trim_start().starts_with(':');
            out.span(
                if key {
                    "nt"
                } else if c == '"' {
                    "s2"
                } else {
                    "s1"
                },
                text,
            );
            i = j.min(chars.len());
            continue;
        }
        // Shell variables and line continuations.
        if lang == Lang::Shell && c == '$' {
            let mut j = i + 1;
            if chars.get(j).map(|c| c.1) == Some('{') {
                while j < chars.len() && chars[j].1 != '}' {
                    j += 1;
                }
                j = (j + 1).min(chars.len());
            } else if chars.get(j).map(|c| c.1) == Some('(') {
                out.span("o", "$(");
                i += 2;
                continue;
            } else {
                while j < chars.len() && (chars[j].1.is_alphanumeric() || chars[j].1 == '_') {
                    j += 1;
                }
            }
            out.span("nv", &s[pos..at(j)]);
            i = j;
            continue;
        }
        if lang == Lang::Shell && c == '\\' {
            out.span("se", "\\");
            i += 1;
            continue;
        }
        if lang == Lang::Python && c == '@' && boundary {
            let mut j = i + 1;
            while j < chars.len() && (chars[j].1.is_alphanumeric() || matches!(chars[j].1, '_' | '.')) {
                j += 1;
            }
            out.span("nd", &s[pos..at(j)]);
            i = j;
            continue;
        }
        // Words: keywords, constants, numbers, names.
        if is_word(c) || (lang == Lang::Yaml && c == '~') {
            let mut j = i + 1;
            loop {
                match chars.get(j).map(|c| c.1) {
                    Some(d) if is_word(d) => j += 1,
                    // A YAML colon inside a scalar (`0.0.0.0:4318`, `env:X`).
                    Some(':')
                        if lang == Lang::Yaml
                            && chars.get(j + 1).is_some_and(|n| !n.1.is_whitespace() && n.1 != ',') =>
                    {
                        j += 1
                    }
                    _ => break,
                }
            }
            // Keys inside YAML flow mappings: `{ name: value }`.
            if lang == Lang::Yaml
                && chars.get(j).map(|c| c.1) == Some(':')
                && chars.get(j + 1).is_none_or(|n| n.1.is_whitespace())
            {
                out.span("nt", &s[pos..at(j)]);
                i = j;
                continue;
            }
            // Shell `NAME=value` assignments.
            if lang == Lang::Shell
                && boundary
                && chars.get(j).map(|c| c.1) == Some('=')
                && s[pos..at(j)].chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                out.span("nv", &s[pos..at(j)]);
                out.span("o", "=");
                i = j + 1;
                continue;
            }
            let word = &s[pos..at(j)];
            let class = if is_number(word) {
                "m"
            } else if lang.keywords().contains(&word) && (lang != Lang::Shell || boundary) {
                "k"
            } else if lang.constants().contains(&word) {
                "kc"
            } else if lang.builtins().contains(&word) && (lang != Lang::Shell || boundary) {
                "nb"
            } else if lang == Lang::Python && (prev_word == "def" || prev_word == "class") {
                "nf"
            } else {
                ""
            };
            out.span(class, word);
            prev_word = word.to_string();
            i = j;
            continue;
        }
        if lang.punctuation().contains(&c) {
            let class = if lang == Lang::Shell || matches!(c, '=' | '<' | '>' | '!' | '+' | '*' | '%' | '&' | '|') {
                "o"
            } else {
                "p"
            };
            out.span(class, &s[pos..at(i + 1)]);
            i += 1;
            continue;
        }
        out.span("", &s[pos..at(i + 1)]);
        i += 1;
    }
}

fn is_number(w: &str) -> bool {
    let w = w.strip_prefix('-').unwrap_or(w);
    !w.is_empty()
        && w.chars().next().is_some_and(|c| c.is_ascii_digit())
        && w.chars().all(|c| c.is_ascii_digit() || matches!(c, '.' | '_' | 'e' | 'x'))
        && w.chars().filter(|c| *c == '.').count() <= 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_keys_strings_numbers_and_comments() {
        let h = highlight("yaml", "telemetry:\n  - name: \"a<b\" # note\n    port: 4318\n    on: true");
        assert!(h.contains(r#"<span class="nt">telemetry</span><span class="p">:</span>"#), "{h}");
        assert!(h.contains(r#"<span class="nt">name</span>"#));
        assert!(h.contains(r#"<span class="s2">&quot;a&lt;b&quot;</span>"#));
        assert!(h.contains(r##"<span class="c1"># note</span>"##));
        assert!(h.contains(r#"<span class="m">4318</span>"#));
        assert!(h.contains(r#"<span class="kc">true</span>"#));
        let h = highlight("yaml", "a: 0.0.0.0:4318\nb: { c: [x], d: env:TOKEN }");
        assert!(h.contains("0.0.0.0:4318"), "{h}");
        assert!(h.contains(r#"<span class="nt">c</span>"#) && h.contains(r#"<span class="nt">d</span>"#), "{h}");
        assert!(h.contains("env:TOKEN"), "{h}");
    }

    #[test]
    fn shell_variables_and_comments() {
        let h = highlight("sh", "OTEL_SERVICE_NAME=gate \\\nnandi run   # start\necho \"$HOME\" a#b");
        assert!(h.contains(r#"<span class="nv">OTEL_SERVICE_NAME</span><span class="o">=</span>gate"#), "{h}");
        assert!(h.contains(r#"<span class="se">\</span>"#));
        assert!(h.contains(r##"<span class="c1"># start</span>"##));
        assert!(h.contains(r#"<span class="nb">echo</span>"#));
        assert!(h.contains("a#b"), "a # inside a word is not a comment");
    }

    #[test]
    fn json_keys_and_plain_text() {
        let h = highlight("json", r#"{"a": 1, "b": "x"}"#);
        assert!(h.contains(r#"<span class="nt">&quot;a&quot;</span>"#), "{h}");
        assert!(h.contains(r#"<span class="s2">&quot;x&quot;</span>"#));
        assert_eq!(highlight("text", "<b> & c"), "&lt;b&gt; &amp; c");
    }

    #[test]
    fn python_definitions() {
        let h = highlight("python", "@app.route\ndef verify(secret: bytes) -> bool:\n    return True");
        assert!(h.contains(r#"<span class="nd">@app.route</span>"#), "{h}");
        assert!(h.contains(r#"<span class="k">def</span> <span class="nf">verify</span>"#));
        assert!(h.contains(r#"<span class="kc">True</span>"#));
    }
}
