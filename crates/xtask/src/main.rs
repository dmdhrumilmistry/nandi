//! Developer tasks for nandi.
//!
//! ```sh
//! cargo xtask site [--out _site] [--base-url https://...]   # build the website
//! cargo xtask check-links _site                             # check every internal link and anchor
//! ```
//!
//! The website is `docs/` rendered into the templates and assets under
//! `website/`, with the navigation in `website/nav.yaml`. Pages use relative
//! links, so the site works from any path (GitHub Pages project sites, a
//! local file server, a subdirectory).

mod highlight;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use pulldown_cmark::{CodeBlockKind, CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use regex::Regex;
use serde::Deserialize;
use serde_json::json;

use highlight::escape;

const REPO: &str = "https://github.com/dmdhrumilmistry/nandi";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repository root")
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    match args.first().map(String::as_str) {
        Some("site") => {
            let out = flag("--out").map(PathBuf::from).unwrap_or_else(|| root().join("_site"));
            let base = flag("--base-url").unwrap_or_default();
            let n = build_site(&root(), &out, &base)?;
            println!("built {n} pages into {}", out.display());
            Ok(())
        }
        Some("check-links") => {
            let dir = args.get(1).map(PathBuf::from).unwrap_or_else(|| root().join("_site"));
            let bad = check_links(&dir)?;
            for b in &bad {
                println!("{b}");
            }
            if !bad.is_empty() {
                bail!("{} broken link(s)", bad.len());
            }
            println!("all links resolve");
            Ok(())
        }
        _ => {
            eprintln!("usage:\n  cargo xtask site [--out DIR] [--base-url URL]\n  cargo xtask check-links [DIR]");
            std::process::exit(2);
        }
    }
}

// ---------- navigation ----------

#[derive(Deserialize)]
struct Section {
    section: String,
    pages: Vec<NavPage>,
}

#[derive(Deserialize, Clone)]
struct NavPage {
    path: String,
    title: String,
}

/// `docs/<x>.md` becomes `docs/<x>.html` (site-relative).
fn out_path(src: &str) -> String {
    format!("docs/{}.html", src.strip_suffix(".md").unwrap_or(src))
}

/// Relative URL from one site path to another.
fn rel(from: &str, to: &str) -> String {
    format!("{}{to}", "../".repeat(from.matches('/').count()))
}

fn sidebar(nav: &[Section], current: &str) -> String {
    nav.iter()
        .map(|s| {
            let links: String = s
                .pages
                .iter()
                .map(|p| {
                    let o = out_path(&p.path);
                    let cur = if o == current { r#" aria-current="page""# } else { "" };
                    format!(r#"<li><a href="{}"{cur}>{}</a></li>"#, rel(current, &o), p.title)
                })
                .collect();
            format!(r#"<div class="nav-section"><p>{}</p><ul>{links}</ul></div>"#, s.section)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Replace `{{name}}` placeholders; unknown names become empty.
fn fill(template: &str, values: &HashMap<&str, String>) -> String {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{(\w+)\}\}").unwrap());
    RE.replace_all(template, |c: &regex::Captures| values.get(&c[1]).cloned().unwrap_or_default()).into_owned()
}

// ---------- markdown ----------

/// A heading in the page's table of contents.
struct TocEntry {
    level: u8,
    id: String,
    text: String,
}

/// Heading ids as Python-Markdown's `toc` extension makes them, so links
/// like `users.md#the-audit-trail` keep working.
fn slugify(text: &str) -> String {
    let kept: String =
        text.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || c.is_whitespace()).collect();
    let lower = kept.trim().to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut sep = false;
    for c in lower.chars() {
        if c == '-' || c.is_whitespace() {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.push(c);
        }
    }
    if sep {
        out.push('-');
    }
    out
}

/// Render a page body. Returns the HTML and the h2/h3 headings.
fn render_markdown(text: &str, root: &Path) -> Result<(String, Vec<TocEntry>)> {
    static INCLUDE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<!--\s*include:\s*(\S+)\s+(\w+)\s*-->").unwrap());
    let mut err = None;
    let text = INCLUDE.replace_all(text, |c: &regex::Captures| match fs::read_to_string(root.join(&c[1])) {
        Ok(body) => format!("```{}\n{}\n```", &c[2], body.trim_end()),
        Err(e) => {
            err = Some(anyhow::anyhow!("include {}: {e}", &c[1]));
            String::new()
        }
    });
    if let Some(e) = err {
        return Err(e);
    }

    let events: Vec<Event> = Parser::new_ext(&text, Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH).collect();
    let mut out: Vec<Event> = Vec::with_capacity(events.len());
    let mut toc = Vec::new();
    let mut used: HashSet<String> = HashSet::new();
    let mut i = 0;
    while i < events.len() {
        match &events[i] {
            // h2 and h3 get ids and a permalink.
            Event::Start(Tag::Heading { level: lvl @ (HeadingLevel::H2 | HeadingLevel::H3), .. }) => {
                let level = if *lvl == HeadingLevel::H2 { 2 } else { 3 };
                let end = events[i..].iter().position(|e| matches!(e, Event::End(TagEnd::Heading(_)))).unwrap() + i;
                let inner = &events[i + 1..end];
                let mut inner_html = String::new();
                pulldown_cmark::html::push_html(&mut inner_html, inner.iter().cloned());
                let plain = text_of(&inner_html);
                let base = slugify(&plain);
                let mut id = base.clone();
                let mut n = 1;
                while !used.insert(id.clone()) {
                    id = format!("{base}_{n}");
                    n += 1;
                }
                out.push(Event::Html(CowStr::from(format!(
                    "<h{level} id=\"{id}\">{inner_html}<a class=\"anchor\" href=\"#{id}\" title=\"Link to this section\">#</a></h{level}>\n"
                ))));
                toc.push(TocEntry { level, id, text: plain });
                i = end + 1;
            }
            // Code blocks: Mermaid diagrams, or highlighted code with a copy button.
            Event::Start(Tag::CodeBlock(kind)) => {
                let lang = match kind {
                    CodeBlockKind::Fenced(info) => info.to_string(),
                    CodeBlockKind::Indented => String::new(),
                };
                let mut code = String::new();
                i += 1;
                while let Some(Event::Text(t)) = events.get(i) {
                    code.push_str(t);
                    i += 1;
                }
                i += 1; // End(CodeBlock)
                let code = code.strip_suffix('\n').unwrap_or(&code);
                let html = if lang.trim() == "mermaid" {
                    format!("<figure class=\"diagram\"><pre class=\"mermaid\">{}</pre></figure>\n", escape(code))
                } else {
                    format!(
                        "<div class=\"hl\"><button class=\"copy\" type=\"button\" aria-label=\"Copy code\">Copy</button><pre><code>{}\n</code></pre></div>\n",
                        highlight::highlight(&lang, code)
                    )
                };
                out.push(Event::Html(CowStr::from(html)));
            }
            // A paragraph holding only an image becomes a figure with a caption.
            Event::Start(Tag::Paragraph) => {
                if let Some(Event::Start(Tag::Image { dest_url, .. })) = events.get(i + 1) {
                    let close = events[i + 2..].iter().position(|e| matches!(e, Event::End(TagEnd::Image)));
                    if let Some(close) = close.map(|c| c + i + 2)
                        && matches!(events.get(close + 1), Some(Event::End(TagEnd::Paragraph)))
                        && events[i + 2..close].iter().all(|e| matches!(e, Event::Text(_) | Event::Code(_)))
                    {
                        let alt: String = events[i + 2..close]
                            .iter()
                            .map(|e| match e {
                                Event::Text(t) | Event::Code(t) => t.to_string(),
                                _ => String::new(),
                            })
                            .collect();
                        out.push(Event::Html(CowStr::from(format!(
                            "<figure><img alt=\"{a}\" src=\"{src}\" loading=\"lazy\"><figcaption>{a}</figcaption></figure>\n",
                            a = escape(&alt),
                            src = escape(dest_url),
                        ))));
                        i = close + 2;
                        continue;
                    }
                }
                out.push(events[i].clone());
                i += 1;
            }
            e => {
                out.push(e.clone());
                i += 1;
            }
        }
    }
    let mut html = String::with_capacity(text.len() * 2);
    pulldown_cmark::html::push_html(&mut html, out.into_iter());
    Ok((html, toc))
}

/// Point links at the built pages: `.md` to `.html`, files in `docs/` to
/// their copies, and other repository files to GitHub.
fn fix_links(body: &str, src: &str, page_out: &str) -> String {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(href|src)="([^"]+)""#).unwrap());
    static EXTERNAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(https?:|mailto:|#)").unwrap());
    let src_dir = Path::new(src).parent().unwrap_or(Path::new(""));
    RE.replace_all(body, |c: &regex::Captures| {
        let (attr, url) = (&c[1], &c[2]);
        if EXTERNAL.is_match(url) {
            return c[0].to_string();
        }
        let (path, frag) = match url.split_once('#') {
            Some((p, f)) => (p, format!("#{f}")),
            None => (url, String::new()),
        };
        // Lexical normalisation of docs/<src dir>/<path>, relative to the root.
        let mut parts: Vec<String> = Vec::new();
        for comp in Path::new("docs").join(src_dir).join(path).components() {
            match comp {
                Component::ParentDir => {
                    parts.pop();
                }
                Component::Normal(p) => parts.push(p.to_string_lossy().into_owned()),
                _ => {}
            }
        }
        let target = parts.join("/");
        match target.strip_prefix("docs/") {
            Some(inside) if path.ends_with(".md") => format!(r#"{attr}="{}{frag}""#, rel(page_out, &out_path(inside))),
            Some(inside) => format!(r#"{attr}="{}{frag}""#, rel(page_out, &format!("docs/{inside}"))),
            None => format!(r#"{attr}="{REPO}/tree/main/{target}{frag}""#),
        }
    })
    .into_owned()
}

/// Visible text of an HTML fragment (without code blocks).
fn text_of(html: &str) -> String {
    static PRE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<pre.*?</pre>").unwrap());
    static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").unwrap());
    static WS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
    let t = PRE.replace_all(html, " ");
    let t = TAG.replace_all(&t, " ");
    WS.replace_all(&unescape(&t), " ").trim().to_string()
}

fn unescape(s: &str) -> String {
    static ENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"&(#x[0-9a-fA-F]+|#[0-9]+|[a-z]+);").unwrap());
    ENT.replace_all(s, |c: &regex::Captures| {
        let e = &c[1];
        let ch = if let Some(h) = e.strip_prefix("#x") {
            u32::from_str_radix(h, 16).ok().and_then(char::from_u32)
        } else if let Some(d) = e.strip_prefix('#') {
            d.parse().ok().and_then(char::from_u32)
        } else {
            match e {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some('\u{a0}'),
                "middot" => Some('·'),
                _ => None,
            }
        };
        ch.map(String::from).unwrap_or_else(|| c[0].to_string())
    })
    .into_owned()
}

fn toc_html(toc: &[TocEntry]) -> String {
    toc.iter()
        .map(|t| format!(r##"<li class="l{}"><a href="#{}">{}</a></li>"##, t.level, t.id, escape(&t.text)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from).with_context(|| format!("reading {}", from.display()))? {
        let entry = entry?;
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &dest)?;
        } else {
            fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}

// ---------- site ----------

/// Build the site into `out`. Returns the number of pages.
fn build_site(root: &Path, out: &Path, base_url: &str) -> Result<usize> {
    let docs = root.join("docs");
    let web = root.join("website");
    let nav: Vec<Section> = serde_saphyr::from_str(&fs::read_to_string(web.join("nav.yaml"))?)
        .map_err(|e| anyhow::anyhow!("website/nav.yaml: {e}"))?;
    if out.exists() {
        fs::remove_dir_all(out).with_context(|| format!("removing {}", out.display()))?;
    }
    fs::create_dir_all(out.join("docs"))?;
    copy_dir(&web.join("assets"), &out.join("assets"))?;
    copy_dir(&docs.join("assets"), &out.join("docs/assets"))?;

    let page_tpl = fs::read_to_string(web.join("templates/page.html"))?;
    let flat: Vec<(&str, &NavPage)> =
        nav.iter().flat_map(|s| s.pages.iter().map(move |p| (s.section.as_str(), p))).collect();
    static H1: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^#\s+(.+)\n").unwrap());
    static HEADING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"<h[23] id="([^"]+)">(.*?)</h[23]>"#).unwrap());
    let mut index = Vec::new();
    for (i, (section, page)) in flat.iter().enumerate() {
        let src = page.path.as_str();
        let text = fs::read_to_string(docs.join(src)).with_context(|| format!("reading docs/{src}"))?;
        let (title, text) = match H1.captures(&text) {
            Some(m) => (m[1].trim().to_string(), text[m.get(0).unwrap().end()..].to_string()),
            None => (page.title.clone(), text),
        };
        let page_out = out_path(src);
        let (body, toc) = render_markdown(&text, root).with_context(|| format!("rendering docs/{src}"))?;
        let body = fix_links(&body, src, &page_out);
        let pager = |j: usize, class: &str, label: &str| {
            let (_, p) = flat[j];
            format!(
                r#"<a class="pn {class}" href="{}"><span>{label}</span>{}</a>"#,
                rel(&page_out, &out_path(&p.path)),
                p.title
            )
        };
        let root_rel = rel(&page_out, "");
        let scripts = if body.contains(r#"class="mermaid""#) {
            format!(
                "<script src=\"{root_rel}assets/vendor/mermaid/mermaid.min.js\" defer></script>\n<script src=\"{root_rel}assets/diagrams.js\" defer></script>"
            )
        } else {
            String::new()
        };
        let description: String = text_of(&body).chars().take(180).collect();
        let values = HashMap::from([
            ("title", escape(&title)),
            ("section", escape(section)),
            ("body", body.clone()),
            ("toc", toc_html(&toc)),
            ("sidebar", sidebar(&nav, &page_out)),
            ("prev", if i > 0 { pager(i - 1, "prev", "Previous") } else { String::new() }),
            ("next", if i + 1 < flat.len() { pager(i + 1, "next", "Next") } else { String::new() }),
            ("root", root_rel.clone()),
            ("edit", format!("{REPO}/edit/main/docs/{src}")),
            ("description", escape(&description)),
            ("scripts", scripts),
            (
                "canonical",
                if base_url.is_empty() {
                    String::new()
                } else {
                    format!("{}/{page_out}", base_url.trim_end_matches('/'))
                },
            ),
        ]);
        let dest = out.join(&page_out);
        fs::create_dir_all(dest.parent().unwrap())?;
        fs::write(&dest, fill(&page_tpl, &values))?;

        // Search: one entry per section of the page.
        let (mut heading, mut anchor, mut last) = (title.clone(), String::new(), 0);
        for m in HEADING.captures_iter(&body) {
            let whole = m.get(0).unwrap();
            let x: String = text_of(&body[last..whole.start()]).chars().take(600).collect();
            index.push(json!({ "t": title, "h": heading, "u": format!("{page_out}{anchor}"), "x": x }));
            heading = text_of(&m[2]).trim_end_matches('#').trim().to_string();
            anchor = format!("#{}", &m[1]);
            last = whole.end();
        }
        let x: String = text_of(&body[last..]).chars().take(600).collect();
        index.push(json!({ "t": title, "h": heading, "u": format!("{page_out}{anchor}"), "x": x }));
    }

    fs::write(out.join("assets/search.json"), serde_json::to_string(&index)?)?;
    let home = fs::read_to_string(web.join("templates/home.html"))?;
    fs::write(
        out.join("index.html"),
        fill(&home, &HashMap::from([("root", String::new()), ("canonical", base_url.to_string())])),
    )?;
    fs::write(out.join(".nojekyll"), "")?;
    Ok(flat.len())
}

// ---------- link check ----------

fn html_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.is_dir() {
            html_files(&p, out)?;
        } else if p.extension().is_some_and(|e| e == "html") {
            out.push(p);
        }
    }
    Ok(())
}

/// Every `href` and `src` inside the site must point at a file that exists,
/// and every `#fragment` on a page at an element with that id.
fn check_links(site: &Path) -> Result<Vec<String>> {
    static LINK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?:href|src)="([^"]*)""#).unwrap());
    static ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\sid="([^"]+)""#).unwrap());
    let mut pages = Vec::new();
    html_files(site, &mut pages)?;
    let mut ids: BTreeMap<PathBuf, HashSet<String>> = BTreeMap::new();
    for p in &pages {
        let text = fs::read_to_string(p)?;
        ids.insert(p.canonicalize()?, ID.captures_iter(&text).map(|c| c[1].to_string()).collect());
    }
    let mut bad = Vec::new();
    for page in &pages {
        let text = fs::read_to_string(page)?;
        let name = page.strip_prefix(site).unwrap_or(page).display().to_string();
        for c in LINK.captures_iter(&text) {
            let url = unescape(&c[1]);
            if url.is_empty() || ["http:", "https:", "mailto:", "data:"].iter().any(|s| url.starts_with(s)) {
                continue;
            }
            let (path, frag) = url.split_once('#').unwrap_or((&url, ""));
            let target = if path.is_empty() { page.clone() } else { page.parent().unwrap().join(path) };
            let Ok(target) = target.canonicalize() else {
                bad.push(format!("{name} -> {url}: no such file"));
                continue;
            };
            if !frag.is_empty()
                && let Some(known) = ids.get(&target)
                && !known.contains(frag)
            {
                bad.push(format!("{name} -> {url}: no element with id {frag}"));
            }
        }
    }
    Ok(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_match_python_markdown() {
        assert_eq!(slugify("The audit trail"), "the-audit-trail");
        assert_eq!(slugify("Metrics, tracing and webhooks"), "metrics-tracing-and-webhooks");
        assert_eq!(slugify("nandi.decision and `x`"), "nandidecision-and-x");
        assert_eq!(slugify("1. Indirect prompt injection"), "1-indirect-prompt-injection");
        assert_eq!(slugify("Status - and testing"), "status-and-testing");
    }

    #[test]
    fn renders_headings_code_diagrams_and_figures() {
        let md = "Intro.\n\n## The audit trail\n\n### The audit trail\n\n```yaml\na: 1\n```\n\n```mermaid\nflowchart LR\n  A --> B\n```\n\n![A screenshot](../assets/s.png)\n\n| a | b |\n|---|---|\n| 1 | 2 |\n";
        let (html, toc) = render_markdown(md, Path::new(".")).unwrap();
        assert!(
            html.contains(r##"<h2 id="the-audit-trail">The audit trail<a class="anchor" href="#the-audit-trail""##),
            "{html}"
        );
        assert!(html.contains(r#"<h3 id="the-audit-trail_1">"#));
        assert_eq!(toc.len(), 2);
        assert!(html.contains(r#"<div class="hl"><button class="copy""#));
        assert!(html.contains(r#"<span class="nt">a</span>"#));
        assert!(html.contains("<pre class=\"mermaid\">flowchart LR\n  A --&gt; B</pre>"));
        assert!(html.contains(r#"<figure><img alt="A screenshot" src="../assets/s.png" loading="lazy"><figcaption>A screenshot</figcaption></figure>"#));
        assert!(html.contains("<table>"));
    }

    #[test]
    fn links_point_at_built_pages() {
        let body = r##"<a href="users.md#the-audit-trail">x</a><img src="../assets/a.png"><a href="../../examples/nandi.yaml">y</a><a href="https://x.org">z</a><a href="#here">h</a>"##;
        let out = fix_links(body, "operations/exports.md", "docs/operations/exports.html");
        assert!(out.contains(r##"href="../../docs/operations/users.html#the-audit-trail""##), "{out}");
        assert!(out.contains(r#"src="../../docs/assets/a.png""#));
        assert!(out.contains(r#"href="https://github.com/dmdhrumilmistry/nandi/tree/main/examples/nandi.yaml""#));
        assert!(out.contains(r#"href="https://x.org""#) && out.contains(r##"href="#here""##));
    }

    #[test]
    fn text_and_entities() {
        assert_eq!(text_of("<p>a &amp; <code>b</code></p><pre>skip</pre>\n c"), "a & b c");
        assert_eq!(rel("docs/a/b.html", "docs/c.html"), "../../docs/c.html");
    }
}
