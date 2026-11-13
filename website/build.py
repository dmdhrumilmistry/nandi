#!/usr/bin/env python3
"""Build the nandi website from docs/ into a static site.

    python3 website/build.py [--out _site] [--base-url https://...]

Needs the `markdown` and `pygments` packages. Pages are written with relative
links so the site works from any path (GitHub Pages project sites, a local
file server, a subdirectory).
"""

import argparse
import html
import json
import re
import shutil
from pathlib import Path

import markdown
from pygments.formatters import HtmlFormatter  # noqa: F401  (codehilite needs pygments)

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
WEB = ROOT / "website"
REPO = "https://github.com/dmdhrumilmistry/nandi"

NAV = [
    ("Start", [
        ("index.md", "Introduction"),
        ("getting-started.md", "Getting started"),
        ("how-it-works.md", "How it works"),
    ]),
    ("Connect agents", [
        ("guides/proxy.md", "Proxy: LLM, MCP, A2A"),
        ("guides/mcp.md", "MCP servers"),
        ("guides/coding-agents.md", "Coding agents"),
        ("guides/discovery.md", "AI footprint and coverage"),
        ("guides/host-sensor.md", "Host sensor"),
        ("guides/ml-classifier.md", "ML classifier"),
    ]),
    ("Policy", [
        ("policy/rules.md", "Writing rules"),
        ("policy/cedar.md", "Cedar policies"),
        ("policy/capabilities.md", "Capabilities and server risk"),
        ("policy/changes.md", "Managing policy in the dashboard"),
        ("policy/data-flow.md", "Data flow and taint"),
        ("policy/detection.md", "Detection"),
        ("policy/packs.md", "Policy packs"),
        ("policy/testing.md", "Testing policy"),
    ]),
    ("Operate", [
        ("operations/enforce.md", "Monitor to enforce"),
        ("operations/approvals.md", "Approvals and kill switch"),
        ("operations/identity.md", "Identity"),
        ("operations/users.md", "Users and audit trail"),
        ("operations/audit.md", "Audit log"),
        ("operations/observability.md", "Observability"),
        ("operations/deployment.md", "Deployment"),
        ("operations/mdm.md", "Fleets: Jamf, Intune, Linux"),
    ]),
    ("Reference", [
        ("reference/configuration.md", "Configuration"),
        ("reference/cli.md", "CLI"),
        ("reference/admin-api.md", "Admin API"),
    ]),
    ("Background", [
        ("background/threat-model.md", "Threat model"),
        ("background/research.md", "Research"),
        ("background/evaluation.md", "Evaluation"),
    ]),
]

INCLUDE = re.compile(r"<!--\s*include:\s*(\S+)\s+(\w+)\s*-->")


def out_path(src: str) -> str:
    """docs/<x>.md -> docs/<x>.html (site-relative)."""
    return "docs/" + src[:-3] + ".html"


def rel(from_path: str, to_path: str) -> str:
    """Relative URL from one site path to another."""
    depth = from_path.count("/")
    return "../" * depth + to_path


MERMAID = re.compile(r"^```mermaid\n(.*?)\n```$", re.S | re.M)


def diagrams(text: str) -> str:
    """Mermaid code blocks become diagrams, drawn in the browser by the
    vendored Mermaid (assets/vendor/mermaid). The source stays readable as a
    fallback and on GitHub."""
    return MERMAID.sub(
        lambda m: '\n<figure class="diagram"><pre class="mermaid">' + html.escape(m.group(1)) + "</pre></figure>\n",
        text,
    )


def render_markdown(text: str, src: str):
    text = INCLUDE.sub(lambda m: "```" + m.group(2) + "\n" + (ROOT / m.group(1)).read_text().rstrip() + "\n```", text)
    text = diagrams(text)
    md = markdown.Markdown(
        extensions=["fenced_code", "codehilite", "tables", "toc", "sane_lists", "attr_list"],
        extension_configs={
            "codehilite": {"css_class": "hl", "guess_lang": False},
            "toc": {"permalink": "#", "permalink_class": "anchor", "permalink_title": "Link to this section", "toc_depth": "2-3"},
        },
    )
    body = md.convert(text)
    return body, md.toc_tokens


def fix_links(body: str, src: str, page_out: str) -> str:
    src_dir = Path(src).parent

    def repl(m):
        attr, url = m.group(1), m.group(2)
        if re.match(r"^(https?:|mailto:|#)", url):
            return m.group(0)
        path, _, frag = url.partition("#")
        frag = "#" + frag if frag else ""
        target = (DOCS / src_dir / path).resolve()
        try:
            inside = target.relative_to(DOCS)
        except ValueError:
            # A repository file outside docs/: link to GitHub.
            return f'{attr}="{REPO}/tree/main/{target.relative_to(ROOT).as_posix()}{frag}"'
        if path.endswith(".md"):
            return f'{attr}="{rel(page_out, out_path(inside.as_posix()))}{frag}"'
        return f'{attr}="{rel(page_out, "docs/" + inside.as_posix())}{frag}"'

    return re.sub(r'(href|src)="([^"]+)"', repl, body)


def figures(body: str) -> str:
    """A paragraph holding only an image becomes a figure with a caption."""
    return re.sub(
        r'<p><img alt="([^"]*)" src="([^"]+)"\s*/?></p>',
        lambda m: f'<figure><img alt="{m.group(1)}" src="{m.group(2)}" loading="lazy">'
        f'<figcaption>{m.group(1)}</figcaption></figure>',
        body,
    )


def code_copy(body: str) -> str:
    return body.replace('<div class="hl"><pre>', '<div class="hl"><button class="copy" type="button" aria-label="Copy code">Copy</button><pre>')


def toc_html(tokens) -> str:
    items = []
    for t in tokens:
        for h in [t] + t.get("children", []):
            level = h["level"]
            if level in (2, 3):
                items.append(f'<li class="l{level}"><a href="#{h["id"]}">{h["name"]}</a></li>')
    return "\n".join(items)


def text_of(html_body: str) -> str:
    t = re.sub(r"<pre.*?</pre>", " ", html_body, flags=re.S)
    t = re.sub(r"<[^>]+>", " ", t)
    return re.sub(r"\s+", " ", html.unescape(t)).strip()


def sidebar(current_out: str) -> str:
    parts = []
    for section, pages in NAV:
        links = []
        for src, label in pages:
            o = out_path(src)
            cur = ' aria-current="page"' if o == current_out else ""
            links.append(f'<li><a href="{rel(current_out, o)}"{cur}>{label}</a></li>')
        parts.append(f'<div class="nav-section"><p>{section}</p><ul>{"".join(links)}</ul></div>')
    return "\n".join(parts)


def fill(template: str, **kw) -> str:
    return re.sub(r"\{\{(\w+)\}\}", lambda m: kw.get(m.group(1), ""), template)


def build(out: Path, base_url: str):
    if out.exists():
        shutil.rmtree(out)
    (out / "docs").mkdir(parents=True)
    shutil.copytree(WEB / "assets", out / "assets")
    shutil.copytree(DOCS / "assets", out / "docs" / "assets")

    page_tpl = (WEB / "templates" / "page.html").read_text()
    flat = [(src, label) for _, pages in NAV for src, label in pages]
    index = []
    for i, (src, label) in enumerate(flat):
        text = (DOCS / src).read_text()
        m = re.match(r"#\s+(.+)\n", text)
        title = m.group(1).strip() if m else label
        text = text[m.end():] if m else text
        page_out = out_path(src)
        body, toc = render_markdown(text, src)
        body = code_copy(figures(fix_links(body, src, page_out)))
        prev_link = next_link = ""
        if i > 0:
            p_src, p_label = flat[i - 1]
            prev_link = f'<a class="pn prev" href="{rel(page_out, out_path(p_src))}"><span>Previous</span>{p_label}</a>'
        if i + 1 < len(flat):
            n_src, n_label = flat[i + 1]
            next_link = f'<a class="pn next" href="{rel(page_out, out_path(n_src))}"><span>Next</span>{n_label}</a>'
        section = next(s for s, pages in NAV if any(p == src for p, _ in pages))
        root = rel(page_out, "")
        page = fill(
            page_tpl,
            title=html.escape(title),
            section=html.escape(section),
            body=body,
            toc=toc_html(toc),
            sidebar=sidebar(page_out),
            prev=prev_link,
            next=next_link,
            root=root,
            edit=f"{REPO}/edit/main/docs/{src}",
            description=html.escape(text_of(body)[:180]),
            scripts=(
                f'<script src="{root}assets/vendor/mermaid/mermaid.min.js" defer></script>\n'
                f'<script src="{root}assets/diagrams.js" defer></script>'
            )
            if 'class="mermaid"' in body
            else "",
            canonical=(base_url.rstrip("/") + "/" + page_out) if base_url else "",
        )
        (out / page_out).parent.mkdir(parents=True, exist_ok=True)
        (out / page_out).write_text(page)

        # Search: one entry per section of the page.
        chunks = re.split(r'(<h[23] id="[^"]+">.*?</h[23]>)', body)
        heading, anchor, buf = title, "", []
        for c in chunks:
            hm = re.match(r'<h[23] id="([^"]+)">(.*?)</h[23]>', c, flags=re.S)
            if hm:
                index.append({"t": title, "h": heading, "u": page_out + anchor, "x": text_of("".join(buf))[:600]})
                heading, anchor, buf = text_of(hm.group(2)).rstrip("#").strip(), "#" + hm.group(1), []
            else:
                buf.append(c)
        index.append({"t": title, "h": heading, "u": page_out + anchor, "x": text_of("".join(buf))[:600]})

    (out / "assets" / "search.json").write_text(json.dumps(index, separators=(",", ":")))
    home = fill((WEB / "templates" / "home.html").read_text(), root="", canonical=base_url)
    (out / "index.html").write_text(home)
    (out / ".nojekyll").write_text("")
    print(f"built {len(flat)} pages into {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "_site"))
    ap.add_argument("--base-url", default="")
    a = ap.parse_args()
    build(Path(a.out), a.base_url)


if __name__ == "__main__":
    main()
