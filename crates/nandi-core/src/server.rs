//! MCP server launch specs and the packages they run.
//!
//! A [`ServerSpec`] records how an MCP server is reached: the command line
//! of a stdio server (`nandi wrap`) or the upstream URL of an HTTP route.
//! [`ServerSpec::package`] works out which package a stdio command line
//! runs, from the launchers people actually use in MCP client configs:
//!
//! | Launcher | Example | Package |
//! |---|---|---|
//! | `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec` | `npx -y @scope/server@1.2.3` | npm |
//! | `uvx`, `uv tool run`, `pipx run`, `python -m` | `uvx --from mcp-x==1.2.3 mcp-x` | pypi |
//! | `docker run`, `podman run` | `docker run -i --rm ghcr.io/org/server:1.4` | oci |
//! | `node`, `python`, `deno run`, `bun run` with a path, or a binary | `node ./build/index.js` | local |
//!
//! A package is *pinned* when its version is exact: npm `1.2.3`, pypi
//! `==1.2.3`, an OCI digest or an explicit tag other than `latest`. Ranges,
//! `latest` and missing versions are unpinned. A local file counts as pinned
//! once its SHA-256 is known ([`PackageRef::digest`]).

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// How an MCP server is reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum ServerSpec {
    /// A child process speaking MCP over stdin / stdout.
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
    },
    /// A remote server over Streamable HTTP (or legacy SSE).
    Http { url: String },
}

impl ServerSpec {
    /// The package a stdio command line runs, when it can be told.
    /// `None` for HTTP servers and for commands such as shells whose payload
    /// is not a package.
    pub fn package(&self) -> Option<PackageRef> {
        match self {
            ServerSpec::Stdio { command, args } => parse_command(command, args),
            ServerSpec::Http { .. } => None,
        }
    }

    /// The URL of an HTTP server.
    pub fn url(&self) -> Option<&str> {
        match self {
            ServerSpec::Http { url } => Some(url),
            ServerSpec::Stdio { .. } => None,
        }
    }

    /// One-line description: the command line or the URL.
    pub fn display(&self) -> String {
        match self {
            ServerSpec::Stdio { command, args } if args.is_empty() => command.clone(),
            ServerSpec::Stdio { command, args } => format!("{command} {}", args.join(" ")),
            ServerSpec::Http { url } => url.clone(),
        }
    }
}

/// Package registry a server comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Npm,
    Pypi,
    /// Container images (Docker, Podman).
    Oci,
    /// A file on this machine: a script or a binary.
    Local,
}

impl Ecosystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
            Ecosystem::Oci => "oci",
            Ecosystem::Local => "local",
        }
    }

    /// Whether packages come from a public registry (and can be pinned to a
    /// version), as opposed to a local file.
    pub fn is_registry(&self) -> bool {
        !matches!(self, Ecosystem::Local)
    }
}

impl FromStr for Ecosystem {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "npm" => Ok(Ecosystem::Npm),
            "pypi" | "pip" => Ok(Ecosystem::Pypi),
            "oci" | "docker" => Ok(Ecosystem::Oci),
            "local" | "file" => Ok(Ecosystem::Local),
            other => Err(format!("unknown package ecosystem `{other}` (npm, pypi, oci or local)")),
        }
    }
}

/// A published advisory for a package, from the OSV database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    /// OSV id (`MAL-2025-1234`, `GHSA-...`, `PYSEC-...`).
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    /// A malicious-package report rather than a vulnerability.
    pub malicious: bool,
}

/// Result of an advisory lookup for one exact package reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryCheck {
    /// The package as looked up ([`PackageRef`]'s `Display` form).
    pub package: String,
    pub checked_ms: u64,
    pub advisories: Vec<Advisory>,
}

/// A package reference parsed from a launcher command line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRef {
    pub ecosystem: Ecosystem,
    /// Package name (`@scope/name`, `mcp-server-x`, `ghcr.io/org/image`) or
    /// the path of a local file.
    pub name: String,
    /// Version, version specifier or image tag as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The reference resolves to exactly one artifact.
    pub pinned: bool,
    /// Content digest: an OCI `sha256:...` digest, or the hex SHA-256 of a
    /// local file once it has been hashed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

impl PackageRef {
    fn new(ecosystem: Ecosystem, name: impl Into<String>, version: Option<String>, pinned: bool) -> Self {
        Self { ecosystem, name: name.into(), version, pinned, digest: None }
    }

    fn local(path: &str) -> Self {
        Self::new(Ecosystem::Local, path, None, false)
    }

    /// Record the SHA-256 of a local file; the reference becomes pinned.
    pub fn with_local_digest(mut self, sha256: String) -> Self {
        if self.ecosystem == Ecosystem::Local {
            self.digest = Some(sha256);
            self.pinned = true;
        }
        self
    }

    /// Parse the `ecosystem:name@version` form used in `servers.approved`
    /// (`npm:@scope/pkg@1.2.3`, `pypi:mcp-x==1.0`, `oci:ghcr.io/o/i:1.2`,
    /// `oci:ghcr.io/o/i@sha256:...`). The version part is optional.
    pub fn parse_spec(spec: &str) -> Result<Self, String> {
        let (eco, rest) =
            spec.split_once(':').ok_or_else(|| format!("package `{spec}` must look like ecosystem:name[@version]"))?;
        let ecosystem: Ecosystem = eco.parse()?;
        let rest = rest.trim();
        if rest.is_empty() {
            return Err(format!("package `{spec}` has no name"));
        }
        Ok(match ecosystem {
            Ecosystem::Npm => parse_npm(rest),
            Ecosystem::Pypi => parse_pypi(rest),
            Ecosystem::Oci => parse_image(rest),
            Ecosystem::Local => PackageRef::local(rest),
        })
    }

    /// Whether `self` (from an allow-list entry) admits `seen`: same
    /// ecosystem and name, and the same version or digest when `self` names
    /// one. npm and pypi names compare case-insensitively and pypi treats
    /// `-`, `_` and `.` alike.
    pub fn admits(&self, seen: &PackageRef) -> bool {
        if self.ecosystem != seen.ecosystem || !names_equal(self.ecosystem, &self.name, &seen.name) {
            return false;
        }
        if let Some(d) = &self.digest
            && !seen.digest.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(d))
        {
            return false;
        }
        match &self.version {
            Some(v) => seen.version.as_deref().is_some_and(|s| normalize_version(s) == normalize_version(v)),
            None => true,
        }
    }
}

impl fmt::Display for PackageRef {
    /// `ecosystem:name@version` (`@digest` for OCI digests).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ecosystem.as_str(), self.name)?;
        match (&self.version, &self.digest) {
            (_, Some(d)) if self.ecosystem == Ecosystem::Oci => write!(f, "@{d}"),
            (Some(v), _) => write!(f, "@{v}"),
            _ => Ok(()),
        }
    }
}

fn names_equal(eco: Ecosystem, a: &str, b: &str) -> bool {
    match eco {
        Ecosystem::Pypi => {
            let norm = |s: &str| s.to_ascii_lowercase().replace(['_', '.'], "-");
            norm(a) == norm(b)
        }
        Ecosystem::Npm | Ecosystem::Oci => a.eq_ignore_ascii_case(b),
        Ecosystem::Local => a == b,
    }
}

fn normalize_version(v: &str) -> &str {
    let v = v.trim();
    v.strip_prefix("===").or_else(|| v.strip_prefix("==")).unwrap_or(v).trim_start_matches('v')
}

/// File name of a command without directories or a Windows extension.
fn base_name(command: &str) -> String {
    let base = command.rsplit(['/', '\\']).next().unwrap_or(command).to_ascii_lowercase();
    for ext in [".exe", ".cmd", ".bat", ".ps1"] {
        if let Some(stem) = base.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    base
}

const SHELLS: &[&str] = &["sh", "bash", "zsh", "fish", "dash", "cmd", "powershell", "pwsh"];

fn parse_command(command: &str, args: &[String]) -> Option<PackageRef> {
    let base = base_name(command);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match base.as_str() {
        "env" => {
            // `env [-i] [NAME=value]... cmd args`
            let rest: Vec<&str> = args.iter().copied().skip_while(|a| a.starts_with('-') || a.contains('=')).collect();
            let (cmd, tail) = rest.split_first()?;
            let tail: Vec<String> = tail.iter().map(|s| s.to_string()).collect();
            parse_command(cmd, &tail)
        }
        "npx" | "bunx" => npm_launcher(&args),
        "pnpm" | "yarn" => match args.split_first() {
            Some((&"dlx", rest)) => npm_launcher(rest),
            _ => None,
        },
        "npm" => match args.split_first() {
            Some((&("exec" | "x"), rest)) => npm_launcher(rest),
            _ => None,
        },
        "uvx" => uv_launcher(&args),
        "uv" => match args.as_slice() {
            ["tool", "run", rest @ ..] => uv_launcher(rest),
            _ => None,
        },
        "pipx" => match args.split_first() {
            Some((&"run", rest)) => pipx_launcher(rest),
            _ => None,
        },
        "docker" | "podman" | "nerdctl" => match args.as_slice() {
            ["run", rest @ ..] | ["container", "run", rest @ ..] => container_launcher(rest),
            _ => None,
        },
        "node" | "nodejs" | "tsx" | "ts-node" => script_arg(&args, &["-r", "--require", "--import", "--loader"]),
        "python" | "python3" | "py" => python_launcher(&args),
        "deno" => match args.split_first() {
            Some((&"run", rest)) => deno_launcher(rest),
            _ => None,
        },
        "bun" => match args.split_first() {
            Some((&"run", rest)) => script_arg(rest, &[]),
            Some((&"x", rest)) => npm_launcher(rest),
            Some((first, _)) if !first.starts_with('-') && looks_like_path(first) => Some(PackageRef::local(first)),
            _ => None,
        },
        s if SHELLS.contains(&s) => None,
        _ => Some(PackageRef::local(command)),
    }
}

fn looks_like_path(s: &str) -> bool {
    s.starts_with('/')
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('~')
        || s.contains('\\')
        || [".js", ".mjs", ".cjs", ".ts", ".mts", ".py", ".jar"].iter().any(|e| s.ends_with(e))
}

/// The first non-flag argument of an interpreter, as a local file.
fn script_arg(args: &[&str], valued: &[&str]) -> Option<PackageRef> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a == "--" {
            return args.get(i + 1).map(|p| PackageRef::local(p));
        }
        if a.starts_with('-') {
            i += if valued.contains(&a) { 2 } else { 1 };
            continue;
        }
        return Some(PackageRef::local(a));
    }
    None
}

/// Value of a `--flag value` / `--flag=value` / `-f value` option.
fn take_value<'a>(args: &[&'a str], i: &mut usize, names: &[&str]) -> Option<Option<&'a str>> {
    let a = args[*i];
    for n in names {
        if a == *n {
            *i += 2;
            return Some(args.get(*i - 1).copied());
        }
        if let Some(v) = a.strip_prefix(n).and_then(|r| r.strip_prefix('=')) {
            *i += 1;
            return Some(Some(v));
        }
    }
    None
}

fn npm_launcher(args: &[&str]) -> Option<PackageRef> {
    const VALUED: &[&str] =
        &["--registry", "--cache", "--userconfig", "--prefix", "--node-options", "-w", "--workspace"];
    let mut package = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if let Some(v) = take_value(args, &mut i, &["--package", "-p"]) {
            package = package.or(v);
            continue;
        }
        if matches!(a, "-c" | "--call") {
            // A shell command line; the payload is not a package.
            return package.map(npm_or_local);
        }
        if a.starts_with('-') {
            i += if VALUED.contains(&a) { 2 } else { 1 };
            continue;
        }
        break;
    }
    package.or_else(|| args.get(i).copied()).map(npm_or_local)
}

fn npm_or_local(spec: &str) -> PackageRef {
    if looks_like_path(spec) || spec.starts_with("file:") {
        PackageRef::local(spec.trim_start_matches("file:"))
    } else {
        parse_npm(spec)
    }
}

/// `@scope/name@1.2.3`, `name@^1`, `name`.
fn parse_npm(spec: &str) -> PackageRef {
    let spec = spec.trim().trim_start_matches("npm:");
    let at = if let Some(rest) = spec.strip_prefix('@') { rest.find('@').map(|i| i + 1) } else { spec.find('@') };
    let (name, version) = match at {
        Some(i) => (&spec[..i], Some(&spec[i + 1..])),
        None => (spec, None),
    };
    let version = version.filter(|v| !v.is_empty());
    let pinned = version.is_some_and(is_exact_semver);
    PackageRef::new(Ecosystem::Npm, name, version.map(str::to_owned), pinned)
}

/// `1.2.3`, `v1.2.3`, `1.2.3-beta.1`, `1.2.3+build`.
fn is_exact_semver(v: &str) -> bool {
    let v = v.strip_prefix('v').unwrap_or(v).strip_prefix('=').unwrap_or(v);
    let core = v.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `name==1.2.3`, `name===1.2.3`, `name@1.2.3` (uv), `name[extra]>=1`, `name`.
fn parse_pypi(spec: &str) -> PackageRef {
    let spec = spec.trim();
    if spec.contains("://") || spec.starts_with("git+") {
        return PackageRef::new(Ecosystem::Pypi, spec, None, false);
    }
    let cut = spec.find(['=', '<', '>', '~', '!', '@', ';', ' ']).unwrap_or(spec.len());
    let name = spec[..cut].split('[').next().unwrap_or("").trim();
    let rest = spec[cut..].trim();
    let rest = rest.split(';').next().unwrap_or("").trim();
    if rest.is_empty() {
        return PackageRef::new(Ecosystem::Pypi, name, None, false);
    }
    let (pinned, version) = if let Some(v) = rest.strip_prefix("===").or_else(|| rest.strip_prefix("==")) {
        (!v.contains(['*', ',']), v.trim())
    } else if let Some(v) = rest.strip_prefix('@') {
        (v.trim() != "latest" && !v.contains(['*', ',', '<', '>', '~', '^']), v.trim())
    } else {
        (false, rest)
    };
    let shown = if rest.starts_with("==") || rest.starts_with('@') { version } else { rest };
    PackageRef::new(Ecosystem::Pypi, name, Some(shown.to_owned()), pinned && !version.is_empty())
}

fn uv_launcher(args: &[&str]) -> Option<PackageRef> {
    const VALUED: &[&str] = &[
        "--with",
        "--with-requirements",
        "--with-editable",
        "--python",
        "-p",
        "--index",
        "--index-url",
        "--extra-index-url",
        "--default-index",
        "--find-links",
        "-f",
        "--constraints",
        "--overrides",
        "--directory",
        "--project",
        "--cache-dir",
        "--config-file",
    ];
    let mut from = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if let Some(v) = take_value(args, &mut i, &["--from"]) {
            from = v;
            continue;
        }
        if a == "--" {
            i += 1;
            break;
        }
        if a.starts_with('-') {
            i += if VALUED.contains(&a) { 2 } else { 1 };
            continue;
        }
        break;
    }
    from.or_else(|| args.get(i).copied()).map(|s| if looks_like_path(s) { PackageRef::local(s) } else { parse_pypi(s) })
}

fn pipx_launcher(args: &[&str]) -> Option<PackageRef> {
    const VALUED: &[&str] = &["--python", "--pip-args", "--index-url", "-i"];
    let mut spec = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if let Some(v) = take_value(args, &mut i, &["--spec"]) {
            spec = v;
            continue;
        }
        if a == "--" {
            i += 1;
            break;
        }
        if a.starts_with('-') {
            i += if VALUED.contains(&a) { 2 } else { 1 };
            continue;
        }
        break;
    }
    spec.or_else(|| args.get(i).copied()).map(parse_pypi)
}

fn python_launcher(args: &[&str]) -> Option<PackageRef> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a == "-m" {
            // An installed module; its version is whatever the environment has.
            return args.get(i + 1).map(|m| PackageRef::new(Ecosystem::Pypi, *m, None, false));
        }
        if a == "-c" {
            return None;
        }
        if a.starts_with('-') {
            i += if matches!(a, "-W" | "-X" | "--check-hash-based-pycs") { 2 } else { 1 };
            continue;
        }
        return Some(PackageRef::local(a));
    }
    None
}

fn deno_launcher(args: &[&str]) -> Option<PackageRef> {
    const VALUED: &[&str] = &["--config", "-c", "--import-map", "--lock", "--cert", "--location", "--seed"];
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a.starts_with('-') {
            i += if VALUED.contains(&a) { 2 } else { 1 };
            continue;
        }
        if let Some(spec) = a.strip_prefix("npm:") {
            return Some(parse_npm(spec));
        }
        if a.contains("://") || a.starts_with("jsr:") {
            return Some(PackageRef::new(Ecosystem::Local, a, None, false));
        }
        return Some(PackageRef::local(a));
    }
    None
}

fn container_launcher(args: &[&str]) -> Option<PackageRef> {
    const VALUED: &[&str] = &[
        "-e",
        "--env",
        "--env-file",
        "-v",
        "--volume",
        "--mount",
        "--name",
        "-p",
        "--publish",
        "--network",
        "--net",
        "-w",
        "--workdir",
        "-u",
        "--user",
        "--entrypoint",
        "-l",
        "--label",
        "--label-file",
        "--platform",
        "--pull",
        "-h",
        "--hostname",
        "--add-host",
        "--cpus",
        "-c",
        "--cpu-shares",
        "-m",
        "--memory",
        "--memory-swap",
        "--device",
        "--cap-add",
        "--cap-drop",
        "--security-opt",
        "--tmpfs",
        "--ulimit",
        "--restart",
        "--log-driver",
        "--log-opt",
        "--dns",
        "--dns-search",
        "--gpus",
        "--ipc",
        "--pid",
        "--shm-size",
        "--stop-signal",
        "--stop-timeout",
        "--runtime",
        "--group-add",
        "--cidfile",
        "-a",
        "--attach",
        "--expose",
        "--health-cmd",
        "--userns",
        "--uts",
        "--volumes-from",
        "--link",
    ];
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if a.starts_with('-') {
            i += if !a.contains('=') && VALUED.contains(&a) { 2 } else { 1 };
            continue;
        }
        break;
    }
    args.get(i).map(|image| parse_image(image))
}

/// `[registry/]name[:tag][@sha256:digest]`.
fn parse_image(image: &str) -> PackageRef {
    let image = image.trim().trim_start_matches("docker://");
    let (rest, digest) = match image.split_once('@') {
        Some((r, d)) => (r, Some(d.to_owned())),
        None => (image, None),
    };
    let last_slash = rest.rfind('/').map_or(0, |i| i + 1);
    let (name, tag) = match rest[last_slash..].rfind(':') {
        Some(i) => (&rest[..last_slash + i], Some(&rest[last_slash + i + 1..])),
        None => (rest, None),
    };
    let tag = tag.filter(|t| !t.is_empty());
    let pinned = digest.is_some() || tag.is_some_and(|t| !t.eq_ignore_ascii_case("latest"));
    let mut p = PackageRef::new(Ecosystem::Oci, name, tag.map(str::to_owned), pinned);
    p.digest = digest;
    p
}

/// Resolve a command to a file: paths are taken as is (relative to the
/// working directory), bare names are searched on `PATH`.
pub fn resolve_executable(command: &str) -> Option<PathBuf> {
    let p = Path::new(command);
    if command.contains(['/', '\\']) {
        return p.is_file().then(|| p.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    // Windows looks up `node` as `node.exe`, `node.cmd` and so on.
    let exts: Vec<String> = if cfg!(windows) && Path::new(command).extension().is_none() {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .filter(|e| !e.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    } else {
        vec![String::new()]
    };
    std::env::split_paths(&path)
        .flat_map(|dir| exts.iter().map(move |e| dir.join(format!("{command}{e}"))))
        .find(|c| c.is_file())
}

/// Hex SHA-256 of a file's contents, read in chunks.
pub fn file_sha256(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode(h.finalize()))
}

/// SHA-256 of the local file a package reference points at, when it is one
/// and it exists.
pub fn local_digest(pkg: &PackageRef) -> Option<String> {
    if pkg.ecosystem != Ecosystem::Local || pkg.name.contains("://") {
        return None;
    }
    let name = pkg.name.strip_prefix("~/").map_or_else(
        || pkg.name.clone(),
        |rest| std::env::var("HOME").map(|h| format!("{h}/{rest}")).unwrap_or_else(|_| pkg.name.clone()),
    );
    resolve_executable(&name).and_then(|p| file_sha256(&p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(cmd: &str) -> Option<PackageRef> {
        let mut parts = cmd.split_whitespace();
        let command = parts.next().unwrap().to_string();
        ServerSpec::Stdio { command, args: parts.map(String::from).collect() }.package()
    }

    fn expect(cmd: &str, eco: Ecosystem, name: &str, version: Option<&str>, pinned: bool) {
        let p = pkg(cmd).unwrap_or_else(|| panic!("no package for {cmd}"));
        assert_eq!(
            (p.ecosystem, p.name.as_str(), p.version.as_deref(), p.pinned),
            (eco, name, version, pinned),
            "{cmd}"
        );
    }

    #[test]
    fn npm_launchers() {
        use Ecosystem::Npm;
        expect(
            "npx -y @modelcontextprotocol/server-github@2025.4.8",
            Npm,
            "@modelcontextprotocol/server-github",
            Some("2025.4.8"),
            true,
        );
        expect(
            "npx @modelcontextprotocol/server-filesystem /tmp",
            Npm,
            "@modelcontextprotocol/server-filesystem",
            None,
            false,
        );
        expect("npx --yes mcp-remote@latest https://x", Npm, "mcp-remote", Some("latest"), false);
        expect("npx -y some-server@^1.2.0", Npm, "some-server", Some("^1.2.0"), false);
        expect("npx -y some-server@1.2", Npm, "some-server", Some("1.2"), false);
        expect("npx -y some-server@1.2.3-beta.1", Npm, "some-server", Some("1.2.3-beta.1"), true);
        expect("npx -p @scope/pkg@3.0.0 pkg-bin --flag", Npm, "@scope/pkg", Some("3.0.0"), true);
        expect("npx --package=@scope/pkg@3.0.0 pkg-bin", Npm, "@scope/pkg", Some("3.0.0"), true);
        expect("npx.cmd -y @playwright/mcp@0.0.29", Npm, "@playwright/mcp", Some("0.0.29"), true);
        expect("/usr/local/bin/npx -y tavily-mcp@0.1.4", Npm, "tavily-mcp", Some("0.1.4"), true);
        expect("bunx @upstash/context7-mcp@1.0.14", Npm, "@upstash/context7-mcp", Some("1.0.14"), true);
        expect("bunx --bun some-server", Npm, "some-server", None, false);
        expect("pnpm dlx @scope/x@2.0.0", Npm, "@scope/x", Some("2.0.0"), true);
        expect("yarn dlx -p @scope/x@2.0.0 x", Npm, "@scope/x", Some("2.0.0"), true);
        expect("npm exec --yes -- @scope/x@1.0.0", Npm, "@scope/x", Some("1.0.0"), true);
        expect("env API_KEY=placeholder npx -y srv@1.0.0", Npm, "srv", Some("1.0.0"), true);
        expect("npx ./local-server", Ecosystem::Local, "./local-server", None, false);
        assert!(pkg("npx").is_none());
        assert!(pkg("pnpm install").is_none());
        assert!(pkg("npx -c 'echo hi'").is_none());
    }

    #[test]
    fn python_launchers() {
        use Ecosystem::Pypi;
        expect("uvx mcp-server-fetch", Pypi, "mcp-server-fetch", None, false);
        expect("uvx mcp-server-git==2025.1.14", Pypi, "mcp-server-git", Some("2025.1.14"), true);
        expect("uvx mcp-server-time@2025.1.14", Pypi, "mcp-server-time", Some("2025.1.14"), true);
        expect("uvx mcp-server-time@latest", Pypi, "mcp-server-time", Some("latest"), false);
        expect("uvx --from mcp-x==1.2.3 mcp-x-cli --port 1", Pypi, "mcp-x", Some("1.2.3"), true);
        expect("uvx --from=mcp-x>=1.2 mcp-x", Pypi, "mcp-x", Some(">=1.2"), false);
        expect("uvx --python 3.12 --with httpx mcp-y===0.4", Pypi, "mcp-y", Some("0.4"), true);
        expect("uv tool run mcp-z[cli]==0.9.1", Pypi, "mcp-z", Some("0.9.1"), true);
        expect("pipx run --spec mcp-a==1.0.0 mcp-a", Pypi, "mcp-a", Some("1.0.0"), true);
        expect("pipx run mcp-a", Pypi, "mcp-a", None, false);
        expect("python -m mcp_server_sqlite --db x.db", Pypi, "mcp_server_sqlite", None, false);
        expect("python3 /opt/srv/server.py", Ecosystem::Local, "/opt/srv/server.py", None, false);
        expect("uvx git+https://github.com/o/r", Pypi, "git+https://github.com/o/r", None, false);
        assert!(pkg("python -c print(1)").is_none());
        assert!(pkg("uv sync").is_none());
    }

    #[test]
    fn container_launchers() {
        use Ecosystem::Oci;
        expect(
            "docker run -i --rm ghcr.io/github/github-mcp-server",
            Oci,
            "ghcr.io/github/github-mcp-server",
            None,
            false,
        );
        expect("docker run -i --rm mcp/fetch:latest", Oci, "mcp/fetch", Some("latest"), false);
        expect(
            "docker run -i --rm -e GITHUB_TOKEN -v /tmp:/tmp --name x ghcr.io/github/github-mcp-server:v0.5.0 stdio",
            Oci,
            "ghcr.io/github/github-mcp-server",
            Some("v0.5.0"),
            true,
        );
        expect(
            "podman run --env=A=b -it localhost:5000/team/srv:1.2",
            Oci,
            "localhost:5000/team/srv",
            Some("1.2"),
            true,
        );
        expect("docker container run --network host mcp/time", Oci, "mcp/time", None, false);
        let p = pkg("docker run -i mcp/git@sha256:0123abcd").unwrap();
        assert_eq!((p.name.as_str(), p.digest.as_deref(), p.pinned), ("mcp/git", Some("sha256:0123abcd"), true));
        assert_eq!(p.to_string(), "oci:mcp/git@sha256:0123abcd");
        assert!(pkg("docker ps").is_none());
        assert!(pkg("docker run --rm").is_none());
    }

    #[test]
    fn local_launchers() {
        use Ecosystem::Local;
        expect("node ./build/index.js", Local, "./build/index.js", None, false);
        expect("node --require dotenv/config /srv/mcp/dist/main.js", Local, "/srv/mcp/dist/main.js", None, false);
        expect("deno run -A ./server.ts", Local, "./server.ts", None, false);
        expect("deno run --allow-net npm:@scope/srv@1.0.0", Ecosystem::Npm, "@scope/srv", Some("1.0.0"), true);
        expect("bun run ./srv.ts", Local, "./srv.ts", None, false);
        expect("/opt/tools/mcp-server --stdio", Local, "/opt/tools/mcp-server", None, false);
        expect("mcp-server-kubernetes", Local, "mcp-server-kubernetes", None, false);
        assert!(pkg("bash -c run.sh").is_none());
        assert!(pkg("node").is_none());
        assert!(ServerSpec::Http { url: "https://x/mcp".into() }.package().is_none());
    }

    #[test]
    fn spec_strings_and_admission() {
        let a = PackageRef::parse_spec("npm:@modelcontextprotocol/server-github@2025.4.8").unwrap();
        assert_eq!(
            (a.name.as_str(), a.version.as_deref(), a.pinned),
            ("@modelcontextprotocol/server-github", Some("2025.4.8"), true)
        );
        assert_eq!(a.to_string(), "npm:@modelcontextprotocol/server-github@2025.4.8");
        let seen = pkg("npx -y @modelcontextprotocol/server-github@2025.4.8").unwrap();
        assert!(a.admits(&seen));
        let newer = pkg("npx -y @modelcontextprotocol/server-github@2025.5.1").unwrap();
        assert!(!a.admits(&newer));
        let any = PackageRef::parse_spec("npm:@modelcontextprotocol/server-github").unwrap();
        assert!(any.admits(&newer));
        assert!(!any.admits(&pkg("uvx server-github").unwrap()));

        let py = PackageRef::parse_spec("pypi:Mcp_Server.Git==2025.1.14").unwrap();
        assert!(py.admits(&pkg("uvx mcp-server-git@2025.1.14").unwrap()));
        let oci = PackageRef::parse_spec("oci:mcp/git@sha256:0123abcd").unwrap();
        assert!(oci.admits(&pkg("docker run -i mcp/git@sha256:0123ABCD").unwrap()));
        assert!(!oci.admits(&pkg("docker run -i mcp/git:1.0").unwrap()));
        let tagged = PackageRef::parse_spec("oci:ghcr.io/o/i:v1").unwrap();
        assert!(tagged.admits(&pkg("docker run ghcr.io/o/i:v1").unwrap()));
        assert!(PackageRef::parse_spec("cargo:x").is_err());
        assert!(PackageRef::parse_spec("nocolon").is_err());
        assert!(PackageRef::parse_spec("npm:").is_err());
    }

    #[test]
    fn local_digest_pins_files() {
        let dir = std::env::temp_dir().join(format!("nandi-server-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("srv.js");
        std::fs::write(&file, b"console.log(1)").unwrap();
        let p = pkg(&format!("node {}", file.display())).unwrap();
        assert!(!p.pinned);
        let digest = local_digest(&p).unwrap();
        assert_eq!(digest, crate::util::sha256_hex(b"console.log(1)"));
        let p = p.with_local_digest(digest);
        assert!(p.pinned);
        assert!(local_digest(&pkg("node /does/not/exist.js").unwrap()).is_none());
        let shell = if cfg!(windows) { "cmd" } else { "sh" };
        assert!(resolve_executable(shell).is_some() || std::env::var_os("PATH").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn spec_serde_and_display() {
        let s = ServerSpec::Stdio { command: "npx".into(), args: vec!["-y".into(), "x@1.0.0".into()] };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["transport"], "stdio");
        assert_eq!(serde_json::from_value::<ServerSpec>(v).unwrap(), s);
        assert_eq!(s.display(), "npx -y x@1.0.0");
        let h = ServerSpec::Http { url: "https://x/mcp".into() };
        assert_eq!(h.url(), Some("https://x/mcp"));
        assert_eq!(serde_json::to_value(&h).unwrap()["transport"], "http");
    }
}
