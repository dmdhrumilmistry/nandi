//! Server-side request forgery checks on outbound content.
//!
//! URLs and host-looking tokens are extracted from strings and classified
//! without DNS: loopback, private, link-local and cloud metadata addresses,
//! internal names (`localhost`, `*.internal`, `*.local`), alternative IPv4
//! spellings (`2130706433`, `0x7f000001`, `0177.0.0.1`), IPv4-mapped IPv6
//! and wildcard DNS services that embed an IP in the name (`nip.io`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nandi_core::util::glob_match;
use regex::Regex;

pub(crate) const RULE_METADATA: &str = "ssrf.metadata";
pub(crate) const RULE_PRIVATE_IP: &str = "ssrf.private-ip";
pub(crate) const RULE_INTERNAL_HOST: &str = "ssrf.internal-host";
pub(crate) const RULE_SCHEME: &str = "ssrf.dangerous-scheme";

/// Number of SSRF rules.
pub(crate) const RULE_COUNT: usize = 4;

/// An internal destination found in a text.
#[derive(Debug, Clone)]
pub(crate) struct SsrfHit {
    pub start: usize,
    pub end: usize,
    pub rule: &'static str,
    pub reason: &'static str,
    pub host: String,
}

/// An IPv4 or IPv6 network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `10.0.0.0/8`, `fd00::/8` or a single address.
    pub fn parse(s: &str) -> Option<Self> {
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, Some(p.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let net: IpAddr = ip.trim_start_matches('[').trim_end_matches(']').parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(Self { net, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                u128::from(n) & mask == u128::from(a) & mask
            }
            (IpAddr::V4(_), IpAddr::V6(a)) => a.to_ipv4_mapped().is_some_and(|v4| self.contains(IpAddr::V4(v4))),
            _ => false,
        }
    }
}

/// Hosts and networks from configuration.
#[derive(Debug, Clone, Default)]
struct HostSet {
    nets: Vec<Cidr>,
    names: Vec<String>,
}

impl HostSet {
    fn new(entries: &[String]) -> Self {
        let mut set = Self::default();
        for e in entries {
            let e = e.trim().to_ascii_lowercase();
            if e.is_empty() {
                continue;
            }
            match Cidr::parse(&e) {
                Some(c) => set.nets.push(c),
                None => set.names.push(e.trim_end_matches('.').to_string()),
            }
        }
        set
    }

    fn matches(&self, host: &str, ip: Option<IpAddr>) -> bool {
        if let Some(ip) = ip
            && self.nets.iter().any(|c| c.contains(ip))
        {
            return true;
        }
        self.names.iter().any(|p| {
            if p.contains('*') || p.contains('?') {
                glob_match(p, host)
            } else {
                host == p || host.strip_suffix(p.as_str()).is_some_and(|rest| rest.ends_with('.'))
            }
        })
    }
}

/// Classifies hosts and finds them in text.
pub(crate) struct SsrfChecker {
    url: Regex,
    bare: Regex,
    internal: HostSet,
    allow: HostSet,
}

const METADATA_V4: &[Ipv4Addr] = &[
    Ipv4Addr::new(169, 254, 169, 254), // AWS, GCP, Azure, OpenStack, DigitalOcean
    Ipv4Addr::new(169, 254, 170, 2),   // AWS ECS task metadata
    Ipv4Addr::new(100, 100, 100, 200), // Alibaba Cloud
    Ipv4Addr::new(192, 0, 0, 192),     // Oracle Cloud
];

const METADATA_NAMES: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
    "metadata.azure.internal",
];

impl SsrfChecker {
    pub fn new(internal_hosts: &[String], allow_hosts: &[String]) -> Self {
        Self {
            url: crate::compile(r#"(?i)\b(?:https?|ftp|wss?|gopher|dict|ldap|tftp|sftp)://[^\s"'<>`]+"#),
            bare: crate::compile(concat!(
                r#"(?i)(?:^|[\s"'(\[=,;])("#,
                r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}|localhost|\[[0-9a-f:.]+\]|",
                r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:internal|local|localhost)",
                r")(:[0-9]{1,5}|/)"
            )),
            internal: HostSet::new(internal_hosts),
            allow: HostSet::new(allow_hosts),
        }
    }

    /// Append internal destinations referenced by `text` to `out`.
    pub fn scan(&self, text: &str, out: &mut Vec<SsrfHit>) {
        let trimmed = text.trim();
        // A string that is entirely a host, host:port or host/path.
        if !trimmed.is_empty()
            && trimmed.len() < 300
            && !trimmed.contains(char::is_whitespace)
            && !trimmed.contains("://")
        {
            let start = text.len() - text.trim_start().len();
            let host = trimmed.split(['/', '?', '#']).next().unwrap_or("");
            if let Some(host) = split_port(host)
                && looks_like_host(host)
                && let Some((rule, reason)) = self.classify(host, false)
            {
                out.push(SsrfHit { start, end: start + trimmed.len(), rule, reason, host: host.to_ascii_lowercase() });
                return;
            }
        }
        if !text.contains("://") && !text.contains(':') && !text.contains('/') {
            return;
        }
        if text.contains("://") {
            for m in self.url.find_iter(text) {
                if let Some((rule, reason, host)) = self.check_url(m.as_str()) {
                    out.push(SsrfHit { start: m.start(), end: m.end(), rule, reason, host });
                }
            }
        }
        if !maybe_bare_host(text) {
            return;
        }
        for c in self.bare.captures_iter(text) {
            let host_m = c.get(1).expect("host group");
            let suffix = c.get(2).expect("suffix group");
            // `10.0.0.0/8` is CIDR notation, not a destination.
            if suffix.as_str() == "/" && text.as_bytes().get(suffix.end()).is_some_and(u8::is_ascii_digit) {
                continue;
            }
            if out.iter().any(|h| h.start <= host_m.start() && host_m.end() <= h.end) {
                continue;
            }
            if let Some((rule, reason)) = self.classify(host_m.as_str(), false) {
                out.push(SsrfHit {
                    start: host_m.start(),
                    end: suffix.end(),
                    rule,
                    reason,
                    host: host_m.as_str().to_ascii_lowercase(),
                });
            }
        }
    }

    fn check_url(&self, url: &str) -> Option<(&'static str, &'static str, String)> {
        let (scheme, rest) = url.split_once("://")?;
        let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
        let hostport = authority.rsplit_once('@').map(|x| x.1).unwrap_or(authority);
        let host = split_port(hostport)?;
        let host = percent_decode_host(host);
        let scheme = scheme.to_ascii_lowercase();
        if let Some((rule, reason)) = self.classify(&host, true) {
            return Some((rule, reason, host.to_ascii_lowercase()));
        }
        if matches!(scheme.as_str(), "gopher" | "dict" | "ldap" | "tftp") && !self.allowed(&host) {
            return Some((RULE_SCHEME, "protocol commonly abused for SSRF", host.to_ascii_lowercase()));
        }
        None
    }

    fn allowed(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        self.allow.matches(h.trim_end_matches('.'), parse_ip(&h, true))
    }

    /// Classify a host. `loose` enables integer, hex and octal IPv4 forms,
    /// which are only trusted inside URLs.
    pub fn classify(&self, host: &str, loose: bool) -> Option<(&'static str, &'static str)> {
        let lower = host.to_ascii_lowercase();
        let h = lower.trim_end_matches('.');
        if h.is_empty() {
            return None;
        }
        let ip = parse_ip(h, loose);
        if self.allow.matches(h, ip) {
            return None;
        }
        if let Some(ip) = ip {
            if let Some(r) = classify_ip(ip) {
                return Some(r);
            }
        } else {
            if METADATA_NAMES.contains(&h) {
                return Some((RULE_METADATA, "cloud metadata hostname"));
            }
            if h == "localhost" || h.ends_with(".localhost") {
                return Some((RULE_INTERNAL_HOST, "localhost"));
            }
            if h.ends_with(".internal") || h.ends_with(".local") || h.ends_with(".intranet") || h.ends_with(".lan") {
                return Some((RULE_INTERNAL_HOST, "internal domain"));
            }
            if matches!(h, "localtest.me" | "lvh.me") || h.ends_with(".localtest.me") || h.ends_with(".lvh.me") {
                return Some((RULE_PRIVATE_IP, "name resolving to loopback"));
            }
            if let Some(embedded) = wildcard_dns_ip(h)
                && classify_ip(IpAddr::V4(embedded)).is_some()
            {
                return Some((RULE_PRIVATE_IP, "wildcard DNS name embedding an internal IP"));
            }
        }
        if self.internal.matches(h, ip) {
            return Some(if ip.is_some() {
                (RULE_PRIVATE_IP, "configured internal network")
            } else {
                (RULE_INTERNAL_HOST, "configured internal host")
            });
        }
        None
    }
}

/// Cheap gate for the bare host regex: a dotted digit pattern, a bracket,
/// or an internal-looking name must occur.
fn maybe_bare_host(text: &str) -> bool {
    let b = text.as_bytes();
    let dotted = b.windows(3).any(|w| w[0].is_ascii_digit() && w[1] == b'.' && w[2].is_ascii_digit());
    if dotted || b.contains(&b'[') {
        return true;
    }
    let lower = text.to_ascii_lowercase();
    lower.contains("localhost") || lower.contains(".internal") || lower.contains(".local")
}

/// Strip `:port` from `host:port` or `[v6]:port`. Returns `None` for an
/// invalid port.
fn split_port(hostport: &str) -> Option<&str> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let end = rest.find(']')?;
        return Some(&hostport[..end + 2]);
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            if p.is_empty() || p.parse::<u16>().is_ok() {
                Some(h)
            } else {
                None
            }
        }
        Some(_) => Some(hostport), // bare IPv6 without brackets
        None => Some(hostport),
    }
}

fn looks_like_host(h: &str) -> bool {
    if h.starts_with('[') {
        return true;
    }
    let lower = h.to_ascii_lowercase();
    if lower == "localhost" || METADATA_NAMES.contains(&lower.as_str()) {
        return true;
    }
    let labels: Vec<&str> = lower.trim_end_matches('.').split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn percent_decode_host(h: &str) -> String {
    if !h.contains('%') || h.starts_with('[') {
        return h.to_string();
    }
    let b = h.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|x| u8::from_str_radix(x, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| h.to_string())
}

/// Parse a host as an IP address. With `loose`, accepts the inet_aton forms
/// that HTTP clients resolve: `2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`.
pub(crate) fn parse_ip(host: &str, loose: bool) -> Option<IpAddr> {
    if let Some(inner) = host.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        let inner = inner.split('%').next().unwrap_or(inner);
        return inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    if host.contains(':') {
        return host.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(v4));
    }
    if loose { parse_ipv4_loose(host).map(IpAddr::V4) } else { None }
}

fn parse_ipv4_loose(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let nums: Vec<u64> = parts.iter().map(|p| parse_num(p)).collect::<Option<_>>()?;
    let (last, head) = nums.split_last()?;
    if head.iter().any(|n| *n > 255) {
        return None;
    }
    let rem_bits = 8 * (4 - head.len() as u32);
    if rem_bits < 64 && *last >= 1u64 << rem_bits {
        return None;
    }
    let mut v: u32 = 0;
    for (i, n) in head.iter().enumerate() {
        v |= (*n as u32) << (24 - 8 * i as u32);
    }
    v |= *last as u32;
    Some(Ipv4Addr::from(v))
}

fn parse_num(p: &str) -> Option<u64> {
    if p.is_empty() {
        return None;
    }
    let (digits, radix) = if let Some(h) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
        (h, 16)
    } else if p.len() > 1 && p.starts_with('0') {
        (&p[1..], 8)
    } else {
        (p, 10)
    };
    if digits.is_empty() {
        return Some(0);
    }
    if digits.len() > 12 {
        return None;
    }
    u64::from_str_radix(digits, radix).ok().filter(|v| *v <= u32::MAX as u64)
}

/// `10.0.0.1.nip.io`, `10-0-0-1.sslip.io` and friends resolve to the
/// embedded address.
fn wildcard_dns_ip(h: &str) -> Option<Ipv4Addr> {
    let base = ["nip.io", "sslip.io", "xip.io", "traefik.me", "localtest.me"]
        .iter()
        .find_map(|d| h.strip_suffix(d).and_then(|r| r.strip_suffix('.')))?;
    // Take the trailing IP-looking part of the prefix.
    let dotted: Vec<&str> = base.split('.').collect();
    if dotted.len() >= 4 {
        let tail = dotted[dotted.len() - 4..].join(".");
        if let Ok(ip) = tail.parse() {
            return Some(ip);
        }
    }
    let last = dotted.last()?;
    let dashed: Vec<&str> = last.split('-').collect();
    if dashed.len() >= 4 {
        let tail = dashed[dashed.len() - 4..].join(".");
        return tail.parse().ok();
    }
    None
}

/// Classify an address. `None` for public addresses.
pub(crate) fn classify_ip(ip: IpAddr) -> Option<(&'static str, &'static str)> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => {
            if v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254) {
                return Some((RULE_METADATA, "cloud metadata endpoint"));
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_v4(v4);
            }
            let seg = v6.segments();
            // NAT64 64:ff9b::/96 embeds an IPv4 address.
            if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6].iter().all(|s| *s == 0) {
                return classify_v4(Ipv4Addr::from(u128::from(v6) as u32));
            }
            if v6.is_loopback() {
                return Some((RULE_PRIVATE_IP, "loopback"));
            }
            if v6.is_unspecified() {
                return Some((RULE_PRIVATE_IP, "unspecified address"));
            }
            // Deprecated IPv4-compatible ::a.b.c.d.
            if seg[..6].iter().all(|s| *s == 0) {
                return classify_v4(Ipv4Addr::from(u128::from(v6) as u32));
            }
            if seg[0] & 0xfe00 == 0xfc00 {
                return Some((RULE_PRIVATE_IP, "unique local address"));
            }
            if seg[0] & 0xffc0 == 0xfe80 || seg[0] & 0xffc0 == 0xfec0 {
                return Some((RULE_PRIVATE_IP, "link-local address"));
            }
            None
        }
    }
}

fn classify_v4(ip: Ipv4Addr) -> Option<(&'static str, &'static str)> {
    if METADATA_V4.contains(&ip) {
        return Some((RULE_METADATA, "cloud metadata endpoint"));
    }
    let o = ip.octets();
    if ip.is_loopback() {
        Some((RULE_PRIVATE_IP, "loopback"))
    } else if o[0] == 0 {
        Some((RULE_PRIVATE_IP, "unspecified address"))
    } else if ip.is_private() {
        Some((RULE_PRIVATE_IP, "private network"))
    } else if ip.is_link_local() {
        Some((RULE_PRIVATE_IP, "link-local address"))
    } else if o[0] == 100 && (64..128).contains(&o[1]) {
        Some((RULE_PRIVATE_IP, "shared address space"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<&'static str> {
        let mut out = Vec::new();
        SsrfChecker::new(&[], &[]).scan(text, &mut out);
        out.iter().map(|h| h.rule).collect()
    }

    #[test]
    fn loose_ipv4() {
        let l = |s| parse_ipv4_loose(s).map(|ip| ip.to_string());
        assert_eq!(l("2130706433").as_deref(), Some("127.0.0.1"));
        assert_eq!(l("0x7f000001").as_deref(), Some("127.0.0.1"));
        assert_eq!(l("0177.0.0.1").as_deref(), Some("127.0.0.1"));
        assert_eq!(l("127.1").as_deref(), Some("127.0.0.1"));
        assert_eq!(l("0xA9.0xFE.0xA9.0xFE").as_deref(), Some("169.254.169.254"));
        assert_eq!(l("256.1.1.1"), None);
        assert_eq!(l("example"), None);
    }

    #[test]
    fn metadata_forms() {
        for t in [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "curl http://metadata.google.internal/computeMetadata/v1/",
            "http://[fd00:ec2::254]/latest/meta-data",
            "http://100.100.100.200/latest/meta-data",
            "http://2852039166/latest",
            "http://0xa9fea9fe/",
            "http://[::ffff:169.254.169.254]/",
            "http://user:pw@169.254.169.254:80/",
            "169.254.169.254",
            "fetch 169.254.169.254/latest/meta-data now",
            "http://%31%36%39.254.169.254/",
        ] {
            assert_eq!(hits(t), [RULE_METADATA], "{t}");
        }
    }

    #[test]
    fn private_forms() {
        for t in [
            "http://127.0.0.1:8080/admin",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://[::1]:3000/",
            "http://[::ffff:10.0.0.1]/",
            "https://10.1.2.3/x",
            "http://192.168.0.1",
            "http://0.0.0.0:8000",
            "http://[fc00::1]/",
            "http://[fe80::1%25eth0]/",
            "connect to 10.0.0.5:5432 please",
            "http://127.0.0.1.nip.io/",
            "http://10-0-0-1.sslip.io/",
        ] {
            assert_eq!(hits(t), [RULE_PRIVATE_IP], "{t}");
        }
    }

    #[test]
    fn internal_names() {
        for t in [
            "http://localhost:3000",
            "http://api.localhost/",
            "db.internal:5432",
            "http://printer.local/",
            "localhost:8080",
        ] {
            assert_eq!(hits(t), [RULE_INTERNAL_HOST], "{t}");
        }
        assert_eq!(hits("gopher://evil.com:70/_x"), [RULE_SCHEME]);
    }

    #[test]
    fn public_and_prose_are_clean() {
        for t in [
            "https://example.com/path?x=1",
            "http://8.8.8.8/",
            "allow 10.0.0.0/8 in the firewall",
            "the build took 2130706433 ms",
            "version 1.2.3.4 released",
            "see config.local for details",
            "use a .env.local file",
            "time 10:30 and ratio 3:4",
        ] {
            assert!(hits(t).is_empty(), "{t}: {:?}", hits(t));
        }
    }

    #[test]
    fn config_lists() {
        let c = SsrfChecker::new(
            &["corp.example".to_string(), "203.0.113.0/24".to_string()],
            &["localhost".to_string(), "10.9.0.0/16".to_string()],
        );
        let rules = |t: &str| {
            let mut out = Vec::new();
            c.scan(t, &mut out);
            out.iter().map(|h| h.rule).collect::<Vec<_>>()
        };
        assert_eq!(rules("https://wiki.corp.example/x"), [RULE_INTERNAL_HOST]);
        assert_eq!(rules("https://203.0.113.9/x"), [RULE_PRIVATE_IP]);
        assert!(rules("http://localhost:8080/mcp").is_empty());
        assert!(rules("http://10.9.1.1/").is_empty());
        assert_eq!(rules("http://10.8.1.1/"), [RULE_PRIVATE_IP]);
    }

    #[test]
    fn cidr() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.200.1.1".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        assert!(Cidr::parse("fd00::/8").unwrap().contains("fd12::1".parse().unwrap()));
        assert!(Cidr::parse("10.0.0.0/40").is_none());
    }
}
