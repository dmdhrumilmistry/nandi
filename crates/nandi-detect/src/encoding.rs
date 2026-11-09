//! Finding and decoding encoded substrings (base64, hex, percent-encoding)
//! so that secrets and honeytokens cannot be smuggled out by wrapping them.
//!
//! Only decodings that produce readable UTF-8 text are kept. Work is capped
//! by a per-scan [`Budget`].

use base64::Engine;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use regex::Regex;

/// Maximum candidate length examined; longer runs are decoded up to this.
const MAX_CANDIDATE: usize = 16 * 1024;
/// Candidates examined per string.
const MAX_PER_STRING: usize = 32;

/// Per-scan limits on decoding work.
#[derive(Debug, Clone)]
pub(crate) struct Budget {
    pub candidates: usize,
    pub bytes: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self { candidates: 256, bytes: 128 * 1024 }
    }
}

/// A decoded substring.
#[derive(Debug, Clone)]
pub(crate) struct Decoded {
    pub start: usize,
    pub end: usize,
    pub encoding: &'static str,
    pub text: String,
}

const CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_padding_mode(DecodePaddingMode::Indifferent)
    .with_decode_allow_trailing_bits(true);
const B64_STD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, CONFIG);
const B64_URL: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, CONFIG);

/// Locates encoded runs in text.
pub(crate) struct Decoder {
    b64: Regex,
    pct: Regex,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            b64: Regex::new(r"[A-Za-z0-9+/_\-]{16,}={0,2}").expect("base64 regex"),
            pct: Regex::new(r#"[^\s"'<>`%]*(?:%[0-9A-Fa-f]{2}[^\s"'<>`%]*)+"#).expect("percent regex"),
        }
    }

    /// Decode encoded runs in `text` into readable strings.
    pub fn decode_all(&self, text: &str, budget: &mut Budget, out: &mut Vec<Decoded>) {
        if text.len() < 16 {
            return;
        }
        let mut taken = 0;
        for m in self.b64.find_iter(text) {
            if taken >= MAX_PER_STRING || budget.candidates == 0 || budget.bytes == 0 {
                break;
            }
            let cand = m.as_str();
            if !worth_trying(cand) {
                continue;
            }
            taken += 1;
            budget.candidates -= 1;
            if let Some((encoding, decoded)) = decode_token(cand, budget) {
                out.push(Decoded { start: m.start(), end: m.end(), encoding, text: decoded });
            }
        }
        if !text.contains('%') {
            return;
        }
        for m in self.pct.find_iter(text) {
            if taken >= MAX_PER_STRING || budget.candidates == 0 || budget.bytes == 0 {
                break;
            }
            taken += 1;
            budget.candidates -= 1;
            let cand = &m.as_str()[..m.len().min(MAX_CANDIDATE)];
            budget.bytes = budget.bytes.saturating_sub(cand.len());
            if let Some(decoded) = percent_decode(cand) {
                out.push(Decoded { start: m.start(), end: m.end(), encoding: "url", text: decoded });
            }
        }
    }
}

fn is_hex_token(s: &str) -> bool {
    s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Cheap rejection of runs that are almost certainly identifiers or words:
/// base64 of real text mixes upper case with lower case or digits.
fn worth_trying(s: &str) -> bool {
    if is_hex_token(s) {
        return true;
    }
    let upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let digit = s.bytes().any(|b| b.is_ascii_digit());
    upper && (lower || digit)
}

fn decode_token(cand: &str, budget: &mut Budget) -> Option<(&'static str, String)> {
    if is_hex_token(cand) {
        let take = cand.len().min(MAX_CANDIDATE) & !1;
        budget.bytes = budget.bytes.saturating_sub(take);
        if let Some(text) = hex_decode(&cand[..take]).and_then(readable) {
            return Some(("hex", text));
        }
    }
    let body = cand.trim_end_matches('=');
    let engine = if body.contains(['-', '_']) {
        if body.contains(['+', '/']) {
            return None;
        }
        &B64_URL
    } else {
        &B64_STD
    };
    // Quick reject on a prefix before decoding a long run.
    if body.len() > 64 {
        let head = engine.decode(&body[..64]).ok()?;
        if !mostly_printable(&head, true) {
            return None;
        }
    }
    let mut take = body.len().min(MAX_CANDIDATE);
    if take % 4 == 1 {
        take -= 1;
    }
    budget.bytes = budget.bytes.saturating_sub(take);
    let bytes = engine.decode(&body[..take]).ok()?;
    readable(bytes).map(|t| ("base64", t))
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let val = |c: u8| (c as char).to_digit(16).map(|v| v as u8);
    let (pairs, _) = b.as_chunks::<2>();
    pairs.iter().map(|p| Some(val(p[0])? << 4 | val(p[1])?)).collect()
}

/// Percent-decode; `None` when nothing changed or the result is not text.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut changed = false;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                changed = true;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    if !changed {
        return None;
    }
    readable(out)
}

/// UTF-8 text made mostly of printable characters.
fn readable(bytes: Vec<u8>) -> Option<String> {
    if bytes.is_empty() || !mostly_printable(&bytes, false) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// At least 90% printable characters. With `prefix` set, a truncated
/// trailing UTF-8 sequence is tolerated.
fn mostly_printable(bytes: &[u8], prefix: bool) -> bool {
    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) if prefix && e.error_len().is_none() => {
            std::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or_default()
        }
        Err(_) => return false,
    };
    let mut total = 0usize;
    let mut bad = 0usize;
    for c in text.chars() {
        total += 1;
        if c.is_control() && !matches!(c, '\n' | '\r' | '\t') || c == char::REPLACEMENT_CHARACTER {
            bad += 1;
        }
    }
    total > 0 && bad * 10 <= total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(text: &str) -> Vec<(String, &'static str)> {
        let mut out = Vec::new();
        Decoder::new().decode_all(text, &mut Budget::default(), &mut out);
        out.into_iter().map(|d| (d.text, d.encoding)).collect()
    }

    #[test]
    fn base64_std_and_url() {
        let enc = B64_STD.encode("the quick brown fox jumps");
        assert_eq!(decode(&format!("x {enc} y")), [("the quick brown fox jumps".to_string(), "base64")]);
        let enc = B64_URL.encode("??>>?? subjects ~~ url safe");
        assert!(enc.contains(['-', '_']));
        assert_eq!(decode(&enc), [("??>>?? subjects ~~ url safe".to_string(), "base64")]);
    }

    #[test]
    fn hex() {
        let enc: String = "canary-token-123".bytes().map(|b| format!("{b:02x}")).collect();
        assert_eq!(decode(&enc), [("canary-token-123".to_string(), "hex")]);
    }

    #[test]
    fn percent() {
        assert_eq!(
            decode(concat!("q=AKIA", "%51YLPMN5HHHFPZAM2%20x")),
            [(concat!("q=AKIA", "QYLPMN5HHHFPZAM2 x").to_string(), "url")]
        );
    }

    #[test]
    fn binary_and_digests_are_skipped() {
        let sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assert!(decode(sha).is_empty());
        let bin: Vec<u8> = (0..300u32).map(|i| (i * 7919 % 251) as u8).collect();
        assert!(decode(&B64_STD.encode(bin)).is_empty());
        assert!(decode("some_long_snake_case_identifier_name").is_empty());
        assert!(decode("550e8400-e29b-41d4-a716-446655440000").is_empty());
    }

    #[test]
    fn budget_is_respected() {
        let enc = B64_STD.encode("hello there general kenobi");
        let text = vec![enc; 100].join(" ");
        let mut out = Vec::new();
        let mut budget = Budget { candidates: 5, bytes: 1 << 20 };
        Decoder::new().decode_all(&text, &mut budget, &mut out);
        assert_eq!(out.len(), 5);
        assert_eq!(budget.candidates, 0);
    }
}
