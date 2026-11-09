//! Personal data detection. Every pattern is backed by a validator
//! (checksums, number ranges, country lengths) to keep false positives low.

use nandi_core::Severity;
use regex::Regex;

/// A piece of personal data found in a text.
#[derive(Debug, Clone)]
pub(crate) struct PiiHit {
    pub start: usize,
    pub end: usize,
    pub rule: &'static str,
    pub desc: &'static str,
    pub severity: Severity,
}

/// Number of PII rules.
pub(crate) const RULE_COUNT: usize = 7;

/// Compiled PII patterns.
pub(crate) struct PiiScanner {
    email: Regex,
    phone: Regex,
    card: Regex,
    ssn: Regex,
    iban: Regex,
    aadhaar: Regex,
    pan: Regex,
}

impl PiiScanner {
    pub fn new() -> Self {
        let re = crate::compile;
        Self {
            email: re(concat!(
                r"\b[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@",
                r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}[A-Za-z0-9])?)*",
                r"\.[A-Za-z]{2,24}\b"
            )),
            phone: re(r"\+[1-9][0-9 ().\-]{7,22}[0-9]"),
            card: re(r"\b(?:[0-9][ \-]?){12,18}[0-9]\b"),
            ssn: re(r"\b([0-9]{3})-([0-9]{2})-([0-9]{4})\b"),
            iban: re(r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"),
            aadhaar: re(r"\b[2-9][0-9]{3}([ \-]?)[0-9]{4}([ \-]?)[0-9]{4}\b"),
            pan: re(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]\b"),
        }
    }

    /// Append PII found in `text` to `out`, skipping spans that overlap an
    /// earlier PII hit.
    pub fn scan(&self, text: &str, out: &mut Vec<PiiHit>) {
        let bytes = text.as_bytes();
        let shape = Shape::of(bytes);
        let push = |out: &mut Vec<PiiHit>, s: usize, e: usize, rule, desc, severity| {
            if !out.iter().any(|h| h.start < e && s < h.end) {
                out.push(PiiHit { start: s, end: e, rule, desc, severity });
            }
        };
        if bytes.contains(&b'@') {
            for m in self.email.find_iter(text) {
                // `user:pass@host` inside a URL is credentials, not an address.
                let in_url = m.start() > 0 && matches!(bytes[m.start() - 1], b':' | b'/');
                if !in_url && valid_email(m.as_str()) {
                    push(out, m.start(), m.end(), "pii.email", "Email address", Severity::Low);
                }
            }
        }
        if shape.number_run < 9 && !shape.iban && !shape.pan && !bytes.contains(&b'+') {
            return;
        }
        for m in self.iban.find_iter(text).take_while(|_| shape.iban) {
            if valid_iban(m.as_str()) {
                push(out, m.start(), m.end(), "pii.iban", "International bank account number", Severity::High);
            }
        }
        for m in self.card.find_iter(text).take_while(|_| shape.number_run >= 13) {
            if standalone_number(bytes, m.start(), m.end()) && valid_card(m.as_str()) {
                push(out, m.start(), m.end(), "pii.credit-card", "Payment card number", Severity::High);
            }
        }
        for c in self.ssn.captures_iter(text).take_while(|_| shape.number_run >= 9 && bytes.contains(&b'-')) {
            let m = c.get(0).expect("group 0");
            if standalone_number(bytes, m.start(), m.end()) && valid_ssn(&c[1], &c[2], &c[3]) {
                push(out, m.start(), m.end(), "pii.us-ssn", "US social security number", Severity::High);
            }
        }
        for c in self.aadhaar.captures_iter(text).take_while(|_| shape.number_run >= 12) {
            let m = c.get(0).expect("group 0");
            // Separators, if any, must be consistent ("1234 5678 9012").
            if c[1] != c[2] || !standalone_number(bytes, m.start(), m.end()) {
                continue;
            }
            if verhoeff_valid(m.as_str()) {
                push(out, m.start(), m.end(), "pii.aadhaar", "India Aadhaar number", Severity::High);
            }
        }
        for m in self.pan.find_iter(text).take_while(|_| shape.pan) {
            push(out, m.start(), m.end(), "pii.india-pan", "India PAN", Severity::Medium);
        }
        if bytes.contains(&b'+') {
            for m in self.phone.find_iter(text) {
                let before = text[..m.start()].chars().next_back();
                if before.is_some_and(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=') {
                    continue;
                }
                if valid_phone(m.as_str()) {
                    push(out, m.start(), m.end(), "pii.phone", "Phone number", Severity::Medium);
                }
            }
        }
    }
}

/// Cheap one-pass facts about a text that gate the PII regexes.
#[derive(Debug, Default)]
struct Shape {
    /// Most digits in a run where digits may be separated by single spaces
    /// or dashes.
    number_run: usize,
    /// Two capitals followed by two digits (IBAN prefix) occurs.
    iban: bool,
    /// Five capitals followed by a digit (PAN shape) occurs.
    pan: bool,
}

impl Shape {
    fn of(b: &[u8]) -> Self {
        let mut s = Shape::default();
        let (mut run, mut upper) = (0usize, 0usize);
        for i in 0..b.len() {
            let c = b[i];
            if c.is_ascii_digit() {
                if upper >= 2 && b.get(i + 1).is_some_and(u8::is_ascii_digit) {
                    s.iban = true;
                }
                if upper >= 5 {
                    s.pan = true;
                }
                run += 1;
                s.number_run = s.number_run.max(run);
                upper = 0;
            } else if c.is_ascii_uppercase() {
                upper += 1;
                run = 0;
            } else {
                upper = 0;
                let continues = matches!(c, b' ' | b'-') && i > 0 && b[i - 1].is_ascii_digit();
                if !continues {
                    run = 0;
                }
            }
        }
        s
    }
}

/// The number is not part of a longer digit group (e.g. the first 12
/// digits of a 16-digit number, or a fragment of `1234-5678-...`).
fn standalone_number(b: &[u8], start: usize, end: usize) -> bool {
    let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    let sep = |i: usize| b.get(i).is_some_and(|c| matches!(c, b' ' | b'-' | b'.'));
    let left_ok = start == 0 || !(digit(start - 1) || (start >= 2 && sep(start - 1) && digit(start - 2)));
    let right_ok = !(digit(end) || (sep(end) && digit(end + 1)));
    left_ok && right_ok
}

fn valid_email(s: &str) -> bool {
    let Some((local, domain)) = s.rsplit_once('@') else { return false };
    let domain = domain.to_ascii_lowercase();
    let tld = domain.rsplit('.').next().unwrap_or("");
    const FILE_EXT: &[&str] =
        &["png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "js", "ts", "css", "json", "map", "py", "rs", "md", "txt"];
    const RESERVED: &[&str] = &["example.com", "example.org", "example.net"];
    if FILE_EXT.contains(&tld) || RESERVED.contains(&domain.as_str()) {
        return false;
    }
    for suffix in [".example", ".test", ".invalid", ".localhost", ".local"] {
        if domain.ends_with(suffix) {
            return false;
        }
    }
    let local = local.to_ascii_lowercase();
    !matches!(local.as_str(), "git" | "noreply" | "no-reply")
}

fn valid_phone(s: &str) -> bool {
    let digits = s.bytes().filter(u8::is_ascii_digit).count();
    if !(10..=15).contains(&digits) {
        return false;
    }
    // No runs of separators like "1--2" or "1  2".
    let b = s.as_bytes();
    !b.windows(2).any(|w| matches!(w[0], b' ' | b'.' | b'-') && matches!(w[1], b' ' | b'.' | b'-'))
}

fn valid_card(s: &str) -> bool {
    let digits: Vec<u8> = s.bytes().filter(u8::is_ascii_digit).map(|b| b - b'0').collect();
    if !(13..=19).contains(&digits.len()) || digits.iter().all(|d| *d == digits[0]) {
        return false;
    }
    known_card_brand(&digits) && luhn_valid(&digits)
}

/// Issuer prefix and length check for the major card networks.
fn known_card_brand(d: &[u8]) -> bool {
    let n = d.len();
    let prefix = |k: usize| d[..k].iter().fold(0u32, |acc, x| acc * 10 + *x as u32);
    match d[0] {
        4 => matches!(n, 13 | 16 | 19),
        5 => (51..=55).contains(&prefix(2)) && n == 16,
        2 => (2221..=2720).contains(&prefix(4)) && n == 16,
        3 => {
            let p2 = prefix(2);
            ((p2 == 34 || p2 == 37) && n == 15)
                || ((p2 == 36 || p2 == 38 || (300..=305).contains(&prefix(3))) && (14..=19).contains(&n))
                || ((3528..=3589).contains(&prefix(4)) && (16..=19).contains(&n))
        }
        6 => {
            let ok_prefix = prefix(4) == 6011
                || prefix(2) == 65
                || (644..=649).contains(&prefix(3))
                || prefix(2) == 62
                || prefix(2) == 60;
            ok_prefix && (16..=19).contains(&n)
        }
        _ => false,
    }
}

/// Luhn mod-10 checksum over decimal digits.
pub(crate) fn luhn_valid(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = *d as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

fn valid_ssn(area: &str, group: &str, serial: &str) -> bool {
    let area_n: u32 = area.parse().unwrap_or(0);
    area_n != 0 && area_n != 666 && area_n < 900 && group != "00" && serial != "0000"
}

const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Verhoeff checksum over the decimal digits of `s` (other chars ignored).
pub(crate) fn verhoeff_valid(s: &str) -> bool {
    let mut c = 0u8;
    let mut n = 0;
    for (i, b) in s.bytes().filter(u8::is_ascii_digit).rev().enumerate() {
        c = VERHOEFF_D[c as usize][VERHOEFF_P[i % 8][(b - b'0') as usize] as usize];
        n += 1;
    }
    n > 0 && c == 0
}

/// IBAN lengths per country (ISO 13616 registry, common subset).
const IBAN_LENGTHS: &[(&str, usize)] = &[
    ("AD", 24),
    ("AE", 23),
    ("AT", 20),
    ("AZ", 28),
    ("BA", 20),
    ("BE", 16),
    ("BG", 22),
    ("BH", 22),
    ("BR", 29),
    ("CH", 21),
    ("CR", 22),
    ("CY", 28),
    ("CZ", 24),
    ("DE", 22),
    ("DK", 18),
    ("DO", 28),
    ("EE", 20),
    ("EG", 29),
    ("ES", 24),
    ("FI", 18),
    ("FO", 18),
    ("FR", 27),
    ("GB", 22),
    ("GE", 22),
    ("GI", 23),
    ("GL", 18),
    ("GR", 27),
    ("GT", 28),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IL", 23),
    ("IS", 26),
    ("IT", 27),
    ("JO", 30),
    ("KW", 30),
    ("KZ", 20),
    ("LB", 28),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("LV", 21),
    ("MC", 27),
    ("MD", 24),
    ("ME", 22),
    ("MK", 19),
    ("MR", 27),
    ("MT", 31),
    ("MU", 30),
    ("NL", 18),
    ("NO", 15),
    ("PK", 24),
    ("PL", 28),
    ("PS", 29),
    ("PT", 25),
    ("QA", 29),
    ("RO", 24),
    ("RS", 22),
    ("SA", 24),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
    ("SM", 27),
    ("TN", 24),
    ("TR", 26),
    ("UA", 29),
    ("VG", 24),
    ("XK", 20),
];

/// Country length check plus ISO 7064 mod-97.
pub(crate) fn valid_iban(s: &str) -> bool {
    let compact: Vec<u8> = s.bytes().filter(|b| *b != b' ').collect();
    let Some(country) = std::str::from_utf8(compact.get(..2).unwrap_or_default()).ok() else { return false };
    match IBAN_LENGTHS.iter().find(|(c, _)| *c == country) {
        Some((_, len)) if *len == compact.len() => {}
        _ => return false,
    }
    let rearranged = compact[4..].iter().chain(&compact[..4]);
    let mut rem: u32 = 0;
    for b in rearranged {
        match b {
            b'0'..=b'9' => rem = (rem * 10 + (b - b'0') as u32) % 97,
            b'A'..=b'Z' => rem = (rem * 100 + (b - b'A' + 10) as u32) % 97,
            _ => return false,
        }
    }
    rem == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    static SCANNER: LazyLock<PiiScanner> = LazyLock::new(PiiScanner::new);

    fn rules(text: &str) -> Vec<&'static str> {
        let mut out = Vec::new();
        SCANNER.scan(text, &mut out);
        out.iter().map(|h| h.rule).collect()
    }

    #[test]
    fn luhn() {
        let d = |s: &str| s.bytes().map(|b| b - b'0').collect::<Vec<_>>();
        assert!(luhn_valid(&d("4111111111111111")));
        assert!(luhn_valid(&d("79927398713")));
        assert!(!luhn_valid(&d("4111111111111112")));
    }

    #[test]
    fn iban() {
        assert!(valid_iban("GB82WEST12345698765432"));
        assert!(valid_iban("DE89 3704 0044 0532 0130 00"));
        assert!(!valid_iban("GB82WEST12345698765431"));
        assert!(!valid_iban("GB82WEST1234569876543"));
        assert!(!valid_iban("ZZ82WEST12345698765432"));
    }

    #[test]
    fn verhoeff() {
        assert!(verhoeff_valid("2363"));
        assert!(!verhoeff_valid("2364"));
        assert!(verhoeff_valid("234123412346"));
        assert!(!verhoeff_valid("234123412347"));
    }

    #[test]
    fn positives() {
        assert_eq!(rules("mail jane.doe@acme-corp.io now"), ["pii.email"]);
        assert_eq!(rules("card 4111 1111 1111 1111 exp"), ["pii.credit-card"]);
        assert_eq!(rules("card 5500-0000-0000-0004"), ["pii.credit-card"]);
        assert_eq!(rules("amex 378282246310005"), ["pii.credit-card"]);
        assert_eq!(rules("ssn 123-45-6789"), ["pii.us-ssn"]);
        assert_eq!(rules("iban GB82 WEST 1234 5698 7654 32"), ["pii.iban"]);
        assert_eq!(rules("aadhaar 2341 2341 2346"), ["pii.aadhaar"]);
        assert_eq!(rules("pan ABCPE1234F"), ["pii.india-pan"]);
        assert_eq!(rules("call +1 (415) 555-0132 today"), ["pii.phone"]);
        assert_eq!(rules("call +44 20 7946 0958"), ["pii.phone"]);
    }

    #[test]
    fn negatives() {
        for text in [
            "user@example.com and icon@2x.png and git@github.com",
            "postgres://admin:s3cr3tP4ss@db.prod.corp:5432/app",
            "4111 1111 1111 1112",
            "timestamp 1700000000000 and 1700000000123",
            "ssn 000-12-3456 or 666-12-3456 or 912-12-3456",
            "ip 192.168.1.1 and version 1.2.3",
            "date 2024-01-15 and 2024-01-2025",
            "aadhaar 2341 2341 2347",
            "aadhaar 1341 2341 2346",
            "id 234123412346 7",
            "math 1+2345678901",
            "uuid 550e8400-e29b-41d4-a716-446655440000",
            "GB82WEST12345698765431",
            "ABCDE1234F",
        ] {
            assert!(rules(text).is_empty(), "false positive in {text:?}: {:?}", rules(text));
        }
    }
}
