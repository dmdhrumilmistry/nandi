//! TLS for the proxy listener, optionally with client certificates (mTLS).
//!
//! When `listen.tls.client_ca` is set, every client must present a
//! certificate chaining to that CA. The agent identity is taken from the
//! leaf: the first `spiffe://` URI SAN, else the subject common name.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use nandi_core::config::TlsConfig;

use crate::app::resolve;

/// Build the acceptor from PEM files (paths relative to `base_dir`).
pub(super) fn acceptor(cfg: &TlsConfig, base_dir: &Path) -> anyhow::Result<TlsAcceptor> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certs = read_certs(&resolve(base_dir, &cfg.cert))?;
    let key_path = resolve(base_dir, &cfg.key);
    let key_pem = std::fs::read(&key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| anyhow::anyhow!("no private key in {}: {e}", key_path.display()))?;
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("configuring TLS versions")?;
    let builder = match &cfg.client_ca {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for cert in read_certs(&resolve(base_dir, ca))? {
                roots.add(cert).context("adding client CA certificate")?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .context("building client certificate verifier")?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_single_cert(certs, key).context("loading TLS certificate and key")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn read_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates in {}", path.display());
    }
    Ok(certs)
}

/// Agent identity of a DER client certificate: the first `spiffe://` URI
/// subject alternative name, else the subject common name.
pub fn peer_identity(cert_der: &[u8]) -> Option<String> {
    let (tag, cert, _) = tlv(cert_der)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, tbs, _) = tlv(cert)?;
    if tag != SEQUENCE {
        return None;
    }
    let mut fields = Vec::with_capacity(10);
    let mut rest = tbs;
    while !rest.is_empty() {
        let (tag, content, next) = tlv(rest)?;
        fields.push((tag, content));
        rest = next;
    }
    // Skip the optional explicit version: serial, signature, issuer,
    // validity, subject, subjectPublicKeyInfo, then optional fields.
    let start = usize::from(fields.first()?.0 == 0xa0);
    let subject = fields.get(start + 4).filter(|(t, _)| *t == SEQUENCE)?.1;
    let spiffe = fields.iter().skip(start + 6).find(|(t, _)| *t == 0xa3).and_then(|(_, ext)| spiffe_san(ext));
    spiffe.or_else(|| common_name(subject))
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const OCTET_STRING: u8 = 0x04;
const BOOLEAN: u8 = 0x01;
/// `[6] IMPLICIT IA5String` uniformResourceIdentifier in GeneralName.
const SAN_URI: u8 = 0x86;
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

/// One DER TLV: `(tag, content, rest)`. Only single-byte tags are needed.
fn tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, buf) = buf.split_first()?;
    let (&first, buf) = buf.split_first()?;
    let (len, buf) = if first < 0x80 {
        (first as usize, buf)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || buf.len() < n {
            return None;
        }
        let len = buf[..n].iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (len, &buf[n..])
    };
    if buf.len() < len {
        return None;
    }
    Some((tag, &buf[..len], &buf[len..]))
}

fn spiffe_san(explicit: &[u8]) -> Option<String> {
    let (tag, mut exts, _) = tlv(explicit)?;
    if tag != SEQUENCE {
        return None;
    }
    while !exts.is_empty() {
        let (_, ext, next) = tlv(exts)?;
        exts = next;
        let (tag, oid, mut rest) = tlv(ext)?;
        if tag != OID || oid != OID_SAN {
            continue;
        }
        let (mut tag, mut value, after) = tlv(rest)?;
        if tag == BOOLEAN {
            rest = after;
            (tag, value, _) = tlv(rest)?;
        }
        if tag != OCTET_STRING {
            return None;
        }
        let (tag, mut names, _) = tlv(value)?;
        if tag != SEQUENCE {
            return None;
        }
        while !names.is_empty() {
            let (tag, name, next) = tlv(names)?;
            names = next;
            if tag == SAN_URI
                && let Ok(uri) = std::str::from_utf8(name)
                && uri.starts_with("spiffe://")
            {
                return Some(uri.to_string());
            }
        }
    }
    None
}

fn common_name(mut rdns: &[u8]) -> Option<String> {
    while !rdns.is_empty() {
        let (tag, set, next) = tlv(rdns)?;
        rdns = next;
        if tag != SET {
            continue;
        }
        let mut attrs = set;
        while !attrs.is_empty() {
            let (_, attr, next) = tlv(attrs)?;
            attrs = next;
            let (tag, oid, rest) = tlv(attr)?;
            if tag != OID || oid != OID_CN {
                continue;
            }
            // UTF8String, PrintableString, IA5String or T61String.
            let (tag, value, _) = tlv(rest)?;
            if matches!(tag, 0x0c | 0x13 | 0x16 | 0x14)
                && let Ok(s) = std::str::from_utf8(value)
            {
                return Some(s.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    // Self-signed P-256 certificates (public parts only).
    const SPIFFE_CERT: &str = "MIIB4jCCAYmgAwIBAgIUJnDVO8JZPJ2IDDqJtEugwOpzaj0wCgYIKoZIzj0EAwIwKDETMBEGA1UECgwKbmFuZGkgdGVzdDERMA8GA1UEAwwIYWdlbnQtY24wHhcNMjYxMTA5MjIzNjE0WhcNMzYxMTA2MjIzNjE0WjAoMRMwEQYDVQQKDApuYW5kaSB0ZXN0MREwDwYDVQQDDAhhZ2VudC1jbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEUVIOuTG38QK+ngS15BFZ7FYqE9EFhQHnkBCt97ckcc00OXW3lNGQEnyxd2teGN5VBbzFMFbNv34qTJvo1Z37mjgZAwgY0wHQYDVR0OBBYEFLb5Q7xRRbIdAgYUdojckKH+5JWiMB8GA1UdIwQYMBaAFLb5Q7xRRbIdAgYUdojckKH+5JWiMA8GA1UdEwEB/wQFMAMBAf8wOgYDVR0RBDMwMYILYWdlbnQubG9jYWyGInNwaWZmZTovL2V4YW1wbGUub3JnL2FnZW50L2JpbGxpbmcwCgYIKoZIzj0EAwIDRwAwRAIgGCBjuVKPqd/Dh3BAtFTZ/IlECe1/k+lA4FdCZAF1WW8CIESXE4Trmh6ybcl64epQRY8ksZG4AYrUcyI55pl5XPym";
    const CN_CERT: &str = "MIIBrDCCAVGgAwIBAgIUNgG25cGy/xiqwDeaNpobNJCQ3IEwCgYIKoZIzj0EAwIwKzETMBEGA1UECgwKbmFuZGkgdGVzdDEUMBIGA1UEAwwLcGxhaW4tYWdlbnQwHhcNMjYxMTA5MjIzNjE0WhcNMzYxMTA2MjIzNjE0WjArMRMwEQYDVQQKDApuYW5kaSB0ZXN0MRQwEgYDVQQDDAtwbGFpbi1hZ2VudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABORSMWxAR2JeriLJ2h7vXtkxzDOsXWOa7b05kf23phvb5At/HmwgV/rdj/eD+bEhCtG3M7InzryXE980U38X8eWjUzBRMB0GA1UdDgQWBBRFKpD1FwSQ2gV5NSB56JtVk21kLTAfBgNVHSMEGDAWgBRFKpD1FwSQ2gV5NSB56JtVk21kLTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCnz8lufq1CLff5t0gy8DphYoXd60zWGMMgO40DgjwK1wIhAMTZtiLeyTaKjvV5MXyDEOMyYacGAc9gX98nXKjihIAF";

    fn der(b64: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(b64).unwrap()
    }

    #[test]
    fn spiffe_uri_san_wins_over_cn() {
        assert_eq!(peer_identity(&der(SPIFFE_CERT)).as_deref(), Some("spiffe://example.org/agent/billing"));
    }

    #[test]
    fn falls_back_to_subject_cn() {
        assert_eq!(peer_identity(&der(CN_CERT)).as_deref(), Some("plain-agent"));
    }

    #[test]
    fn garbage_yields_none() {
        assert_eq!(peer_identity(b""), None);
        assert_eq!(peer_identity(&[0x30, 0x82, 0xff]), None);
        let mut truncated = der(CN_CERT);
        truncated.truncate(100);
        assert_eq!(peer_identity(&truncated), None);
    }

    #[test]
    fn acceptor_reports_missing_files() {
        let cfg =
            TlsConfig { cert: "/nonexistent/cert.pem".into(), key: "/nonexistent/key.pem".into(), client_ca: None };
        let err = acceptor(&cfg, Path::new(".")).err().unwrap();
        assert!(err.to_string().contains("/nonexistent/cert.pem"));
    }
}
