use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use hkdf::Hkdf;
use rustls::sign::SigningKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use sha2::Sha256;
use x509_parser::prelude::*;

const HKDF_INFO: &[u8] = b"rw-v1";
const TLDS: [&str; 6] = ["com", "net", "org", "io", "dev", "app"];

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodePayload {
    pub ca_cert_pem: String,
    pub jwt_public_key: String,
    pub node_cert_pem: String,
    pub node_key_pem: String,
}

pub(crate) fn normalize_pem(pem: &str) -> String {
    let mut s = pem.replace("\\n", "\n").replace("\r\n", "\n");
    // Make sure the BEGIN/END markers sit on their own lines.
    let mut out = String::with_capacity(s.len() + 8);
    let mut rest = s.as_str();
    while let Some(pos) = rest.find("-----") {
        out.push_str(&rest[..pos]);
        let marker_start = &rest[pos..];
        // marker is "-----BEGIN X-----" or "-----END X-----"
        if let Some(end) = marker_start[5..].find("-----") {
            let marker = &marker_start[..5 + end + 5];
            if marker.starts_with("-----BEGIN ") {
                out.push_str(marker);
                out.push('\n');
            } else if marker.starts_with("-----END ") {
                out.push('\n');
                out.push_str(marker);
            } else {
                out.push_str(marker);
            }
            rest = &marker_start[marker.len()..];
        } else {
            out.push_str(marker_start);
            rest = "";
        }
    }
    out.push_str(rest);
    s = out;
    // collapse repeated newlines and trim
    let mut collapsed = String::with_capacity(s.len());
    let mut prev_nl = false;
    for ch in s.chars() {
        if ch == '\n' {
            if !prev_nl {
                collapsed.push('\n');
            }
            prev_nl = true;
        } else {
            collapsed.push(ch);
            prev_nl = false;
        }
    }
    collapsed.trim().to_string()
}

pub fn parse_node_payload(secret_key: &str) -> Result<NodePayload> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(secret_key.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(secret_key.trim()))
        .context("SECRET_KEY is not valid base64")?;
    let parsed: NodePayload = serde_json::from_slice(&raw).map_err(|e| {
        anyhow!("SECRET_KEY contains invalid JSON or has an invalid structure: {e}")
    })?;
    Ok(NodePayload {
        ca_cert_pem: normalize_pem(&parsed.ca_cert_pem),
        jwt_public_key: normalize_pem(&parsed.jwt_public_key),
        node_cert_pem: normalize_pem(&parsed.node_cert_pem),
        node_key_pem: normalize_pem(&parsed.node_key_pem),
    })
}

/// Drops `-----BEGIN ...-----` style markers and everything that is not base64.
pub(crate) fn canon(pem: &str) -> String {
    let mut out = String::new();
    for line in pem.lines() {
        if line.trim_start().starts_with("-----") {
            continue;
        }
        out.extend(
            line.chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')),
        );
    }
    out
}

/// SNI the panel is expected to use: HKDF-SHA256 over (jwt key || CA), info `rw-v1`.
pub fn derive_sni(ca_cert_pem: &str, jwt_public_key: &str) -> String {
    let mut ikm = canon(jwt_public_key).into_bytes();
    ikm.extend_from_slice(canon(ca_cert_pem).as_bytes());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 22];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("22 bytes is a valid HKDF length");

    format!(
        "{}.{}.{}",
        hex::encode(&okm[..16]),
        hex::encode(&okm[16..21]),
        TLDS[okm[21] as usize % TLDS.len()]
    )
}

pub struct CheckResult {
    pub name: &'static str,
    pub result: Result<String, String>,
}

fn cert_der(pem: &str) -> Result<CertificateDer<'static>> {
    CertificateDer::from_pem_slice(pem.as_bytes()).map_err(|e| anyhow!("{e}"))
}

pub fn run_checks(p: &NodePayload) -> Vec<CheckResult> {
    let mut out = Vec::new();
    let mut push = |name: &'static str, r: Result<String>| {
        out.push(CheckResult {
            name,
            result: r.map_err(|e| e.to_string().lines().next().unwrap_or("").to_string()),
        });
    };

    let ca_der = cert_der(&p.ca_cert_pem);
    let node_der = cert_der(&p.node_cert_pem);

    let ca = ca_der.as_ref().map_err(|e| anyhow!("{e}")).and_then(|d| {
        X509Certificate::from_der(d.as_ref())
            .map(|(_, c)| c)
            .map_err(|e| anyhow!("{e}"))
    });
    let node = node_der.as_ref().map_err(|e| anyhow!("{e}")).and_then(|d| {
        X509Certificate::from_der(d.as_ref())
            .map(|(_, c)| c)
            .map_err(|e| anyhow!("{e}"))
    });

    push(
        "CA parses",
        match &ca {
            Ok(c) => Ok(c.subject().to_string()),
            Err(e) => Err(anyhow!("{e}")),
        },
    );
    push(
        "CA not expired",
        match &ca {
            Ok(c) => {
                let v = c.validity();
                if !v.is_valid() {
                    if v.time_to_expiration().is_none() {
                        Err(anyhow!("expired"))
                    } else {
                        Err(anyhow!("not yet valid"))
                    }
                } else {
                    Ok(format!("until {}", v.not_after))
                }
            }
            Err(_) => Err(anyhow!("CA unavailable")),
        },
    );
    push(
        "CA self-signature",
        match &ca {
            Ok(c) => c
                .verify_signature(None)
                .map(|_| "valid".to_string())
                .map_err(|_| anyhow!("mismatch - corrupted")),
            Err(_) => Err(anyhow!("CA unavailable")),
        },
    );
    push(
        "node cert parses",
        match &node {
            Ok(c) => Ok(c.subject().to_string()),
            Err(e) => Err(anyhow!("{e}")),
        },
    );
    push(
        "node signed by CA",
        match (&ca, &node) {
            (Ok(ca), Ok(n)) => n
                .verify_signature(Some(ca.public_key()))
                .map(|_| "valid".to_string())
                .map_err(|_| anyhow!("not signed by this CA")),
            _ => Err(anyhow!("cert unavailable")),
        },
    );
    push(
        "node key matches cert",
        match &node {
            Ok(n) => load_signing_key(&p.node_key_pem).and_then(|k| {
                let spki = k
                    .public_key()
                    .ok_or_else(|| anyhow!("cannot derive public key"))?;
                if spki.as_ref() == n.public_key().raw {
                    Ok("valid".to_string())
                } else {
                    Err(anyhow!("key does not match cert"))
                }
            }),
            Err(_) => Err(anyhow!("cert unavailable")),
        },
    );
    push(
        "jwt public key",
        jwt_decoding_key(&p.jwt_public_key).map(|_| "ok".to_string()),
    );
    out
}

pub fn assert_payload_integrity(p: &NodePayload) -> Result<()> {
    let checks = run_checks(p);
    let all_ok = checks.iter().all(|c| c.result.is_ok());
    let mut report = String::from(if all_ok {
        "SECRET_KEY OK"
    } else {
        "SECRET_KEY INVALID"
    });
    for c in &checks {
        match &c.result {
            Ok(d) => report.push_str(&format!("\n  ✓ {:<22} {}", c.name, d)),
            Err(d) => report.push_str(&format!("\n  ✗ {:<22} {}", c.name, d)),
        }
    }
    if all_ok {
        report.push_str(&format!(
            "\n  SNI: {}",
            derive_sni(&p.ca_cert_pem, &p.jwt_public_key)
        ));
        tracing::info!("\n{report}");
        Ok(())
    } else {
        tracing::error!("\n{report}");
        bail!("SECRET_KEY payload validation failed. Double check your SECRET_KEY.")
    }
}

pub fn load_signing_key(pem: &str) -> Result<std::sync::Arc<dyn SigningKey>> {
    let key = PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| anyhow!("invalid node key: {e}"))?;
    rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow!("unsupported node key: {e}"))
}

pub fn jwt_decoding_key(pem: &str) -> Result<jsonwebtoken::DecodingKey> {
    jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes())
        .map_err(|e| anyhow!("invalid JWT public key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_escaped_and_glued_pem() {
        let glued = "-----BEGIN CERTIFICATE-----MIIB\\nabcd-----END CERTIFICATE-----";
        assert_eq!(
            normalize_pem(glued),
            "-----BEGIN CERTIFICATE-----\nMIIB\nabcd\n-----END CERTIFICATE-----"
        );
    }

    #[test]
    fn canon_strips_markers() {
        let pem = "-----BEGIN PUBLIC KEY-----\nAB+/=\ncd\n-----END PUBLIC KEY-----";
        assert_eq!(canon(pem), "AB+/=cd");
    }

    #[test]
    fn sni_shape() {
        let sni = derive_sni(
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
            "BBBB",
        );
        let parts: Vec<_> = sni.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 32);
        assert_eq!(parts[1].len(), 10);
        assert!(TLDS.contains(&parts[2]));
    }
}
