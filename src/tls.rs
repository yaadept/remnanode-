use std::sync::Arc;

use anyhow::{Result, anyhow};
use rustls::{
    RootCertStore, ServerConfig,
    crypto::ring as ring_provider,
    server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier},
    sign::CertifiedKey,
};
use rustls_pki_types::{CertificateDer, pem::PemObject};

use crate::payload::{NodePayload, derive_sni, load_signing_key};

#[derive(Debug)]
struct SniResolver {
    key: Arc<CertifiedKey>,
    /// When set, only this server name gets the certificate (SNI_VERIFICATION).
    expected: Option<String>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match &self.expected {
            None => Some(self.key.clone()),
            Some(expected) => {
                let got = hello.server_name()?;
                constant_time_eq(got.as_bytes(), expected.as_bytes()).then(|| self.key.clone())
            }
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// TLS 1.3 only, mandatory client certificate signed by the panel CA.
pub fn build_server_config(p: &NodePayload, sni_verification: bool) -> Result<Arc<ServerConfig>> {
    let provider = Arc::new(ring_provider::default_provider());

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(p.ca_cert_pem.as_bytes()) {
        roots.add(cert.map_err(|e| anyhow!("invalid CA certificate: {e}"))?)?;
    }

    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| anyhow!("cannot build client verifier: {e}"))?;

    let chain = CertificateDer::pem_slice_iter(p.node_cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("invalid node certificate: {e}"))?;
    let key = CertifiedKey::new(chain, load_signing_key(&p.node_key_pem)?);

    let resolver = SniResolver {
        key: Arc::new(key),
        expected: sni_verification.then(|| derive_sni(&p.ca_cert_pem, &p.jwt_public_key)),
    };

    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(resolver));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}
