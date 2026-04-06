use rcgen::{Certificate, CertificateParams, KeyPair, PKCS_ED25519};
use crate::identity::IdentityManager;
use rustls::{Certificate as RustlsCert, PrivateKey as RustlsKey};

/// HIGH-04 Fix: Generate a self-signed certificate bound to the Node ID.
/// This bridges the Ed25519 node identity to the TLS 1.3 requirements of QUIC.
pub fn generate_node_certificate(identity: &IdentityManager) -> anyhow::Result<(RustlsCert, RustlsKey)> {
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![rcgen::SanType::DnsName("phantom-node".to_string())];
    
    // Bridge Ed25519 to rcgen KeyPair
    let key_pair = KeyPair::from_der(&identity.export_ed25519_der())?;
    params.key_pair = Some(key_pair);
    params.alg = &PKCS_ED25519;

    let cert = Certificate::from_params(params)?;
    let cert_der = cert.serialize_der()?;
    let priv_key_der = cert.serialize_private_key_der();

    Ok((RustlsCert(cert_der), RustlsKey(priv_key_der)))
}
