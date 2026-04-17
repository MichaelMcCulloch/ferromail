use std::net::IpAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::net::lookup_host;

use crate::types::{FerromailError, Result};

/// Install rustls's aws-lc-rs crypto provider as the process-global default,
/// exactly once. `rustls_platform_verifier::Verifier::new()` and some rustls
/// paths consult `CryptoProvider::get_default()` and panic if it's unset, so
/// every library entry point that may build a TLS config calls this first.
///
/// aws-lc-rs is used (rather than ring) so we pick up the X25519MLKEM768
/// hybrid post-quantum key exchange, which the provider has enabled by
/// default since rustls 0.23.20 / aws-lc-rs 1.12.
pub fn install_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // install_default returns Err if already installed; either outcome
        // is fine for our purposes.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub fn build_tls_config(verify_certs: bool, min_tls_version: &str) -> Result<Arc<ClientConfig>> {
    install_crypto_provider();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let min_version = match min_tls_version {
        "1.3" => &rustls::version::TLS13,
        _ => &rustls::version::TLS12,
    };

    let config = if verify_certs {
        let verifier = rustls_platform_verifier::Verifier::new();
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[min_version])
            .map_err(|e| FerromailError::TlsError(format!("failed to set TLS version: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
    } else {
        tracing::warn!(
            "TLS certificate verification DISABLED for connection. \
             Credentials are exposed to network attackers."
        );
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[min_version])
            .map_err(|e| FerromailError::TlsError(format!("failed to set TLS version: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    };

    Ok(Arc::new(config))
}

pub async fn check_loopback(host: &str) -> Result<IpAddr> {
    let addr = lookup_host(format!("{host}:0"))
        .await
        .map_err(|e| FerromailError::TlsError(format!("failed to resolve host {host}: {e}")))?
        .next()
        .ok_or_else(|| {
            FerromailError::TlsError(format!("host {host} did not resolve to any address"))
        })?;

    let ip = addr.ip();

    let is_loopback = match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 127,
        IpAddr::V6(v6) => v6 == std::net::Ipv6Addr::LOCALHOST,
    };

    if !is_loopback {
        return Err(FerromailError::TlsError(format!(
            "tls = none requires a loopback address. {host} resolved to {ip}, which is not loopback."
        )));
    }

    Ok(ip)
}

pub fn verify_imap_greeting(data: &[u8]) -> Result<()> {
    let prefix = if data.len() >= 10 { &data[..10] } else { data };
    let upper = String::from_utf8_lossy(prefix).to_uppercase();

    if upper.starts_with("* OK") || upper.starts_with("* PREAUTH") || upper.starts_with("* BYE") {
        return Ok(());
    }

    Err(FerromailError::ProtocolViolation(
        "Post-TLS protocol mismatch — possible Opossum desynchronization".into(),
    ))
}

#[derive(Debug)]
struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_tls_config_verified() {
        let config = build_tls_config(true, "1.2");
        assert!(config.is_ok());
    }

    #[test]
    fn build_tls_config_insecure() {
        let config = build_tls_config(false, "1.3");
        assert!(config.is_ok());
    }

    #[test]
    fn greeting_ok() {
        assert!(verify_imap_greeting(b"* OK Dovecot ready.\r\n").is_ok());
    }

    #[test]
    fn greeting_preauth() {
        assert!(verify_imap_greeting(b"* PREAUTH welcome\r\n").is_ok());
    }

    #[test]
    fn greeting_bye() {
        assert!(verify_imap_greeting(b"* BYE server shutting down\r\n").is_ok());
    }

    #[test]
    fn greeting_case_insensitive() {
        assert!(verify_imap_greeting(b"* ok hello\r\n").is_ok());
        assert!(verify_imap_greeting(b"* Ok ready\r\n").is_ok());
    }

    #[test]
    fn greeting_invalid() {
        assert!(verify_imap_greeting(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(verify_imap_greeting(b"").is_err());
        assert!(verify_imap_greeting(b"garbage").is_err());
    }

    #[tokio::test]
    async fn check_loopback_localhost() {
        let result = check_loopback("localhost").await;
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert!(
            ip == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                || ip == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        );
    }

    #[tokio::test]
    async fn check_loopback_127_0_0_1() {
        let result = check_loopback("127.0.0.1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_loopback_rejects_non_loopback() {
        let result = check_loopback("1.1.1.1").await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not loopback"));
    }
}
