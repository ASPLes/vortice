// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The rustls backend: the default, and the one the interop tests run against.
//!
//! Nothing outside this module knows rustls exists. What it provides is the two traits of
//! [`crate::backend`] implemented for tokio-rustls' types, plus the configuration helpers a
//! caller needs to get one of those built from PEM.

use std::io;
use std::sync::Arc;

use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use vortice::BoxedTransport;

use crate::backend::{Acceptor, Connector, Handshake};
use crate::error::{Error, Result};

impl Acceptor for TlsAcceptor {
    fn accept(&self, io: BoxedTransport) -> Handshake {
        let acceptor = self.clone();
        Box::pin(async move {
            let stream = acceptor.accept(io).await?;
            Ok(Box::pin(stream) as BoxedTransport)
        })
    }
}

impl Connector for TlsConnector {
    fn connect(&self, server_name: &str, io: BoxedTransport) -> Handshake {
        let connector = self.clone();
        let name = ServerName::try_from(server_name).map(|name| name.to_owned());
        Box::pin(async move {
            let name = name.map_err(|_| io::Error::other("not a valid server name"))?;
            let stream = connector.connect(name, io).await?;
            Ok(Box::pin(stream) as BoxedTransport)
        })
    }
}

/// So that a caller with a configuration in hand need not build a connector first.
///
/// One is built per handshake, which for the connecting end is once per session anyway.
impl Connector for ClientConfig {
    fn connect(&self, server_name: &str, io: BoxedTransport) -> Handshake {
        Connector::connect(&TlsConnector::from(Arc::new(self.clone())), server_name, io)
    }
}

/// An acceptor for `tls`, to be shared across connections.
#[must_use]
pub fn acceptor(tls: ServerConfig) -> TlsAcceptor {
    TlsAcceptor::from(Arc::new(tls))
}

/// The protocol names offered by a client configuration, for ALPN.
///
/// ALPN is how one TLS port carries more than one protocol: the client lists what it speaks,
/// the server picks, and the choice is available before a single application octet is read.
/// That makes it the tidiest of the port-sharing mechanisms — no sniffing, no upgrade round
/// trip — at the cost of requiring TLS, since there is nowhere else to put the list.
///
/// [`BEEP_ALPN`](crate::BEEP_ALPN) is the name this project uses. Nothing registers it with IANA, so both ends
/// have to agree, exactly as with the `Upgrade` token.
pub fn with_client_alpn(mut tls: ClientConfig, protocols: &[&str]) -> ClientConfig {
    tls.alpn_protocols = protocols
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    tls
}

/// The protocol names a server will accept, in order of preference.
///
/// See [`with_client_alpn`].
pub fn with_server_alpn(mut tls: ServerConfig, protocols: &[&str]) -> ServerConfig {
    tls.alpn_protocols = protocols
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    tls
}

/// Builds a server configuration from PEM certificates and a PEM private key.
///
/// # Errors
///
/// Returns [`Error::Certificate`] if either cannot be parsed, or if they do not go together.
pub fn server_config(certificates: &[u8], key: &[u8]) -> Result<ServerConfig> {
    let chain = read_certificates(certificates)?;
    let key = read_key(key)?;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|error| {
            Error::Certificate(format!("certificate and key do not go together: {error}"))
        })
}

/// Builds a client configuration trusting the given PEM certificates and nothing else.
///
/// # Errors
///
/// Returns [`Error::Certificate`] if they cannot be parsed.
pub fn client_config(roots: &[u8]) -> Result<ClientConfig> {
    let mut store = RootCertStore::empty();
    for certificate in read_certificates(roots)? {
        store
            .add(certificate)
            .map_err(|error| Error::Certificate(format!("not a usable root: {error}")))?;
    }
    Ok(ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth())
}

/// Reads a PEM certificate chain.
fn read_certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = io::BufReader::new(pem);
    let chain: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let chain =
        chain.map_err(|error| Error::Certificate(format!("unreadable certificate: {error}")))?;
    if chain.is_empty() {
        return Err(Error::Certificate(
            "no certificate found in the PEM given".to_owned(),
        ));
    }
    Ok(chain)
}

/// Reads a PEM private key in any of the encodings rustls accepts.
fn read_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut reader = io::BufReader::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| Error::Certificate(format!("unreadable private key: {error}")))?
        .ok_or_else(|| Error::Certificate("no private key found in the PEM given".to_owned()))
}

/// A client configuration that accepts any certificate, for tests and for interoperating.
///
/// **This authenticates nothing.** It exists because it is what a great deal of deployed BEEP
/// does — LibVortex verifies no certificate unless asked to, and its regression suite is built
/// on a self-signed one — and because refusing to provide it would only push people to write a
/// worse version. Encryption without authentication still stops passive interception; it does
/// not stop anyone who can sit in the middle. Use [`client_config`] with the roots you expect
/// wherever that matters.
#[must_use]
pub fn insecure_client_config() -> ClientConfig {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(danger::AcceptAnyCertificate))
        .with_no_client_auth();
    config.enable_sni = true;
    config
}

mod danger {
    //! The certificate verifier behind [`super::insecure_client_config`], kept in a module of
    //! its own so that what it does is impossible to import by accident.

    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme};

    /// Accepts every certificate presented, without checking anything at all.
    #[derive(Debug)]
    pub(super) struct AcceptAnyCertificate;

    impl ServerCertVerifier for AcceptAnyCertificate {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &tokio_rustls::rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &tokio_rustls::rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            tokio_rustls::rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
