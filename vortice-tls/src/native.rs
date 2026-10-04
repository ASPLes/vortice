// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The `native-tls` backend: the platform's own TLS, behind the `native-tls` feature.
//!
//! Reachable through the same [`Acceptor`] and [`Connector`] the rustls backend implements, so
//! the profile, the policy and the swap are the same code either way. What differs is what
//! ends up doing the encryption: OpenSSL on Linux and the BSDs, Secure Transport on macOS,
//! SChannel on Windows.
//!
//! Why offer it at all, when rustls is the default and works: because a deployment that has
//! already decided what its TLS is — a policy about FIPS, a system trust store that has to be
//! the one consulted, an OpenSSL that is patched a particular way — should not have to give
//! that up to speak BEEP. It is also the proof that the profile is not married to one library,
//! which is easy to claim and only demonstrated by a second implementation.
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use vortice::{Config, Role};
//!
//! let listener = vortice_tls::native::acceptor(
//!     &std::fs::read("certificate.pem")?,
//!     &std::fs::read("key.pem")?,
//! )?;
//! # let _ = (listener, Config::new(Role::Listener));
//! # Ok(())
//! # }
//! ```
//!
//! # ALPN
//!
//! Both ends, through [`connector_with_alpn`] and [`acceptor_with_alpn`]: `native-tls`'s own
//! `alpn` and `alpn-accept` features are enabled here, so the port sharing of
//! [`BEEP_ALPN`](crate::BEEP_ALPN) works whichever backend terminates it.

use tokio_native_tls::native_tls;
use vortice::BoxedTransport;

use crate::backend::{Acceptor, Connector, Handshake};
use crate::error::{Error, Result};

pub use tokio_native_tls::{TlsAcceptor, TlsConnector};

impl Acceptor for TlsAcceptor {
    fn accept(&self, io: BoxedTransport) -> Handshake {
        let acceptor = self.clone();
        Box::pin(async move {
            let stream = acceptor
                .accept(io)
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            Ok(Box::pin(stream) as BoxedTransport)
        })
    }
}

impl Connector for TlsConnector {
    fn connect(&self, server_name: &str, io: BoxedTransport) -> Handshake {
        let connector = self.clone();
        let name = server_name.to_owned();
        Box::pin(async move {
            let stream = connector
                .connect(&name, io)
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            Ok(Box::pin(stream) as BoxedTransport)
        })
    }
}

/// An acceptor presenting a PEM certificate chain and its PEM private key.
///
/// The same two files the rustls backend's `server_config` takes, so a listener can be moved
/// from one to the other without touching how its material is stored.
///
/// # Errors
///
/// Returns [`Error::Certificate`] when the pair cannot be read or do not go together.
pub fn acceptor(certificate: &[u8], key: &[u8]) -> Result<TlsAcceptor> {
    let acceptor = native_tls::TlsAcceptor::new(identity(certificate, key)?)
        .map_err(|error| Error::Certificate(format!("unable to build an acceptor: {error}")))?;
    Ok(TlsAcceptor::from(acceptor))
}

/// As [`acceptor`], announcing the given protocol names for ALPN, most preferred first.
///
/// # Errors
///
/// As [`acceptor`].
pub fn acceptor_with_alpn(
    certificate: &[u8],
    key: &[u8],
    protocols: &[&str],
) -> Result<TlsAcceptor> {
    let acceptor = native_tls::TlsAcceptor::builder(identity(certificate, key)?)
        .accept_alpn(protocols)
        .build()
        .map_err(|error| Error::Certificate(format!("unable to build an acceptor: {error}")))?;
    Ok(TlsAcceptor::from(acceptor))
}

/// The certificate and key a listener presents, read from PEM.
fn identity(certificate: &[u8], key: &[u8]) -> Result<native_tls::Identity> {
    native_tls::Identity::from_pkcs8(certificate, key)
        .map_err(|error| Error::Certificate(format!("certificate and key unusable: {error}")))
}

/// A connector trusting the given PEM certificates in addition to the system roots.
///
/// # Errors
///
/// Returns [`Error::Certificate`] when a certificate cannot be read.
pub fn connector(roots: &[u8]) -> Result<TlsConnector> {
    build_connector(roots, false, &[])
}

/// As [`connector`], offering the given protocol names for ALPN.
///
/// # Errors
///
/// As [`connector`].
pub fn connector_with_alpn(roots: &[u8], protocols: &[&str]) -> Result<TlsConnector> {
    build_connector(roots, false, protocols)
}

/// A connector that accepts any certificate, for tests and for interoperating.
///
/// **This authenticates nothing**, exactly as the rustls backend's `insecure_client_config`
/// does not, and for the same reasons: it is what a great deal of deployed BEEP does, and
/// refusing to provide it would only push people to write a worse version. Encryption without
/// authentication stops passive interception and nothing else. Use [`connector`] with the
/// roots you expect wherever that matters.
///
/// # Errors
///
/// Returns [`Error::Certificate`] when the connector cannot be built at all.
pub fn insecure_connector() -> Result<TlsConnector> {
    build_connector(&[], true, &[])
}

/// The one place a connector is actually assembled.
fn build_connector(
    roots: &[u8],
    accept_anything: bool,
    protocols: &[&str],
) -> Result<TlsConnector> {
    let mut builder = native_tls::TlsConnector::builder();

    if !roots.is_empty() {
        // `Certificate::from_pem` takes one certificate, so a file with several is split on
        // the end line and fed in one at a time.
        for block in split_pem(roots) {
            let certificate = native_tls::Certificate::from_pem(&block).map_err(|error| {
                Error::Certificate(format!("not a usable root certificate: {error}"))
            })?;
            builder.add_root_certificate(certificate);
        }
    }

    if accept_anything {
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
    }

    if !protocols.is_empty() {
        builder.request_alpns(protocols);
    }

    let connector = builder
        .build()
        .map_err(|error| Error::Certificate(format!("unable to build a connector: {error}")))?;
    Ok(TlsConnector::from(connector))
}

/// Splits a PEM file into one buffer per certificate.
fn split_pem(pem: &[u8]) -> Vec<Vec<u8>> {
    const END: &[u8] = b"-----END CERTIFICATE-----";

    let mut blocks = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at + END.len() <= pem.len() {
        if &pem[at..at + END.len()] == END {
            let mut end = at + END.len();
            // Take the newline that follows, when there is one.
            if pem.get(end) == Some(&b'\r') {
                end += 1;
            }
            if pem.get(end) == Some(&b'\n') {
                end += 1;
            }
            blocks.push(pem[start..end].to_vec());
            start = end;
            at = end;
        } else {
            at += 1;
        }
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::split_pem;

    #[test]
    fn splits_a_file_holding_several_certificates() {
        let pem = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n\
                    -----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";
        let blocks = split_pem(pem);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].starts_with(b"-----BEGIN"));
        assert!(blocks[1].ends_with(b"-----END CERTIFICATE-----\n"));
    }

    #[test]
    fn reports_nothing_for_a_file_with_no_certificate() {
        assert!(split_pem(b"not a certificate at all\n").is_empty());
    }
}
