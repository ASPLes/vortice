// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! What this crate needs from a TLS library, and nothing more.
//!
//! The BEEP TLS profile is a negotiation in XML followed by a transport being replaced. Only
//! the last step involves TLS at all, and all it asks of a TLS library is: given a transport,
//! give one back that is encrypted. That is two traits, one per end.
//!
//! Everything else in this crate — the channel exchange, `<ready />` and `<proceed />`, the
//! policy deciding who gets tuned, the swap itself — is written against these and compiles
//! whether or not any backend feature is on. Which is the point: `rustls` and `native-tls` are
//! two implementations of a shape a caller can also fill in itself, with a TLS library this
//! crate has never heard of, or with something that is not TLS at all.

use std::future::Future;
use std::io;
use std::pin::Pin;

use vortice::BoxedTransport;

/// A handshake in progress, yielding the encrypted transport it produced.
pub type Handshake = Pin<Box<dyn Future<Output = io::Result<BoxedTransport>> + Send>>;

/// The accepting end of a TLS backend: what a listener terminates with.
///
/// Implemented for `tokio_rustls::TlsAcceptor` and `tokio_native_tls::TlsAcceptor` when the
/// matching feature is on.
pub trait Acceptor: Send + Sync + 'static {
    /// Terminates TLS on a transport that has just been accepted.
    fn accept(&self, io: BoxedTransport) -> Handshake;
}

/// The connecting end of a TLS backend.
///
/// `server_name` is what the certificate is checked against and what goes in SNI.
///
/// Implemented for `tokio_rustls::TlsConnector` and `tokio_native_tls::TlsConnector` when the
/// matching feature is on.
pub trait Connector: Send + Sync + 'static {
    /// Starts TLS on a transport, as the end that opened it.
    fn connect(&self, server_name: &str, io: BoxedTransport) -> Handshake;
}
