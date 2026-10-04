// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! BEEP inside TLS from the first octet, rather than tuned in band.
//!
//! The in-band profile is what RFC3080 specifies, and it has one property implicit TLS does
//! not: a passive observer sees the session begin in the clear, including which profiles were
//! offered. It also has a cost — a round trip, and a window in which a peer that will not tune
//! has already learnt something.
//!
//! Implicit TLS — BEEPS, by analogy with HTTPS — is what deployments actually reach for when
//! there is a port to spare, and it is what a TLS-terminating load balancer produces whether
//! anyone planned it or not. Nothing here is BEEP-specific: the session simply starts on a
//! transport that happens to be encrypted, which is [`Connection::from_io`]'s whole point.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};
use vortice::{Config, Connection, Router};

use crate::backend::{Acceptor, Connector};
use crate::error::Result;

/// Whether these octets look like the start of a TLS connection.
///
/// A TLS record begins with a content type and a two octet version, and a handshake opens with
/// `0x16 0x03`. No BEEP frame can start that way — a header begins with one of six keywords,
/// all upper-case ASCII — and neither can an HTTP request. That makes the three
/// distinguishable on a shared port from the first two octets, which is what
/// [`vortice_ws::serve_shared`](https://docs.rs/vortice-ws) needs to also take `wss`.
///
/// Answers `false` when given fewer than two octets: undecided rather than a guess.
///
/// ```
/// assert!(vortice_tls::looks_like_tls(&[0x16, 0x03, 0x01]));
/// assert!(!vortice_tls::looks_like_tls(b"RPY 0 0 . 0 0"));
/// assert!(!vortice_tls::looks_like_tls(b"GET / HTTP/1.1"));
/// assert!(!vortice_tls::looks_like_tls(&[0x16]));
/// ```
#[must_use]
pub fn looks_like_tls(prefix: &[u8]) -> bool {
    matches!(prefix, [0x16, 0x03, ..])
}

/// Connects over TLS and runs a BEEP session inside it.
///
/// `server_name` is what the certificate is checked against and what goes in SNI; it is
/// usually the host part of `address`.
///
/// # Errors
///
/// Returns [`Error::Handshake`](crate::Error::Handshake) if TLS fails and [`Error::Session`](crate::Error::Session) if the greeting exchange
/// does.
pub async fn connect(
    address: impl ToSocketAddrs,
    server_name: &str,
    tls: impl Connector,
    config: Config,
) -> Result<Connection> {
    let stream = TcpStream::connect(address).await?;
    stream.set_nodelay(true)?;
    connect_over(stream, server_name, tls, config).await
}

/// As [`connect`], over a transport the caller has already established.
///
/// # Errors
///
/// As [`connect`].
pub async fn connect_over<T>(
    io: T,
    server_name: &str,
    tls: impl Connector,
    config: Config,
) -> Result<Connection>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let stream = tls.connect(server_name, Box::pin(io)).await?;
    Ok(Connection::from_io(stream, config).await?)
}

/// Terminates TLS on an accepted transport and serves BEEP inside it.
///
/// # Errors
///
/// As [`connect`].
pub async fn accept<T>(
    io: T,
    tls: &impl Acceptor,
    config: Config,
    router: Router,
) -> Result<Connection>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let stream = tls.accept(Box::pin(io)).await?;
    Ok(Connection::serve_io(stream, config, router).await?)
}

/// Terminates TLS and runs the session until it ends.
///
/// # Errors
///
/// As [`connect`].
pub async fn serve<T>(io: T, tls: &impl Acceptor, config: Config, router: Router) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let connection = accept(io, tls, config, router).await?;
    // Holding the handle is what keeps the session alive: dropping it would close it.
    connection.closed().await;
    Ok(())
}

/// The ALPN name this project uses for BEEP directly inside TLS.
pub const BEEP_ALPN: &str = "beep";

#[cfg(test)]
mod tests {
    use super::looks_like_tls;

    #[test]
    fn tells_a_tls_handshake_from_what_else_may_arrive() {
        // TLS 1.0 through 1.3 all begin their handshake record the same way.
        assert!(looks_like_tls(&[0x16, 0x03, 0x01]));
        assert!(looks_like_tls(&[0x16, 0x03, 0x03]));

        // The six BEEP frame keywords, and an HTTP request line.
        for beginning in [
            &b"MSG 1 0 . 0 5"[..],
            b"RPY 0 0 . 0 0",
            b"ERR 1 0 . 0 0",
            b"ANS 1 0 . 0 0 0",
            b"NUL 1 0 . 0 0",
            b"SEQ 0 0 4096",
            b"GET / HTTP/1.1",
        ] {
            assert!(
                !looks_like_tls(beginning),
                "{:?} should not be read as TLS",
                String::from_utf8_lossy(beginning)
            );
        }
    }

    #[test]
    fn refuses_to_guess_from_too_little() {
        assert!(!looks_like_tls(&[]));
        assert!(!looks_like_tls(&[0x16]));
    }
}
