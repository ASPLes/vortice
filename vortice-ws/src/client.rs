// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Opening a WebSocket to a server and running BEEP over it.

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use vortice::{Config, Connection};

use crate::error::Result;
use crate::handshake;
use crate::stream::WsStream;

/// Connects to `address`, opens a WebSocket on `path` and completes the greeting exchange.
///
/// `host` is what goes in the `Host` header, which a virtual host or an ingress may route on;
/// it is usually the same as `address`.
///
/// ```no_run
/// # async fn example() -> vortice_ws::Result<()> {
/// use vortice::{Config, Role};
///
/// let session = vortice_ws::connect(
///     "127.0.0.1:44013",
///     "127.0.0.1:44013",
///     "/",
///     Config::new(Role::Initiator),
/// )
/// .await?;
/// # let _ = session;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`Error::NotUpgraded`](crate::Error::NotUpgraded) when the server answers anything
/// but `101`, [`Error::Handshake`](crate::Error::Handshake) when its answer does not match
/// the key sent, and [`Error::Session`](crate::Error::Session) when the greeting exchange
/// fails.
pub async fn connect(
    address: impl ToSocketAddrs,
    host: &str,
    path: &str,
    config: Config,
) -> Result<Connection> {
    let stream = TcpStream::connect(address).await?;
    stream.set_nodelay(true)?;
    connect_over(stream, host, path, config).await
}

/// As [`connect`], over a transport the caller has already established.
///
/// This is the entry point for WebSocket over TLS: hand it a connected TLS stream and the
/// handshake runs inside the tunnel, which is what `wss://` is.
///
/// # Errors
///
/// As [`connect`].
pub async fn connect_over<T>(
    mut io: T,
    host: &str,
    path: &str,
    config: Config,
) -> Result<Connection>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let key = handshake::client_key()?;
    io.write_all(handshake::request(path, host, &key).as_bytes())
        .await?;
    io.flush().await?;

    let (head, leftover) = handshake::read_head(&mut io, BytesMut::new()).await?;
    handshake::parse_response(&head, &key)?;

    // Whatever arrived past the blank line is already a WebSocket frame: the server may well
    // send its BEEP greeting in the same segment as the handshake response.
    Ok(Connection::from_io(WsStream::client(io, leftover), config).await?)
}
