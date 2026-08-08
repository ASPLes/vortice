// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Accepting WebSocket connections and running BEEP over them.

use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, ToSocketAddrs};
use vortice::{Config, Connection, Rewind, Role, Router};

use crate::error::Result;
use crate::handshake;
use crate::stream::WsStream;

/// Completes a WebSocket handshake and runs a BEEP session over the result.
///
/// The returned handle behaves exactly like one from [`vortice::Connection`]: the WebSocket
/// is a transport and nothing above it knows the difference.
///
/// # Errors
///
/// Returns [`Error::Handshake`](crate::Error::Handshake) if the request is not a valid
/// WebSocket handshake, [`Error::Io`](crate::Error::Io) if the transport fails, and
/// [`Error::Session`](crate::Error::Session) if the greeting exchange does.
pub async fn accept<T>(io: T, config: Config, router: Router) -> Result<Connection>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    accept_with_seed(io, BytesMut::new(), config, router).await
}

/// The body behind [`accept`], which port sharing enters with octets already read.
async fn accept_with_seed<T>(
    mut io: T,
    seed: BytesMut,
    config: Config,
    router: Router,
) -> Result<Connection>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (head, leftover) = handshake::read_head(&mut io, seed).await?;
    let request = handshake::parse_request(&head)?;
    io.write_all(handshake::response(&request.key).as_bytes())
        .await?;
    io.flush().await?;

    // Whatever arrived past the blank line is already a WebSocket frame: a client may well
    // send its BEEP greeting in the same segment as the handshake.
    Ok(Connection::serve_io(WsStream::server(io, leftover), config, router).await?)
}

/// Runs a BEEP session over an accepted WebSocket until it ends.
///
/// # Errors
///
/// As [`accept`].
pub async fn serve<T>(io: T, config: Config, router: Router) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let connection = accept(io, config, router).await?;
    // Holding the handle is what keeps the session alive: dropping it would close it.
    connection.closed().await;
    Ok(())
}

/// A listener accepting BEEP sessions over WebSocket.
///
/// The same shape as [`vortice::Server`], differing only in the handshake each accepted
/// connection starts with.
#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    config: Config,
    router: Router,
    shared: bool,
}

impl Server {
    /// Binds a TCP port and prepares to serve the router's profiles over WebSocket.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`](crate::Error::Io) if the port cannot be bound.
    pub async fn bind(address: impl ToSocketAddrs, router: Router) -> Result<Self> {
        Self::bind_with(address, Config::new(Role::Listener), router).await
    }

    /// As [`Server::bind`], with a configuration of the caller's own.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`](crate::Error::Io) if the port cannot be bound.
    pub async fn bind_with(
        address: impl ToSocketAddrs,
        mut config: Config,
        router: Router,
    ) -> Result<Self> {
        config.role = Role::Listener;
        let mut uris: Vec<&str> = router.uris().collect();
        // Sorted so the greeting is byte-for-byte reproducible across runs.
        uris.sort_unstable();
        for uri in uris {
            if !config.greeting.advertises(uri) {
                config.greeting = config.greeting.clone().with_profile(uri);
            }
        }

        let listener = TcpListener::bind(address).await?;
        Ok(Self {
            listener,
            config,
            router,
            shared: false,
        })
    }

    /// Also accepts plain BEEP on this port, deciding per connection.
    ///
    /// See [`serve_shared`] for how the two are told apart, and why it is safe.
    #[must_use]
    pub const fn with_plain_beep(mut self) -> Self {
        self.shared = true;
        self
    }

    /// The address actually bound, which is how a test finds the port after asking for zero.
    ///
    /// # Errors
    ///
    /// Propagates the failure of the underlying socket call.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Accepts sessions until the listening socket fails.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`](crate::Error::Io) when the accept loop fails.
    pub async fn serve(self) -> Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let config = self.config.clone();
            let router = self.router.clone();
            let shared = self.shared;

            tokio::spawn(async move {
                let result = match stream.set_nodelay(true) {
                    Ok(()) if shared => serve_shared(stream, config, router).await,
                    Ok(()) => serve(stream, config, router).await,
                    Err(error) => Err(error.into()),
                };
                if let Err(error) = result {
                    tracing::debug!(%peer, %error, "session ended");
                }
            });
        }
    }
}

/// Serves one connection that may be either a WebSocket handshake or plain BEEP.
///
/// A BEEP peer opens by sending its greeting, `RPY 0 0 . 0 …`, and a WebSocket peer opens
/// with `GET `. The two are told apart by those first four octets, which is sound rather than
/// a guess: a BEEP frame header can only begin with one of the six frame keywords, and `GET `
/// is not among them.
///
/// # Errors
///
/// As [`accept`], plus [`Error::Session`](crate::Error::Session) for a plain BEEP session
/// that fails.
pub async fn serve_shared<T>(mut io: T, config: Config, router: Router) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let seed = peek(&mut io, 4).await?;

    let connection = if seed.starts_with(b"GET ") {
        accept_with_seed(io, seed, config, router).await?
    } else {
        Connection::serve_io(Rewind::new(seed.freeze(), io), config, router).await?
    };

    // Holding the handle is what keeps the session alive: dropping it would close it.
    connection.closed().await;
    Ok(())
}

/// Reads until at least `want` octets are buffered, or the peer stops.
async fn peek<T: AsyncRead + Unpin>(io: &mut T, want: usize) -> Result<BytesMut> {
    use tokio::io::AsyncReadExt;

    let mut seen = BytesMut::with_capacity(want.max(64));
    let mut chunk = [0u8; 64];
    while seen.len() < want {
        let read = io.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        seen.extend_from_slice(&chunk[..read]);
    }
    Ok(seen)
}
