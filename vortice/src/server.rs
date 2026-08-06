// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Accepting BEEP sessions.
//!
//! [`Server`] is the thin part: it binds a socket, accepts, and hands each connection to a
//! session that serves the given [`Router`]. Everything interesting happens in the router
//! and in the session driver.
//!
//! An application that already has its own accept loop — because it is sharing a port with
//! an HTTP server, say — does not need this type at all: it calls
//! [`Connection::serve_io`](crate::Connection::serve_io) with whatever transport it has.

use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use vortice_proto::session::{Config, Role};

use crate::connection::Connection;
use crate::error::Result;
use crate::router::Router;

/// A listening BEEP endpoint.
#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    config: Config,
    router: Router,
}

impl Server {
    /// Binds a TCP port and prepares to serve the router's profiles.
    ///
    /// The greeting is made to advertise every profile the router serves, since announcing
    /// anything else would be a lie the peer discovers only when its channel is refused.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`](crate::Error::Io) when the address cannot be bound.
    pub async fn bind(address: impl ToSocketAddrs, router: Router) -> Result<Self> {
        Self::bind_with(address, Config::new(Role::Listener), router).await
    }

    /// As [`Server::bind`], with a configuration of the caller's own.
    ///
    /// The role is forced to [`Role::Listener`]: a peer that accepted the transport allocates
    /// even channel numbers, whatever the configuration says.
    ///
    /// # Errors
    ///
    /// As [`Server::bind`].
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
        })
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
    /// Each accepted connection runs as its own task and is held open until the peer ends
    /// the session, so this future only returns when accepting itself stops working.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`](crate::Error::Io) when the accept loop fails.
    pub async fn serve(self) -> Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let config = self.config.clone();
            let router = self.router.clone();
            tokio::spawn(async move {
                if let Err(error) = Self::session(stream, config, router).await {
                    tracing::debug!(%peer, %error, "session ended");
                }
            });
        }
    }

    async fn session(stream: TcpStream, config: Config, router: Router) -> Result<()> {
        stream.set_nodelay(true)?;
        let connection = Connection::serve_io(stream, config, router).await?;
        // Holding the handle is what keeps the session alive: dropping it would close it.
        connection.closed().await;
        Ok(())
    }
}
