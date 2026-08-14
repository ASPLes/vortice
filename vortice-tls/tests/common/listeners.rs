// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The listeners the suite's WebSocket-over-TLS tests need, and the three-way shared port.
//!
//! Shared by the interop test and by `examples/tls-ws-regression-listener.rs`, so that what CI
//! checks is exactly what a developer gets running it by hand.
//!
//! Nothing here is new protocol work. `vortice-ws` serves BEEP over anything that reads and
//! writes, and `vortice-tls` produces such a thing, so `wss` is the two composed — which is
//! the whole argument for keeping the transports in separate crates.

#![allow(dead_code, unreachable_pub)]

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use vortice::{Config, Rewind, Role};
use vortice_interop::profiles::regression_router;

/// A certificate for `localhost`, generated rather than read from the suite.
pub fn certificate() -> (Vec<u8>, Vec<u8>) {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate a certificate");
    (
        issued.cert.pem().into_bytes(),
        issued.signing_key.serialize_pem().into_bytes(),
    )
}

/// An acceptor presenting that certificate.
pub fn acceptor() -> TlsAcceptor {
    let (certificates, key) = certificate();
    vortice_tls::acceptor(
        vortice_tls::server_config(&certificates, &key).expect("server configuration"),
    )
}

/// The configuration a listener greets with, offering everything the router serves.
pub fn listener_config() -> Config {
    let mut config = Config::new(Role::Listener);
    let mut uris: Vec<String> = regression_router().uris().map(str::to_owned).collect();
    uris.sort_unstable();
    for uri in &uris {
        if !config.greeting.advertises(uri.as_str()) {
            config.greeting = config.greeting.clone().with_profile(uri.as_str());
        }
    }
    config
}

/// Serves BEEP over WebSocket over TLS on `port`, which is what `wss` is.
///
/// # Errors
///
/// Fails when the port cannot be bound.
pub async fn serve_wss(port: u16, acceptor: TlsAcceptor) -> std::io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let _ = vortice_ws::serve(tls, listener_config(), regression_router()).await;
            });
        }
    });
    Ok(())
}

/// Serves plain BEEP, BEEP over WebSocket and BEEP over WebSocket over TLS, all on `port`.
///
/// The three are told apart from the first octets and nothing else: a TLS handshake record
/// opens `0x16 0x03`, a WebSocket handshake opens `GET `, and a BEEP session opens with one of
/// six upper-case frame keywords. None of the three can be mistaken for another, so the
/// decision is sound rather than a guess — see [`vortice_tls::looks_like_tls`].
///
/// Once TLS is terminated the same question is asked again inside it, which is how `wss` and
/// plain `beeps` share the port too.
///
/// # Errors
///
/// Fails when the port cannot be bound.
pub async fn serve_shared(port: u16, acceptor: TlsAcceptor) -> std::io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = serve_one_shared(stream, acceptor).await;
            });
        }
    });
    Ok(())
}

/// Decides what one accepted connection is, and serves it.
async fn serve_one_shared(
    mut stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
) -> std::io::Result<()> {
    let mut prefix = Vec::new();
    let mut chunk = [0u8; 8];
    // Two octets is enough to recognise TLS; read a few so the decision is never made on a
    // single-octet segment.
    while prefix.len() < 2 {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        prefix.extend_from_slice(&chunk[..read]);
    }

    let rewound = Rewind::new(prefix.clone().into(), stream);

    if vortice_tls::looks_like_tls(&prefix) {
        let tls = acceptor.accept(rewound).await?;
        // Inside the tunnel it is the same question again: a handshake, or BEEP directly.
        let _ = vortice_ws::serve_shared(tls, listener_config(), regression_router()).await;
    } else {
        let _ = vortice_ws::serve_shared(rewound, listener_config(), regression_router()).await;
    }
    Ok(())
}

/// Everything the suite's WebSocket tests need, bound and serving.
///
/// # Errors
///
/// Fails when any of the ports cannot be bound.
pub async fn serve_all(offset: u16) -> std::io::Result<()> {
    // One certificate for every port, as the suite's own listener does.
    let acceptor = acceptor();

    // 44013 plain WebSocket, for test_17; 44014 WebSocket over TLS, for test_18 and test_19.
    let ws = vortice_ws::Server::bind_with(
        ("0.0.0.0", 44013 + offset),
        listener_config(),
        regression_router(),
    )
    .await
    .map_err(std::io::Error::other)?;
    tokio::spawn(ws.serve());

    serve_wss(44014 + offset, acceptor.clone()).await?;

    // 44015 takes all three, which is what test_20 walks through in turn.
    serve_shared(44015 + offset, acceptor).await?;

    Ok(())
}
