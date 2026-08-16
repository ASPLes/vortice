// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! A bulk one-to-many transfer over each transport, as a guard against the cost of one
//! collapsing.
//!
//! These are here because a regression in this area does not fail, it crawls — and a test that
//! merely completes would not notice. Sending one BEEP frame per write made WebSocket over TLS
//! take over two minutes for what takes under two seconds, because every frame became its own
//! TLS record; nothing was wrong with the result, only with the time. So each of the three
//! paths is timed and held to a bound generous enough never to be flaky and tight enough that
//! a sixty-fold regression cannot hide under it.

use std::time::Duration;

use vortice::{Config, Profile, Role};

#[path = "common/listeners.rs"]
mod listeners;

const BLOCKS: &str = "http://iana.org/beep/transient/vortex-regression/4";

/// What 16 MB may take. Every path does it in under two seconds on a quiet machine; this is
/// loose enough to survive a busy one and still catch a collapse.
const BUDGET: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread")]
async fn a_bulk_ans_transfer_survives_websocket_over_tls() {
    let acceptor = listeners::acceptor();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address").to_string();

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
                let _ = vortice_ws::serve(
                    tls,
                    listeners::listener_config(),
                    vortice_interop::profiles::regression_router(),
                )
                .await;
            });
        }
    });

    // Client: TCP -> TLS -> WebSocket -> BEEP.
    let stream = tokio::net::TcpStream::connect(&address)
        .await
        .expect("connect");
    stream.set_nodelay(true).expect("nodelay");
    let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        vortice_tls::insecure_client_config(),
    ))
    .connect(
        tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        stream,
    )
    .await
    .expect("tls handshake");

    let session = vortice_ws::connect_over(
        tls,
        "localhost",
        "/",
        Config::new(Role::Initiator).with_profile(BLOCKS),
    )
    .await
    .expect("websocket over tls");

    let channel = session
        .open_channel(Profile::new(BLOCKS))
        .await
        .expect("open the bulk channel");

    // The shape test_04a asks for: 4096 answers of 4096 octets, about 16 MB.
    let started = std::time::Instant::now();
    let reply = tokio::time::timeout(BUDGET, channel.request("bulk,4096,4096"))
        .await
        .expect("the transfer stalled")
        .expect("reply");
    let took = started.elapsed();
    eprintln!("websocket over tls: 16 MB in {took:?}");

    assert_eq!(reply.answers().len(), 4096, "every answer should arrive");
    assert!(
        took < BUDGET,
        "16 MB over wss took {took:?}, which is far beyond the couple of seconds it costs \
         over either transport alone — something is packaging writes badly again"
    );
}

/// The same transfer with TLS taken out, to say whether the cost is the tunnel or the path.
#[tokio::test(flavor = "multi_thread")]
async fn a_bulk_ans_transfer_over_plain_websocket() {
    let server = vortice_ws::Server::bind_with(
        "127.0.0.1:0",
        listeners::listener_config(),
        vortice_interop::profiles::regression_router(),
    )
    .await
    .expect("bind");
    let address = server.local_addr().expect("address").to_string();
    tokio::spawn(server.serve());

    let session = vortice_ws::connect(
        address.as_str(),
        &address,
        "/",
        Config::new(Role::Initiator).with_profile(BLOCKS),
    )
    .await
    .expect("websocket");

    let channel = session
        .open_channel(Profile::new(BLOCKS))
        .await
        .expect("open the bulk channel");

    let started = std::time::Instant::now();
    let reply = tokio::time::timeout(BUDGET, channel.request("bulk,4096,4096"))
        .await
        .expect("the transfer stalled")
        .expect("reply");
    eprintln!("plain websocket: 16 MB in {:?}", started.elapsed());

    assert_eq!(reply.answers().len(), 4096);
}

/// The same transfer over TLS but without WebSocket, which separates "TLS is slow here" from
/// "the two tunnels composed are slow".
#[tokio::test(flavor = "multi_thread")]
async fn a_bulk_ans_transfer_over_implicit_tls() {
    let acceptor = listeners::acceptor();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address").to_string();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let _ = stream.set_nodelay(true);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = vortice_tls::serve(
                    stream,
                    &acceptor,
                    listeners::listener_config(),
                    vortice_interop::profiles::regression_router(),
                )
                .await;
            });
        }
    });

    let session = vortice_tls::connect(
        address.as_str(),
        "localhost",
        vortice_tls::insecure_client_config(),
        Config::new(Role::Initiator).with_profile(BLOCKS),
    )
    .await
    .expect("implicit tls");

    let channel = session
        .open_channel(Profile::new(BLOCKS))
        .await
        .expect("open the bulk channel");

    let started = std::time::Instant::now();
    let reply = tokio::time::timeout(BUDGET, channel.request("bulk,4096,4096"))
        .await
        .expect("the transfer stalled")
        .expect("reply");
    eprintln!("implicit tls: 16 MB in {:?}", started.elapsed());

    assert_eq!(reply.answers().len(), 4096);
}
