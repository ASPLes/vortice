// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! A Vortice client and a Vortice server talking BEEP over WebSocket.
//!
//! Everything here is ordinary BEEP: the point of these tests is that nothing above the
//! transport changes, so what is being checked is that the tunnel is transparent.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vortice::{Config, Message, Profile, Responder, Role, Router};

const ECHO: &str = "urn:example:echo";

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .expect("operation timed out")
}

/// An echo router, the smallest thing that exercises a full request and reply.
fn echo_router() -> Router {
    Router::new().profile(ECHO, |responder: Responder, message: Message| async move {
        let _ = responder.reply(message.msgno, message.payload).await;
    })
}

/// Starts a WebSocket BEEP server on an ephemeral port and returns its address.
async fn start() -> String {
    let server = vortice_ws::Server::bind("127.0.0.1:0", echo_router())
        .await
        .expect("bind");
    let address = server.local_addr().expect("local address").to_string();
    tokio::spawn(server.serve());
    address
}

/// Connects to a running server.
async fn client(address: &str) -> vortice::Connection {
    within(vortice_ws::connect(
        address,
        address,
        "/",
        Config::new(Role::Initiator).with_profile(ECHO),
    ))
    .await
    .expect("open a websocket session")
}

#[tokio::test]
async fn a_session_runs_over_a_websocket() {
    let address = start().await;
    let session = client(&address).await;

    assert!(
        session.peer_greeting().advertises(ECHO),
        "the greeting should have crossed the tunnel"
    );

    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open the echo channel");
    let reply = within(channel.request("over websocket"))
        .await
        .expect("reply");
    assert_eq!(reply.payload(), b"over websocket");

    within(session.close()).await.expect("close the session");
}

/// Sixteen times the default window, so fragmentation and `SEQ` pacing run over the tunnel
/// and cross the point where one write becomes several WebSocket frames.
#[tokio::test]
async fn a_large_payload_survives_the_tunnel() {
    let address = start().await;
    let session = client(&address).await;

    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open the echo channel");

    let payload: Vec<u8> = (0..64 * 1024u32).map(|index| (index % 251) as u8).collect();
    let reply = within(channel.request(payload.clone()))
        .await
        .expect("reply");
    assert_eq!(reply.payload(), &payload[..]);
}

/// The payload BEEP carries is arbitrary octets, which is exactly what a text frame may not
/// hold — so this is the case that decides whether the binding is honest about binary.
#[tokio::test]
async fn a_payload_that_is_not_utf8_survives_the_tunnel() {
    let address = start().await;
    let session = client(&address).await;

    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open the echo channel");

    // Lone continuation octets, an overlong encoding and a bare 0xff: none of it is UTF-8.
    let payload: Vec<u8> = vec![0x00, 0x80, 0xbf, 0xc0, 0x80, 0xff, 0xfe, 0x41, 0x00];
    let reply = within(channel.request(payload.clone()))
        .await
        .expect("reply");
    assert_eq!(reply.payload(), &payload[..]);
}

#[tokio::test]
async fn many_channels_share_one_websocket() {
    let address = start().await;
    let session = client(&address).await;

    let mut channels = Vec::new();
    for _ in 0..8 {
        channels.push(
            within(session.open_channel(Profile::new(ECHO)))
                .await
                .expect("open a channel"),
        );
    }

    for (index, channel) in channels.iter().enumerate() {
        let sent = format!("channel {index}");
        let reply = within(channel.request(sent.clone())).await.expect("reply");
        assert_eq!(reply.payload(), sent.as_bytes());
    }
}

#[tokio::test]
async fn a_handshake_on_any_path_is_accepted() {
    let address = start().await;
    // LibVortex asks for `/`, a reverse proxy may rewrite to anything; a listener that only
    // answered one path would refuse deployments for no reason.
    for path in ["/", "/beep", "/some/deep/path"] {
        let session = within(vortice_ws::connect(
            address.as_str(),
            &address,
            path,
            Config::new(Role::Initiator).with_profile(ECHO),
        ))
        .await
        .unwrap_or_else(|error| panic!("{path} should be accepted: {error}"));
        within(session.close()).await.expect("close");
    }
}

#[tokio::test]
async fn a_request_that_is_not_a_handshake_is_refused() {
    let address = start().await;
    let mut stream = TcpStream::connect(&address).await.expect("connect");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("write");

    // No `101`, and the server does not leave the connection hanging as a session.
    let mut answer = Vec::new();
    within(stream.read_to_end(&mut answer)).await.expect("read");
    assert!(
        !String::from_utf8_lossy(&answer).contains("101"),
        "a request without the websocket headers must not be upgraded"
    );
}

#[tokio::test]
async fn a_server_that_does_not_speak_websocket_fails_cleanly() {
    // A plain BEEP listener: it will never answer the handshake.
    let beep = vortice::Server::bind("127.0.0.1:0", echo_router())
        .await
        .expect("bind");
    let address = beep.local_addr().expect("local address").to_string();
    tokio::spawn(beep.serve());

    let error = within(vortice_ws::connect(
        address.as_str(),
        &address,
        "/",
        Config::new(Role::Initiator),
    ))
    .await
    .expect_err("a plain BEEP listener cannot answer a websocket handshake");

    // It greets rather than answering, so the handshake reader sees no status line it knows.
    assert!(
        matches!(
            error,
            vortice_ws::Error::NotUpgraded { .. } | vortice_ws::Error::Handshake { .. }
        ),
        "expected a handshake failure, got {error}"
    );
}
