// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! One port taking both plain BEEP and BEEP over WebSocket.
//!
//! LibVortex calls this transparent port sharing, and `test_20` is the suite's check of it.

use std::time::Duration;

use vortice::{Config, Message, Profile, Responder, Role, Router};

const ECHO: &str = "urn:example:echo";

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .expect("operation timed out")
}

fn echo_router() -> Router {
    Router::new().profile(ECHO, |responder: Responder, message: Message| async move {
        let _ = responder.reply(message.msgno, message.payload).await;
    })
}

/// A shared-port listener on an ephemeral port.
async fn start() -> String {
    let server = vortice_ws::Server::bind_with(
        "127.0.0.1:0",
        Config::new(Role::Listener).with_profile(ECHO),
        echo_router(),
    )
    .await
    .expect("bind")
    .with_plain_beep();

    let address = server.local_addr().expect("local address").to_string();
    tokio::spawn(server.serve());
    address
}

/// Opens a channel, echoes through it, and returns what came back.
async fn echo(session: &vortice::Connection, payload: &str) -> Vec<u8> {
    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open the echo channel");
    within(channel.request(payload.to_owned()))
        .await
        .expect("reply")
        .payload()
        .to_vec()
}

#[tokio::test]
async fn one_port_takes_plain_beep_and_websocket() {
    let address = start().await;

    // Plain BEEP, the way `vortice::Connection::connect` speaks.
    let plain = within(vortice::Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator).with_profile(ECHO),
    ))
    .await
    .expect("a plain BEEP session");
    assert_eq!(echo(&plain, "over tcp").await, b"over tcp");

    // The same port, now spoken to through a WebSocket handshake.
    let tunnelled = within(vortice_ws::connect(
        address.as_str(),
        &address,
        "/",
        Config::new(Role::Initiator).with_profile(ECHO),
    ))
    .await
    .expect("a websocket session");
    assert_eq!(echo(&tunnelled, "over websocket").await, b"over websocket");

    within(plain.close())
        .await
        .expect("close the plain session");
    within(tunnelled.close())
        .await
        .expect("close the tunnelled session");
}

/// The two kinds of session must be able to overlap, not merely alternate.
#[tokio::test]
async fn both_kinds_of_session_run_at_the_same_time() {
    let address = start().await;

    let plain = within(vortice::Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator).with_profile(ECHO),
    ))
    .await
    .expect("a plain BEEP session");
    let tunnelled = within(vortice_ws::connect(
        address.as_str(),
        &address,
        "/",
        Config::new(Role::Initiator).with_profile(ECHO),
    ))
    .await
    .expect("a websocket session");

    let (from_plain, from_tunnel) = tokio::join!(
        echo(&plain, "concurrent tcp"),
        echo(&tunnelled, "concurrent websocket"),
    );
    assert_eq!(from_plain, b"concurrent tcp");
    assert_eq!(from_tunnel, b"concurrent websocket");
}
