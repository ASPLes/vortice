// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Two Vortice sessions wired to each other with no socket in between.
//!
//! `tokio::io::duplex` satisfies `AsyncRead + AsyncWrite`, which is all
//! [`Connection::from_io`] asks for, so the whole driver — greeting exchange, channel
//! management, the reply routing — runs without touching the network.

use std::time::Duration;

use tokio::io::duplex;
use vortice::{Config, Connection, Error, Profile, Role};

const ECHO: &str = "http://iana.org/beep/transient/vortex-regression";

/// Fails loudly instead of hanging when something never completes.
async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("operation timed out")
}

/// Brings up both ends of a session over an in-memory pipe.
async fn pair() -> (Connection, Connection) {
    let (client_io, server_io) = duplex(64 * 1024);

    let server = tokio::spawn(Connection::from_io(
        server_io,
        Config::new(Role::Listener).with_profile(ECHO),
    ));
    let client = Connection::from_io(client_io, Config::new(Role::Initiator).with_profile(ECHO));

    let (client, server) = tokio::join!(within(client), within(server));
    (
        client.expect("client session"),
        server.expect("server task").expect("server session"),
    )
}

#[tokio::test]
async fn exchanges_greetings_over_an_in_memory_pipe() {
    let (client, server) = pair().await;
    assert!(client.peer_greeting().advertises(ECHO));
    assert!(server.peer_greeting().advertises(ECHO));
}

#[tokio::test]
async fn a_peer_that_serves_nothing_refuses_a_channel() {
    // Serving profiles is phase F4, so the answer is a proper BEEP refusal rather than a
    // hang or a panic. The round trip itself is what this exercises: start, error, routed
    // back to the caller that asked.
    let (client, _server) = pair().await;

    let error = within(client.open_channel(Profile::new(ECHO)))
        .await
        .expect_err("the peer serves no profiles yet");
    match error {
        Error::Refused(reply) => assert_eq!(reply.code, vortice::code::REQUESTED_ACTION_NOT_TAKEN),
        other => panic!("expected a refusal, got {other}"),
    }
}

#[tokio::test]
async fn closing_the_session_is_agreed_with_the_peer() {
    let (client, _server) = pair().await;
    within(client.close()).await.expect("close the session");
}

#[tokio::test]
async fn operations_after_the_transport_dies_report_it() {
    let (client_io, server_io) = duplex(64 * 1024);
    let server = tokio::spawn(Connection::from_io(
        server_io,
        Config::new(Role::Listener).with_profile(ECHO),
    ));
    let client = within(Connection::from_io(
        client_io,
        Config::new(Role::Initiator).with_profile(ECHO),
    ))
    .await
    .expect("client session");

    // Dropping the server ends its half of the pipe.
    drop(
        within(server)
            .await
            .expect("server task")
            .expect("server session"),
    );

    let error = within(client.open_channel(Profile::new(ECHO)))
        .await
        .expect_err("the transport is gone");
    assert!(matches!(error, Error::Closed), "got {error}");
}
