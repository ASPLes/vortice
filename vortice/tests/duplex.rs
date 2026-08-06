// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Two Vortice sessions wired to each other with no socket in between.
//!
//! `tokio::io::duplex` satisfies `AsyncRead + AsyncWrite`, which is all
//! [`Connection::from_io`] asks for, so the whole driver — greeting exchange, channel
//! management, profile serving, reply routing — runs without touching the network.

use std::time::Duration;

use tokio::io::duplex;
use vortice::{
    AlwaysRefuse, Config, Connection, Error, Message, Profile, Responder, Role, Router, code,
};

const ECHO: &str = "http://iana.org/beep/transient/vortex-regression";
const DENY_SUPPORTED: &str = "http://iana.org/beep/transient/vortex-regression/deny_supported";

/// Fails loudly instead of hanging when something never completes.
async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("operation timed out")
}

/// The profiles the serving end offers in these tests.
fn router() -> Router {
    Router::new()
        .profile(ECHO, |responder: Responder, message: Message| async move {
            let _ = responder.reply(message.msgno, message.payload).await;
        })
        .profile(
            DENY_SUPPORTED,
            AlwaysRefuse::new(code::SERVICE_NOT_AVAILABLE),
        )
}

/// Brings up a client and a serving peer over an in-memory pipe.
async fn pair() -> (Connection, Connection) {
    let (client_io, server_io) = duplex(64 * 1024);

    let server = tokio::spawn(Connection::serve_io(
        server_io,
        Config::new(Role::Listener)
            .with_profile(ECHO)
            .with_profile(DENY_SUPPORTED),
        router(),
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
async fn a_served_profile_answers() {
    let (client, _server) = pair().await;
    let channel = within(client.open_channel(Profile::new(ECHO)))
        .await
        .expect("open the echo channel");

    let reply = within(channel.request("hola")).await.expect("echo reply");
    assert!(reply.is_ok(), "expected a positive reply, got {reply:?}");
    assert_eq!(reply.payload(), b"hola");
}

#[tokio::test]
async fn an_unserved_profile_is_refused_as_unsupported() {
    let (client, _server) = pair().await;
    let error = within(client.open_channel(Profile::new("urn:absent")))
        .await
        .expect_err("nothing serves that profile");
    match error {
        // 554 is what LibVortex reports for a profile that is not registered at all, and
        // what its test_02 asserts on.
        Error::Refused(reply) => assert_eq!(reply.code, code::TRANSACTION_FAILED),
        other => panic!("expected a refusal, got {other}"),
    }
}

#[tokio::test]
async fn a_profile_that_refuses_is_told_apart_from_one_that_is_absent() {
    let (client, _server) = pair().await;
    let error = within(client.open_channel(Profile::new(DENY_SUPPORTED)))
        .await
        .expect_err("that profile always refuses");
    match error {
        Error::Refused(reply) => assert_eq!(reply.code, code::SERVICE_NOT_AVAILABLE),
        other => panic!("expected a refusal, got {other}"),
    }
}

/// The shape of LibVortex `test_02_common`: many channels on one session, a message on each.
#[tokio::test]
async fn carries_many_channels_on_one_session() {
    let (client, _server) = pair().await;

    let mut channels = Vec::new();
    for index in 0..24u32 {
        let channel = within(client.open_channel(Profile::new(ECHO)))
            .await
            .unwrap_or_else(|error| panic!("failed to open channel {index}: {error}"));
        channels.push(channel);
    }

    for (index, channel) in channels.iter().enumerate() {
        let payload = format!("Message: {index}");
        let reply = within(channel.request(payload.clone()))
            .await
            .unwrap_or_else(|error| panic!("no reply on channel {index}: {error}"));
        assert_eq!(reply.payload(), payload.as_bytes());
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
    let server = tokio::spawn(Connection::serve_io(
        server_io,
        Config::new(Role::Listener).with_profile(ECHO),
        router(),
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
