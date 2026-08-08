// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Serving a profile with a `tower::Service`, middleware and all.
//!
//! The point of the integration is that nothing about the middleware is Vortice's code: a
//! timeout, a concurrency limit or a tracing layer written for tower applies to a BEEP
//! profile unchanged. These tests check that the plumbing really does carry a layered
//! service, including the case where a layer — not the profile — decides to fail.

#![cfg(feature = "tower")]

use std::convert::Infallible;
use std::time::Duration;

use tokio::io::duplex;
use tower::ServiceBuilder;
use vortice::service::{Request, Response, service_fn};
use vortice::{Config, Connection, Profile, Role, Router};

const ECHO: &str = "urn:example:echo";
const SLOW: &str = "urn:example:slow";

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("operation timed out")
}

/// Brings up a client against a peer serving `router`.
///
/// Both handles are returned: dropping the server one would close the session under the
/// client's feet.
async fn pair(router: Router) -> (Connection, Connection) {
    let (client_io, server_io) = duplex(64 * 1024);
    let server = tokio::spawn(Connection::serve_io(
        server_io,
        Config::new(Role::Listener),
        router,
    ));
    let client = Connection::from_io(client_io, Config::new(Role::Initiator));
    let (client, server) = tokio::join!(within(client), within(server));

    (
        client.expect("client session"),
        server.expect("server task").expect("server session"),
    )
}

#[tokio::test]
async fn a_tower_service_serves_a_profile() {
    let echo = service_fn(|request: Request| async move {
        Ok::<_, Infallible>(Response::Rpy(request.message.payload))
    });
    let (client, _server) = pair(Router::new().service(ECHO, echo)).await;

    let channel = within(client.open_channel(Profile::new(ECHO)))
        .await
        .expect("open the channel");
    let reply = within(channel.request("hola")).await.expect("reply");
    assert_eq!(reply.payload(), b"hola");
}

#[tokio::test]
async fn a_service_may_answer_one_to_many() {
    let listing = service_fn(|_: Request| async move {
        Ok::<_, Infallible>(Response::Answers(vec![
            bytes::Bytes::from_static(b"one"),
            bytes::Bytes::from_static(b"two"),
        ]))
    });
    let (client, _server) = pair(Router::new().service(ECHO, listing)).await;

    let channel = within(client.open_channel(Profile::new(ECHO)))
        .await
        .expect("open the channel");
    let reply = within(channel.request("list")).await.expect("reply");
    assert_eq!(reply.answers().len(), 2, "got {reply:?}");
    assert_eq!(reply.answers()[0], b"one"[..]);
    assert_eq!(reply.answers()[1], b"two"[..]);
}

#[tokio::test]
async fn a_tower_layer_that_fails_is_reported_to_the_peer() {
    // The profile itself would answer eventually; the timeout layer decides it will not.
    // Nothing in Vortice knows what a timeout is — that is the whole point.
    let slow = service_fn(|_: Request| async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok::<_, Infallible>(Response::rpy("too late"))
    });
    let guarded = ServiceBuilder::new()
        .timeout(Duration::from_millis(50))
        .service(slow);
    let (client, _server) = pair(Router::new().service(SLOW, guarded)).await;

    let channel = within(client.open_channel(Profile::new(SLOW)))
        .await
        .expect("open the channel");
    let reply = within(channel.request("wait for it"))
        .await
        .expect("the layer should answer even though the profile did not");

    assert!(
        !reply.is_ok(),
        "expected the timeout to become a negative reply, got {reply:?}"
    );
    assert!(
        !reply.payload().is_empty(),
        "the refusal should carry the layer's reason"
    );
}
