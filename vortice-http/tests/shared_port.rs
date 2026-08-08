// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! BEEP and HTTP answering on the same port, in the same process.
//!
//! This is the phase F5 exit criterion for the upgrade mechanism: one axum router serving
//! `/health`, a REST route and `/beep`, exercised concurrently over a single port.

#![cfg(feature = "axum")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Router as HttpRouter, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vortice::{Config, Message, Profile, Responder, Role, Router};
use vortice_http::BeepUpgrade;

const ECHO: &str = "urn:example:echo";

/// Counts what each side of the process has handled, to prove they really are one process.
#[derive(Debug, Default)]
struct Counters {
    http: AtomicU64,
    beep: AtomicU64,
}

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .expect("operation timed out")
}

/// Starts the shared-port server on an ephemeral port and returns its address.
async fn start() -> (String, Arc<Counters>) {
    let counters = Arc::new(Counters::default());
    let state = Arc::clone(&counters);

    let app = HttpRouter::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/v1/echo",
            post(
                |State(counters): State<Arc<Counters>>, body: String| async move {
                    counters.http.fetch_add(1, Ordering::Relaxed);
                    body
                },
            ),
        )
        .route("/beep", get(beep))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address").to_string();
    tokio::spawn(async move {
        let _ = serve(listener, app).await;
    });

    (address, counters)
}

async fn beep(State(counters): State<Arc<Counters>>, upgrade: BeepUpgrade) -> Response {
    let router = Router::new().profile(ECHO, move |responder: Responder, message: Message| {
        let counters = Arc::clone(&counters);
        async move {
            counters.beep.fetch_add(1, Ordering::Relaxed);
            let _ = responder.reply(message.msgno, message.payload).await;
        }
    });
    upgrade.serve(Config::new(Role::Listener).with_profile(ECHO), router)
}

/// Issues one HTTP request by hand and returns the status line and body.
async fn http_request(address: &str, request: &str) -> (String, String) {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream.write_all(request.as_bytes()).await.expect("write");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read");
    let response = String::from_utf8_lossy(&response).into_owned();

    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
    let status = head.lines().next().unwrap_or_default().to_owned();
    (status, body.to_owned())
}

#[tokio::test]
async fn http_and_beep_answer_on_one_port() {
    let (address, counters) = start().await;

    // 1. The health route, plain HTTP.
    let (status, body) = within(http_request(
        &address,
        &format!("GET /health HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"),
    ))
    .await;
    assert!(status.contains("200"), "health said {status}");
    assert_eq!(body, "ok");

    // 2. The REST route, same port.
    let (status, body) = within(http_request(
        &address,
        &format!(
            "POST /v1/echo HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\
             Content-Length: 4\r\n\r\nhola"
        ),
    ))
    .await;
    assert!(status.contains("200"), "echo said {status}");
    assert_eq!(body, "hola");

    // 3. BEEP, same port, reached by upgrading.
    let session = within(vortice_http::connect(
        address.as_str(),
        &address,
        "/beep",
        Config::new(Role::Initiator).with_profile(ECHO),
    ))
    .await
    .expect("upgrade to BEEP");

    assert!(
        session.peer_greeting().advertises(ECHO),
        "the upgraded session should carry a BEEP greeting"
    );

    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open the echo channel");
    let reply = within(channel.request("over beep")).await.expect("reply");
    assert_eq!(reply.payload(), b"over beep");

    // Both sides ran in the same process, over the same port.
    assert_eq!(counters.http.load(Ordering::Relaxed), 1);
    assert_eq!(counters.beep.load(Ordering::Relaxed), 1);

    within(session.close()).await.expect("close the session");
}

#[tokio::test]
async fn a_large_payload_survives_the_upgraded_transport() {
    let (address, _counters) = start().await;
    let session = within(vortice_http::connect(
        address.as_str(),
        &address,
        "/beep",
        Config::new(Role::Initiator).with_profile(ECHO),
    ))
    .await
    .expect("upgrade to BEEP");

    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open the echo channel");

    // Sixteen times the default window, so the whole fragmentation and SEQ pacing path runs
    // over a connection hyper handed over rather than one Vortice opened itself.
    let payload: Vec<u8> = (0..64 * 1024u32).map(|index| (index % 251) as u8).collect();
    let reply = within(channel.request(payload.clone()))
        .await
        .expect("reply");
    assert_eq!(reply.payload(), &payload[..]);
}

#[tokio::test]
async fn a_request_without_the_upgrade_headers_is_refused() {
    let (address, _counters) = start().await;
    let (status, _) = within(http_request(
        &address,
        &format!("GET /beep HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"),
    ))
    .await;
    assert!(
        status.contains("400"),
        "a plain GET on the BEEP route should be refused, got {status}"
    );
}

#[tokio::test]
async fn upgrading_a_route_that_does_not_serve_beep_fails_cleanly() {
    let (address, _counters) = start().await;
    let error = within(vortice_http::connect(
        address.as_str(),
        &address,
        "/health",
        Config::new(Role::Initiator),
    ))
    .await
    .expect_err("/health does not upgrade");

    assert!(
        matches!(error, vortice_http::Error::NotUpgraded { .. }),
        "expected a status other than 101, got {error}"
    );
}
