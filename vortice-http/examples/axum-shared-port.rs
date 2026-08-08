// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! A REST API and a BEEP endpoint on one port, in one process.
//!
//! ```sh
//! cargo run -p vortice-http --features axum --example axum-shared-port -- --port=18080
//!
//! curl -s localhost:18080/health
//! curl -s -X POST localhost:18080/v1/echo -d 'hola'
//! ```
//!
//! The BEEP side is reached by upgrading `/beep`, which
//! `vortice_http::connect(address, address, "/beep", config)` does.
//!
//! Nothing here is a bridge or a proxy: `/v1/echo` and `/beep` are routes of the same axum
//! router, so they share the port, the TLS configuration a reverse proxy terminates in front
//! of them, and any state the process holds.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Router as HttpRouter, response::Response};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use vortice::{Config, Message, Responder, Role, Router};
use vortice_http::BeepUpgrade;

/// The profile this example serves over BEEP.
const ECHO: &str = "urn:example:echo";

/// State shared by the HTTP routes and the BEEP profile — the point of one process.
#[derive(Debug, Default)]
struct Counters {
    http: AtomicU64,
    beep: AtomicU64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let counters = Arc::new(Counters::default());

    let app = HttpRouter::new()
        .route("/health", get(health))
        .route("/v1/echo", post(http_echo))
        .route("/beep", get(beep))
        .with_state(Arc::clone(&counters));

    // Configurable because 8080 is a popular port: a development machine often already has
    // something on it, and binding over it is not this example's business.
    let port: u16 = std::env::args()
        .find_map(|arg| arg.strip_prefix("--port=").map(str::to_owned))
        .map_or(Ok(8080), |value| value.parse())?;

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    println!("REST on http://0.0.0.0:{port}/v1/echo, BEEP on the same port at /beep");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(counters): State<Arc<Counters>>) -> String {
    format!(
        "ok\nhttp requests: {}\nbeep messages: {}\n",
        counters.http.load(Ordering::Relaxed),
        counters.beep.load(Ordering::Relaxed),
    )
}

async fn http_echo(State(counters): State<Arc<Counters>>, body: String) -> String {
    counters.http.fetch_add(1, Ordering::Relaxed);
    body
}

/// Upgrades the request and serves BEEP over what comes back.
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
