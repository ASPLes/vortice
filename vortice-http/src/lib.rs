// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! BEEP reached through an HTTP/1.1 upgrade, so it can share a port with an HTTP server.
//!
//! BEEP expects a port of its own — 602 — and modern infrastructure is built around 443 and
//! around HTTP semantics on top of it. That makes a plain BEEP listener hard to deploy:
//! managed ingresses, corporate egress filters and CDNs are all in the way. Reaching it
//! through an upgrade on the port the HTTP service already uses removes the problem.
//!
//! What that buys is not a saved port. It is that the BEEP endpoint inherits everything the
//! HTTP server already has — TLS termination, edge authentication, rate limiting, `/health`,
//! `/metrics` — and that the two are the same process, sharing state with no IPC.
//!
//! ```text
//! C→S  GET /beep HTTP/1.1
//!      Host: api.example.com
//!      Connection: Upgrade
//!      Upgrade: BEEP
//!
//! S→C  HTTP/1.1 101 Switching Protocols
//!      Connection: Upgrade
//!      Upgrade: BEEP
//!
//!      ── from here on the socket is no longer HTTP ──
//! S→C  RPY 0 0 . 0 52\r\nContent-Type: application/beep+xml\r\n\r\n<greeting/>...
//! ```
//!
//! # Server
//!
//! With the `axum` feature, a BEEP endpoint is one more route:
//!
//! ```no_run
//! # #[cfg(feature = "axum")] {
//! use axum::{Router as HttpRouter, routing::get};
//! use vortice::{Config, Role, Router};
//! use vortice_http::BeepUpgrade;
//!
//! async fn beep(upgrade: BeepUpgrade) -> axum::response::Response {
//!     upgrade.serve(Config::new(Role::Listener), Router::new())
//! }
//!
//! let app: HttpRouter = HttpRouter::new()
//!     .route("/health", get(|| async { "ok" }))
//!     .route("/beep", get(beep));
//! # let _ = app;
//! # }
//! ```
//!
//! Without it, [`serve_upgraded`] takes hyper's `OnUpgrade` directly, which is all the axum
//! extractor does underneath.
//!
//! # The upgrade token
//!
//! [`UPGRADE_TOKEN`] is `BEEP`. No such token is registered with IANA — RFC3080 predates the
//! practice — so this is a convention of this project, and both ends have to agree on it.
//! For traffic crossing the public internet prefer BEEP over WebSocket, which intermediaries
//! pass reliably where they may strip an `Upgrade` header they do not recognise.

#![forbid(unsafe_code)]

mod client;
mod error;
mod rewind;
mod server;

pub use client::connect;
pub use error::{Error, Result};
pub use rewind::Rewind;
pub use server::{is_beep_upgrade, serve_upgraded};

#[cfg(feature = "axum")]
pub use server::BeepUpgrade;

/// The token naming BEEP in an `Upgrade` header.
pub const UPGRADE_TOKEN: &str = "BEEP";

/// The path a Vortice server conventionally serves the upgrade on.
///
/// Nothing enforces it; it is a default so that both ends of an example agree.
pub const DEFAULT_PATH: &str = "/beep";
