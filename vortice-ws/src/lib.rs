// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! BEEP carried over WebSocket (RFC6455), so it reaches through infrastructure that only
//! passes web traffic.
//!
//! An `Upgrade: BEEP` header, which [`vortice-http`](https://docs.rs/vortice-http) uses, is
//! the tidier mechanism but the more fragile one in the field: an intermediary that does not
//! recognise the token may strip it, and the connection then quietly stays HTTP. WebSocket is
//! the mechanism that survives the public internet, because proxies, load balancers and
//! corporate egress filters all handle it deliberately.
//!
//! The whole binding is [`WsStream`], which implements `AsyncRead` and `AsyncWrite`. The BEEP
//! layer above it needs no change and never learns it is not on a socket.
//!
//! ```no_run
//! # async fn example() -> vortice_ws::Result<()> {
//! use vortice::{Config, Profile, Role, Router};
//!
//! // Server: the same shape as `vortice::Server`.
//! let server = vortice_ws::Server::bind("0.0.0.0:44013", Router::new()).await?;
//! tokio::spawn(server.serve());
//!
//! // Client.
//! let session = vortice_ws::connect(
//!     "127.0.0.1:44013",
//!     "127.0.0.1:44013",
//!     "/",
//!     Config::new(Role::Initiator),
//! )
//! .await?;
//! # let _ = session;
//! # Ok(())
//! # }
//! ```
//!
//! # What the binding is
//!
//! BEEP is already a framed protocol with its own sequencing and flow control, so WebSocket
//! is used purely as a tunnel: the payload of the data frames, concatenated, is the BEEP
//! octet stream. Ping, pong and close are handled by this crate and never reach the session.
//!
//! Message boundaries therefore carry no information, and **on receive** none is assumed: a
//! BEEP frame may arrive split across WebSocket frames, or several may share one, and both
//! are read the same way.
//!
//! **On send**, however, each WebSocket frame carries exactly one BEEP frame. That is not an
//! optimisation, it is what the binding is in practice — see the interoperability note
//! below.
//!
//! No subprotocol is negotiated. LibVortex does not send `Sec-WebSocket-Protocol`, and
//! requiring one would refuse every existing deployment for no gain.
//!
//! # Interoperating with LibVortex
//!
//! LibVortex sends BEEP in WebSocket **text** frames (`nopoll_conn_send_text`), whatever the
//! payload holds. RFC6455 §5.6 requires a text frame's payload to be valid UTF-8, and BEEP
//! payloads are arbitrary octets — the regression suite's own `test_01a` sends zeroed binary
//! frames and `test_04ab` sends files. A conforming WebSocket peer must fail such a
//! connection, and a strict library will: this is the one place where interoperating and
//! conforming genuinely pull apart.
//!
//! This crate resolves it the way Postel's rule suggests, and the asymmetry is deliberate:
//!
//! - **Sending**, it emits binary frames, which is what RFC6455 says arbitrary octets are
//!   for. noPoll's receive path dispatches on the opcode only to separate control frames from
//!   data, so binary is accepted by an unmodified LibVortex.
//! - **Receiving**, it accepts a text frame's payload without validating UTF-8, because
//!   rejecting it would make every LibVortex peer unreachable while protecting nothing: the
//!   octets go to a BEEP parser that has no opinion about encoding.
//!
//! The result interoperates in both directions and puts nothing non-conforming on the wire.
//! A peer that is strict about what it receives sees only valid binary frames from us.
//!
//! The second is the framing rule above. LibVortex could not read a WebSocket frame carrying
//! more than one BEEP frame: it took the first and left the rest in noPoll's buffer, where
//! `select` cannot see it, and the session then stalled and the connection died. That has
//! since been fixed upstream — the reader now drains the transport instead of assuming one
//! frame per readable event — but the alignment stays, and not only for deployed peers that
//! predate the fix: one BEEP frame per WebSocket frame is what every LibVortex on the wire
//! already sends, and a WebSocket header is two to four octets, so it is the safer default
//! either way. [`vortice_proto::codec::frame_boundary`] finds the boundary; no BEEP parsing
//! is duplicated here.
//!
//! # Sharing a port with plain BEEP
//!
//! [`serve_shared`] takes either on one port, deciding per connection from the first four
//! octets. This is what LibVortex calls transparent port sharing.

#![forbid(unsafe_code)]

mod client;
mod codec;
mod digest;
mod error;
mod frame;
mod handshake;
mod server;
mod stream;

pub use client::{connect, connect_over};
pub use error::{Error, Result};
pub use frame::ProtocolError;
pub use handshake::accept_key;
pub use server::{Server, accept, serve, serve_shared};
pub use stream::WsStream;

/// The path a Vortice WebSocket server conventionally answers on.
///
/// Nothing enforces it — [`Server`] answers a handshake on any path, as LibVortex does — and
/// it is here so that both ends of an example agree.
pub const DEFAULT_PATH: &str = "/";
