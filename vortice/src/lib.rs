// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! BEEP (RFC3080/RFC3081) for Rust, asynchronous.
//!
//! This crate puts a tokio driver around [`vortice_proto`], which holds the protocol itself.
//! The split is deliberate: everything that decides what BEEP does lives in the sans-IO
//! core, and everything here is about moving octets and waking tasks.
//!
//! ```no_run
//! use vortice::{Config, Connection, Profile, Role};
//!
//! # async fn example() -> vortice::Result<()> {
//! let echo = "http://iana.org/beep/transient/vortex-regression";
//! let session = Connection::connect("127.0.0.1:44010", Config::new(Role::Initiator).with_profile(echo)).await?;
//!
//! let channel = session.open_channel(Profile::new(echo)).await?;
//! let reply = channel.request("hola").await?;
//! assert_eq!(reply.payload(), b"hola");
//!
//! session.close().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # What the transport has to be
//!
//! [`Connection::from_io`] accepts anything implementing `AsyncRead + AsyncWrite`, which is
//! what makes TCP, TLS, Unix sockets, `tokio::io::duplex` and any user-supplied transport
//! the same case. There is no separate "external transport" API to learn.
//!
//! # Flow control
//!
//! A payload handed to [`Channel::request`] is fragmented to fit the peer's window and
//! paced against the `SEQ` frames it sends back. None of that is visible to the caller.

#![forbid(unsafe_code)]

mod channel;
mod connection;
mod error;
mod router;
mod server;

#[cfg(feature = "tower")]
pub mod service;

pub use channel::{Channel, Message, Reply};
pub use connection::{Connection, SessionId};
pub use error::{Error, Result};
pub use router::{AlwaysRefuse, Handler, HandlerFuture, Responder, Router};
pub use server::Server;

pub use vortice_proto::frame::FrameKind;
pub use vortice_proto::greeting::Greeting;
pub use vortice_proto::management::{ErrorReply, Profile, Start, code};
pub use vortice_proto::session::{Config, Role};
