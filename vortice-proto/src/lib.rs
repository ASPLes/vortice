// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Sans-IO core of Vortice.
//!
//! This crate contains no sockets, no async runtime and no threads: it is a pure state
//! machine that turns octets into BEEP frames and back. Everything here is deterministic
//! and directly reachable from unit tests, property tests and fuzz targets.
//!
//! The wire behaviour implemented here is deliberately aligned with
//! [LibVortex 1.1](https://github.com/ASPLes/libvortex-1.1), which is the reference
//! implementation and conformance oracle for this project. Where the two could disagree,
//! the LibVortex parser (`src/vortex_frame_factory.c`) is treated as authoritative and the
//! divergence is documented at the point where it is introduced.
//!
//! # Layers
//!
//! - [`frame`] — frame types and the numeric limits BEEP places on header fields.
//! - [`codec`] — incremental [`Decoder`](codec::Decoder) turning a byte buffer into frames.
//! - [`mime`] — minimal MIME splitting, enough for channel-management messages.
//! - [`greeting`] — the greeting exchange on channel 0.
//! - [`management`] — the `<start>`/`<close>` vocabulary of channel 0.
//! - [`window`] — sequence number arithmetic and the sliding window.
//! - [`channel`] — per-channel numbering, flow control and fragment reassembly.
//!
//! # Example
//!
//! ```
//! use bytes::BytesMut;
//! use vortice_proto::codec::Decoder;
//! use vortice_proto::greeting::Greeting;
//!
//! let greeting = Greeting::new().with_profile("urn:example:echo");
//! let mut buf = BytesMut::new();
//! greeting.to_frame(0).unwrap().encode(&mut buf);
//!
//! let mut decoder = Decoder::new();
//! let frame = decoder.decode(&mut buf).unwrap().expect("a complete frame");
//! let parsed = Greeting::from_payload(frame.as_data().unwrap().payload()).unwrap();
//! assert!(parsed.advertises("urn:example:echo"));
//! ```

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod channel;
pub mod codec;
pub mod error;
pub mod frame;
pub mod greeting;
pub mod management;
pub mod mime;
pub mod session;
pub mod window;

mod xml;

pub use error::Error;
pub use frame::{DataFrame, Frame, FrameKind, SeqFrame};
pub use window::{SeqNo, Window};
