// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Drives a whole session from hostile octets.
//!
//! This is the target that stands in for a malicious peer: it feeds arbitrary input to a
//! [`Session`] in arbitrary chunks and drains whatever comes out. Nothing may panic — an
//! ill-formed peer must produce an error and a closed session, never a crash. It is the
//! sans-IO analogue of what LibVortex `test_01g1` and `test_01h` do over a raw socket.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use vortice_proto::session::{Config, Role, Session};

#[derive(Debug, Arbitrary)]
struct Input {
    /// Whether the session under test initiated or listened.
    listener: bool,
    /// How many octets to deliver before each drain, cycled through.
    chunks: Vec<u8>,
    /// The octets a hostile peer sends.
    data: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let role = if input.listener {
        Role::Listener
    } else {
        Role::Initiator
    };
    let mut session = Session::new(Config::new(role).with_profile("urn:fuzz"));

    // Whatever the session wanted to say on construction is of no interest here.
    while session.poll_transmit().is_some() {}

    let sizes: Vec<usize> = input
        .chunks
        .iter()
        .map(|&size| usize::from(size).max(1))
        .collect();
    let mut rest = &input.data[..];
    let mut next = 0usize;

    while !rest.is_empty() {
        let size = if sizes.is_empty() {
            rest.len()
        } else {
            let size = sizes[next % sizes.len()];
            next += 1;
            size.min(rest.len())
        };
        let (head, tail) = rest.split_at(size);
        rest = tail;

        if session.handle_input(head).is_err() {
            // A fatal protocol error ends the session, exactly as it would on a socket.
            break;
        }
        while session.poll_event().is_some() {}
        while session.poll_transmit().is_some() {}
    }
});
