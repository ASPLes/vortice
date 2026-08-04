// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Feeds arbitrary payloads to the channel-management parser.
//!
//! As with the greeting, anything that parses must render back to something that parses to
//! an equal value: the escaping on the way out has to undo exactly what the entity expansion
//! and `CDATA` handling do on the way in.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vortice_proto::management::Message;

fuzz_target!(|data: &[u8]| {
    let Ok(message) = Message::from_payload(data) else {
        return;
    };
    let rendered = message.to_payload();
    let reparsed = Message::from_payload(&rendered).expect("rendered message must parse");
    assert_eq!(reparsed, message, "rendering changed the message");
});
