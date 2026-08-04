// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Feeds arbitrary payloads to the greeting parser, and with it to the XML reader.
//!
//! Beyond "does not panic", any greeting that parses must render back to a payload that
//! parses to an equal greeting: the escaping done on the way out has to undo exactly what
//! the entity expansion does on the way in.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vortice_proto::greeting::Greeting;

fuzz_target!(|data: &[u8]| {
    let Ok(greeting) = Greeting::from_payload(data) else {
        return;
    };
    let rendered = greeting.to_payload();
    let reparsed = Greeting::from_payload(&rendered).expect("rendered greeting must parse");
    assert_eq!(reparsed, greeting, "rendering changed the greeting");
});
