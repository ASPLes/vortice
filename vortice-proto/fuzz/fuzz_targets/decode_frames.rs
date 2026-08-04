// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Feeds arbitrary octets to the frame decoder.
//!
//! Two properties are asserted beyond "does not panic":
//!
//! - when the decoder returns `None` without having parsed a header, it leaves the buffer
//!   untouched, so the caller can simply append more octets and retry (once a header *has*
//!   been parsed it is legitimately consumed and held in the decoder);
//! - every frame that decodes re-encodes to octets that decode back to an equal frame,
//!   which is what keeps the encoder and the decoder from drifting apart.

#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use vortice_proto::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut decoder = Decoder::new();
    let mut buf = BytesMut::from(data);

    loop {
        let before = buf.len();
        match decoder.decode(&mut buf) {
            Ok(Some(frame)) => {
                let mut round_trip = BytesMut::with_capacity(frame.encoded_len());
                frame.encode(&mut round_trip);
                assert_eq!(
                    round_trip.len(),
                    frame.encoded_len(),
                    "encoded_len disagrees with encode"
                );

                let decoded = Decoder::new()
                    .decode(&mut round_trip)
                    .expect("re-encoded frame must decode")
                    .expect("re-encoded frame must be complete");
                assert_eq!(decoded, frame, "round trip changed the frame");
                assert!(round_trip.is_empty(), "round trip left octets behind");
            }
            Ok(None) => {
                if !decoder.has_partial_frame() {
                    assert_eq!(
                        buf.len(),
                        before,
                        "decoder consumed octets without parsing a header"
                    );
                }
                break;
            }
            Err(_) => break,
        }
    }
});
