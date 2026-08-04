// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Delivers the same octets in arbitrary chunks, the way a real socket does.
//!
//! This is the target that matters most: a decoder can be perfectly correct on whole
//! buffers and still lose or duplicate data when a frame straddles two reads. The property
//! asserted is that fragmentation is invisible — feeding the octets in arbitrary pieces
//! must yield exactly the frames feeding them in one piece yields.

#![no_main]

use arbitrary::Arbitrary;
use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use vortice_proto::codec::Decoder;
use vortice_proto::Frame;

#[derive(Debug, Arbitrary)]
struct Input {
    /// How many octets to append before each decode attempt, cycled through.
    chunks: Vec<u8>,
    /// The octets to deliver.
    data: Vec<u8>,
}

/// Decodes everything available, stopping at the first error.
fn drain(decoder: &mut Decoder, buf: &mut BytesMut, out: &mut Vec<Frame>) -> bool {
    loop {
        match decoder.decode(buf) {
            Ok(Some(frame)) => out.push(frame),
            Ok(None) => return true,
            Err(_) => return false,
        }
    }
}

fuzz_target!(|input: Input| {
    // Reference: everything at once.
    let mut whole = BytesMut::from(&input.data[..]);
    let mut expected = Vec::new();
    let whole_ok = drain(&mut Decoder::new(), &mut whole, &mut expected);

    // Under test: the same octets in arbitrary pieces.
    let sizes: Vec<usize> = input
        .chunks
        .iter()
        .map(|&size| usize::from(size).max(1))
        .collect();
    let mut decoder = Decoder::new();
    let mut buf = BytesMut::new();
    let mut actual = Vec::new();
    let mut rest = &input.data[..];
    let mut fragmented_ok = true;
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
        buf.extend_from_slice(head);
        rest = tail;
        if !drain(&mut decoder, &mut buf, &mut actual) {
            fragmented_ok = false;
            break;
        }
    }

    // A run that errored may stop earlier than the reference one, so only compare the
    // frames both runs got to, and require agreement on whichever prefix is shared.
    if whole_ok && fragmented_ok {
        assert_eq!(
            actual, expected,
            "fragmented delivery produced different frames"
        );
    } else {
        let shared = actual.len().min(expected.len());
        assert_eq!(
            actual[..shared],
            expected[..shared],
            "fragmented delivery diverged before the error"
        );
    }
});
