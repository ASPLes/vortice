// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Base64 as RFC4648 §4 defines it, with padding.
//!
//! Here because two bindings need it and neither should carry a dependency for it: the
//! WebSocket handshake encodes a digest, and the SASL profiles carry every blob this way. It
//! is a transfer encoding with nothing secret in it — the objection to hand-written
//! cryptography does not apply — and both directions are checked against the vectors in
//! RFC4648 §10.
//!
//! Decoding is strict. A SASL blob arrives from the far end of a connection, so anything that
//! is not exactly what the alphabet and the padding rules allow is rejected rather than
//! guessed at: an implementation that accepts sloppy input ends up disagreeing with the peer
//! about what the octets were.

use alloc::string::String;
use alloc::vec::Vec;

/// The alphabet of RFC4648 §4.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `data`, padded to a multiple of four characters.
///
/// ```
/// assert_eq!(vortice_proto::base64::encode(b"foobar"), "Zm9vYmFy");
/// assert_eq!(vortice_proto::base64::encode(b"fo"), "Zm8=");
/// ```
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut encoded = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));

        encoded.push(char::from(ALPHABET[(bits >> 18) as usize & 0x3f]));
        encoded.push(char::from(ALPHABET[(bits >> 12) as usize & 0x3f]));
        encoded.push(if chunk.len() > 1 {
            char::from(ALPHABET[(bits >> 6) as usize & 0x3f])
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            char::from(ALPHABET[bits as usize & 0x3f])
        } else {
            '='
        });
    }

    encoded
}

/// Decodes `text`, which must be padded and hold nothing outside the alphabet.
///
/// Whitespace is the one exception, and only because it is what peers do: a long blob is
/// folded across lines by more than one implementation, and refusing that would be refusing
/// the wire rather than the specification.
///
/// # Errors
///
/// Returns [`NotBase64`] for a length that is not a multiple of four, a character outside the
/// alphabet, padding anywhere but at the end, or bits set in a final character that the
/// padding says are not there.
///
/// ```
/// assert_eq!(vortice_proto::base64::decode("Zm9vYmFy").unwrap(), b"foobar");
/// assert!(vortice_proto::base64::decode("Zm9vYmFy=").is_err());
/// ```
pub fn decode(text: &str) -> Result<Vec<u8>, NotBase64> {
    let packed: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();

    if packed.len() % 4 != 0 {
        return Err(NotBase64);
    }

    let mut decoded = Vec::with_capacity(packed.len() / 4 * 3);
    for (index, quad) in packed.chunks(4).enumerate() {
        let last = index == packed.len() / 4 - 1;
        let padding = if last {
            usize::from(quad[3] == b'=') + usize::from(quad[2] == b'=')
        } else {
            0
        };
        // `=` before the final quad, or in the middle of one, is not padding but a character
        // outside the alphabet, and `value` below refuses it.
        if padding == 2 && quad[2] != b'=' {
            return Err(NotBase64);
        }

        let mut bits = 0u32;
        for (at, byte) in quad.iter().enumerate() {
            let six = if last && at >= 4 - padding {
                0
            } else {
                u32::from(value(*byte)?)
            };
            bits = (bits << 6) | six;
        }

        decoded.push((bits >> 16) as u8);
        if padding < 2 {
            decoded.push((bits >> 8) as u8);
        }
        if padding < 1 {
            decoded.push(bits as u8);
        }

        // The padded characters stand for bits that are not there, and a peer that leaves
        // them set is sending something other than what it thinks it is.
        if padding > 0 && (bits & ((1 << (padding * 8)) - 1)) != 0 {
            return Err(NotBase64);
        }
    }

    Ok(decoded)
}

/// What [`decode`] reports for input that is not Base64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotBase64;

impl core::fmt::Display for NotBase64 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("not valid Base64")
    }
}

impl core::error::Error for NotBase64 {}

/// The six bits a character stands for.
fn value(byte: u8) -> Result<u8, NotBase64> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(NotBase64),
    }
}

#[cfg(test)]
mod tests {
    use super::{NotBase64, decode, encode};
    use alloc::vec::Vec;

    /// The vectors of RFC4648 §10, both ways.
    #[test]
    fn matches_the_rfc4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded, "encoding {plain:?}");
            assert_eq!(
                decode(encoded).expect("the vectors decode"),
                plain.as_bytes(),
                "decoding {encoded:?}"
            );
        }
    }

    /// Whatever goes in comes back, including octets no text encoding would produce.
    #[test]
    fn survives_a_round_trip_over_every_octet() {
        let every: Vec<u8> = (0..=255).collect();
        for length in 0..every.len() {
            let data = &every[..length];
            assert_eq!(decode(&encode(data)).expect("round trip"), data);
        }
    }

    #[test]
    fn refuses_what_is_not_base64() {
        for bad in [
            "Zm9vYmFy=", // length not a multiple of four
            "Zm9v YmF",  // likewise, once whitespace is dropped
            "Zm9*YmFy",  // outside the alphabet
            "Zm==Zm9v",  // padding before the last quad
            "Zm9=",      // padding in the middle of a quad
            "Zm9vYm=y",  // padding followed by a character
            "Zh==",      // bits set where the padding says there are none
        ] {
            assert_eq!(decode(bad), Err(NotBase64), "{bad:?} should be refused");
        }
    }

    /// Folded across lines is what more than one peer sends.
    #[test]
    fn accepts_a_blob_folded_across_lines() {
        assert_eq!(decode("Zm9v\r\nYmFy\n").expect("folded input"), b"foobar");
    }
}
