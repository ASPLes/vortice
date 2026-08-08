// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The two primitives the WebSocket handshake needs.
//!
//! Neither is a security primitive here. RFC6455 §1.3 is explicit that the
//! `Sec-WebSocket-Key` exchange proves nothing about the peer: it exists so that a caching
//! intermediary cannot be tricked into treating a WebSocket handshake as an ordinary
//! response. The SHA-1 is a fixed, publicly computable checksum over a public constant, and
//! nothing downstream trusts it. That is why implementing it here rather than taking a
//! dependency is acceptable — the usual objection to hand-written hashing does not apply to
//! a value with no secret in it and no integrity claim on it.
//!
//! Both are checked against the vectors published in the RFCs.

/// The Base64 alphabet of RFC4648 §4.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `data` as Base64 with padding.
pub(crate) fn base64(data: &[u8]) -> String {
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

/// The SHA-1 digest of `message`, as specified in RFC3174.
pub(crate) fn sha1(message: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];

    let mut blocks = message.chunks_exact(64);
    for block in blocks.by_ref() {
        compress(&mut state, block);
    }

    // The tail is the remainder, a 0x80 terminator, zero padding and the message length in
    // bits. It needs a second block when the remainder leaves no room for those nine octets.
    let remainder = blocks.remainder();
    let tail_len = if remainder.len() + 9 <= 64 { 64 } else { 128 };
    let mut tail = [0u8; 128];
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 0x80;
    let bits = message.len() as u64 * 8;
    tail[tail_len - 8..tail_len].copy_from_slice(&bits.to_be_bytes());
    for block in tail[..tail_len].chunks_exact(64) {
        compress(&mut state, block);
    }

    let mut digest = [0u8; 20];
    for (slot, word) in digest.chunks_exact_mut(4).zip(state) {
        slot.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Mixes one 64-octet block into the running state.
fn compress(state: &mut [u32; 5], block: &[u8]) {
    let mut schedule = [0u32; 80];
    for (word, octets) in schedule.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    }
    for index in 16..80 {
        schedule[index] = (schedule[index - 3]
            ^ schedule[index - 8]
            ^ schedule[index - 14]
            ^ schedule[index - 16])
            .rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (round, word) in schedule.iter().enumerate() {
        let (mixed, constant) = match round {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999u32),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let next = a
            .rotate_left(5)
            .wrapping_add(mixed)
            .wrapping_add(e)
            .wrapping_add(constant)
            .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = next;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::{base64, sha1};

    /// Renders a digest as lowercase hexadecimal, to compare against published vectors.
    fn hex(digest: [u8; 20]) -> String {
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn matches_the_rfc3174_vectors() {
        assert_eq!(
            hex(sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex(sha1(&[b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn digests_the_empty_message() {
        assert_eq!(hex(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    /// The block boundaries are where a padding mistake hides, so walk across both of them.
    #[test]
    fn digests_every_length_around_a_block_boundary() {
        // 55 is the last length that still fits its padding in one block, 56 the first that
        // does not; 119 and 120 are the same boundary one block further on.
        let expected = [
            (56usize, "901305367c259952f4e7af8323f480d59f81335b"),
            (64, "bb2fa3ee7afb9f54c6dfb5d021f14b1ffe40c163"),
            (119, "4300320394f7ee239bcdce7d3b8bcee173a0cd5c"),
            (120, "ceb2821639c4b6dcb10bce0e522ca2e608ce056d"),
        ];
        for (length, digest) in expected {
            assert_eq!(hex(sha1(&vec![b'x'; length])), digest, "length {length}");
        }
    }

    #[test]
    fn matches_the_rfc4648_base64_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
