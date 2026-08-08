// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! WebSocket frame headers, as specified in RFC6455 §5.2. Sans-IO: buffers in, buffers out.

use core::fmt;

use bytes::{BufMut, BytesMut};

/// Largest frame payload accepted from a peer.
///
/// A frame header can declare a 64-bit length, so without a ceiling a single header would let
/// a peer name more memory than the machine has. BEEP frames are bounded by the channel
/// window and never approach this.
pub(crate) const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Largest payload put into one outgoing frame.
///
/// Writes larger than this are split across frames. Message boundaries carry no meaning in
/// this binding, so splitting is free.
pub(crate) const MAX_SEND_PAYLOAD: usize = 64 * 1024;

/// A frame type, from the four-bit opcode of RFC6455 §5.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpCode {
    /// More of the message the previous frame began.
    Continuation,
    /// A text message. Accepted, but see [`crate`] on why its payload is not validated.
    Text,
    /// A binary message.
    Binary,
    /// The peer is closing.
    Close,
    /// A liveness probe, to be answered with [`OpCode::Pong`].
    Ping,
    /// The answer to a ping.
    Pong,
}

impl OpCode {
    /// The opcode for `value`, or `None` if RFC6455 reserves it.
    const fn from_bits(value: u8) -> Option<Self> {
        match value {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xa => Some(Self::Pong),
            _ => None,
        }
    }

    /// The four bits naming this opcode on the wire.
    const fn bits(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xa,
        }
    }

    /// Whether this is a control frame, which must be short and must not be fragmented.
    pub(crate) const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// A decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    /// Whether this frame ends its message.
    pub(crate) fin: bool,
    /// What kind of frame follows.
    pub(crate) opcode: OpCode,
    /// The masking key, if the peer masked the payload.
    pub(crate) mask: Option<[u8; 4]>,
    /// Octets of payload following the header.
    pub(crate) payload_len: usize,
    /// Octets the header itself occupies.
    pub(crate) header_len: usize,
}

/// A peer's framing that RFC6455 does not allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// A reserved bit was set without an extension having been negotiated.
    ReservedBits,
    /// The opcode is one RFC6455 reserves.
    UnknownOpCode(u8),
    /// A control frame carried more than the 125 octets §5.5 allows.
    ControlFrameTooLarge(usize),
    /// A control frame arrived without its FIN bit, which §5.5 forbids.
    FragmentedControlFrame,
    /// The declared payload is larger than [`MAX_PAYLOAD`].
    PayloadTooLarge(u64),
    /// A length was encoded in more octets than it needed, which §5.2 forbids.
    NonMinimalLength,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedBits => write!(formatter, "a reserved bit is set on a frame header"),
            Self::UnknownOpCode(code) => write!(formatter, "reserved websocket opcode {code:#x}"),
            Self::ControlFrameTooLarge(len) => {
                write!(formatter, "control frame of {len} octets, the limit is 125")
            }
            Self::FragmentedControlFrame => write!(formatter, "a control frame was fragmented"),
            Self::PayloadTooLarge(len) => write!(
                formatter,
                "frame declares {len} octets of payload, the limit is {MAX_PAYLOAD}"
            ),
            Self::NonMinimalLength => {
                write!(formatter, "a payload length was not minimally encoded")
            }
        }
    }
}

impl core::error::Error for ProtocolError {}

/// Reads a header from the front of `buffer` without consuming it.
///
/// Returns `Ok(None)` when the header is not yet complete, so a caller can wait for more
/// octets. The payload itself is not required to be present.
pub(crate) fn decode_header(buffer: &[u8]) -> Result<Option<Header>, ProtocolError> {
    let Some((&first, &second)) = buffer.first().zip(buffer.get(1)) else {
        return Ok(None);
    };

    if first & 0x70 != 0 {
        // RSV1..RSV3. No extension is negotiated, so §5.2 says these must be zero, and a peer
        // setting one is describing a framing we would misread rather than one we can skip.
        return Err(ProtocolError::ReservedBits);
    }

    let fin = first & 0x80 != 0;
    let opcode =
        OpCode::from_bits(first & 0x0f).ok_or(ProtocolError::UnknownOpCode(first & 0x0f))?;
    let masked = second & 0x80 != 0;

    let (payload_len, len_octets) = match second & 0x7f {
        126 => {
            let Some(octets) = buffer.get(2..4) else {
                return Ok(None);
            };
            let len = u64::from(u16::from_be_bytes([octets[0], octets[1]]));
            if len < 126 {
                return Err(ProtocolError::NonMinimalLength);
            }
            (len, 2)
        }
        127 => {
            let Some(octets) = buffer.get(2..10) else {
                return Ok(None);
            };
            let mut be = [0u8; 8];
            be.copy_from_slice(octets);
            let len = u64::from_be_bytes(be);
            if len <= 0xffff {
                return Err(ProtocolError::NonMinimalLength);
            }
            (len, 8)
        }
        short => (u64::from(short), 0),
    };

    if payload_len > MAX_PAYLOAD as u64 {
        return Err(ProtocolError::PayloadTooLarge(payload_len));
    }
    // Checked against MAX_PAYLOAD, which is far below usize::MAX on any supported target.
    let payload_len = payload_len as usize;

    if opcode.is_control() {
        if payload_len > 125 {
            return Err(ProtocolError::ControlFrameTooLarge(payload_len));
        }
        if !fin {
            return Err(ProtocolError::FragmentedControlFrame);
        }
    }

    let mask_at = 2 + len_octets;
    let mask = if masked {
        let Some(octets) = buffer.get(mask_at..mask_at + 4) else {
            return Ok(None);
        };
        Some([octets[0], octets[1], octets[2], octets[3]])
    } else {
        None
    };

    Ok(Some(Header {
        fin,
        opcode,
        mask,
        payload_len,
        header_len: mask_at + if masked { 4 } else { 0 },
    }))
}

/// Appends a frame header to `out`.
pub(crate) fn encode_header(
    out: &mut BytesMut,
    opcode: OpCode,
    fin: bool,
    payload_len: usize,
    mask: Option<[u8; 4]>,
) {
    out.put_u8(if fin { 0x80 } else { 0 } | opcode.bits());

    let masked = if mask.is_some() { 0x80 } else { 0 };
    if payload_len < 126 {
        // Fits the short form, and §5.2 requires the shortest form that fits.
        out.put_u8(masked | payload_len as u8);
    } else if let Ok(len) = u16::try_from(payload_len) {
        out.put_u8(masked | 126);
        out.put_u16(len);
    } else {
        out.put_u8(masked | 127);
        out.put_u64(payload_len as u64);
    }

    if let Some(mask) = mask {
        out.put_slice(&mask);
    }
}

/// Applies a masking key to a payload, starting `offset` octets into the message.
///
/// Masking is its own inverse, so this both masks and unmasks. The offset matters only when
/// a payload is masked in more than one pass.
pub(crate) fn apply_mask(payload: &mut [u8], mask: [u8; 4], offset: usize) {
    for (index, octet) in payload.iter_mut().enumerate() {
        *octet ^= mask[(index + offset) % 4];
    }
}

/// Four unpredictable octets for masking a client frame.
///
/// RFC6455 §5.3 requires these to be unpredictable: a proxy that can be made to see chosen
/// plaintext on the wire is the attack the masking exists to stop, so a counter will not do.
pub(crate) fn masking_key() -> Result<[u8; 4], getrandom::Error> {
    let mut key = [0u8; 4];
    getrandom::fill(&mut key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::{
        Header, MAX_PAYLOAD, OpCode, ProtocolError, apply_mask, decode_header, encode_header,
    };
    use bytes::BytesMut;

    /// Encodes a header and reads it back, which is the property the two share.
    fn roundtrip(opcode: OpCode, fin: bool, len: usize, mask: Option<[u8; 4]>) -> Header {
        let mut buffer = BytesMut::new();
        encode_header(&mut buffer, opcode, fin, len, mask);
        decode_header(&buffer)
            .expect("valid header")
            .expect("complete header")
    }

    #[test]
    fn round_trips_every_length_form() {
        // 125 is the last short length, 126 the first sixteen-bit one, 65536 the first
        // sixty-four-bit one.
        for len in [0usize, 1, 125, 126, 127, 65_535, 65_536, 100_000] {
            let header = roundtrip(OpCode::Binary, true, len, None);
            assert_eq!(header.payload_len, len, "length {len}");
            assert_eq!(header.opcode, OpCode::Binary);
            assert!(header.fin);
            assert_eq!(header.mask, None);
        }
    }

    #[test]
    fn round_trips_a_masked_header() {
        let header = roundtrip(OpCode::Binary, true, 300, Some([1, 2, 3, 4]));
        assert_eq!(header.mask, Some([1, 2, 3, 4]));
        assert_eq!(header.payload_len, 300);
        // Two octets of prefix, two of length, four of mask.
        assert_eq!(header.header_len, 8);
    }

    #[test]
    fn reports_an_incomplete_header() {
        let mut buffer = BytesMut::new();
        encode_header(&mut buffer, OpCode::Binary, true, 70_000, Some([9; 4]));
        for prefix in 0..buffer.len() {
            assert_eq!(
                decode_header(&buffer[..prefix]),
                Ok(None),
                "a {prefix}-octet prefix should not decode"
            );
        }
        assert!(decode_header(&buffer).expect("valid").is_some());
    }

    #[test]
    fn refuses_reserved_bits_and_opcodes() {
        assert_eq!(
            decode_header(&[0x40, 0x00]),
            Err(ProtocolError::ReservedBits)
        );
        assert_eq!(
            decode_header(&[0x83, 0x00]),
            Err(ProtocolError::UnknownOpCode(3))
        );
    }

    #[test]
    fn refuses_malformed_control_frames() {
        // A close frame of 126 octets: longer than §5.5 allows.
        assert_eq!(
            decode_header(&[0x88, 126, 0x00, 0x7e]),
            Err(ProtocolError::ControlFrameTooLarge(126))
        );
        // A ping without FIN.
        assert_eq!(
            decode_header(&[0x09, 0x00]),
            Err(ProtocolError::FragmentedControlFrame)
        );
    }

    #[test]
    fn refuses_a_payload_larger_than_the_ceiling() {
        let mut header = vec![0x82, 127];
        header.extend_from_slice(&(MAX_PAYLOAD as u64 + 1).to_be_bytes());
        assert_eq!(
            decode_header(&header),
            Err(ProtocolError::PayloadTooLarge(MAX_PAYLOAD as u64 + 1))
        );
    }

    #[test]
    fn refuses_a_length_padded_into_a_longer_form() {
        // 125 octets announced through the sixteen-bit form, which §5.2 forbids.
        assert_eq!(
            decode_header(&[0x82, 126, 0x00, 0x7d]),
            Err(ProtocolError::NonMinimalLength)
        );
        // And through the sixty-four-bit one.
        assert_eq!(
            decode_header(&[0x82, 127, 0, 0, 0, 0, 0, 0, 0xff, 0xff]),
            Err(ProtocolError::NonMinimalLength)
        );
    }

    #[test]
    fn masking_is_its_own_inverse() {
        let mask = [0xde, 0xad, 0xbe, 0xef];
        let original: Vec<u8> = (0..=255).collect();
        let mut payload = original.clone();
        apply_mask(&mut payload, mask, 0);
        assert_ne!(payload, original, "masking should change the payload");
        apply_mask(&mut payload, mask, 0);
        assert_eq!(payload, original);
    }

    #[test]
    fn masking_in_two_passes_matches_masking_in_one() {
        let mask = [1, 2, 3, 4];
        let original: Vec<u8> = (0..100).collect();

        let mut once = original.clone();
        apply_mask(&mut once, mask, 0);

        // Split at 7, which is not a multiple of four, so the offset has to be carried.
        let mut twice = original.clone();
        let (head, tail) = twice.split_at_mut(7);
        apply_mask(head, mask, 0);
        apply_mask(tail, mask, 7);

        assert_eq!(once, twice);
    }
}
