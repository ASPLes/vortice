// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Turning a stream of octets into WebSocket frames. Sans-IO, like `vortice-proto`.

use bytes::{Buf, Bytes, BytesMut};

use crate::frame::{self, OpCode, ProtocolError};

/// What a decoded frame asks the transport to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    /// Payload octets, to be handed to the BEEP session.
    Data(Bytes),
    /// A liveness probe carrying the payload to echo back.
    Ping(Bytes),
    /// The answer to a probe. Nothing to do; kept so the caller can see it arrived.
    Pong(Bytes),
    /// The peer is closing, with the code and reason it gave.
    Close {
        /// The status code of RFC6455 §7.4, absent if the peer sent an empty close.
        code: Option<u16>,
        /// The human-readable reason, which may be empty.
        reason: Bytes,
    },
}

/// Pulls frames off a growing buffer of received octets.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Decoder;

impl Decoder {
    /// A decoder with nothing buffered.
    pub(crate) const fn new() -> Self {
        Self
    }

    /// Takes the next complete frame out of `buffer`.
    ///
    /// Returns `Ok(None)` when the buffer holds less than one whole frame, leaving it
    /// untouched so the caller can read more and try again.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] when the peer's framing is one RFC6455 does not allow.
    pub(crate) fn poll(&mut self, buffer: &mut BytesMut) -> Result<Option<Event>, ProtocolError> {
        let Some(header) = frame::decode_header(buffer)? else {
            return Ok(None);
        };
        // Nothing is consumed until the whole frame is here, so a short read costs only the
        // re-parse of a header that is at most fourteen octets.
        if buffer.len() < header.header_len + header.payload_len {
            return Ok(None);
        }

        buffer.advance(header.header_len);
        let mut payload = buffer.split_to(header.payload_len);
        if let Some(mask) = header.mask {
            frame::apply_mask(&mut payload, mask, 0);
        }
        let payload = payload.freeze();

        Ok(Some(match header.opcode {
            OpCode::Ping => Event::Ping(payload),
            OpCode::Pong => Event::Pong(payload),
            OpCode::Close => {
                // §5.5.1: the code is the first two octets if there are any at all.
                let (code, reason) = if payload.len() >= 2 {
                    let code = u16::from_be_bytes([payload[0], payload[1]]);
                    (Some(code), payload.slice(2..))
                } else {
                    (None, Bytes::new())
                };
                Event::Close { code, reason }
            }
            // Text, Binary and Continuation are all just payload. This binding carries a byte
            // stream, so message boundaries and the text/binary distinction mean nothing here
            // — see the note on leniency in the crate documentation.
            OpCode::Text | OpCode::Binary | OpCode::Continuation => Event::Data(payload),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{Decoder, Event};
    use crate::frame::{self, OpCode, ProtocolError};
    use bytes::{Bytes, BytesMut};

    /// Builds one frame the way a peer would.
    fn frame(opcode: OpCode, fin: bool, payload: &[u8], mask: Option<[u8; 4]>) -> BytesMut {
        let mut buffer = BytesMut::new();
        frame::encode_header(&mut buffer, opcode, fin, payload.len(), mask);
        let at = buffer.len();
        buffer.extend_from_slice(payload);
        if let Some(mask) = mask {
            frame::apply_mask(&mut buffer[at..], mask, 0);
        }
        buffer
    }

    #[test]
    fn decodes_a_binary_frame() {
        let mut buffer = frame(OpCode::Binary, true, b"RPY 0 0 . 0 0", None);
        let event = Decoder::new().poll(&mut buffer).expect("valid");
        assert_eq!(
            event,
            Some(Event::Data(Bytes::from_static(b"RPY 0 0 . 0 0")))
        );
        assert!(buffer.is_empty(), "the frame should have been consumed");
    }

    #[test]
    fn unmasks_a_client_frame() {
        let mut buffer = frame(OpCode::Binary, true, b"masked payload", Some([7, 8, 9, 10]));
        let event = Decoder::new().poll(&mut buffer).expect("valid");
        assert_eq!(
            event,
            Some(Event::Data(Bytes::from_static(b"masked payload")))
        );
    }

    /// The interop requirement: LibVortex sends BEEP in text frames, payload and all.
    #[test]
    fn accepts_a_text_frame_carrying_arbitrary_octets() {
        let payload = [0x00, 0xff, 0xfe, 0x80, 0x41];
        let mut buffer = frame(OpCode::Text, true, &payload, None);
        let event = Decoder::new().poll(&mut buffer).expect("valid");
        assert_eq!(
            event,
            Some(Event::Data(Bytes::copy_from_slice(&payload))),
            "a text frame whose payload is not UTF-8 must still be delivered"
        );
    }

    /// Message boundaries carry nothing, so a fragmented message is just more payload.
    #[test]
    fn treats_continuation_frames_as_more_payload() {
        let mut buffer = frame(OpCode::Binary, false, b"first", None);
        buffer.extend_from_slice(&frame(OpCode::Continuation, true, b"second", None));

        let mut decoder = Decoder::new();
        assert_eq!(
            decoder.poll(&mut buffer).expect("valid"),
            Some(Event::Data(Bytes::from_static(b"first")))
        );
        assert_eq!(
            decoder.poll(&mut buffer).expect("valid"),
            Some(Event::Data(Bytes::from_static(b"second")))
        );
    }

    #[test]
    fn leaves_a_partial_frame_alone() {
        let complete = frame(OpCode::Binary, true, b"a whole payload", None);
        let mut decoder = Decoder::new();

        for prefix in 0..complete.len() {
            let mut buffer = BytesMut::from(&complete[..prefix]);
            assert_eq!(
                decoder.poll(&mut buffer).expect("valid"),
                None,
                "{prefix} octets is not a whole frame"
            );
            assert_eq!(
                buffer.len(),
                prefix,
                "an incomplete frame must not be consumed"
            );
        }
    }

    #[test]
    fn decodes_frames_arriving_one_octet_at_a_time() {
        let mut wire = frame(OpCode::Binary, true, b"first", Some([1, 2, 3, 4]));
        wire.extend_from_slice(&frame(OpCode::Binary, true, b"second", None));

        let mut decoder = Decoder::new();
        let mut buffer = BytesMut::new();
        let mut seen = Vec::new();
        for octet in wire {
            buffer.extend_from_slice(&[octet]);
            while let Some(event) = decoder.poll(&mut buffer).expect("valid") {
                seen.push(event);
            }
        }

        assert_eq!(
            seen,
            vec![
                Event::Data(Bytes::from_static(b"first")),
                Event::Data(Bytes::from_static(b"second")),
            ]
        );
    }

    #[test]
    fn decodes_a_ping_and_a_pong() {
        let mut buffer = frame(OpCode::Ping, true, b"probe", None);
        buffer.extend_from_slice(&frame(OpCode::Pong, true, b"probe", None));

        let mut decoder = Decoder::new();
        assert_eq!(
            decoder.poll(&mut buffer).expect("valid"),
            Some(Event::Ping(Bytes::from_static(b"probe")))
        );
        assert_eq!(
            decoder.poll(&mut buffer).expect("valid"),
            Some(Event::Pong(Bytes::from_static(b"probe")))
        );
    }

    #[test]
    fn decodes_a_close_with_and_without_a_code() {
        let mut payload = 1000u16.to_be_bytes().to_vec();
        payload.extend_from_slice(b"going away");
        let mut buffer = frame(OpCode::Close, true, &payload, None);
        assert_eq!(
            Decoder::new().poll(&mut buffer).expect("valid"),
            Some(Event::Close {
                code: Some(1000),
                reason: Bytes::from_static(b"going away"),
            })
        );

        let mut buffer = frame(OpCode::Close, true, b"", None);
        assert_eq!(
            Decoder::new().poll(&mut buffer).expect("valid"),
            Some(Event::Close {
                code: None,
                reason: Bytes::new(),
            })
        );
    }

    #[test]
    fn reports_a_protocol_error() {
        let mut buffer = BytesMut::from(&[0x40u8, 0x00][..]);
        assert_eq!(
            Decoder::new().poll(&mut buffer),
            Err(ProtocolError::ReservedBits)
        );
    }
}
