// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Incremental decoding of BEEP frames from a byte buffer.
//!
//! [`Decoder`] is fed whatever octets have arrived and yields whole frames as they become
//! available. It never blocks, never allocates a copy of the payload (payloads are split
//! out of the input [`BytesMut`], so they share its allocation) and keeps no reference to
//! the transport.
//!
//! # Strictness
//!
//! The decoder is deliberately stricter than the LibVortex parser in three places where
//! LibVortex is lenient by accident rather than by design:
//!
//! - an empty numeric field is rejected instead of being read as zero (`strtol("")`),
//! - trailing octets after the last header field are rejected,
//! - the single space after the three character frame type token is required.
//!
//! Nothing LibVortex emits is affected by any of the three, so a LibVortex peer always
//! interoperates. Everything else follows `src/vortex_frame_factory.c` exactly, including
//! the digits-only rule for numeric fields and the `CRLF`-terminated header line, which
//! together cover the malformed headers of LibVortex `test_01h`.

use bytes::{Buf, BytesMut};

use crate::error::Error;
use crate::frame::{
    COMPLETE, DataFrame, Frame, FrameKind, INTERMEDIATE, MAX_ANS_NO, MAX_CHANNEL_NO,
    MAX_FRAME_SIZE, MAX_HEADER_LEN, MAX_MSG_NO, MAX_SEQ_NO, SeqFrame, TRAILER,
};

/// A parsed data frame header, still waiting for its payload and trailer.
#[derive(Debug, Clone, Copy)]
struct DataHeader {
    kind: FrameKind,
    channel: u32,
    msgno: u32,
    more: bool,
    seqno: u32,
    size: u32,
    ansno: Option<u32>,
}

/// Incremental BEEP frame decoder.
///
/// # Example
///
/// ```
/// use bytes::BytesMut;
/// use vortice_proto::codec::Decoder;
/// use vortice_proto::FrameKind;
///
/// let mut decoder = Decoder::new();
/// let mut buf = BytesMut::from(&b"RPY 0 0 . 0 5\r\nhelloEND\r\n"[..]);
///
/// let frame = decoder.decode(&mut buf).unwrap().expect("complete frame");
/// let data = frame.as_data().unwrap();
/// assert_eq!(data.kind(), FrameKind::Rpy);
/// assert_eq!(data.payload(), b"hello");
/// assert!(decoder.decode(&mut buf).unwrap().is_none());
/// ```
#[derive(Debug, Clone)]
pub struct Decoder {
    max_frame_size: u32,
    pending: Option<DataHeader>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// Creates a decoder accepting frames up to [`MAX_FRAME_SIZE`].
    ///
    /// Note that this is the protocol ceiling, not a resource limit: what actually bounds
    /// how much a peer may send is the BEEP window, enforced by the session layer. Use
    /// [`Decoder::with_max_frame_size`] to add a hard cap on top of it.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_frame_size: MAX_FRAME_SIZE,
            pending: None,
        }
    }

    /// Creates a decoder that refuses any frame announcing more than `max` payload octets.
    #[must_use]
    pub const fn with_max_frame_size(max: u32) -> Self {
        Self {
            max_frame_size: max,
            pending: None,
        }
    }

    /// The configured payload ceiling.
    #[must_use]
    pub const fn max_frame_size(&self) -> u32 {
        self.max_frame_size
    }

    /// Whether a header has been parsed and its payload is still being awaited.
    #[must_use]
    pub const fn has_partial_frame(&self) -> bool {
        self.pending.is_some()
    }

    /// Consumes as many octets of `src` as one whole frame needs and returns it.
    ///
    /// Returns `Ok(None)` when `src` does not yet hold a complete frame; the octets already
    /// examined are retained, so the caller simply appends more and calls again.
    ///
    /// # Errors
    ///
    /// Any [`Error`] returned here is fatal for the session: LibVortex shuts the connection
    /// down in every one of these cases, and a Vortice transport is expected to do the same.
    /// The decoder is left in an unspecified state and must not be reused.
    pub fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, Error> {
        if self.pending.is_none() {
            match self.decode_header(src)? {
                None => return Ok(None),
                Some(Parsed::Seq(seq)) => return Ok(Some(Frame::Seq(seq))),
                Some(Parsed::Data(header)) => self.pending = Some(header),
            }
        }

        let header = self.pending.expect("header just stored");
        let size = header.size as usize;
        let needed = size + TRAILER.len();
        if src.len() < needed {
            return Ok(None);
        }

        let payload = src.split_to(size).freeze();
        if &src[..TRAILER.len()] != TRAILER {
            return Err(Error::MissingTrailer);
        }
        src.advance(TRAILER.len());
        self.pending = None;

        let frame = match header.ansno {
            Some(ansno) => {
                DataFrame::new_ans(header.channel, header.msgno, header.seqno, ansno, payload)?
            }
            None => DataFrame::new(
                header.kind,
                header.channel,
                header.msgno,
                header.seqno,
                payload,
            )?,
        };
        Ok(Some(Frame::Data(frame.with_more(header.more))))
    }

    /// Reads and consumes one header line, if a complete one is present.
    fn decode_header(&self, src: &mut BytesMut) -> Result<Option<Parsed>, Error> {
        let window = src.len().min(MAX_HEADER_LEN);
        let Some(lf) = find(&src[..window], b'\n') else {
            if src.len() >= MAX_HEADER_LEN {
                return Err(Error::HeaderTooLong {
                    limit: MAX_HEADER_LEN,
                });
            }
            return Ok(None);
        };
        if lf == 0 || src[lf - 1] != b'\r' {
            return Err(Error::BareNewlineInHeader);
        }

        let parsed = parse_header(&src[..lf - 1], self.max_frame_size)?;
        src.advance(lf + 1);
        Ok(Some(parsed))
    }
}

/// Outcome of parsing one header line.
enum Parsed {
    Data(DataHeader),
    Seq(SeqFrame),
}

fn parse_header(line: &[u8], max_frame_size: u32) -> Result<Parsed, Error> {
    if line.len() < 3 {
        return Err(Error::MalformedHeader {
            reason: "frame type token truncated",
        });
    }
    let (token, rest) = line.split_at(3);
    match rest.first() {
        Some(b' ') => {}
        _ => {
            return Err(Error::MalformedHeader {
                reason: "expected a single space after the frame type",
            });
        }
    }
    let mut fields = Fields::new(&rest[1..]);

    if token == b"SEQ" {
        // SEQ channel ackno window
        let channel = parse_u32(fields.next("channel")?, "channel", MAX_CHANNEL_NO)?;
        let ackno = parse_u32(fields.next("ackno")?, "ackno", MAX_SEQ_NO)?;
        let window = parse_u32(fields.next("window")?, "window", MAX_FRAME_SIZE)?;
        fields.finish()?;
        return Ok(Parsed::Seq(SeqFrame::new(channel, ackno, window)?));
    }

    let kind = FrameKind::from_token(token).ok_or(Error::UnknownFrameType)?;

    // KIND channel msgno more seqno size [ansno]
    let channel = parse_u32(fields.next("channel")?, "channel", MAX_CHANNEL_NO)?;
    let msgno = parse_u32(fields.next("msgno")?, "msgno", MAX_MSG_NO)?;
    let more = parse_continuation(fields.next("more")?)?;
    let seqno = parse_u32(fields.next("seqno")?, "seqno", MAX_SEQ_NO)?;
    let size = parse_u32(fields.next("size")?, "size", MAX_FRAME_SIZE)?;
    let ansno = if kind.has_ansno() {
        Some(parse_u32(fields.next("ansno")?, "ansno", MAX_ANS_NO)?)
    } else {
        None
    };
    fields.finish()?;

    if size > max_frame_size {
        return Err(Error::FrameTooLarge {
            size,
            limit: max_frame_size,
        });
    }

    Ok(Parsed::Data(DataHeader {
        kind,
        channel,
        msgno,
        more,
        seqno,
        size,
        ansno,
    }))
}

/// Splits a header line into space separated fields, rejecting empty ones.
struct Fields<'a> {
    rest: Option<&'a [u8]>,
}

impl<'a> Fields<'a> {
    const fn new(rest: &'a [u8]) -> Self {
        Self { rest: Some(rest) }
    }

    fn next(&mut self, field: &'static str) -> Result<&'a [u8], Error> {
        let rest = self.rest.ok_or(Error::MissingField { field })?;
        let value = match find(rest, b' ') {
            Some(i) => {
                self.rest = Some(&rest[i + 1..]);
                &rest[..i]
            }
            None => {
                self.rest = None;
                rest
            }
        };
        if value.is_empty() {
            return Err(Error::MissingField { field });
        }
        Ok(value)
    }

    fn finish(&self) -> Result<(), Error> {
        if self.rest.is_some() {
            return Err(Error::MalformedHeader {
                reason: "trailing octets after the last header field",
            });
        }
        Ok(())
    }
}

fn parse_u32(field: &[u8], name: &'static str, max: u32) -> Result<u32, Error> {
    let mut value: u64 = 0;
    for &byte in field {
        if !byte.is_ascii_digit() {
            return Err(Error::InvalidDigit { field: name });
        }
        value = value * 10 + u64::from(byte - b'0');
        if value > u64::from(max) {
            return Err(Error::ValueOutOfRange { field: name, max });
        }
    }
    // `value <= max <= u32::MAX` holds by the check above.
    Ok(value as u32)
}

fn parse_continuation(field: &[u8]) -> Result<bool, Error> {
    match field {
        [COMPLETE] => Ok(false),
        [INTERMEDIATE] => Ok(true),
        [found] => Err(Error::InvalidContinuation { found: *found }),
        _ => Err(Error::MalformedHeader {
            reason: "continuation indicator must be a single character",
        }),
    }
}

fn find(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn decode_one(input: &[u8]) -> Result<Option<Frame>, Error> {
        let mut buf = BytesMut::from(input);
        Decoder::new().decode(&mut buf)
    }

    fn decode_err(input: &[u8]) -> Error {
        decode_one(input).expect_err("expected a decode error")
    }

    #[test]
    fn decodes_a_complete_data_frame() {
        let frame = decode_one(b"RPY 0 0 . 0 5\r\nhelloEND\r\n")
            .unwrap()
            .unwrap();
        let data = frame.as_data().unwrap();
        assert_eq!(data.kind(), FrameKind::Rpy);
        assert_eq!(data.channel(), 0);
        assert_eq!(data.msgno(), 0);
        assert!(!data.more());
        assert_eq!(data.seqno(), 0);
        assert_eq!(data.payload(), b"hello");
        assert_eq!(data.ansno(), None);
    }

    #[test]
    fn decodes_an_intermediate_frame() {
        let frame = decode_one(b"MSG 1 2 * 300 2\r\nabEND\r\n")
            .unwrap()
            .unwrap();
        assert!(frame.as_data().unwrap().more());
    }

    #[test]
    fn decodes_an_ans_frame_with_its_answer_number() {
        let frame = decode_one(b"ANS 3 4 . 5 1 6\r\nxEND\r\n").unwrap().unwrap();
        let data = frame.as_data().unwrap();
        assert_eq!(data.kind(), FrameKind::Ans);
        assert_eq!(data.ansno(), Some(6));
        assert_eq!(data.payload(), b"x");
    }

    #[test]
    fn decodes_a_seq_frame_which_has_no_payload() {
        let mut buf = BytesMut::from(&b"SEQ 1 4096 8192\r\n"[..]);
        let mut decoder = Decoder::new();
        let frame = decoder.decode(&mut buf).unwrap().unwrap();
        let seq = frame.as_seq().unwrap();
        assert_eq!((seq.channel(), seq.ackno(), seq.window()), (1, 4096, 8192));
        assert!(buf.is_empty());
        assert!(!decoder.has_partial_frame());
    }

    #[test]
    fn decodes_a_nul_frame_carrying_mime_headers() {
        // LibVortex does not force NUL frames to be empty: with automatic MIME on they
        // carry the channel's MIME headers, which is what test_02l1 contrasts against.
        let frame = decode_one(b"NUL 1 0 . 10 2\r\n\r\nEND\r\n")
            .unwrap()
            .unwrap();
        let data = frame.as_data().unwrap();
        assert_eq!(data.kind(), FrameKind::Nul);
        assert_eq!(data.payload(), b"\r\n");
    }

    #[test]
    fn round_trips_every_frame_kind() {
        let frames = [
            Frame::Data(DataFrame::new(FrameKind::Msg, 1, 2, 3, Bytes::from_static(b"a")).unwrap()),
            Frame::Data(DataFrame::new(FrameKind::Rpy, 0, 0, 0, Bytes::new()).unwrap()),
            Frame::Data(
                DataFrame::new(FrameKind::Err, 7, 8, 9, Bytes::from_static(b"boom")).unwrap(),
            ),
            Frame::Data(DataFrame::new_ans(1, 2, 3, 4, Bytes::from_static(b"ans")).unwrap()),
            Frame::Data(DataFrame::new(FrameKind::Nul, 1, 2, 3, Bytes::new()).unwrap()),
            Frame::Seq(SeqFrame::new(2, 100, 4096).unwrap()),
        ];
        for original in frames {
            let mut buf = BytesMut::new();
            original.encode(&mut buf);
            let decoded = Decoder::new().decode(&mut buf).unwrap().unwrap();
            assert_eq!(decoded, original);
            assert!(buf.is_empty(), "decoder left octets behind");
        }
    }

    #[test]
    fn decodes_frames_arriving_one_octet_at_a_time() {
        let wire = b"MSG 1 0 . 0 11\r\nhello worldEND\r\nSEQ 1 11 4096\r\n";
        let mut decoder = Decoder::new();
        let mut buf = BytesMut::new();
        let mut frames = alloc::vec::Vec::new();
        for &byte in wire {
            buf.extend_from_slice(&[byte]);
            while let Some(frame) = decoder.decode(&mut buf).unwrap() {
                frames.push(frame);
            }
        }
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].as_data().unwrap().payload(), b"hello world");
        assert_eq!(frames[1].as_seq().unwrap().ackno(), 11);
    }

    #[test]
    fn decodes_several_frames_from_one_buffer() {
        let mut buf = BytesMut::from(&b"RPY 0 0 . 0 1\r\naEND\r\nRPY 0 1 . 1 1\r\nbEND\r\n"[..]);
        let mut decoder = Decoder::new();
        assert_eq!(
            decoder
                .decode(&mut buf)
                .unwrap()
                .unwrap()
                .as_data()
                .unwrap()
                .payload(),
            b"a"
        );
        assert_eq!(
            decoder
                .decode(&mut buf)
                .unwrap()
                .unwrap()
                .as_data()
                .unwrap()
                .payload(),
            b"b"
        );
        assert!(decoder.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn waits_for_the_payload_without_losing_the_header() {
        let mut decoder = Decoder::new();
        let mut buf = BytesMut::from(&b"RPY 0 0 . 0 5\r\nhel"[..]);
        assert!(decoder.decode(&mut buf).unwrap().is_none());
        assert!(decoder.has_partial_frame());
        buf.extend_from_slice(b"loEND\r\n");
        let frame = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.as_data().unwrap().payload(), b"hello");
        assert!(!decoder.has_partial_frame());
    }

    // --- malformed headers: the cases LibVortex test_01h drives over a raw socket ---

    #[test]
    fn rejects_a_header_terminated_by_a_bare_lf() {
        assert_eq!(decode_err(b"RPY\n"), Error::BareNewlineInHeader);
        assert_eq!(decode_err(b"RPY 0 0 . 0 0\n"), Error::BareNewlineInHeader);
    }

    #[test]
    fn accepts_only_crlf_terminated_headers() {
        // "RPY\r\n" is CRLF terminated but has no fields at all.
        assert_eq!(
            decode_err(b"RPY\r\n"),
            Error::MalformedHeader {
                reason: "expected a single space after the frame type"
            }
        );
    }

    #[test]
    fn rejects_a_nul_octet_inside_a_numeric_field() {
        assert_eq!(
            decode_err(b"RPY 1234123\0\r\n"),
            Error::InvalidDigit { field: "channel" }
        );
        assert_eq!(
            decode_err(b"RPY 0 0 . 0 \0\r\n"),
            Error::InvalidDigit { field: "size" }
        );
    }

    #[test]
    fn rejects_a_bare_nul_octet_as_a_frame_type() {
        assert_eq!(decode_err(b"\0\0\0 0 0 . 0 0\r\n"), Error::UnknownFrameType);
    }

    #[test]
    fn rejects_an_unknown_frame_type() {
        assert_eq!(decode_err(b"XXX 0 0 . 0 0\r\n"), Error::UnknownFrameType);
    }

    #[test]
    fn rejects_a_header_with_no_crlf_within_the_limit() {
        let mut wire = alloc::vec::Vec::from(&b"RPY "[..]);
        wire.resize(MAX_HEADER_LEN + 10, b'0');
        assert_eq!(
            decode_err(&wire),
            Error::HeaderTooLong {
                limit: MAX_HEADER_LEN
            }
        );
    }

    #[test]
    fn waits_when_the_header_is_still_short_of_the_limit() {
        let mut buf = BytesMut::from(&b"RPY 0 0 . 0 5"[..]);
        assert!(Decoder::new().decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 13, "unterminated header must not be consumed");
    }

    #[test]
    fn rejects_an_invalid_continuation_indicator() {
        assert_eq!(
            decode_err(b"RPY 0 0 x 0 0\r\n"),
            Error::InvalidContinuation { found: b'x' }
        );
        assert_eq!(
            decode_err(b"RPY 0 0 .. 0 0\r\n"),
            Error::MalformedHeader {
                reason: "continuation indicator must be a single character"
            }
        );
    }

    #[test]
    fn rejects_missing_and_empty_header_fields() {
        assert_eq!(
            decode_err(b"RPY 0 0 . 0\r\n"),
            Error::MissingField { field: "size" }
        );
        assert_eq!(
            decode_err(b"RPY 0 0 .  0 0\r\n"),
            Error::MissingField { field: "seqno" }
        );
        assert_eq!(
            decode_err(b"SEQ 1 4096\r\n"),
            Error::MissingField { field: "window" }
        );
    }

    #[test]
    fn rejects_trailing_octets_after_the_last_field() {
        assert_eq!(
            decode_err(b"RPY 0 0 . 0 0 7\r\n"),
            Error::MalformedHeader {
                reason: "trailing octets after the last header field"
            }
        );
        // A trailing space counts as an empty extra field.
        assert_eq!(
            decode_err(b"SEQ 1 0 4096 \r\n"),
            Error::MalformedHeader {
                reason: "trailing octets after the last header field"
            }
        );
    }

    #[test]
    fn rejects_an_ans_frame_without_an_answer_number() {
        assert_eq!(
            decode_err(b"ANS 0 0 . 0 0\r\n"),
            Error::MissingField { field: "ansno" }
        );
    }

    #[test]
    fn rejects_out_of_range_values() {
        assert_eq!(
            decode_err(b"RPY 2147483648 0 . 0 0\r\n"),
            Error::ValueOutOfRange {
                field: "channel",
                max: MAX_CHANNEL_NO
            }
        );
        assert_eq!(
            decode_err(b"RPY 0 0 . 4294967296 0\r\n"),
            Error::ValueOutOfRange {
                field: "seqno",
                max: MAX_SEQ_NO
            }
        );
        // Overflow must be caught while accumulating, not after wrapping.
        assert_eq!(
            decode_err(b"RPY 0 0 . 99999999999999999999999 0\r\n"),
            Error::ValueOutOfRange {
                field: "seqno",
                max: MAX_SEQ_NO
            }
        );
    }

    #[test]
    fn accepts_the_maximum_sequence_number() {
        let frame = decode_one(b"RPY 0 0 . 4294967295 0\r\nEND\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(frame.as_data().unwrap().seqno(), MAX_SEQ_NO);
    }

    #[test]
    fn rejects_a_missing_trailer() {
        assert_eq!(
            decode_err(b"RPY 0 0 . 0 5\r\nhelloXXXXX"),
            Error::MissingTrailer
        );
        assert_eq!(
            decode_err(b"RPY 0 0 . 0 5\r\nhelloEND\n\r"),
            Error::MissingTrailer
        );
    }

    #[test]
    fn enforces_the_configured_frame_size_limit() {
        let mut buf = BytesMut::from(&b"RPY 0 0 . 0 5000\r\n"[..]);
        let err = Decoder::with_max_frame_size(4096)
            .decode(&mut buf)
            .expect_err("frame above the limit");
        assert_eq!(
            err,
            Error::FrameTooLarge {
                size: 5000,
                limit: 4096
            }
        );
    }
}
