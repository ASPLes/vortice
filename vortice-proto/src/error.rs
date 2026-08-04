// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Errors produced by the sans-IO core.

use core::fmt;

/// An error detected while building or decoding BEEP protocol elements.
///
/// Every variant here describes a condition that LibVortex treats as fatal for the session:
/// on the wire, a peer that produces any of these has its connection shut down. The core
/// reports the condition and leaves the decision to the transport layer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The frame header did not start with one of `MSG`, `RPY`, `ERR`, `ANS`, `NUL`, `SEQ`.
    UnknownFrameType,

    /// No `CRLF` was found within the maximum header length.
    ///
    /// LibVortex reads the header with a 99 byte line buffer and rejects the frame when no
    /// terminator is found, which is what [`frame::MAX_HEADER_LEN`](crate::frame::MAX_HEADER_LEN)
    /// mirrors.
    HeaderTooLong {
        /// The limit that was exceeded, in bytes.
        limit: usize,
    },

    /// A bare `LF` appeared in the header where `CRLF` was required.
    BareNewlineInHeader,

    /// The header was structurally wrong.
    MalformedHeader {
        /// What was expected at the point the parse failed.
        reason: &'static str,
    },

    /// A numeric header field contained a byte that is not an ASCII digit.
    ///
    /// This covers the embedded-NUL and control-character cases exercised by LibVortex
    /// `test_01h`.
    InvalidDigit {
        /// Name of the header field being parsed.
        field: &'static str,
    },

    /// A header field the frame type requires was absent or empty.
    MissingField {
        /// Name of the missing header field.
        field: &'static str,
    },

    /// A numeric header field parsed correctly but exceeded the range BEEP allows for it.
    ValueOutOfRange {
        /// Name of the header field.
        field: &'static str,
        /// Largest value the field accepts.
        max: u32,
    },

    /// The continuation indicator was neither `.` nor `*`.
    InvalidContinuation {
        /// The byte that was found instead.
        found: u8,
    },

    /// The frame declared a payload larger than the configured limit.
    FrameTooLarge {
        /// Size announced in the header.
        size: u32,
        /// Configured maximum.
        limit: u32,
    },

    /// The five byte `END\r\n` trailer was not present where the header said it would be.
    MissingTrailer,

    /// A payload that had to be valid UTF-8 was not.
    NotUtf8,

    /// The XML of a channel-management message could not be parsed.
    Xml {
        /// What was expected at the point the parse failed.
        reason: &'static str,
    },

    /// A channel-management message had a root element other than the expected one.
    UnexpectedElement,

    /// A greeting frame did not carry `Content-Type: application/beep+xml`.
    ///
    /// LibVortex rejects the session in this case (`vortex_greetings.c`).
    NotBeepXml,

    /// A frame offered as the greeting did not have the shape a greeting must have.
    ///
    /// LibVortex requires an `RPY` on channel 0 with message number 0 and sequence number 0.
    NotAGreeting {
        /// Which of those expectations was violated.
        reason: &'static str,
    },

    /// A frame fell outside the window this end advertised.
    ///
    /// This is what `vortex_channel_check_incoming_seqno` guards, and LibVortex drops the
    /// session when it trips.
    OutsideWindow {
        /// Sequence number the frame announced.
        seqno: u32,
        /// Payload length the frame announced.
        len: u32,
        /// First sequence number beyond the advertised window.
        limit: u32,
    },

    /// A frame arrived with a sequence number other than the one expected next.
    ///
    /// BEEP numbers octets contiguously within a channel, so a gap or an overlap is a
    /// protocol violation rather than something to be reordered.
    UnexpectedSeqNo {
        /// Sequence number the frame announced.
        found: u32,
        /// Sequence number the channel was waiting for.
        expected: u32,
    },

    /// A message number still awaiting its reply was used for a new message.
    MsgNoInUse {
        /// The message number that is still outstanding.
        msgno: u32,
    },

    /// Every message number is currently outstanding.
    MsgNoExhausted,

    /// A reply arrived for a message number this end never sent, or already completed.
    UnknownMsgNo {
        /// The message number the reply referred to.
        msgno: u32,
    },

    /// A fragment of one message arrived while another was still being reassembled.
    ///
    /// BEEP sends the fragments of a message contiguously on its channel; LibVortex keeps a
    /// single partial frame per channel for the same reason.
    InterleavedFragment,

    /// Nothing more may be sent until a `SEQ` frame advances the window.
    ChannelStalled,

    /// The channel number is already in use, or is not one this peer may allocate.
    ChannelNumber {
        /// What is wrong with it.
        reason: &'static str,
    },

    /// A frame arrived for a channel that is not open.
    ///
    /// LibVortex closes the session in this case, which is what `test_02a2` drives.
    NoSuchChannel {
        /// The channel the frame referred to.
        channel: u32,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFrameType => f.write_str("unknown BEEP frame type"),
            Self::HeaderTooLong { limit } => {
                write!(f, "no CRLF found within {limit} bytes of frame header")
            }
            Self::BareNewlineInHeader => f.write_str("bare LF in frame header, CRLF required"),
            Self::MalformedHeader { reason } => write!(f, "malformed frame header: {reason}"),
            Self::InvalidDigit { field } => {
                write!(f, "non-digit byte in header field '{field}'")
            }
            Self::MissingField { field } => write!(f, "missing header field '{field}'"),
            Self::ValueOutOfRange { field, max } => {
                write!(f, "header field '{field}' exceeds its maximum of {max}")
            }
            Self::InvalidContinuation { found } => {
                write!(
                    f,
                    "invalid continuation indicator {found:#04x}, expected '.' or '*'"
                )
            }
            Self::FrameTooLarge { size, limit } => {
                write!(
                    f,
                    "frame payload of {size} bytes exceeds the limit of {limit}"
                )
            }
            Self::MissingTrailer => f.write_str("frame trailer 'END' CRLF not found"),
            Self::NotUtf8 => f.write_str("payload is not valid UTF-8"),
            Self::Xml { reason } => write!(f, "malformed XML: {reason}"),
            Self::UnexpectedElement => f.write_str("unexpected root element"),
            Self::NotBeepXml => f.write_str("expected Content-Type: application/beep+xml"),
            Self::NotAGreeting { reason } => write!(f, "not a greeting frame: {reason}"),
            Self::OutsideWindow { seqno, len, limit } => write!(
                f,
                "frame at seqno {seqno} of {len} octets runs past the advertised window limit {limit}"
            ),
            Self::UnexpectedSeqNo { found, expected } => {
                write!(f, "expected seqno {expected}, found {found}")
            }
            Self::MsgNoInUse { msgno } => {
                write!(f, "message number {msgno} is still awaiting its reply")
            }
            Self::MsgNoExhausted => f.write_str("no message number is free on this channel"),
            Self::UnknownMsgNo { msgno } => {
                write!(f, "no message {msgno} is outstanding on this channel")
            }
            Self::InterleavedFragment => {
                f.write_str("a new message began while another was still being reassembled")
            }
            Self::ChannelStalled => f.write_str("channel stalled, waiting for a SEQ frame"),
            Self::ChannelNumber { reason } => write!(f, "invalid channel number: {reason}"),
            Self::NoSuchChannel { channel } => write!(f, "channel {channel} is not open"),
        }
    }
}

impl core::error::Error for Error {}
