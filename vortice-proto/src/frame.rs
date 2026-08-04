// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! BEEP frames and the limits BEEP places on their header fields.
//!
//! A data frame is
//!
//! ```text
//! KIND channel msgno more seqno size [ansno] CRLF
//! payload
//! END CRLF
//! ```
//!
//! where `ansno` is present for `ANS` frames only, and `more` is `.` for a complete frame
//! or `*` for an intermediate one. A `SEQ` frame (RFC3081 §3.1.3) is a header line on its
//! own, with neither payload nor trailer:
//!
//! ```text
//! SEQ channel ackno window CRLF
//! ```

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::Error;

/// Largest channel number BEEP allows.
pub const MAX_CHANNEL_NO: u32 = 2_147_483_647;

/// Largest message number BEEP allows.
pub const MAX_MSG_NO: u32 = 2_147_483_647;

/// Largest answer number BEEP allows.
pub const MAX_ANS_NO: u32 = 2_147_483_647;

/// Largest payload size a single frame may announce.
pub const MAX_FRAME_SIZE: u32 = 2_147_483_647;

/// Largest sequence number BEEP allows, after which the counter wraps to zero.
///
/// The arithmetic around that wrap lives in [`crate::window`].
pub const MAX_SEQ_NO: u32 = u32::MAX;

/// Maximum length of a frame header line, including its terminating `CRLF`.
///
/// LibVortex reads the header with `vortex_frame_readline (connection, line, 99)`, whose
/// loop runs `for (n = 1; n < maxlen; n++)` and therefore accepts at most 98 bytes before
/// giving up and rejecting the frame. Vortice enforces the same bound so that a header a
/// LibVortex peer would refuse is refused here too.
pub const MAX_HEADER_LEN: usize = 98;

/// The five byte trailer that terminates every data frame.
pub const TRAILER: &[u8] = b"END\r\n";

/// Continuation indicator for a complete frame.
pub const COMPLETE: u8 = b'.';

/// Continuation indicator for an intermediate frame.
pub const INTERMEDIATE: u8 = b'*';

/// The kind of a BEEP data frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameKind {
    /// A message starting an exchange.
    Msg,
    /// A positive reply.
    Rpy,
    /// A negative reply.
    Err,
    /// One answer of a one-to-many reply.
    Ans,
    /// The terminator of a one-to-many reply.
    Nul,
}

impl FrameKind {
    /// The three character token used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Msg => "MSG",
            Self::Rpy => "RPY",
            Self::Err => "ERR",
            Self::Ans => "ANS",
            Self::Nul => "NUL",
        }
    }

    /// Parses a three byte wire token, returning `None` if it is not a data frame kind.
    #[must_use]
    pub const fn from_token(token: &[u8]) -> Option<Self> {
        match token {
            b"MSG" => Some(Self::Msg),
            b"RPY" => Some(Self::Rpy),
            b"ERR" => Some(Self::Err),
            b"ANS" => Some(Self::Ans),
            b"NUL" => Some(Self::Nul),
            _ => None,
        }
    }

    /// Whether this kind carries an `ansno` field in its header.
    #[must_use]
    pub const fn has_ansno(self) -> bool {
        matches!(self, Self::Ans)
    }
}

/// A BEEP data frame: `MSG`, `RPY`, `ERR`, `ANS` or `NUL`.
///
/// The payload is carried opaquely. MIME structure inside it is the concern of
/// [`crate::mime`] and of the layers above, not of framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrame {
    kind: FrameKind,
    channel: u32,
    msgno: u32,
    more: bool,
    seqno: u32,
    ansno: Option<u32>,
    payload: Bytes,
}

impl DataFrame {
    /// Builds a complete (`more` unset) frame of a kind that carries no `ansno`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingField`] when `kind` is [`FrameKind::Ans`], which requires an
    /// answer number and must be built with [`DataFrame::new_ans`]. Returns
    /// [`Error::ValueOutOfRange`] when a field exceeds the range BEEP allows, and
    /// [`Error::FrameTooLarge`] when the payload exceeds [`MAX_FRAME_SIZE`].
    pub fn new(
        kind: FrameKind,
        channel: u32,
        msgno: u32,
        seqno: u32,
        payload: Bytes,
    ) -> Result<Self, Error> {
        if kind.has_ansno() {
            return Err(Error::MissingField { field: "ansno" });
        }
        Self::build(kind, channel, msgno, seqno, None, payload)
    }

    /// Builds a complete (`more` unset) `ANS` frame.
    ///
    /// # Errors
    ///
    /// As [`DataFrame::new`], plus [`Error::ValueOutOfRange`] when `ansno` exceeds
    /// [`MAX_ANS_NO`].
    pub fn new_ans(
        channel: u32,
        msgno: u32,
        seqno: u32,
        ansno: u32,
        payload: Bytes,
    ) -> Result<Self, Error> {
        Self::build(FrameKind::Ans, channel, msgno, seqno, Some(ansno), payload)
    }

    fn build(
        kind: FrameKind,
        channel: u32,
        msgno: u32,
        seqno: u32,
        ansno: Option<u32>,
        payload: Bytes,
    ) -> Result<Self, Error> {
        check_range("channel", channel, MAX_CHANNEL_NO)?;
        check_range("msgno", msgno, MAX_MSG_NO)?;
        if let Some(ansno) = ansno {
            check_range("ansno", ansno, MAX_ANS_NO)?;
        }
        let size = u32::try_from(payload.len()).map_err(|_| Error::FrameTooLarge {
            size: MAX_FRAME_SIZE,
            limit: MAX_FRAME_SIZE,
        })?;
        if size > MAX_FRAME_SIZE {
            return Err(Error::FrameTooLarge {
                size,
                limit: MAX_FRAME_SIZE,
            });
        }
        Ok(Self {
            kind,
            channel,
            msgno,
            more: false,
            seqno,
            ansno,
            payload,
        })
    }

    /// Marks the frame as intermediate (`*`) or complete (`.`).
    #[must_use]
    pub fn with_more(mut self, more: bool) -> Self {
        self.more = more;
        self
    }

    /// The frame kind.
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        self.kind
    }

    /// The channel this frame belongs to.
    #[must_use]
    pub const fn channel(&self) -> u32 {
        self.channel
    }

    /// The message number.
    #[must_use]
    pub const fn msgno(&self) -> u32 {
        self.msgno
    }

    /// Whether more frames follow for this message.
    #[must_use]
    pub const fn more(&self) -> bool {
        self.more
    }

    /// The sequence number of the first payload octet.
    #[must_use]
    pub const fn seqno(&self) -> u32 {
        self.seqno
    }

    /// The answer number, present for [`FrameKind::Ans`] only.
    #[must_use]
    pub const fn ansno(&self) -> Option<u32> {
        self.ansno
    }

    /// The payload octets.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Takes ownership of the payload.
    #[must_use]
    pub fn into_payload(self) -> Bytes {
        self.payload
    }

    /// A handle to the payload sharing the same allocation.
    ///
    /// Cloning a [`Bytes`] bumps a reference count rather than copying, so this is the cheap
    /// way to keep the payload of a frame that is only borrowed.
    #[must_use]
    pub fn payload_bytes(&self) -> Bytes {
        self.payload.clone()
    }

    /// The `size` announced in the header, i.e. the payload length.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn size(&self) -> u32 {
        // Checked against MAX_FRAME_SIZE at construction and at decode.
        self.payload.len() as u32
    }

    /// Number of octets [`DataFrame::encode`] will append.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let mut len = 3 // kind
            + 1 + digits(self.channel)
            + 1 + digits(self.msgno)
            + 1 + 1 // more
            + 1 + digits(self.seqno)
            + 1 + digits(self.size());
        if let Some(ansno) = self.ansno {
            len += 1 + digits(ansno);
        }
        len + 2 + self.payload.len() + TRAILER.len()
    }

    /// Appends the wire representation of this frame to `dst`.
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(self.encoded_len());
        dst.put_slice(self.kind.as_str().as_bytes());
        dst.put_u8(b' ');
        put_u32(dst, self.channel);
        dst.put_u8(b' ');
        put_u32(dst, self.msgno);
        dst.put_u8(b' ');
        dst.put_u8(if self.more { INTERMEDIATE } else { COMPLETE });
        dst.put_u8(b' ');
        put_u32(dst, self.seqno);
        dst.put_u8(b' ');
        put_u32(dst, self.size());
        if let Some(ansno) = self.ansno {
            dst.put_u8(b' ');
            put_u32(dst, ansno);
        }
        dst.put_slice(b"\r\n");
        dst.put_slice(&self.payload);
        dst.put_slice(TRAILER);
    }
}

/// A `SEQ` frame, the flow control primitive of RFC3081.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqFrame {
    channel: u32,
    ackno: u32,
    window: u32,
}

impl SeqFrame {
    /// Builds a `SEQ` frame acknowledging `ackno` and advertising `window` octets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ValueOutOfRange`] when `channel` or `window` exceed their limits.
    pub fn new(channel: u32, ackno: u32, window: u32) -> Result<Self, Error> {
        check_range("channel", channel, MAX_CHANNEL_NO)?;
        check_range("window", window, MAX_FRAME_SIZE)?;
        Ok(Self {
            channel,
            ackno,
            window,
        })
    }

    /// The channel this frame refers to.
    #[must_use]
    pub const fn channel(&self) -> u32 {
        self.channel
    }

    /// The sequence number of the next octet expected.
    #[must_use]
    pub const fn ackno(&self) -> u32 {
        self.ackno
    }

    /// How many octets beyond `ackno` the peer may send.
    #[must_use]
    pub const fn window(&self) -> u32 {
        self.window
    }

    /// Number of octets [`SeqFrame::encode`] will append.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        3 + 1 + digits(self.channel) + 1 + digits(self.ackno) + 1 + digits(self.window) + 2
    }

    /// Appends the wire representation of this frame to `dst`.
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(self.encoded_len());
        dst.put_slice(b"SEQ ");
        put_u32(dst, self.channel);
        dst.put_u8(b' ');
        put_u32(dst, self.ackno);
        dst.put_u8(b' ');
        put_u32(dst, self.window);
        dst.put_slice(b"\r\n");
    }
}

/// Any BEEP frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A data frame.
    Data(DataFrame),
    /// A flow control frame.
    Seq(SeqFrame),
}

impl Frame {
    /// The channel the frame refers to.
    #[must_use]
    pub const fn channel(&self) -> u32 {
        match self {
            Self::Data(f) => f.channel(),
            Self::Seq(f) => f.channel(),
        }
    }

    /// Borrows the frame as a data frame, or `None` if it is a `SEQ` frame.
    #[must_use]
    pub const fn as_data(&self) -> Option<&DataFrame> {
        match self {
            Self::Data(f) => Some(f),
            Self::Seq(_) => None,
        }
    }

    /// Borrows the frame as a `SEQ` frame, or `None` if it is a data frame.
    #[must_use]
    pub const fn as_seq(&self) -> Option<&SeqFrame> {
        match self {
            Self::Seq(f) => Some(f),
            Self::Data(_) => None,
        }
    }

    /// Number of octets [`Frame::encode`] will append.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Data(f) => f.encoded_len(),
            Self::Seq(f) => f.encoded_len(),
        }
    }

    /// Appends the wire representation of this frame to `dst`.
    pub fn encode(&self, dst: &mut BytesMut) {
        match self {
            Self::Data(f) => f.encode(dst),
            Self::Seq(f) => f.encode(dst),
        }
    }
}

impl From<DataFrame> for Frame {
    fn from(f: DataFrame) -> Self {
        Self::Data(f)
    }
}

impl From<SeqFrame> for Frame {
    fn from(f: SeqFrame) -> Self {
        Self::Seq(f)
    }
}

fn check_range(field: &'static str, value: u32, max: u32) -> Result<(), Error> {
    if value > max {
        return Err(Error::ValueOutOfRange { field, max });
    }
    Ok(())
}

/// Decimal digit count of `value`, used to size the header without formatting it twice.
fn digits(value: u32) -> usize {
    let mut n = 1;
    let mut v = value;
    while v >= 10 {
        v /= 10;
        n += 1;
    }
    n
}

/// Appends `value` in decimal, without going through `core::fmt`.
#[allow(clippy::cast_possible_truncation)]
fn put_u32(dst: &mut BytesMut, value: u32) {
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    let mut v = value;
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    dst.put_slice(&buf[i..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digit_count_matches_rendering() {
        for value in [0u32, 9, 10, 99, 100, 4_294_967_295, MAX_FRAME_SIZE] {
            let mut buf = BytesMut::new();
            put_u32(&mut buf, value);
            assert_eq!(buf.len(), digits(value), "value {value}");
        }
    }

    #[test]
    fn encodes_a_data_frame() {
        let frame = DataFrame::new(FrameKind::Rpy, 0, 0, 0, Bytes::from_static(b"hello")).unwrap();
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        assert_eq!(&buf[..], b"RPY 0 0 . 0 5\r\nhelloEND\r\n");
        assert_eq!(buf.len(), frame.encoded_len());
    }

    #[test]
    fn encodes_an_intermediate_frame() {
        let frame = DataFrame::new(FrameKind::Msg, 1, 2, 300, Bytes::from_static(b"ab"))
            .unwrap()
            .with_more(true);
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        assert_eq!(&buf[..], b"MSG 1 2 * 300 2\r\nabEND\r\n");
    }

    #[test]
    fn encodes_an_ans_frame_with_its_answer_number() {
        let frame = DataFrame::new_ans(3, 4, 5, 6, Bytes::from_static(b"x")).unwrap();
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        assert_eq!(&buf[..], b"ANS 3 4 . 5 1 6\r\nxEND\r\n");
        assert_eq!(buf.len(), frame.encoded_len());
    }

    #[test]
    fn encodes_a_seq_frame_without_payload_or_trailer() {
        let frame = SeqFrame::new(1, 4096, 8192).unwrap();
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        assert_eq!(&buf[..], b"SEQ 1 4096 8192\r\n");
        assert_eq!(buf.len(), frame.encoded_len());
    }

    #[test]
    fn ans_cannot_be_built_without_an_answer_number() {
        let err = DataFrame::new(FrameKind::Ans, 0, 0, 0, Bytes::new()).unwrap_err();
        assert_eq!(err, Error::MissingField { field: "ansno" });
    }

    #[test]
    fn rejects_out_of_range_header_fields() {
        assert_eq!(
            DataFrame::new(FrameKind::Msg, MAX_CHANNEL_NO + 1, 0, 0, Bytes::new()).unwrap_err(),
            Error::ValueOutOfRange {
                field: "channel",
                max: MAX_CHANNEL_NO
            }
        );
        assert_eq!(
            DataFrame::new(FrameKind::Msg, 0, MAX_MSG_NO + 1, 0, Bytes::new()).unwrap_err(),
            Error::ValueOutOfRange {
                field: "msgno",
                max: MAX_MSG_NO
            }
        );
    }

    #[test]
    fn seqno_uses_the_full_unsigned_range() {
        let frame = DataFrame::new(FrameKind::Msg, 0, 0, MAX_SEQ_NO, Bytes::new()).unwrap();
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        assert_eq!(&buf[..], b"MSG 0 0 . 4294967295 0\r\nEND\r\n");
    }
}
