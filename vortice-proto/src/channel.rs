// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Per-channel state: message numbering, flow control and fragment reassembly.
//!
//! A [`Channel`] owns the bookkeeping BEEP requires for one channel of one session, and
//! nothing else — it has no idea what a socket is, and it never decides policy. It answers
//! two questions:
//!
//! - *what may I send right now, and what frames does that become?* — [`Channel::emit`],
//!   which fragments a payload to fit both the peer's window and the frame size limit, and
//!   hands back whatever did not fit so the caller can resume after the next `SEQ`;
//! - *is this arriving frame legal, and does it complete a message?* — [`Channel::accept`].
//!
//! # Message numbers
//!
//! A message number identifies an exchange, and may be reused once that exchange finishes.
//! [`Channel::allocate_msgno`] hands out the next free one, wrapping past
//! [`MAX_MSG_NO`](crate::frame::MAX_MSG_NO) back to zero; [`Channel::reserve_msgno`] takes a
//! specific one, which is what LibVortex `test_02n` drives as it walks the sequences
//! 0,1,2…, 1,2,3…, the wrap at 2147483646, 2147483647, 0, 1, and the descending 7,5,3,1.
//! Either way a number in flight cannot be handed out twice.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use bytes::{Bytes, BytesMut};

use crate::error::Error;
use crate::frame::{DataFrame, FrameKind, MAX_FRAME_SIZE, MAX_MSG_NO, SeqFrame};
use crate::window::{DEFAULT_WINDOW_SIZE, SeqNo, Window};

/// What one call to [`Channel::emit`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emitted {
    /// The frames to write, in order. All but the last carry the continuation indicator when
    /// more of the message is still to come.
    pub frames: Vec<DataFrame>,
    /// The part of the payload the window could not take.
    ///
    /// Empty means the message was emitted in full. Otherwise the channel is stalled: hold
    /// these octets and call [`Channel::emit`] again once a `SEQ` frame has been applied.
    pub remaining: Bytes,
}

impl Emitted {
    /// Whether the whole payload was turned into frames.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.remaining.is_empty()
    }
}

/// A message reassembled from one or more frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Which of `MSG`, `RPY`, `ERR`, `ANS` or `NUL` carried it.
    pub kind: FrameKind,
    /// The message number of the exchange.
    pub msgno: u32,
    /// The answer number, for `ANS` only.
    pub ansno: Option<u32>,
    /// The joined payload.
    pub payload: Bytes,
}

/// A message being reassembled from continuation frames.
#[derive(Debug, Clone)]
struct Partial {
    kind: FrameKind,
    msgno: u32,
    ansno: Option<u32>,
    payload: BytesMut,
}

impl Partial {
    fn matches(&self, frame: &DataFrame) -> bool {
        self.kind == frame.kind() && self.msgno == frame.msgno() && self.ansno == frame.ansno()
    }
}

/// One channel of a BEEP session.
#[derive(Debug, Clone)]
pub struct Channel {
    number: u32,
    profile: String,

    send_window: Window,
    next_seqno: SeqNo,
    next_msgno: u32,
    outstanding: BTreeSet<u32>,
    next_ansno: BTreeMap<u32, u32>,

    recv_window: Window,
    expected_seqno: SeqNo,
    awaiting_reply: BTreeSet<u32>,
    partial: Option<Partial>,
}

impl Channel {
    /// Opens a channel with the default window in both directions.
    #[must_use]
    pub fn new(number: u32, profile: impl Into<String>) -> Self {
        Self::with_window_size(number, profile, DEFAULT_WINDOW_SIZE)
    }

    /// Opens a channel advertising `window_size` octets in both directions.
    #[must_use]
    pub fn with_window_size(number: u32, profile: impl Into<String>, window_size: u32) -> Self {
        Self {
            number,
            profile: profile.into(),
            send_window: Window::new(SeqNo::ZERO, window_size),
            next_seqno: SeqNo::ZERO,
            next_msgno: 0,
            outstanding: BTreeSet::new(),
            next_ansno: BTreeMap::new(),
            recv_window: Window::new(SeqNo::ZERO, window_size),
            expected_seqno: SeqNo::ZERO,
            awaiting_reply: BTreeSet::new(),
            partial: None,
        }
    }

    /// The channel number.
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// The profile URI the channel was started with.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    // ---- outgoing ----------------------------------------------------------------

    /// The peer's window: what it has acknowledged and how much more it will take.
    #[must_use]
    pub const fn send_window(&self) -> Window {
        self.send_window
    }

    /// The sequence number the next outgoing octet will carry.
    #[must_use]
    pub const fn next_seqno(&self) -> SeqNo {
        self.next_seqno
    }

    /// How many octets may still be written before the channel stalls.
    #[must_use]
    pub fn writable(&self) -> u32 {
        self.send_window.remaining(self.next_seqno)
    }

    /// Whether nothing more may be written until a `SEQ` frame arrives.
    #[must_use]
    pub fn is_stalled(&self) -> bool {
        self.writable() == 0
    }

    /// Message numbers sent and not yet completed.
    pub fn outstanding(&self) -> impl Iterator<Item = u32> + '_ {
        self.outstanding.iter().copied()
    }

    /// Takes the next free message number, wrapping past [`MAX_MSG_NO`] back to zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MsgNoExhausted`] when every number is in flight, which needs
    /// 2³¹ concurrent unanswered messages on one channel.
    pub fn allocate_msgno(&mut self) -> Result<u32, Error> {
        for _ in 0..=u64::from(MAX_MSG_NO) {
            let candidate = self.next_msgno;
            self.next_msgno = if candidate == MAX_MSG_NO {
                0
            } else {
                candidate + 1
            };
            if !self.outstanding.contains(&candidate) {
                self.outstanding.insert(candidate);
                return Ok(candidate);
            }
        }
        Err(Error::MsgNoExhausted)
    }

    /// Takes a specific message number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MsgNoInUse`] when that number is still awaiting its reply, and
    /// [`Error::ValueOutOfRange`] when it exceeds [`MAX_MSG_NO`].
    pub fn reserve_msgno(&mut self, msgno: u32) -> Result<(), Error> {
        if msgno > MAX_MSG_NO {
            return Err(Error::ValueOutOfRange {
                field: "msgno",
                max: MAX_MSG_NO,
            });
        }
        if !self.outstanding.insert(msgno) {
            return Err(Error::MsgNoInUse { msgno });
        }
        self.next_msgno = if msgno == MAX_MSG_NO { 0 } else { msgno + 1 };
        Ok(())
    }

    /// Marks an exchange as finished, freeing its message number for reuse.
    pub fn release_msgno(&mut self, msgno: u32) {
        self.outstanding.remove(&msgno);
    }

    /// Turns a payload into frames that fit the peer's window and the frame size limit.
    ///
    /// All but the final frame of a message carry the continuation indicator, and so does
    /// the final one emitted when the window ran out before the payload did — in which case
    /// [`Emitted::remaining`] holds the rest.
    ///
    /// An empty payload always produces exactly one frame, since a zero length frame
    /// consumes no window. That is the case LibVortex `test_02p` covers with an empty `RPY`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChannelStalled`] when there is payload to send and no window at all,
    /// and [`Error::MissingField`] when an `ANS` is requested without an answer number.
    pub fn emit(
        &mut self,
        kind: FrameKind,
        msgno: u32,
        ansno: Option<u32>,
        payload: Bytes,
        max_frame_size: u32,
    ) -> Result<Emitted, Error> {
        if kind.has_ansno() != ansno.is_some() {
            return Err(Error::MissingField { field: "ansno" });
        }
        let chunk_limit = max_frame_size.clamp(1, MAX_FRAME_SIZE);

        if payload.is_empty() {
            let frame = self.build(kind, msgno, ansno, Bytes::new(), false)?;
            return Ok(Emitted {
                frames: alloc::vec![frame],
                remaining: Bytes::new(),
            });
        }

        let budget = self.writable();
        if budget == 0 {
            return Err(Error::ChannelStalled);
        }

        let total = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let mut head = payload;
        let remaining = head.split_off(budget.min(total) as usize);

        let mut frames = Vec::new();
        while !head.is_empty() {
            let take = chunk_limit.min(u32::try_from(head.len()).unwrap_or(u32::MAX));
            let chunk = head.split_to(take as usize);
            let more = !head.is_empty() || !remaining.is_empty();
            frames.push(self.build(kind, msgno, ansno, chunk, more)?);
        }
        Ok(Emitted { frames, remaining })
    }

    /// Builds one frame and charges its payload against the outgoing counters.
    fn build(
        &mut self,
        kind: FrameKind,
        msgno: u32,
        ansno: Option<u32>,
        payload: Bytes,
        more: bool,
    ) -> Result<DataFrame, Error> {
        let len = u32::try_from(payload.len()).map_err(|_| Error::FrameTooLarge {
            size: MAX_FRAME_SIZE,
            limit: MAX_FRAME_SIZE,
        })?;
        let seqno = self.next_seqno;
        let frame = match ansno {
            Some(ansno) => DataFrame::new_ans(self.number, msgno, seqno.get(), ansno, payload)?,
            None => DataFrame::new(kind, self.number, msgno, seqno.get(), payload)?,
        };
        self.next_seqno = seqno.advance(len);
        Ok(frame.with_more(more))
    }

    /// Takes the next answer number for a one-to-many reply to `msgno`.
    ///
    /// Answer numbers restart at zero for every message being answered, and
    /// [`Channel::finish_answers`] releases the counter when the `NUL` goes out.
    pub fn allocate_ansno(&mut self, msgno: u32) -> u32 {
        let slot = self.next_ansno.entry(msgno).or_insert(0);
        let ansno = *slot;
        *slot = slot.wrapping_add(1);
        ansno
    }

    /// Ends a one-to-many reply, discarding its answer numbering.
    pub fn finish_answers(&mut self, msgno: u32) {
        self.next_ansno.remove(&msgno);
    }

    /// Applies a received `SEQ` frame, moving the peer's window forward.
    pub fn apply_seq(&mut self, seq: &SeqFrame) {
        self.send_window = self
            .send_window
            .updated(SeqNo::new(seq.ackno()), seq.window());
    }

    // ---- incoming ----------------------------------------------------------------

    /// The window this end has advertised for incoming traffic.
    #[must_use]
    pub const fn recv_window(&self) -> Window {
        self.recv_window
    }

    /// The sequence number the next incoming octet must carry.
    #[must_use]
    pub const fn expected_seqno(&self) -> SeqNo {
        self.expected_seqno
    }

    /// Message numbers received and not yet replied to.
    pub fn awaiting_reply(&self) -> impl Iterator<Item = u32> + '_ {
        self.awaiting_reply.iter().copied()
    }

    /// Whether a message is partly reassembled and waiting for its continuation.
    #[must_use]
    pub const fn has_partial_message(&self) -> bool {
        self.partial.is_some()
    }

    /// Accepts an incoming data frame, returning the message when it completes one.
    ///
    /// Continuation frames return `Ok(None)` until the final fragment arrives.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedSeqNo`] for a gap or overlap in the octet stream,
    /// [`Error::OutsideWindow`] when the frame runs past what was advertised, and
    /// [`Error::InterleavedFragment`] when a different message begins while one is still
    /// being reassembled. LibVortex drops the session on all three.
    pub fn accept(&mut self, frame: &DataFrame) -> Result<Option<Message>, Error> {
        let seqno = SeqNo::new(frame.seqno());
        if seqno != self.expected_seqno {
            return Err(Error::UnexpectedSeqNo {
                found: frame.seqno(),
                expected: self.expected_seqno.get(),
            });
        }
        let len = frame.size();
        if !self.recv_window.accepts(seqno, len) {
            return Err(Error::OutsideWindow {
                seqno: frame.seqno(),
                len,
                limit: self.recv_window.limit().get(),
            });
        }
        self.expected_seqno = seqno.advance(len);

        if frame.kind() == FrameKind::Msg && !frame.more() {
            self.awaiting_reply.insert(frame.msgno());
        }

        match self.partial.take() {
            Some(mut partial) => {
                if !partial.matches(frame) {
                    return Err(Error::InterleavedFragment);
                }
                partial.payload.extend_from_slice(frame.payload());
                if frame.more() {
                    self.partial = Some(partial);
                    return Ok(None);
                }
                Ok(Some(Message {
                    kind: partial.kind,
                    msgno: partial.msgno,
                    ansno: partial.ansno,
                    payload: partial.payload.freeze(),
                }))
            }
            None => {
                if frame.more() {
                    self.partial = Some(Partial {
                        kind: frame.kind(),
                        msgno: frame.msgno(),
                        ansno: frame.ansno(),
                        payload: BytesMut::from(frame.payload()),
                    });
                    return Ok(None);
                }
                Ok(Some(Message {
                    kind: frame.kind(),
                    msgno: frame.msgno(),
                    ansno: frame.ansno(),
                    payload: frame.payload_bytes(),
                }))
            }
        }
    }

    /// Marks an incoming message as replied to.
    pub fn replied(&mut self, msgno: u32) {
        self.awaiting_reply.remove(&msgno);
    }

    /// Records that `octets` of received payload have been handed to the application, and
    /// returns the `SEQ` frame that reopens the window.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ValueOutOfRange`] if the channel number or window size cannot be
    /// carried in a header, which the constructors already rule out.
    pub fn consume(&mut self, octets: u32) -> Result<SeqFrame, Error> {
        self.recv_window = self.recv_window.consumed(octets);
        self.recv_window.to_seq_frame(self.number)
    }

    /// Changes the window advertised for incoming traffic.
    ///
    /// `test_04d` drives this down to 1024 octets across successive sends, and `test_02m1`
    /// negotiates it upward.
    pub fn set_recv_window_size(&mut self, size: u32) {
        self.recv_window = self.recv_window.resized(size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(len: usize) -> Bytes {
        Bytes::from(alloc::vec![b'x'; len])
    }

    fn channel() -> Channel {
        Channel::with_window_size(1, "urn:example:echo", 4096)
    }

    // ---- message numbering: the sequences test_02n walks ----

    #[test]
    fn allocates_message_numbers_in_order() {
        let mut channel = channel();
        assert_eq!(channel.allocate_msgno().unwrap(), 0);
        assert_eq!(channel.allocate_msgno().unwrap(), 1);
        assert_eq!(channel.allocate_msgno().unwrap(), 2);
    }

    #[test]
    fn reuses_a_message_number_once_its_exchange_finishes() {
        let mut channel = channel();
        assert_eq!(channel.allocate_msgno().unwrap(), 0);
        channel.release_msgno(0);
        channel.reserve_msgno(0).unwrap();
        assert_eq!(channel.outstanding().collect::<Vec<_>>(), [0]);
    }

    #[test]
    fn refuses_a_message_number_still_in_flight() {
        let mut channel = channel();
        channel.reserve_msgno(4).unwrap();
        assert_eq!(
            channel.reserve_msgno(4).unwrap_err(),
            Error::MsgNoInUse { msgno: 4 }
        );
    }

    #[test]
    fn skips_numbers_that_are_in_flight_when_allocating() {
        let mut channel = channel();
        channel.reserve_msgno(1).unwrap();
        channel.reserve_msgno(2).unwrap();
        // next_msgno now points past 2; allocation must not collide with either.
        let allocated = channel.allocate_msgno().unwrap();
        assert_eq!(allocated, 3);
    }

    #[test]
    fn wraps_message_numbers_past_the_maximum() {
        // test_02n drives exactly this: 2147483646, 2147483647, 0, 1.
        let mut channel = channel();
        for msgno in [MAX_MSG_NO - 1, MAX_MSG_NO] {
            channel.reserve_msgno(msgno).unwrap();
            channel.release_msgno(msgno);
        }
        assert_eq!(channel.allocate_msgno().unwrap(), 0);
        assert_eq!(channel.allocate_msgno().unwrap(), 1);
    }

    #[test]
    fn accepts_the_descending_sequence() {
        // test_02n also walks 7, 5, 3, 1.
        let mut channel = channel();
        for msgno in [7, 5, 3, 1] {
            channel.reserve_msgno(msgno).unwrap();
        }
        assert_eq!(channel.outstanding().collect::<Vec<_>>(), [1, 3, 5, 7]);
    }

    #[test]
    fn rejects_a_message_number_beyond_the_maximum() {
        let mut channel = channel();
        assert_eq!(
            channel.reserve_msgno(MAX_MSG_NO + 1).unwrap_err(),
            Error::ValueOutOfRange {
                field: "msgno",
                max: MAX_MSG_NO
            }
        );
    }

    // ---- emitting ----

    #[test]
    fn emits_a_short_message_as_one_frame() {
        let mut channel = channel();
        let emitted = channel
            .emit(FrameKind::Msg, 0, None, payload(10), 4096)
            .unwrap();
        assert!(emitted.is_complete());
        assert_eq!(emitted.frames.len(), 1);
        assert!(!emitted.frames[0].more());
        assert_eq!(channel.next_seqno(), SeqNo::new(10));
    }

    #[test]
    fn emits_an_empty_frame_even_with_no_window_left() {
        // test_02p sends an empty RPY; a zero length frame consumes no window.
        let mut channel = channel();
        channel
            .emit(FrameKind::Msg, 0, None, payload(4096), 4096)
            .unwrap();
        assert!(channel.is_stalled());
        let emitted = channel
            .emit(FrameKind::Rpy, 0, None, Bytes::new(), 4096)
            .unwrap();
        assert_eq!(emitted.frames.len(), 1);
        assert_eq!(emitted.frames[0].size(), 0);
    }

    #[test]
    fn fragments_a_message_that_exceeds_the_frame_size() {
        let mut channel = channel();
        let emitted = channel
            .emit(FrameKind::Msg, 0, None, payload(1000), 300)
            .unwrap();
        assert!(emitted.is_complete());
        assert_eq!(emitted.frames.len(), 4);
        let sizes: Vec<_> = emitted.frames.iter().map(DataFrame::size).collect();
        assert_eq!(sizes, [300, 300, 300, 100]);
        let more: Vec<_> = emitted.frames.iter().map(DataFrame::more).collect();
        assert_eq!(more, [true, true, true, false]);
    }

    #[test]
    fn stops_at_the_window_and_hands_back_the_rest() {
        let mut channel = Channel::with_window_size(1, "urn:a", 1024);
        let emitted = channel
            .emit(FrameKind::Msg, 0, None, payload(4096), 4096)
            .unwrap();
        assert!(!emitted.is_complete());
        assert_eq!(emitted.remaining.len(), 3072);
        assert_eq!(emitted.frames.len(), 1);
        // The message is unfinished, so the frame that did go out says so.
        assert!(emitted.frames[0].more());
        assert!(channel.is_stalled());
    }

    #[test]
    fn resumes_once_a_seq_frame_reopens_the_window() {
        let mut channel = Channel::with_window_size(1, "urn:a", 1024);
        let first = channel
            .emit(FrameKind::Msg, 0, None, payload(2048), 4096)
            .unwrap();
        assert_eq!(
            channel.emit(FrameKind::Msg, 0, None, first.remaining.clone(), 4096),
            Err(Error::ChannelStalled)
        );

        channel.apply_seq(&SeqFrame::new(1, 1024, 4096).unwrap());
        let second = channel
            .emit(FrameKind::Msg, 0, None, first.remaining, 4096)
            .unwrap();
        assert!(second.is_complete());
        assert!(!second.frames.last().unwrap().more());
        assert_eq!(channel.next_seqno(), SeqNo::new(2048));
    }

    #[test]
    fn refuses_an_ans_without_an_answer_number() {
        let mut channel = channel();
        assert_eq!(
            channel.emit(FrameKind::Ans, 0, None, payload(1), 4096),
            Err(Error::MissingField { field: "ansno" })
        );
        assert_eq!(
            channel.emit(FrameKind::Rpy, 0, Some(0), payload(1), 4096),
            Err(Error::MissingField { field: "ansno" })
        );
    }

    #[test]
    fn numbers_answers_from_zero_for_each_message() {
        let mut channel = channel();
        assert_eq!(channel.allocate_ansno(3), 0);
        assert_eq!(channel.allocate_ansno(3), 1);
        assert_eq!(channel.allocate_ansno(4), 0);
        channel.finish_answers(3);
        assert_eq!(channel.allocate_ansno(3), 0);
    }

    // ---- accepting ----

    #[test]
    fn accepts_a_complete_frame_as_a_whole_message() {
        let mut channel = channel();
        let frame = DataFrame::new(FrameKind::Msg, 1, 0, 0, payload(5)).unwrap();
        let message = channel.accept(&frame).unwrap().unwrap();
        assert_eq!(message.kind, FrameKind::Msg);
        assert_eq!(message.payload.len(), 5);
        assert_eq!(channel.expected_seqno(), SeqNo::new(5));
        assert_eq!(channel.awaiting_reply().collect::<Vec<_>>(), [0]);
    }

    #[test]
    fn joins_continuation_frames_into_one_message() {
        let mut channel = channel();
        let first = DataFrame::new(FrameKind::Msg, 1, 0, 0, Bytes::from_static(b"hello "))
            .unwrap()
            .with_more(true);
        let second = DataFrame::new(FrameKind::Msg, 1, 0, 6, Bytes::from_static(b"world")).unwrap();

        assert!(channel.accept(&first).unwrap().is_none());
        assert!(channel.has_partial_message());
        let message = channel.accept(&second).unwrap().unwrap();
        assert_eq!(&message.payload[..], b"hello world");
        assert!(!channel.has_partial_message());
    }

    #[test]
    fn rejects_a_different_message_arriving_mid_reassembly() {
        let mut channel = channel();
        let first = DataFrame::new(FrameKind::Msg, 1, 0, 0, payload(4))
            .unwrap()
            .with_more(true);
        let other = DataFrame::new(FrameKind::Msg, 1, 1, 4, payload(4)).unwrap();
        channel.accept(&first).unwrap();
        assert_eq!(
            channel.accept(&other).unwrap_err(),
            Error::InterleavedFragment
        );
    }

    #[test]
    fn rejects_a_gap_in_the_octet_stream() {
        let mut channel = channel();
        let frame = DataFrame::new(FrameKind::Msg, 1, 0, 8, payload(4)).unwrap();
        assert_eq!(
            channel.accept(&frame).unwrap_err(),
            Error::UnexpectedSeqNo {
                found: 8,
                expected: 0
            }
        );
    }

    #[test]
    fn rejects_a_frame_that_overruns_the_advertised_window() {
        let mut channel = Channel::with_window_size(1, "urn:a", 16);
        let frame = DataFrame::new(FrameKind::Msg, 1, 0, 0, payload(17)).unwrap();
        assert_eq!(
            channel.accept(&frame).unwrap_err(),
            Error::OutsideWindow {
                seqno: 0,
                len: 17,
                limit: 16
            }
        );
    }

    #[test]
    fn consuming_payload_advertises_a_fresh_window() {
        let mut channel = Channel::with_window_size(1, "urn:a", 4096);
        let frame = DataFrame::new(FrameKind::Msg, 1, 0, 0, payload(1000)).unwrap();
        channel.accept(&frame).unwrap();
        let seq = channel.consume(1000).unwrap();
        assert_eq!((seq.channel(), seq.ackno(), seq.window()), (1, 1000, 4096));
    }

    #[test]
    fn tracks_answers_and_their_terminator() {
        let mut channel = channel();
        let ans = DataFrame::new_ans(1, 0, 0, 0, payload(3)).unwrap();
        let nul = DataFrame::new(FrameKind::Nul, 1, 0, 3, Bytes::new()).unwrap();

        let first = channel.accept(&ans).unwrap().unwrap();
        assert_eq!(first.ansno, Some(0));
        let last = channel.accept(&nul).unwrap().unwrap();
        assert_eq!(last.kind, FrameKind::Nul);
        assert_eq!(last.ansno, None);
    }

    #[test]
    fn a_whole_message_survives_the_four_gigabyte_boundary() {
        // The receiving half of what test_02o probes.
        let mut channel = Channel::with_window_size(1, "urn:a", 4096);
        let start = SeqNo::new(u32::MAX - 1000);
        channel.expected_seqno = start;
        channel.recv_window = Window::new(start, 4096);

        let frame = DataFrame::new(FrameKind::Msg, 1, 0, start.get(), payload(2000)).unwrap();
        channel.accept(&frame).unwrap().unwrap();
        assert_eq!(channel.expected_seqno(), start.advance(2000));
        assert_eq!(channel.expected_seqno(), SeqNo::new(999));
    }
}
