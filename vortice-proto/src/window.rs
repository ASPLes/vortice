// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Sequence numbers and the sliding window that governs how much may be in flight.
//!
//! BEEP numbers octets, not frames. Each direction of a channel has its own counter, and
//! RFC3081 §3.1.3 makes it a 32 bit value that **wraps modulo 2³²**. The `SEQ` frame moves
//! the window forward: `SEQ <channel> <ackno> <window>` says "I have consumed everything
//! below `ackno` and will accept `window` octets beyond it".
//!
//! Everything here is modular arithmetic on [`SeqNo`], which is what makes the wrap
//! invisible to callers: there is no "before the wrap" and "after the wrap" case to get
//! wrong, because subtraction is always taken modulo 2³².
//!
//! # Divergence from LibVortex around the wrap point
//!
//! LibVortex advances its counters with `(counter + size) % MAX_SEQ_NO`, where `MAX_SEQ_NO`
//! is 4294967295 — that is, modulo 2³² − 1. Since the counters are `unsigned int`, the
//! addition has already wrapped modulo 2³² by the time the remainder is taken, so the
//! remainder is a no-op for every value except exactly 4294967295, which it maps to 0.
//!
//! The effect is that LibVortex never emits the sequence number 4294967295: if a frame
//! boundary lands precisely on it, the counter jumps to 0 and everything afterwards is
//! offset by one octet relative to a conformant peer, which then rejects the traffic as
//! outside its window.
//!
//! Vortice follows RFC3081 and wraps modulo 2³². The two agree everywhere except at that
//! single value, and the header of the affected LibVortex code carries the constant that
//! would make it agree — `MAX_SEQ_MOD`, defined as 4294967296 in `vortex_types.h` with a
//! comment saying rotation should use it, and never referenced anywhere in the source. This
//! looks like an oversight in the C rather than a deliberate choice, and it is being raised
//! with the LibVortex maintainers; if it is instead confirmed as intended, this module is
//! the single place that has to change.

use crate::frame::MAX_FRAME_SIZE;

/// The modulus sequence numbers wrap at, 2³².
pub const SEQ_MODULUS: u64 = 4_294_967_296;

/// A BEEP sequence number: a count of octets that wraps modulo 2³².
///
/// ```
/// use vortice_proto::window::SeqNo;
///
/// let near_the_end = SeqNo::new(u32::MAX - 3);
/// let wrapped = near_the_end.advance(10);
/// assert_eq!(wrapped, SeqNo::new(6));
/// assert_eq!(wrapped.distance_from(near_the_end), 10);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct SeqNo(u32);

impl SeqNo {
    /// The sequence number every channel starts from.
    pub const ZERO: Self = Self(0);

    /// Wraps a raw counter value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The raw counter value, as it appears in a frame header.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The sequence number `octets` further on, wrapping modulo 2³².
    #[must_use]
    pub const fn advance(self, octets: u32) -> Self {
        Self(self.0.wrapping_add(octets))
    }

    /// How many octets forward `self` is from `base`, modulo 2³².
    ///
    /// Because the counter is modular there is no notion of "behind": a sequence number one
    /// octet before `base` is reported as 2³² − 1 octets ahead of it. Callers decide what
    /// counts as plausible by comparing against a window size.
    #[must_use]
    pub const fn distance_from(self, base: Self) -> u32 {
        self.0.wrapping_sub(base.0)
    }
}

impl From<u32> for SeqNo {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<SeqNo> for u32 {
    fn from(value: SeqNo) -> Self {
        value.0
    }
}

/// One direction of a channel's flow control: what the peer has consumed, and how much more
/// it will take.
///
/// The same type serves both directions. For incoming traffic it holds what this end has
/// consumed and advertised, and [`Window::accepts`] decides whether an arriving frame is
/// within what was offered. For outgoing traffic it holds what the peer last acknowledged
/// in a `SEQ` frame, and [`Window::remaining`] says how much may still be written before
/// the channel stalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    base: SeqNo,
    size: u32,
}

/// Window size a channel starts with, matching the LibVortex default.
pub const DEFAULT_WINDOW_SIZE: u32 = 4096;

impl Default for Window {
    fn default() -> Self {
        Self {
            base: SeqNo::ZERO,
            size: DEFAULT_WINDOW_SIZE,
        }
    }
}

impl Window {
    /// A window of `size` octets starting at `base`.
    #[must_use]
    pub const fn new(base: SeqNo, size: u32) -> Self {
        Self { base, size }
    }

    /// The first octet not yet acknowledged.
    #[must_use]
    pub const fn base(&self) -> SeqNo {
        self.base
    }

    /// How many octets the window spans.
    #[must_use]
    pub const fn size(&self) -> u32 {
        self.size
    }

    /// The first sequence number beyond the window.
    #[must_use]
    pub const fn limit(&self) -> SeqNo {
        self.base.advance(self.size)
    }

    /// Whether a frame of `len` octets starting at `seqno` falls entirely inside the window.
    ///
    /// This is `vortex_channel_check_incoming_seqno` with its two branches collapsed into
    /// one: the C splits the comparison into a normal case and a wrapped case because it
    /// subtracts in plain arithmetic, whereas modular subtraction handles both at once.
    #[must_use]
    pub fn accepts(&self, seqno: SeqNo, len: u32) -> bool {
        let offset = u64::from(seqno.distance_from(self.base));
        offset + u64::from(len) <= u64::from(self.size)
    }

    /// How many octets may still be written, given that `next` is the next to be sent.
    ///
    /// Zero means the channel is stalled: nothing more may go out until a `SEQ` frame
    /// advances the window. This is `vortex_channel_is_stalled` expressed as a quantity.
    #[must_use]
    pub fn remaining(&self, next: SeqNo) -> u32 {
        self.size.saturating_sub(next.distance_from(self.base))
    }

    /// Whether nothing more may be written before the window moves.
    #[must_use]
    pub fn is_stalled(&self, next: SeqNo) -> bool {
        self.remaining(next) == 0
    }

    /// Applies a received `SEQ` frame.
    #[must_use]
    pub const fn updated(self, ackno: SeqNo, size: u32) -> Self {
        Self { base: ackno, size }
    }

    /// Moves the window forward by `octets` without changing its size.
    ///
    /// This is what the receiving side does as it consumes payload and becomes willing to
    /// advertise a fresh window.
    #[must_use]
    pub const fn consumed(self, octets: u32) -> Self {
        Self {
            base: self.base.advance(octets),
            size: self.size,
        }
    }

    /// Resizes the window in place, keeping its base.
    ///
    /// Used by `test_04d`, which drives the receiving side down to 1024 octets across
    /// successive sends, and by `test_02m1`, which negotiates it upward.
    #[must_use]
    pub const fn resized(self, size: u32) -> Self {
        Self {
            base: self.base,
            size,
        }
    }

    /// The `SEQ` frame that advertises this window, for the given channel.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValueOutOfRange`] when the channel number or the window size
    /// exceed what a header may carry.
    pub fn to_seq_frame(&self, channel: u32) -> Result<crate::SeqFrame, crate::Error> {
        crate::SeqFrame::new(channel, self.base.get(), self.size)
    }
}

/// Largest window size that can be advertised in a `SEQ` frame.
pub const MAX_WINDOW_SIZE: u32 = MAX_FRAME_SIZE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advances_and_measures_without_wrapping() {
        let base = SeqNo::new(100);
        assert_eq!(base.advance(50), SeqNo::new(150));
        assert_eq!(SeqNo::new(150).distance_from(base), 50);
        assert_eq!(base.distance_from(base), 0);
    }

    #[test]
    fn advances_and_measures_across_the_wrap() {
        let base = SeqNo::new(u32::MAX - 3);
        assert_eq!(base.advance(4), SeqNo::ZERO);
        assert_eq!(base.advance(10), SeqNo::new(6));
        assert_eq!(SeqNo::new(6).distance_from(base), 10);
    }

    #[test]
    fn uses_the_sequence_number_libvortex_skips() {
        // LibVortex's `% MAX_SEQ_NO` maps exactly this value to 0; RFC3081 does not.
        assert_eq!(SeqNo::new(u32::MAX - 1).advance(1), SeqNo::new(u32::MAX));
        assert_eq!(SeqNo::new(u32::MAX).advance(1), SeqNo::ZERO);
        assert_eq!(u64::from(u32::MAX) + 1, SEQ_MODULUS);
    }

    #[test]
    fn accepts_frames_that_fit_the_window() {
        let window = Window::new(SeqNo::new(1000), 4096);
        assert!(window.accepts(SeqNo::new(1000), 4096));
        assert!(window.accepts(SeqNo::new(5000), 96));
        assert!(window.accepts(SeqNo::new(5096), 0));
    }

    #[test]
    fn rejects_frames_that_overrun_the_window() {
        let window = Window::new(SeqNo::new(1000), 4096);
        assert!(!window.accepts(SeqNo::new(1000), 4097));
        assert!(!window.accepts(SeqNo::new(5096), 1));
        // A sequence number before the base reads as almost 2^32 octets ahead.
        assert!(!window.accepts(SeqNo::new(999), 1));
    }

    #[test]
    fn accepts_frames_that_straddle_the_wrap() {
        let window = Window::new(SeqNo::new(u32::MAX - 100), 4096);
        assert!(window.accepts(SeqNo::new(u32::MAX - 100), 200));
        assert!(window.accepts(SeqNo::new(50), 100));
        assert!(!window.accepts(SeqNo::new(50), u32::MAX));
    }

    #[test]
    fn reports_what_is_left_to_send() {
        let window = Window::new(SeqNo::new(1000), 4096);
        assert_eq!(window.remaining(SeqNo::new(1000)), 4096);
        assert_eq!(window.remaining(SeqNo::new(3000)), 2096);
        assert_eq!(window.remaining(SeqNo::new(5096)), 0);
        assert!(window.is_stalled(SeqNo::new(5096)));
        assert!(!window.is_stalled(SeqNo::new(5095)));
    }

    #[test]
    fn reports_nothing_left_once_the_window_is_overrun() {
        let window = Window::new(SeqNo::new(1000), 4096);
        assert_eq!(window.remaining(SeqNo::new(6000)), 0);
    }

    #[test]
    fn a_seq_frame_moves_the_window() {
        let window = Window::new(SeqNo::ZERO, 4096).updated(SeqNo::new(4096), 4096);
        assert_eq!(window.base(), SeqNo::new(4096));
        assert_eq!(window.remaining(SeqNo::new(4096)), 4096);
    }

    #[test]
    fn consuming_payload_slides_the_window_forward() {
        let window = Window::new(SeqNo::ZERO, 4096).consumed(1000);
        assert_eq!(window.base(), SeqNo::new(1000));
        assert_eq!(window.size(), 4096);
    }

    #[test]
    fn resizing_keeps_the_base() {
        // test_04d drives the receiving window down to 1024 across successive sends.
        let window = Window::new(SeqNo::new(2048), 4096).resized(1024);
        assert_eq!(window.base(), SeqNo::new(2048));
        assert_eq!(window.size(), 1024);
        assert!(!window.accepts(SeqNo::new(2048), 1025));
    }

    #[test]
    fn renders_the_seq_frame_that_advertises_it() {
        let mut buf = bytes::BytesMut::new();
        Window::new(SeqNo::new(4096), 8192)
            .to_seq_frame(1)
            .unwrap()
            .encode(&mut buf);
        assert_eq!(&buf[..], b"SEQ 1 4096 8192\r\n");
    }

    /// Walks a channel across the 4 GB boundary the way `test_02o` does, one window at a
    /// time, checking that every frame is accepted and the counter lands where RFC3081 says.
    #[test]
    #[allow(clippy::items_after_statements)]
    fn survives_a_full_pass_over_the_four_gigabyte_boundary() {
        const CHUNK: u32 = 4096;
        let start = SeqNo::new(u32::MAX - CHUNK * 4);
        let mut next = start;
        let mut window = Window::new(start, CHUNK);

        for _ in 0..10 {
            assert!(window.accepts(next, CHUNK), "frame at {next:?} refused");
            next = next.advance(CHUNK);
            window = window.updated(next, CHUNK);
        }

        let expected = u64::from(start.get())
            .checked_add(u64::from(CHUNK) * 10)
            .map(|total| total % SEQ_MODULUS)
            .and_then(|value| u32::try_from(value).ok())
            .expect("modulo keeps the value in range");
        assert_eq!(next, SeqNo::new(expected));
    }
}

/// Property tests for the window arithmetic.
///
/// These exist because the wrap at 2³² is the single place in BEEP where an implementation
/// can be right on every hand-written example and still be wrong: the interesting states are
/// four billion octets into a channel's life, where no unit test naturally goes. Generating
/// the base uniformly over the whole range puts the wrap under test on most runs.
#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Advancing then measuring is the identity, at any distance and from any point.
        #[test]
        fn advance_and_distance_are_inverses(base: u32, octets: u32) {
            let base = SeqNo::new(base);
            prop_assert_eq!(base.advance(octets).distance_from(base), octets);
        }

        /// Advancing by a total is the same as advancing in two steps.
        #[test]
        fn advancing_is_additive(base: u32, first: u32, second: u32) {
            let base = SeqNo::new(base);
            prop_assert_eq!(
                base.advance(first).advance(second),
                base.advance(first.wrapping_add(second))
            );
        }

        /// A full turn of the counter returns to where it started.
        #[test]
        fn a_full_cycle_is_the_identity(base: u32) {
            let base = SeqNo::new(base);
            prop_assert_eq!(base.advance(u32::MAX).advance(1), base);
        }

        /// Acceptance depends only on the offset into the window, never on where the window
        /// happens to sit. This is the property that makes the wrap a non-event: sliding both
        /// the window and the frame by the same amount drags them across 2³² on most runs and
        /// must change nothing.
        #[test]
        fn acceptance_is_invariant_under_translation(
            base: u32,
            offset in 0u32..16_384,
            len in 0u32..16_384,
            size in 0u32..16_384,
            shift: u32,
        ) {
            let here = Window::new(SeqNo::new(base), size);
            let there = Window::new(SeqNo::new(base).advance(shift), size);
            prop_assert_eq!(
                here.accepts(SeqNo::new(base).advance(offset), len),
                there.accepts(SeqNo::new(base).advance(shift).advance(offset), len)
            );
        }

        /// A frame is accepted exactly when it ends at or before the window limit.
        #[test]
        fn acceptance_matches_the_arithmetic_definition(
            base: u32,
            offset in 0u32..16_384,
            len in 0u32..16_384,
            size in 0u32..16_384,
        ) {
            let window = Window::new(SeqNo::new(base), size);
            let fits = u64::from(offset) + u64::from(len) <= u64::from(size);
            prop_assert_eq!(window.accepts(SeqNo::new(base).advance(offset), len), fits);
        }

        /// Having room left and accepting one more octet are the same statement.
        #[test]
        fn remaining_agrees_with_acceptance(base: u32, offset: u32, size in 0u32..16_384) {
            let window = Window::new(SeqNo::new(base), size);
            let next = SeqNo::new(base).advance(offset);
            prop_assert_eq!(window.remaining(next) > 0, window.accepts(next, 1));
            prop_assert_eq!(window.remaining(next) == 0, window.is_stalled(next));
        }

        /// Writing everything the window allows stalls the channel, and not a byte sooner.
        #[test]
        fn a_window_is_exhausted_exactly_at_its_limit(base: u32, size in 1u32..16_384) {
            let window = Window::new(SeqNo::new(base), size);
            let next = SeqNo::new(base).advance(size);
            prop_assert!(window.is_stalled(next));
            prop_assert!(!window.is_stalled(SeqNo::new(base).advance(size - 1)));
            prop_assert_eq!(window.limit(), next);
        }

        /// Consuming payload moves the base and leaves the size alone, so the amount still
        /// offered to the peer is restored to the full window.
        #[test]
        fn consuming_restores_the_offer(base: u32, octets in 0u32..16_384, size in 0u32..16_384) {
            let window = Window::new(SeqNo::new(base), size);
            let after = window.consumed(octets);
            prop_assert_eq!(after.size(), size);
            prop_assert_eq!(after.base(), SeqNo::new(base).advance(octets));
            prop_assert_eq!(after.remaining(after.base()), size);
        }

        /// A SEQ frame round-trips through the header encoding it is advertised with.
        #[test]
        fn seq_frames_round_trip(channel in 0u32..=crate::frame::MAX_CHANNEL_NO, base: u32, size in 0u32..=MAX_WINDOW_SIZE) {
            use bytes::BytesMut;

            let window = Window::new(SeqNo::new(base), size);
            let mut buf = BytesMut::new();
            window.to_seq_frame(channel).unwrap().encode(&mut buf);

            let frame = crate::codec::Decoder::new().decode(&mut buf).unwrap().unwrap();
            let seq = frame.as_seq().unwrap();
            prop_assert_eq!(seq.channel(), channel);
            prop_assert_eq!(seq.ackno(), base);
            prop_assert_eq!(seq.window(), size);
        }
    }
}
