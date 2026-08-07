// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The session state machine: one BEEP conversation, driven entirely by method calls.
//!
//! [`Session`] is where the pieces meet. It owns the decoder, the greeting exchange, the
//! channel table and the outbound buffer, and it exposes the sans-IO shape the rest of
//! Vortice is built on:
//!
//! - [`Session::handle_input`] takes whatever octets arrived;
//! - [`Session::poll_transmit`] hands back whatever should be written;
//! - [`Session::poll_event`] reports what happened, one [`Event`] at a time.
//!
//! Nothing here blocks, allocates a socket or spawns anything. Two sessions can be wired to
//! each other inside a single test function, which is how the handshake and channel
//! lifecycle are checked below.
//!
//! # Roles and channel numbers
//!
//! RFC3080 §2.3.1.2 splits the channel number space so the two peers can allocate without
//! negotiating: the peer that initiated the session uses odd numbers, the one that listened
//! uses even ones. Channel 0 is shared and carries management traffic.
//!
//! # Flow control
//!
//! A payload handed to [`Session::send`] is fragmented to fit the peer's window and the
//! frame size limit. Whatever does not fit stays queued on the channel and goes out as
//! `SEQ` frames arrive, which is the job LibVortex gives its sequencer thread. Callers see
//! none of that: they hand over a payload and it leaves in order.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use bytes::{Bytes, BytesMut};

use crate::channel::Channel;
use crate::codec::Decoder;
use crate::error::Error;
use crate::frame::{DataFrame, Frame, FrameKind, SeqFrame};
use crate::greeting::{GREETING_CHANNEL, Greeting};
use crate::management::{Close, ErrorReply, Message as Management, Profile, Start, code};
use crate::window::DEFAULT_WINDOW_SIZE;

/// Which end of the session this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The peer that opened the transport. Allocates odd channel numbers.
    Initiator,
    /// The peer that accepted it. Allocates even channel numbers.
    Listener,
}

impl Role {
    /// The first channel number this role may allocate.
    #[must_use]
    pub const fn first_channel(self) -> u32 {
        match self {
            Self::Initiator => 1,
            Self::Listener => 2,
        }
    }

    /// Whether `channel` is one this role is allowed to allocate.
    #[must_use]
    pub const fn owns(self, channel: u32) -> bool {
        match self {
            Self::Initiator => channel % 2 == 1,
            Self::Listener => channel % 2 == 0 && channel != 0,
        }
    }
}

/// How far the session has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// The greeting has been queued; the peer's has not arrived.
    AwaitingGreeting,
    /// Both greetings have been exchanged; channels may be started.
    Ready,
    /// The session has been closed.
    Closed,
}

/// Something the session observed, for the layer above to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The peer announced itself. Carries the profiles it is willing to serve.
    GreetingReceived(Greeting),
    /// The peer asked for a channel. Answer with [`Session::accept_start`] or
    /// [`Session::refuse_start`].
    StartRequested {
        /// Channel number requested.
        channel: u32,
        /// Message number to reply to.
        msgno: u32,
        /// The request, including every profile offered.
        start: Start,
    },
    /// A channel this end asked for is now open.
    ChannelOpened {
        /// The channel number.
        channel: u32,
        /// The profile the peer confirmed, with any piggybacked content.
        profile: Profile,
    },
    /// A channel this end asked for was refused.
    StartRefused {
        /// The channel number that was requested.
        channel: u32,
        /// Why the peer refused.
        error: ErrorReply,
    },
    /// The peer asked to close a channel. Answer with [`Session::accept_close`] or
    /// [`Session::refuse_close`].
    CloseRequested {
        /// Channel to close; zero means the whole session.
        channel: u32,
        /// Message number to reply to.
        msgno: u32,
        /// The request.
        close: Close,
    },
    /// A channel is gone.
    ChannelClosed {
        /// The channel number.
        channel: u32,
    },
    /// A close this end asked for was refused.
    CloseRefused {
        /// The channel that stays open.
        channel: u32,
        /// Why the peer refused.
        error: ErrorReply,
    },
    /// The session is closed; no more traffic will be exchanged.
    SessionClosed,
    /// A complete message arrived on a channel.
    MessageReceived {
        /// The channel it arrived on.
        channel: u32,
        /// The reassembled message.
        message: crate::channel::Message,
    },
}

/// How a session is set up.
#[derive(Debug, Clone)]
pub struct Config {
    /// Which end this is.
    pub role: Role,
    /// The greeting to announce.
    pub greeting: Greeting,
    /// Window advertised on every channel, in octets.
    pub window_size: u32,
    /// Largest payload put in a single frame.
    pub max_frame_size: u32,
}

impl Config {
    /// A configuration for the given role, advertising no profiles.
    #[must_use]
    pub fn new(role: Role) -> Self {
        Self {
            role,
            greeting: Greeting::new(),
            window_size: DEFAULT_WINDOW_SIZE,
            max_frame_size: DEFAULT_WINDOW_SIZE,
        }
    }

    /// Announces a profile in the greeting.
    #[must_use]
    pub fn with_profile(mut self, uri: impl Into<String>) -> Self {
        self.greeting = self.greeting.with_profile(uri);
        self
    }

    /// Sets the window advertised on every channel.
    #[must_use]
    pub const fn with_window_size(mut self, size: u32) -> Self {
        self.window_size = size;
        self
    }

    /// Sets the largest payload put in a single frame.
    #[must_use]
    pub const fn with_max_frame_size(mut self, size: u32) -> Self {
        self.max_frame_size = size;
        self
    }
}

/// A payload waiting for window space.
#[derive(Debug, Clone)]
struct Queued {
    kind: FrameKind,
    msgno: u32,
    ansno: Option<u32>,
    payload: Bytes,
}

/// What a message number on channel 0 was asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    Start(u32),
    Close(u32),
}

/// One BEEP session.
#[derive(Debug)]
pub struct Session {
    config: Config,
    decoder: Decoder,
    state: State,
    peer_greeting: Option<Greeting>,

    inbound: BytesMut,
    zero: Channel,
    channels: BTreeMap<u32, Channel>,
    queues: BTreeMap<u32, VecDeque<Queued>>,
    pending: BTreeMap<u32, Pending>,
    /// Message numbers received on each channel, in arrival order, still awaiting a reply.
    reply_order: BTreeMap<u32, VecDeque<u32>>,
    /// Replies produced before their turn, by channel and then by message number.
    held_replies: BTreeMap<u32, BTreeMap<u32, VecDeque<Queued>>>,
    half_open: BTreeMap<u32, Profile>,
    unacked: BTreeMap<u32, u32>,

    next_channel: u32,
    outbound: BytesMut,
    events: VecDeque<Event>,
}

impl Session {
    /// Starts a session, queueing this end's greeting for transmission.
    #[must_use]
    pub fn new(config: Config) -> Self {
        let mut session = Self {
            zero: Channel::with_window_size(GREETING_CHANNEL, "", config.window_size),
            next_channel: config.role.first_channel(),
            config,
            decoder: Decoder::new(),
            inbound: BytesMut::new(),
            state: State::AwaitingGreeting,
            peer_greeting: None,
            channels: BTreeMap::new(),
            queues: BTreeMap::new(),
            pending: BTreeMap::new(),
            reply_order: BTreeMap::new(),
            held_replies: BTreeMap::new(),
            half_open: BTreeMap::new(),
            unacked: BTreeMap::new(),
            outbound: BytesMut::new(),
            events: VecDeque::new(),
        };
        // The greeting is an RPY on channel 0 with message and sequence number zero. It goes
        // through the same queue as everything else, so a greeting larger than the initial
        // window is paced rather than truncated.
        let payload = session.config.greeting.to_payload();
        session.enqueue(GREETING_CHANNEL, FrameKind::Rpy, 0, None, payload);
        session
            .flush(GREETING_CHANNEL)
            .expect("a fresh channel 0 cannot fail to emit");
        session
    }

    /// How far the session has got.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// Which end this is.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.config.role
    }

    /// The greeting the peer sent, once it has arrived.
    #[must_use]
    pub fn peer_greeting(&self) -> Option<&Greeting> {
        self.peer_greeting.as_ref()
    }

    /// The open channels, by number. Channel 0 is not included.
    #[must_use]
    pub fn channel(&self, number: u32) -> Option<&Channel> {
        self.channels.get(&number)
    }

    /// Octets to write to the transport, or `None` when there is nothing pending.
    #[must_use]
    pub fn poll_transmit(&mut self) -> Option<Bytes> {
        if self.outbound.is_empty() {
            return None;
        }
        Some(self.outbound.split().freeze())
    }

    /// The next thing that happened, or `None` when nothing is queued.
    #[must_use]
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Feeds octets received from the transport.
    ///
    /// # Errors
    ///
    /// Any [`Error`] here is fatal for the session, exactly as in
    /// [`Decoder::decode`](crate::codec::Decoder::decode): LibVortex drops the connection in
    /// every one of these cases.
    pub fn handle_input(&mut self, input: &[u8]) -> Result<(), Error> {
        // Octets that do not yet complete a frame are kept for the next call: a transport
        // hands over whatever happened to arrive, and a frame straddling two reads must not
        // lose its first half.
        self.inbound.extend_from_slice(input);
        while let Some(frame) = self.decoder.decode(&mut self.inbound)? {
            self.handle_frame(&frame)?;
        }
        Ok(())
    }

    /// Octets received but not yet forming a complete frame.
    #[must_use]
    pub fn buffered_input(&self) -> usize {
        self.inbound.len()
    }

    fn handle_frame(&mut self, frame: &Frame) -> Result<(), Error> {
        match frame {
            Frame::Seq(seq) => self.handle_seq(seq),
            Frame::Data(data) => self.handle_data(data),
        }
    }

    fn handle_seq(&mut self, seq: &SeqFrame) -> Result<(), Error> {
        if seq.channel() == GREETING_CHANNEL {
            self.zero.apply_seq(seq);
        } else {
            let channel = self
                .channels
                .get_mut(&seq.channel())
                .ok_or(Error::NoSuchChannel {
                    channel: seq.channel(),
                })?;
            channel.apply_seq(seq);
        }
        self.flush(seq.channel())
    }

    fn handle_data(&mut self, frame: &DataFrame) -> Result<(), Error> {
        if frame.channel() == GREETING_CHANNEL {
            return self.handle_channel_zero(frame);
        }
        let number = frame.channel();
        let channel = self
            .channels
            .get_mut(&number)
            .ok_or(Error::NoSuchChannel { channel: number })?;
        let complete = channel.accept(frame)?;
        self.acknowledge(number, frame.size())?;
        if let Some(message) = complete {
            if message.kind == FrameKind::Msg {
                // Replies have to leave in the order the messages arrived, so the order is
                // recorded here rather than inferred from the message numbers, which say
                // nothing about arrival.
                self.reply_order
                    .entry(number)
                    .or_default()
                    .push_back(message.msgno);
            }
            self.events.push_back(Event::MessageReceived {
                channel: number,
                message,
            });
        }
        Ok(())
    }

    fn handle_channel_zero(&mut self, frame: &DataFrame) -> Result<(), Error> {
        if self.state == State::AwaitingGreeting {
            let greeting = Greeting::from_frame(frame)?;
            self.zero.accept(frame)?;
            self.acknowledge(GREETING_CHANNEL, frame.size())?;
            self.peer_greeting = Some(greeting.clone());
            self.state = State::Ready;
            self.events.push_back(Event::GreetingReceived(greeting));
            return Ok(());
        }

        let complete = self.zero.accept(frame)?;
        self.acknowledge(GREETING_CHANNEL, frame.size())?;
        let Some(message) = complete else {
            return Ok(());
        };
        let management = Management::from_payload(&message.payload)?;
        self.dispatch_management(message.kind, message.msgno, management)
    }

    fn dispatch_management(
        &mut self,
        kind: FrameKind,
        msgno: u32,
        management: Management,
    ) -> Result<(), Error> {
        match (kind, management) {
            (FrameKind::Msg, Management::Start(start)) => {
                self.events.push_back(Event::StartRequested {
                    channel: start.number,
                    msgno,
                    start,
                });
            }
            (FrameKind::Msg, Management::Close(close)) => {
                self.events.push_back(Event::CloseRequested {
                    channel: close.number,
                    msgno,
                    close,
                });
            }
            (FrameKind::Rpy, Management::Profile(profile)) => {
                let Some(Pending::Start(number)) = self.pending.remove(&msgno) else {
                    return Err(Error::UnknownMsgNo { msgno });
                };
                self.zero.release_msgno(msgno);
                self.half_open.remove(&number);
                self.channels.insert(
                    number,
                    Channel::with_window_size(number, &profile.uri, self.config.window_size),
                );
                self.events.push_back(Event::ChannelOpened {
                    channel: number,
                    profile,
                });
            }
            (FrameKind::Rpy, Management::Ok) => {
                let Some(Pending::Close(number)) = self.pending.remove(&msgno) else {
                    return Err(Error::UnknownMsgNo { msgno });
                };
                self.zero.release_msgno(msgno);
                self.finish_close(number);
            }
            (FrameKind::Err, Management::Error(error)) => {
                let pending = self
                    .pending
                    .remove(&msgno)
                    .ok_or(Error::UnknownMsgNo { msgno })?;
                self.zero.release_msgno(msgno);
                match pending {
                    Pending::Start(number) => {
                        self.half_open.remove(&number);
                        self.events.push_back(Event::StartRefused {
                            channel: number,
                            error,
                        });
                    }
                    Pending::Close(number) => {
                        self.events.push_back(Event::CloseRefused {
                            channel: number,
                            error,
                        });
                    }
                }
            }
            _ => {
                return Err(Error::UnexpectedElement);
            }
        }
        Ok(())
    }

    // ---- outgoing requests ----------------------------------------------------------

    /// Asks the peer for a new channel, returning the number allocated for it.
    ///
    /// The channel does not exist until the peer accepts; [`Event::ChannelOpened`] or
    /// [`Event::StartRefused`] reports which way it went.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChannelNumber`] before the greetings have been exchanged, since
    /// nothing may be started until both peers have announced themselves.
    pub fn start_channel(&mut self, profile: Profile) -> Result<u32, Error> {
        self.require_ready()?;
        let number = self.next_channel;
        self.next_channel = self.next_channel.wrapping_add(2);
        let start = Start::new(number, profile.clone());
        self.half_open.insert(number, profile);
        self.request(Management::Start(start), Pending::Start(number))?;
        Ok(number)
    }

    /// Accepts a channel the peer asked for.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChannelNumber`] when the requested number is not one the peer may
    /// allocate, or is already open.
    pub fn accept_start(
        &mut self,
        channel: u32,
        msgno: u32,
        profile: Profile,
    ) -> Result<(), Error> {
        if channel == GREETING_CHANNEL || self.config.role.owns(channel) {
            return Err(Error::ChannelNumber {
                reason: "the peer may not allocate that number",
            });
        }
        if self.channels.contains_key(&channel) {
            return Err(Error::ChannelNumber {
                reason: "already open",
            });
        }
        self.channels.insert(
            channel,
            Channel::with_window_size(channel, &profile.uri, self.config.window_size),
        );
        self.reply(FrameKind::Rpy, msgno, &Management::Profile(profile))
    }

    /// Refuses a channel the peer asked for.
    ///
    /// # Errors
    ///
    /// Propagates a framing failure while rendering the reply.
    pub fn refuse_start(&mut self, msgno: u32, error: ErrorReply) -> Result<(), Error> {
        self.reply(FrameKind::Err, msgno, &Management::Error(error))
    }

    /// Asks the peer to close a channel, or the whole session when `channel` is zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoSuchChannel`] for a channel that is not open.
    pub fn close_channel(&mut self, channel: u32) -> Result<(), Error> {
        self.require_ready()?;
        if channel != GREETING_CHANNEL && !self.channels.contains_key(&channel) {
            return Err(Error::NoSuchChannel { channel });
        }
        self.request(
            Management::Close(Close::new(channel)),
            Pending::Close(channel),
        )
    }

    /// Accepts a close the peer asked for.
    ///
    /// # Errors
    ///
    /// Propagates a framing failure while rendering the reply.
    pub fn accept_close(&mut self, channel: u32, msgno: u32) -> Result<(), Error> {
        self.reply(FrameKind::Rpy, msgno, &Management::Ok)?;
        self.finish_close(channel);
        Ok(())
    }

    /// Refuses a close the peer asked for.
    ///
    /// # Errors
    ///
    /// Propagates a framing failure while rendering the reply.
    pub fn refuse_close(&mut self, msgno: u32, error: ErrorReply) -> Result<(), Error> {
        self.reply(FrameKind::Err, msgno, &Management::Error(error))
    }

    /// Queues a payload for a channel, fragmenting and pacing it against the peer's window.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoSuchChannel`] for a channel that is not open, and
    /// [`Error::MissingField`] when an `ANS` is sent without an answer number.
    pub fn send(
        &mut self,
        channel: u32,
        kind: FrameKind,
        msgno: u32,
        ansno: Option<u32>,
        payload: Bytes,
    ) -> Result<(), Error> {
        let Some(state) = self.channels.get_mut(&channel) else {
            return Err(Error::NoSuchChannel { channel });
        };
        // Answer numbers run from zero for each message being answered, so the caller does
        // not have to track them: an ANS without one is given the next in sequence.
        let ansno = match (kind, ansno) {
            (FrameKind::Ans, None) => Some(state.allocate_ansno(msgno)),
            (kind, ansno) => {
                if kind == FrameKind::Nul {
                    state.finish_answers(msgno);
                }
                ansno
            }
        };
        if is_reply(kind) && !self.is_next_reply(channel, msgno) {
            // Not this message's turn yet. RFC3080 requires replies on a channel to leave in
            // the order the messages arrived, and a peer with ordered delivery enabled will
            // sit waiting for the one it expects rather than accept a later one. Hold it.
            self.held_replies
                .entry(channel)
                .or_default()
                .entry(msgno)
                .or_default()
                .push_back(Queued {
                    kind,
                    msgno,
                    ansno,
                    payload,
                });
            return Ok(());
        }
        self.enqueue(channel, kind, msgno, ansno, payload);
        self.flush(channel)?;
        if completes_reply(kind) {
            self.reply_finished(channel, msgno)?;
        }
        Ok(())
    }

    /// Whether a reply for `msgno` may be written now.
    ///
    /// A channel with nothing recorded — a peer replying to a message this end never saw —
    /// is left alone rather than blocked, since ordering only means anything relative to
    /// messages actually received.
    fn is_next_reply(&self, channel: u32, msgno: u32) -> bool {
        self.reply_order
            .get(&channel)
            .and_then(VecDeque::front)
            .is_none_or(|next| *next == msgno)
    }

    /// Retires a finished exchange and releases whatever was waiting behind it.
    fn reply_finished(&mut self, channel: u32, msgno: u32) -> Result<(), Error> {
        if let Some(order) = self.reply_order.get_mut(&channel)
            && order.front() == Some(&msgno)
        {
            order.pop_front();
        }

        // Releasing one message can unblock the next, and so on down the queue.
        loop {
            let Some(next) = self
                .reply_order
                .get(&channel)
                .and_then(VecDeque::front)
                .copied()
            else {
                return Ok(());
            };
            let Some(held) = self
                .held_replies
                .get_mut(&channel)
                .and_then(|channel_held| channel_held.remove(&next))
            else {
                return Ok(());
            };

            let mut finished = false;
            for queued in held {
                finished |= completes_reply(queued.kind);
                self.enqueue(
                    channel,
                    queued.kind,
                    queued.msgno,
                    queued.ansno,
                    queued.payload,
                );
            }
            self.flush(channel)?;
            if !finished {
                return Ok(());
            }
            if let Some(order) = self.reply_order.get_mut(&channel) {
                order.pop_front();
            }
        }
    }

    /// Changes the window advertised for incoming traffic on a channel.
    ///
    /// This is `vortex_channel_set_window_size`, which the regression suite's
    /// `/simple-ans-nul` profile drives from the wire.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoSuchChannel`] when the channel is not open.
    pub fn set_window_size(&mut self, channel: u32, size: u32) -> Result<(), Error> {
        self.channels
            .get_mut(&channel)
            .ok_or(Error::NoSuchChannel { channel })?
            .set_recv_window_size(size);
        Ok(())
    }

    /// Sends a `MSG` on a channel, allocating a message number for it.
    ///
    /// # Errors
    ///
    /// As [`Session::send`], plus [`Error::MsgNoExhausted`] when no message number is free.
    pub fn send_msg(&mut self, channel: u32, payload: Bytes) -> Result<u32, Error> {
        let msgno = self
            .channels
            .get_mut(&channel)
            .ok_or(Error::NoSuchChannel { channel })?
            .allocate_msgno()?;
        self.send(channel, FrameKind::Msg, msgno, None, payload)?;
        Ok(msgno)
    }

    // ---- internals -------------------------------------------------------------------

    fn require_ready(&self) -> Result<(), Error> {
        if self.state == State::Ready {
            return Ok(());
        }
        Err(Error::ChannelNumber {
            reason: "greetings have not been exchanged yet",
        })
    }

    /// Sends a management request on channel 0 and remembers what it was asking for.
    fn request(&mut self, management: Management, pending: Pending) -> Result<(), Error> {
        let msgno = self.zero.allocate_msgno()?;
        self.pending.insert(msgno, pending);
        self.write_zero(FrameKind::Msg, msgno, &management)
    }

    /// Sends a management reply on channel 0.
    fn reply(&mut self, kind: FrameKind, msgno: u32, management: &Management) -> Result<(), Error> {
        self.zero.replied(msgno);
        self.write_zero(kind, msgno, management)
    }

    fn write_zero(
        &mut self,
        kind: FrameKind,
        msgno: u32,
        management: &Management,
    ) -> Result<(), Error> {
        self.enqueue(GREETING_CHANNEL, kind, msgno, None, management.to_payload());
        self.flush(GREETING_CHANNEL)
    }

    fn enqueue(
        &mut self,
        number: u32,
        kind: FrameKind,
        msgno: u32,
        ansno: Option<u32>,
        payload: Bytes,
    ) {
        self.queues.entry(number).or_default().push_back(Queued {
            kind,
            msgno,
            ansno,
            payload,
        });
    }

    /// Writes as much of a channel's queue as its window allows.
    ///
    /// This is the job LibVortex gives its sequencer thread: take what the application
    /// asked to send, cut it to the peer's window, and hold the rest until a `SEQ` frame
    /// makes room.
    fn flush(&mut self, number: u32) -> Result<(), Error> {
        let Some(queue) = self.queues.get_mut(&number) else {
            return Ok(());
        };
        let channel = if number == GREETING_CHANNEL {
            &mut self.zero
        } else {
            let Some(channel) = self.channels.get_mut(&number) else {
                return Ok(());
            };
            channel
        };
        while let Some(front) = queue.front_mut() {
            if channel.is_stalled() && !front.payload.is_empty() {
                break;
            }
            let emitted = channel.emit(
                front.kind,
                front.msgno,
                front.ansno,
                front.payload.clone(),
                self.config.max_frame_size,
            )?;
            for frame in &emitted.frames {
                frame.encode(&mut self.outbound);
            }
            if emitted.is_complete() {
                queue.pop_front();
            } else {
                front.payload = emitted.remaining;
                break;
            }
        }
        Ok(())
    }

    /// Charges received octets against the incoming window, emitting a `SEQ` once enough
    /// have accumulated.
    ///
    /// Acknowledging every frame would work but doubles the frame count on a busy channel,
    /// so the window is reopened once half of it has been consumed — the same trade
    /// `vortex_channel_update_incoming_buffer` makes.
    fn acknowledge(&mut self, number: u32, octets: u32) -> Result<(), Error> {
        let channel = if number == GREETING_CHANNEL {
            &mut self.zero
        } else {
            let Some(channel) = self.channels.get_mut(&number) else {
                return Ok(());
            };
            channel
        };
        let pending = self.unacked.entry(number).or_insert(0);
        *pending = pending.saturating_add(octets);
        let threshold = (channel.recv_window().size() / 2).max(1);
        if *pending >= threshold {
            let seq = channel.consume(*pending)?;
            *pending = 0;
            seq.encode(&mut self.outbound);
        }
        Ok(())
    }

    fn finish_close(&mut self, channel: u32) {
        if channel == GREETING_CHANNEL {
            self.state = State::Closed;
            self.channels.clear();
            self.queues.clear();
            self.unacked.clear();
            self.reply_order.clear();
            self.held_replies.clear();
            self.events.push_back(Event::SessionClosed);
            return;
        }
        self.channels.remove(&channel);
        self.queues.remove(&channel);
        self.unacked.remove(&channel);
        self.reply_order.remove(&channel);
        self.held_replies.remove(&channel);
        self.events.push_back(Event::ChannelClosed { channel });
    }
}

/// Whether a frame kind answers a message rather than starting an exchange.
const fn is_reply(kind: FrameKind) -> bool {
    matches!(
        kind,
        FrameKind::Rpy | FrameKind::Err | FrameKind::Ans | FrameKind::Nul
    )
}

/// Whether a frame kind ends the exchange it belongs to.
///
/// `ANS` does not: a one-to-many reply runs until its `NUL`.
const fn completes_reply(kind: FrameKind) -> bool {
    matches!(kind, FrameKind::Rpy | FrameKind::Err | FrameKind::Nul)
}

/// Convenience for the common refusal: the profile is not supported.
#[must_use]
pub fn profile_not_supported() -> ErrorReply {
    ErrorReply::new(code::REQUESTED_ACTION_NOT_TAKEN).with_text("profile not supported", None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const ECHO: &str = "http://iana.org/beep/transient/vortex-regression";

    /// Two sessions wired to each other with no transport in between.
    struct Pair {
        initiator: Session,
        listener: Session,
    }

    impl Pair {
        fn new() -> Self {
            Self::with_config(
                Config::new(Role::Initiator).with_profile(ECHO),
                Config::new(Role::Listener).with_profile(ECHO),
            )
        }

        fn with_config(initiator: Config, listener: Config) -> Self {
            let mut pair = Self {
                initiator: Session::new(initiator),
                listener: Session::new(listener),
            };
            pair.pump();
            pair
        }

        /// Moves octets both ways until neither side has anything more to say.
        fn pump(&mut self) {
            for _ in 0..64 {
                let mut moved = false;
                if let Some(bytes) = self.initiator.poll_transmit() {
                    self.listener.handle_input(&bytes).unwrap();
                    moved = true;
                }
                if let Some(bytes) = self.listener.poll_transmit() {
                    self.initiator.handle_input(&bytes).unwrap();
                    moved = true;
                }
                if !moved {
                    return;
                }
            }
            panic!("sessions never went quiet");
        }

        fn initiator_events(&mut self) -> Vec<Event> {
            core::iter::from_fn(|| self.initiator.poll_event()).collect()
        }

        fn listener_events(&mut self) -> Vec<Event> {
            core::iter::from_fn(|| self.listener.poll_event()).collect()
        }

        /// Runs the full start handshake and returns the channel number.
        fn open_channel(&mut self) -> u32 {
            let number = self.initiator.start_channel(Profile::new(ECHO)).unwrap();
            self.pump();
            let Some(Event::StartRequested { channel, msgno, .. }) = self
                .listener_events()
                .into_iter()
                .find(|event| matches!(event, Event::StartRequested { .. }))
            else {
                panic!("listener never saw the start request");
            };
            self.listener
                .accept_start(channel, msgno, Profile::new(ECHO))
                .unwrap();
            self.pump();
            assert!(
                self.initiator_events()
                    .iter()
                    .any(|event| matches!(event, Event::ChannelOpened { .. })),
                "initiator never saw the channel open"
            );
            number
        }
    }

    #[test]
    fn retains_input_that_does_not_yet_complete_a_frame() {
        // A socket hands over whatever arrived. Feeding a session one octet at a time must
        // deliver exactly what feeding it the whole buffer would: anything less means a
        // frame straddling two reads loses its first half.
        let mut listener = Session::new(Config::new(Role::Listener).with_profile(ECHO));
        let initiator = Session::new(Config::new(Role::Initiator).with_profile(ECHO));

        let mut wire = BytesMut::new();
        let mut source = initiator;
        while let Some(bytes) = source.poll_transmit() {
            wire.extend_from_slice(&bytes);
        }
        assert!(
            wire.len() > 8,
            "the greeting should be more than a few octets"
        );

        for octet in wire.clone() {
            listener.handle_input(&[octet]).unwrap();
        }
        assert_eq!(listener.state(), State::Ready);
        assert!(listener.peer_greeting().unwrap().advertises(ECHO));
        assert_eq!(listener.buffered_input(), 0);
    }

    #[test]
    fn exchanges_greetings_on_construction() {
        let mut pair = Pair::new();
        assert_eq!(pair.initiator.state(), State::Ready);
        assert_eq!(pair.listener.state(), State::Ready);
        assert!(pair.initiator.peer_greeting().unwrap().advertises(ECHO));
        assert!(pair.listener.peer_greeting().unwrap().advertises(ECHO));

        assert!(matches!(
            pair.initiator_events().first(),
            Some(Event::GreetingReceived(_))
        ));
    }

    #[test]
    fn refuses_to_start_a_channel_before_the_greetings_are_in() {
        let mut lonely = Session::new(Config::new(Role::Initiator));
        assert!(matches!(
            lonely.start_channel(Profile::new(ECHO)),
            Err(Error::ChannelNumber { .. })
        ));
    }

    #[test]
    fn allocates_channel_numbers_by_role() {
        assert!(Role::Initiator.owns(1));
        assert!(Role::Initiator.owns(3));
        assert!(!Role::Initiator.owns(2));
        assert!(Role::Listener.owns(2));
        assert!(!Role::Listener.owns(0));
        assert!(!Role::Listener.owns(1));

        let mut pair = Pair::new();
        assert_eq!(pair.open_channel(), 1);
        assert_eq!(
            pair.initiator.start_channel(Profile::new(ECHO)).unwrap(),
            3,
            "the initiator must keep to odd numbers"
        );
    }

    #[test]
    fn opens_a_channel_on_both_ends() {
        let mut pair = Pair::new();
        let number = pair.open_channel();
        assert!(pair.initiator.channel(number).is_some());
        assert!(pair.listener.channel(number).is_some());
        assert_eq!(pair.listener.channel(number).unwrap().profile(), ECHO);
    }

    #[test]
    fn reports_a_refused_start_without_opening_anything() {
        let mut pair = Pair::new();
        pair.initiator
            .start_channel(Profile::new("urn:absent"))
            .unwrap();
        pair.pump();
        let Some(Event::StartRequested { msgno, .. }) = pair
            .listener_events()
            .into_iter()
            .find(|event| matches!(event, Event::StartRequested { .. }))
        else {
            panic!("no start request");
        };
        pair.listener
            .refuse_start(msgno, profile_not_supported())
            .unwrap();
        pair.pump();

        let events = pair.initiator_events();
        let Some(Event::StartRefused { channel, error }) = events
            .into_iter()
            .find(|event| matches!(event, Event::StartRefused { .. }))
        else {
            panic!("no refusal reported");
        };
        assert_eq!(channel, 1);
        assert_eq!(error.code, code::REQUESTED_ACTION_NOT_TAKEN);
        assert!(pair.initiator.channel(1).is_none());
    }

    #[test]
    fn carries_a_message_end_to_end() {
        let mut pair = Pair::new();
        let number = pair.open_channel();

        let msgno = pair
            .initiator
            .send_msg(number, Bytes::from_static(b"hola"))
            .unwrap();
        pair.pump();

        let events = pair.listener_events();
        let Some(Event::MessageReceived { channel, message }) = events
            .into_iter()
            .find(|event| matches!(event, Event::MessageReceived { .. }))
        else {
            panic!("listener never received the message");
        };
        assert_eq!(channel, number);
        assert_eq!(message.kind, FrameKind::Msg);
        assert_eq!(message.msgno, msgno);
        assert_eq!(&message.payload[..], b"hola");
    }

    #[test]
    fn carries_a_reply_back() {
        let mut pair = Pair::new();
        let number = pair.open_channel();
        pair.initiator
            .send_msg(number, Bytes::from_static(b"ping"))
            .unwrap();
        pair.pump();
        pair.listener_events();

        pair.listener
            .send(number, FrameKind::Rpy, 0, None, Bytes::from_static(b"pong"))
            .unwrap();
        pair.pump();

        let events = pair.initiator_events();
        let Some(Event::MessageReceived { message, .. }) = events
            .into_iter()
            .find(|event| matches!(event, Event::MessageReceived { .. }))
        else {
            panic!("initiator never received the reply");
        };
        assert_eq!(message.kind, FrameKind::Rpy);
        assert_eq!(&message.payload[..], b"pong");
    }

    #[test]
    fn reassembles_a_payload_larger_than_the_window() {
        // The payload is four times the window and eight times the frame size, so it can
        // only arrive if fragmentation, SEQ pacing and reassembly all work together.
        let mut pair = Pair::with_config(
            Config::new(Role::Initiator)
                .with_profile(ECHO)
                .with_window_size(1024)
                .with_max_frame_size(512),
            Config::new(Role::Listener)
                .with_profile(ECHO)
                .with_window_size(1024)
                .with_max_frame_size(512),
        );
        let number = pair.open_channel();

        let payload = Bytes::from(alloc::vec![b'z'; 4096]);
        pair.initiator
            .send(number, FrameKind::Msg, 0, None, payload)
            .unwrap();
        pair.pump();

        let events = pair.listener_events();
        let Some(Event::MessageReceived { message, .. }) = events
            .into_iter()
            .find(|event| matches!(event, Event::MessageReceived { .. }))
        else {
            panic!("the large message never arrived");
        };
        assert_eq!(message.payload.len(), 4096);
        assert!(message.payload.iter().all(|&byte| byte == b'z'));
    }

    #[test]
    fn delivers_an_ans_nul_sequence() {
        let mut pair = Pair::new();
        let number = pair.open_channel();
        pair.initiator
            .send_msg(number, Bytes::from_static(b"list"))
            .unwrap();
        pair.pump();
        pair.listener_events();

        for (ansno, answer) in [&b"one"[..], &b"two"[..]].into_iter().enumerate() {
            let ansno = u32::try_from(ansno).unwrap();
            pair.listener
                .send(
                    number,
                    FrameKind::Ans,
                    0,
                    Some(ansno),
                    Bytes::from_static(answer),
                )
                .unwrap();
        }
        pair.listener
            .send(number, FrameKind::Nul, 0, None, Bytes::new())
            .unwrap();
        pair.pump();

        let kinds: Vec<_> = pair
            .initiator_events()
            .into_iter()
            .filter_map(|event| match event {
                Event::MessageReceived { message, .. } => Some((message.kind, message.ansno)),
                _ => None,
            })
            .collect();
        assert_eq!(
            kinds,
            [
                (FrameKind::Ans, Some(0)),
                (FrameKind::Ans, Some(1)),
                (FrameKind::Nul, None)
            ]
        );
    }

    #[test]
    fn closes_a_channel_on_both_ends() {
        let mut pair = Pair::new();
        let number = pair.open_channel();

        pair.initiator.close_channel(number).unwrap();
        pair.pump();
        let Some(Event::CloseRequested { channel, msgno, .. }) = pair
            .listener_events()
            .into_iter()
            .find(|event| matches!(event, Event::CloseRequested { .. }))
        else {
            panic!("no close request");
        };
        pair.listener.accept_close(channel, msgno).unwrap();
        pair.pump();

        assert!(
            pair.initiator_events()
                .iter()
                .any(|event| matches!(event, Event::ChannelClosed { .. }))
        );
        assert!(pair.initiator.channel(number).is_none());
        assert!(pair.listener.channel(number).is_none());
    }

    #[test]
    fn a_refused_close_leaves_the_channel_open() {
        let mut pair = Pair::new();
        let number = pair.open_channel();

        pair.initiator.close_channel(number).unwrap();
        pair.pump();
        let Some(Event::CloseRequested { msgno, .. }) = pair
            .listener_events()
            .into_iter()
            .find(|event| matches!(event, Event::CloseRequested { .. }))
        else {
            panic!("no close request");
        };
        pair.listener
            .refuse_close(msgno, ErrorReply::new(code::ACTION_NOT_TAKEN))
            .unwrap();
        pair.pump();

        assert!(
            pair.initiator_events()
                .iter()
                .any(|event| matches!(event, Event::CloseRefused { .. }))
        );
        assert!(pair.initiator.channel(number).is_some());
    }

    #[test]
    fn closing_channel_zero_ends_the_session() {
        let mut pair = Pair::new();
        pair.open_channel();

        pair.initiator.close_channel(GREETING_CHANNEL).unwrap();
        pair.pump();
        let Some(Event::CloseRequested { channel, msgno, .. }) = pair
            .listener_events()
            .into_iter()
            .find(|event| matches!(event, Event::CloseRequested { .. }))
        else {
            panic!("no close request");
        };
        assert_eq!(channel, GREETING_CHANNEL);
        pair.listener.accept_close(channel, msgno).unwrap();
        pair.pump();

        assert_eq!(pair.listener.state(), State::Closed);
        assert_eq!(pair.initiator.state(), State::Closed);
    }

    #[test]
    fn rejects_a_frame_for_a_channel_that_is_not_open() {
        // What test_02a2 drives: a raw frame naming a channel that was never started.
        let mut pair = Pair::new();
        let mut buf = BytesMut::new();
        DataFrame::new(FrameKind::Msg, 9, 0, 0, Bytes::from_static(b"x"))
            .unwrap()
            .encode(&mut buf);
        assert_eq!(
            pair.listener.handle_input(&buf).unwrap_err(),
            Error::NoSuchChannel { channel: 9 }
        );
    }

    #[test]
    fn refuses_to_accept_a_channel_number_the_peer_may_not_allocate() {
        let mut pair = Pair::new();
        // The listener owns even numbers, so it must not accept a start naming one.
        assert!(matches!(
            pair.listener.accept_start(2, 0, Profile::new(ECHO)),
            Err(Error::ChannelNumber { .. })
        ));
    }

    #[test]
    fn sending_on_an_unopened_channel_is_an_error() {
        let mut pair = Pair::new();
        assert_eq!(
            pair.initiator.send_msg(5, Bytes::new()).unwrap_err(),
            Error::NoSuchChannel { channel: 5 }
        );
    }
}
