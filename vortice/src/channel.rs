// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The handle an application holds on an open channel.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;
use tokio::sync::{mpsc, oneshot};
use vortice_proto::frame::FrameKind;
use vortice_proto::management::Profile;

use crate::connection::Command;
use crate::error::{Error, Result};

/// What the peer answered.
///
/// A `MSG` is answered either once, positively or negatively, or by a run of answers ended
/// by a `NUL`. [`Reply`] covers the three shapes; the payloads it carries are MIME bodies,
/// with the entity headers already stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reply {
    /// A positive reply, carried in an `RPY`.
    Rpy(Bytes),
    /// A negative reply, carried in an `ERR`.
    Err(Bytes),
    /// A one-to-many reply: every `ANS` received, in order, up to its `NUL`.
    Answers(Vec<Bytes>),
}

impl Reply {
    /// Whether the peer answered positively.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Rpy(_) | Self::Answers(_))
    }

    /// The payload of a one-to-one reply, or the first answer of a one-to-many one.
    ///
    /// Empty when a one-to-many reply carried no answers at all.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Rpy(payload) | Self::Err(payload) => payload,
            Self::Answers(answers) => answers.first().map_or(&[][..], |first| &first[..]),
        }
    }

    /// The answers of a one-to-many reply; empty for the other shapes.
    #[must_use]
    pub fn answers(&self) -> &[Bytes] {
        match self {
            Self::Answers(answers) => answers,
            Self::Rpy(_) | Self::Err(_) => &[],
        }
    }
}

/// A message that arrived on a channel outside a reply this end was waiting for.
///
/// On a client this is traffic the peer initiated; on a listener it is every request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Which of `MSG`, `RPY`, `ERR`, `ANS` or `NUL` carried it.
    pub kind: FrameKind,
    /// The message number of the exchange.
    pub msgno: u32,
    /// The answer number, for `ANS` only.
    pub ansno: Option<u32>,
    /// The MIME body, entity headers already stripped.
    pub payload: Bytes,
}

/// An open channel.
///
/// Dropping the handle leaves the channel open on the wire; use
/// [`Connection::close_channel`](crate::Connection::close_channel) to close it properly.
#[derive(Debug)]
pub struct Channel {
    number: u32,
    profile: Profile,
    commands: mpsc::Sender<Command>,
    inbound: mpsc::Receiver<Message>,
}

impl Channel {
    pub(crate) const fn new(
        number: u32,
        profile: Profile,
        commands: mpsc::Sender<Command>,
        inbound: mpsc::Receiver<Message>,
    ) -> Self {
        Self {
            number,
            profile,
            commands,
            inbound,
        }
    }

    /// The channel number.
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// The profile the channel was opened with, including any piggybacked content.
    #[must_use]
    pub const fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Sends a `MSG` and waits for the reply.
    ///
    /// The payload is fragmented and paced against the peer's window, so a payload larger
    /// than the window is not an error: it simply takes more round trips.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when the session ended before the reply arrived, and
    /// [`Error::Protocol`] when the peer violated the protocol.
    pub async fn request(&self, payload: impl Into<Bytes>) -> Result<Reply> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Request {
                channel: self.number,
                payload: payload.into(),
                reply,
            })
            .await
            .map_err(|_| Error::Closed)?;
        answer.await.map_err(|_| Error::Closed)?
    }

    /// Sends a frame without waiting for anything.
    ///
    /// This is the building block replies are made of: answer a [`Message`] with
    /// `send(FrameKind::Rpy, message.msgno, None, payload)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when the session has ended, and [`Error::Protocol`] when
    /// the frame is not one the channel may send.
    pub async fn send(
        &self,
        kind: FrameKind,
        msgno: u32,
        ansno: Option<u32>,
        payload: impl Into<Bytes>,
    ) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Send {
                channel: self.number,
                kind,
                msgno,
                ansno,
                payload: payload.into(),
                reply,
            })
            .await
            .map_err(|_| Error::Closed)?;
        answer.await.map_err(|_| Error::Closed)?
    }

    /// Waits for the next message the peer sent on its own initiative.
    ///
    /// Returns `None` once the channel is closed and nothing more will arrive.
    pub async fn recv(&mut self) -> Option<Message> {
        self.inbound.recv().await
    }
}

impl Stream for Channel {
    type Item = Message;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().inbound.poll_recv(cx)
    }
}
