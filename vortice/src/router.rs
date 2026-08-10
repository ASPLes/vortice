// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Serving profiles: what a peer gets when it asks this end for a channel.
//!
//! A [`Router`] maps profile URIs to handlers. When a peer sends a `<start>`, the router
//! decides whether any of the profiles offered is one this end serves; if so the channel is
//! accepted and every message arriving on it goes to that handler.
//!
//! ```
//! use vortice::{Message, Responder, Router};
//!
//! let echo = "http://iana.org/beep/transient/vortex-regression";
//! let router = Router::new().profile(echo, |responder: Responder, message: Message| async move {
//!     let _ = responder.reply(message.msgno, message.payload).await;
//! });
//! assert!(router.serves(echo));
//! ```
//!
//! Handlers run as their own tasks, so one that takes its time does not hold up the session
//! or the other channels. That also means replies may be produced in any order; putting them
//! back into the order BEEP requires is the session layer's job.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use vortice_proto::frame::FrameKind;
use vortice_proto::greeting::Greeting;
use vortice_proto::management::{ErrorReply, Profile, Start, code};
use vortice_proto::session::Config;

use crate::channel::{Message, Reply};
use crate::connection::{BoxedTransport, Command, SessionId};
use crate::error::{Error, Result};

/// What a handler returns: a task the session will drive to completion.
pub type HandlerFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Serves one profile.
///
/// Implemented for any `Fn(Responder, Message) -> Future`, which is the form the examples
/// and tests use; implement it directly when a profile needs to decide whether to accept a
/// channel at all.
pub trait Handler: Send + Sync + 'static {
    /// Handles one message received on a channel of this profile.
    fn handle(&self, responder: Responder, message: Message) -> HandlerFuture;

    /// Called once a channel of this profile has been accepted.
    ///
    /// The default does nothing. A profile that pushes content as soon as its channel exists
    /// — rather than only answering what it is asked — implements this. The regression
    /// suite has two such profiles, `/fast-send` and `/ans-nul-reply-close`, and LibVortex
    /// reaches them through a connection-accepted hook that installs a channel-added hook;
    /// hanging it off the profile itself says the same thing in one step.
    fn on_open(&self, _responder: Responder) -> HandlerFuture {
        Box::pin(core::future::ready(()))
    }

    /// Decides whether to accept a channel start offering this profile.
    ///
    /// The default accepts, echoing the URI back with no piggybacked content. Returning an
    /// error refuses the channel with that code and text.
    ///
    /// # Errors
    ///
    /// Whatever the profile wants the peer to be told.
    fn accept(&self, uri: &str, _start: &Start) -> std::result::Result<Profile, ErrorReply> {
        Ok(Profile::new(uri))
    }

    /// Whether accepting a channel of this profile is about to replace the transport.
    ///
    /// A profile that answers `true` promises to call [`Responder::upgrade`] from
    /// [`Handler::on_open`]. In exchange the session stops reading the moment the start is
    /// accepted, and does not start again until the transport has been replaced.
    ///
    /// That pause is not an optimisation, it is the whole point. BEEP's TLS profile agrees to
    /// the upgrade in the channel exchange itself, and the peer begins its handshake as soon
    /// as it sees the accepting reply — so without the pause the session would race to read
    /// those octets and hand them to a BEEP parser, ending the connection. The window is
    /// small, which is worse than large: it would fail rarely and under load.
    ///
    /// A handler that answers `true` and then never upgrades leaves the session unable to
    /// read, so only a profile that really does replace the transport should.
    fn upgrades_transport(&self) -> bool {
        false
    }
}

impl<F, Fut> Handler for F
where
    F: Fn(Responder, Message) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn handle(&self, responder: Responder, message: Message) -> HandlerFuture {
        Box::pin(self(responder, message))
    }
}

/// A handler that refuses every channel offering its profile.
///
/// The profile is still advertised in the greeting, which is the distinction the regression
/// suite draws between its `/deny` profile — not registered at all, so the start fails
/// because the profile is unknown — and `/deny_supported`, advertised but always refused.
#[derive(Debug, Clone)]
pub struct AlwaysRefuse {
    code: u32,
    text: Option<String>,
}

impl AlwaysRefuse {
    /// Refuses with the given code.
    #[must_use]
    pub const fn new(code: u32) -> Self {
        Self { code, text: None }
    }

    /// Refuses with the given code and explanation.
    #[must_use]
    pub fn with_text(code: u32, text: impl Into<String>) -> Self {
        Self {
            code,
            text: Some(text.into()),
        }
    }
}

impl Default for AlwaysRefuse {
    fn default() -> Self {
        Self::new(code::REQUESTED_ACTION_NOT_TAKEN)
    }
}

impl Handler for AlwaysRefuse {
    fn handle(&self, _responder: Responder, _message: Message) -> HandlerFuture {
        // No channel of this profile is ever opened, so nothing can arrive on one.
        Box::pin(std::future::ready(()))
    }

    fn accept(&self, _uri: &str, _start: &Start) -> std::result::Result<Profile, ErrorReply> {
        let mut error = ErrorReply::new(self.code);
        if let Some(text) = &self.text {
            error = ErrorReply::new(self.code).with_text(text.clone(), None);
        }
        Err(error)
    }
}

/// The profiles this end serves.
#[derive(Clone, Default)]
pub struct Router {
    profiles: HashMap<String, Arc<dyn Handler>>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("profiles", &self.profiles.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Router {
    /// An empty router, serving nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serves `uri` with the given handler.
    #[must_use]
    pub fn profile(mut self, uri: impl Into<String>, handler: impl Handler) -> Self {
        self.profiles.insert(uri.into(), Arc::new(handler));
        self
    }

    /// Serves `uri` with a [`tower::Service`].
    ///
    /// Everything tower offers applies: wrap the service in a `ServiceBuilder` and the
    /// layers come with it. See [`crate::service`].
    #[cfg(feature = "tower")]
    #[must_use]
    pub fn service<S>(self, uri: impl Into<String>, service: S) -> Self
    where
        S: tower::Service<crate::service::Request, Response = crate::service::Response>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send,
        S::Error: core::fmt::Display + Send,
    {
        self.profile(uri, crate::service::ServiceHandler::new(service))
    }

    /// Whether a profile URI is served.
    #[must_use]
    pub fn serves(&self, uri: &str) -> bool {
        self.profiles.contains_key(uri)
    }

    /// Every profile URI served, for the greeting to advertise.
    pub fn uris(&self) -> impl Iterator<Item = &str> {
        self.profiles.keys().map(String::as_str)
    }

    /// Picks the first profile in a start request that this end serves.
    ///
    /// BEEP lets a peer offer several profiles in preference order, and the answer names the
    /// one chosen.
    pub(crate) fn choose(&self, start: &Start) -> Option<(String, Arc<dyn Handler>)> {
        start.profiles.iter().find_map(|offered| {
            self.profiles
                .get(&offered.uri)
                .map(|handler| (offered.uri.clone(), Arc::clone(handler)))
        })
    }
}

/// How a handler answers the message it was given.
///
/// Dropping it without replying leaves the peer waiting, which is legal BEEP but rarely
/// what was meant.
#[derive(Debug, Clone)]
pub struct Responder {
    session: SessionId,
    channel: u32,
    commands: mpsc::Sender<Command>,
}

impl Responder {
    pub(crate) const fn new(
        session: SessionId,
        channel: u32,
        commands: mpsc::Sender<Command>,
    ) -> Self {
        Self {
            session,
            channel,
            commands,
        }
    }

    /// The channel this message arrived on.
    #[must_use]
    pub const fn channel(&self) -> u32 {
        self.channel
    }

    /// Which session this is, for a handler that keeps state per connection.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Replies to `msgno` and then replaces the transport, as one step.
    ///
    /// The listening half of [`Connection::upgrade`](crate::Connection::upgrade), and the
    /// reason it exists rather than a plain `reply` followed by an upgrade: the peer starts
    /// its TLS handshake the instant it sees the reply, so if the driver got a chance to read
    /// between the two it would feed the first octets of that handshake to a BEEP parser and
    /// end the session. Sending the reply and swapping the transport in one command removes
    /// the window entirely.
    ///
    /// Returns the greeting of the session that follows.
    ///
    /// # Errors
    ///
    /// As [`Connection::upgrade`](crate::Connection::upgrade).
    pub async fn reply_then_upgrade<F, Fut>(
        &self,
        msgno: u32,
        payload: impl Into<Bytes>,
        config: Config,
        swap: F,
    ) -> Result<Greeting>
    where
        F: FnOnce(BoxedTransport) -> Fut + Send + 'static,
        Fut: Future<Output = Result<BoxedTransport>> + Send + 'static,
    {
        crate::connection::upgrade_session(
            &self.commands,
            Some((self.channel, msgno, payload.into())),
            config,
            swap,
        )
        .await
    }

    /// Replaces the transport once whatever is already queued has gone out.
    ///
    /// This is the shape BEEP's TLS profile actually needs. Its agreement is piggybacked on
    /// the channel exchange itself — `<ready />` inside the `<start>`, `<proceed />` inside the
    /// `<profile>` that answers it — so by the time a handler runs there is no reply left to
    /// send, only a transport to replace.
    ///
    /// Safe to call from [`Handler::on_open`] **only** when the handler also returns `true`
    /// from [`Handler::upgrades_transport`]. That is what stops the session reading between
    /// the accepting reply and this call; without it the peer's first handshake octets would
    /// reach a BEEP parser instead.
    ///
    /// # Errors
    ///
    /// As [`Connection::upgrade`](crate::Connection::upgrade).
    pub async fn upgrade<F, Fut>(&self, config: Config, swap: F) -> Result<Greeting>
    where
        F: FnOnce(BoxedTransport) -> Fut + Send + 'static,
        Fut: Future<Output = Result<BoxedTransport>> + Send + 'static,
    {
        crate::connection::upgrade_session(&self.commands, None, config, swap).await
    }

    /// Changes the window advertised for incoming traffic on this channel.
    ///
    /// # Errors
    ///
    /// As [`Responder::reply`].
    pub async fn set_window_size(&self, size: u32) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::SetWindowSize {
                channel: self.channel,
                size,
                reply,
            })
            .await
            .map_err(|_| Error::Closed)?;
        answer.await.map_err(|_| Error::Closed)?
    }

    /// Answers positively, with an `RPY`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when the session ended before the reply could be queued.
    pub async fn reply(&self, msgno: u32, payload: impl Into<Bytes>) -> Result<()> {
        self.send(FrameKind::Rpy, msgno, None, payload.into()).await
    }

    /// Answers negatively, with an `ERR`.
    ///
    /// # Errors
    ///
    /// As [`Responder::reply`].
    pub async fn error(&self, msgno: u32, payload: impl Into<Bytes>) -> Result<()> {
        self.send(FrameKind::Err, msgno, None, payload.into()).await
    }

    /// Sends one answer of a one-to-many reply.
    ///
    /// The answer number is allocated by the session, running from zero for each message
    /// being answered, so a handler cannot get the sequence wrong.
    ///
    /// # Errors
    ///
    /// As [`Responder::reply`].
    pub async fn answer(&self, msgno: u32, payload: impl Into<Bytes>) -> Result<()> {
        self.send(FrameKind::Ans, msgno, None, payload.into()).await
    }

    /// Ends a one-to-many reply, with a `NUL`.
    ///
    /// # Errors
    ///
    /// As [`Responder::reply`].
    pub async fn finish(&self, msgno: u32) -> Result<()> {
        self.send(FrameKind::Nul, msgno, None, Bytes::new()).await
    }

    /// Sends a `MSG` of this end's own and waits for the peer to answer.
    ///
    /// A profile is not obliged to only answer: it may start exchanges of its own on the
    /// channel, which is what the regression suite's `/3` profile does to check that a peer
    /// may reply to several messages in any order it likes.
    ///
    /// # Errors
    ///
    /// As [`Responder::reply`].
    pub async fn request(&self, payload: impl Into<Bytes>) -> Result<Reply> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Request {
                channel: self.channel,
                payload: payload.into(),
                reply,
            })
            .await
            .map_err(|_| Error::Closed)?;
        answer.await.map_err(|_| Error::Closed)?
    }

    /// Closes the channel this message arrived on.
    ///
    /// A profile that answers and then closes will often have its `<close>` cross the peer's
    /// on the wire. That is legal and expected — BEEP calls it a close collision, and both
    /// ends resolve it by accepting the one they receive.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Refused`] if the peer declines to close, and [`Error::Closed`] when
    /// the session ended first.
    pub async fn close(&self) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::CloseChannel {
                number: self.channel,
                reply,
            })
            .await
            .map_err(|_| Error::Closed)?;
        answer.await.map_err(|_| Error::Closed)?
    }

    async fn send(
        &self,
        kind: FrameKind,
        msgno: u32,
        ansno: Option<u32>,
        payload: Bytes,
    ) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Send {
                channel: self.channel,
                kind,
                msgno,
                ansno,
                payload,
                reply,
            })
            .await
            .map_err(|_| Error::Closed)?;
        answer.await.map_err(|_| Error::Closed)?
    }
}
