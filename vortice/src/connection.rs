// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The session handle and the task that drives it.
//!
//! The protocol state machine is not shared: it lives in one task, and every handle talks to
//! that task over a channel. That is what makes the whole thing free of locks — no mutex
//! guards a [`Session`], because only the driver ever touches one.
//!
//! Channels the peer asks for are answered from the [`Router`] the session was given: a
//! start offering a profile it serves is accepted, anything else is refused with `550`.
//! Closes the peer asks for are accepted, which is the BEEP default action.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::{mpsc, oneshot};
use vortice_proto::frame::FrameKind;
use vortice_proto::greeting::Greeting;
use vortice_proto::management::{ErrorReply, Profile, Start, code};
use vortice_proto::mime;
use vortice_proto::session::{Config, Event, Session, State};

use crate::channel::{Channel, Message, Reply};
use crate::error::{Error, Result};
use crate::router::{Handler, Responder, Router};

/// How many octets are read from the transport at a time.
const READ_CHUNK: usize = 16 * 1024;

/// How many commands may be in flight before callers are made to wait.
const COMMAND_QUEUE: usize = 64;

/// How many messages may pile up on a channel before the driver stops accepting more.
const INBOUND_QUEUE: usize = 64;

/// A request from a handle to the driver.
#[derive(Debug)]
pub(crate) enum Command {
    OpenChannel {
        profile: Profile,
        reply: oneshot::Sender<Result<Channel>>,
    },
    CloseChannel {
        number: u32,
        reply: oneshot::Sender<Result<()>>,
    },
    Request {
        channel: u32,
        payload: Bytes,
        reply: oneshot::Sender<Result<Reply>>,
    },
    Send {
        channel: u32,
        kind: FrameKind,
        msgno: u32,
        ansno: Option<u32>,
        payload: Bytes,
        reply: oneshot::Sender<Result<()>>,
    },
    CloseSession {
        reply: oneshot::Sender<Result<()>>,
    },
    SetWindowSize {
        channel: u32,
        size: u32,
        reply: oneshot::Sender<Result<()>>,
    },
}

/// Distinguishes one session from another.
///
/// A [`Handler`] is shared by every session serving its profile, so anything it wants to
/// remember per connection has to be keyed by this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl SessionId {
    fn next() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// A BEEP session.
///
/// Cloning is deliberately not offered: the handle is cheap to share behind an `Arc` when
/// that is what an application wants, and making it implicitly shareable would hide the fact
/// that closing it ends the session for everyone.
#[derive(Debug)]
pub struct Connection {
    commands: mpsc::Sender<Command>,
    peer_greeting: Greeting,
}

impl Connection {
    /// Connects over TCP and completes the greeting exchange.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the transport fails and [`Error::Protocol`] when the peer's
    /// greeting is not one.
    pub async fn connect(address: impl ToSocketAddrs, config: Config) -> Result<Self> {
        let stream = TcpStream::connect(address).await?;
        stream.set_nodelay(true)?;
        Self::from_io(stream, config).await
    }

    /// Runs a session over an already established transport.
    ///
    /// Anything implementing `AsyncRead + AsyncWrite` will do: TCP, TLS, a Unix socket,
    /// `tokio::io::duplex` in a test, or a transport of the caller's own. The returned handle
    /// is live once both greetings have been exchanged.
    ///
    /// # Errors
    ///
    /// As [`Connection::connect`].
    pub async fn from_io<T>(io: T, config: Config) -> Result<Self>
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        Self::serve_io(io, config, Router::new()).await
    }

    /// Runs a session that also serves the profiles in `router`.
    ///
    /// A channel the peer asks for is accepted when the router serves one of the profiles
    /// offered, and refused otherwise.
    ///
    /// # Errors
    ///
    /// As [`Connection::connect`].
    pub async fn serve_io<T>(io: T, config: Config, router: Router) -> Result<Self>
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (commands, receiver) = mpsc::channel(COMMAND_QUEUE);
        let (ready, greeted) = oneshot::channel();

        let (reader, writer) = tokio::io::split(io);
        let driver = Driver {
            session: Session::new(config),
            reader,
            writer,
            commands: receiver,
            out: BytesMut::new(),
            routes: Routes::new(commands.downgrade()),
            router: Arc::new(router),
            served: HashMap::new(),
            id: SessionId::next(),
        };
        tokio::spawn(driver.run(ready));

        let peer_greeting = greeted.await.map_err(|_| Error::Closed)??;
        Ok(Self {
            commands,
            peer_greeting,
        })
    }

    /// The greeting the peer sent, listing the profiles it is willing to serve.
    #[must_use]
    pub const fn peer_greeting(&self) -> &Greeting {
        &self.peer_greeting
    }

    /// Resolves once the session has ended, however it ended.
    ///
    /// A server holds the handle open on this until the peer goes away; dropping it instead
    /// would take the session down with it.
    pub async fn closed(&self) {
        self.commands.closed().await;
    }

    /// Asks the peer for a channel and waits for its answer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Refused`] with the peer's code and text when it declines, and
    /// [`Error::Closed`] when the session ended first.
    pub async fn open_channel(&self, profile: Profile) -> Result<Channel> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::OpenChannel { profile, reply })
            .await
            .map_err(|_| Error::Closed)?;
        answer.await.map_err(|_| Error::Closed)?
    }

    /// Closes a channel and waits for the peer to accept.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Refused`] when the peer declines to close it.
    pub async fn close_channel(&self, number: u32) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::CloseChannel { number, reply })
            .await
            .map_err(|_| Error::Closed)?;
        answer.await.map_err(|_| Error::Closed)?
    }

    /// Closes the session, waiting for the peer to accept.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Refused`] when the peer declines.
    pub async fn close(&self) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        if self
            .commands
            .send(Command::CloseSession { reply })
            .await
            .is_err()
        {
            // The driver is already gone, which is what closing asks for.
            return Ok(());
        }
        match answer.await {
            Ok(result) => result,
            Err(_) => Ok(()),
        }
    }
}

/// A reply this end is waiting for.
#[derive(Debug)]
struct PendingRequest {
    reply: oneshot::Sender<Result<Reply>>,
    answers: Vec<Bytes>,
}

/// Everything the driver has to route replies and messages back to.
#[derive(Debug)]
struct Routes {
    /// A weak handle, deliberately: holding a strong one here would keep the receiver alive
    /// for as long as the driver runs, so the driver would never learn that every
    /// [`Connection`] and [`Channel`] had been dropped and would outlive its own session.
    commands: mpsc::WeakSender<Command>,
    opens: HashMap<u32, oneshot::Sender<Result<Channel>>>,
    closes: HashMap<u32, oneshot::Sender<Result<()>>>,
    session_close: Option<oneshot::Sender<Result<()>>>,
    requests: HashMap<(u32, u32), PendingRequest>,
    inbound: HashMap<u32, mpsc::Sender<Message>>,
}

impl Routes {
    fn new(commands: mpsc::WeakSender<Command>) -> Self {
        Self {
            commands,
            opens: HashMap::new(),
            closes: HashMap::new(),
            session_close: None,
            requests: HashMap::new(),
            inbound: HashMap::new(),
        }
    }

    /// Completes everything still waiting, so no caller is left hanging when the session ends.
    fn shutdown(&mut self) {
        for (_, sender) in self.opens.drain() {
            let _ = sender.send(Err(Error::Closed));
        }
        for (_, sender) in self.closes.drain() {
            let _ = sender.send(Err(Error::Closed));
        }
        if let Some(sender) = self.session_close.take() {
            let _ = sender.send(Ok(()));
        }
        for (_, pending) in self.requests.drain() {
            let _ = pending.reply.send(Err(Error::Closed));
        }
        self.inbound.clear();
    }
}

/// The task that owns the protocol state machine.
struct Driver<T> {
    session: Session,
    reader: ReadHalf<T>,
    writer: WriteHalf<T>,
    commands: mpsc::Receiver<Command>,
    out: BytesMut,
    routes: Routes,
    router: Arc<Router>,
    /// Handlers for the channels this end accepted, by channel number.
    served: HashMap<u32, Arc<dyn Handler>>,
    id: SessionId,
}

impl<T> Driver<T>
where
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    async fn run(mut self, ready: oneshot::Sender<Result<Greeting>>) {
        let mut ready = Some(ready);
        let outcome = self.pump(&mut ready).await;
        if let Err(error) = outcome {
            tracing::debug!(%error, "session ended");
            if let Some(sender) = ready.take() {
                let _ = sender.send(Err(error));
            }
        } else if let Some(sender) = ready.take() {
            let _ = sender.send(Err(Error::Closed));
        }
        self.routes.shutdown();
    }

    async fn pump(&mut self, ready: &mut Option<oneshot::Sender<Result<Greeting>>>) -> Result<()> {
        let mut read = BytesMut::with_capacity(READ_CHUNK);
        loop {
            // Handling an event can itself queue octets — refusing a start writes an ERR,
            // accepting a close writes an OK — so draining once in each direction is not
            // enough: the reply would sit in the session until something else woke the loop,
            // which for a peer waiting on that very reply is never.
            loop {
                let mut progressed = false;
                while let Some(bytes) = self.session.poll_transmit() {
                    self.out.extend_from_slice(&bytes);
                    progressed = true;
                }
                while let Some(event) = self.session.poll_event() {
                    self.handle_event(event, ready);
                    progressed = true;
                }
                if !progressed {
                    break;
                }
            }
            if self.session.state() == State::Closed {
                return Ok(());
            }

            read.clear();
            read.reserve(READ_CHUNK);

            if self.out.is_empty() {
                tokio::select! {
                    command = self.commands.recv() => match command {
                        Some(command) => self.apply(command),
                        None => return Ok(()),
                    },
                    result = self.reader.read_buf(&mut read) => {
                        if result? == 0 {
                            return Ok(());
                        }
                        self.session.handle_input(&read)?;
                    }
                }
            } else {
                let written = {
                    let writer = &mut self.writer;
                    let reader = &mut self.reader;
                    let commands = &mut self.commands;
                    let out = &self.out;
                    tokio::select! {
                        command = commands.recv() => Progress::Command(command),
                        result = reader.read_buf(&mut read) => Progress::Read(result?),
                        result = writer.write(out) => Progress::Wrote(result?),
                    }
                };
                match written {
                    Progress::Command(Some(command)) => self.apply(command),
                    Progress::Command(None) => return Ok(()),
                    Progress::Read(0) => return Ok(()),
                    Progress::Read(_) => self.session.handle_input(&read)?,
                    Progress::Wrote(n) => self.out.advance(n),
                }
            }
        }
    }

    /// Carries out one request from a handle.
    fn apply(&mut self, command: Command) {
        match command {
            Command::OpenChannel { profile, reply } => match self.session.start_channel(profile) {
                Ok(number) => {
                    self.routes.opens.insert(number, reply);
                }
                Err(error) => {
                    let _ = reply.send(Err(error.into()));
                }
            },
            Command::CloseChannel { number, reply } => match self.session.close_channel(number) {
                Ok(()) => {
                    self.routes.closes.insert(number, reply);
                }
                Err(error) => {
                    let _ = reply.send(Err(error.into()));
                }
            },
            Command::Request {
                channel,
                payload,
                reply,
            } => match self.session.send_msg(channel, with_mime(&payload)) {
                Ok(msgno) => {
                    self.routes.requests.insert(
                        (channel, msgno),
                        PendingRequest {
                            reply,
                            answers: Vec::new(),
                        },
                    );
                }
                Err(error) => {
                    let _ = reply.send(Err(error.into()));
                }
            },
            Command::Send {
                channel,
                kind,
                msgno,
                ansno,
                payload,
                reply,
            } => {
                let result = self
                    .session
                    .send(channel, kind, msgno, ansno, with_mime(&payload))
                    .map_err(Error::from);
                let _ = reply.send(result);
            }
            Command::SetWindowSize {
                channel,
                size,
                reply,
            } => {
                let result = self
                    .session
                    .set_window_size(channel, size)
                    .map_err(Error::from);
                let _ = reply.send(result);
            }
            Command::CloseSession { reply } => {
                match self
                    .session
                    .close_channel(vortice_proto::greeting::GREETING_CHANNEL)
                {
                    Ok(()) => self.routes.session_close = Some(reply),
                    Err(error) => {
                        let _ = reply.send(Err(error.into()));
                    }
                }
            }
        }
    }

    /// Answers a channel start by asking the router whether it serves anything offered.
    fn start_requested(&mut self, channel: u32, msgno: u32, start: &Start) {
        let Some((uri, handler)) = self.router.choose(start) else {
            // 554 rather than 550: this is the code LibVortex reports when none of the
            // profiles offered is registered, and the regression suite asserts on it.
            let _ = self.session.refuse_start(
                msgno,
                ErrorReply::new(code::TRANSACTION_FAILED).with_text("profile not supported", None),
            );
            return;
        };
        match handler.accept(&uri, start) {
            Ok(profile) => {
                if self.session.accept_start(channel, msgno, profile).is_ok() {
                    self.served.insert(channel, Arc::clone(&handler));
                    if let Some(commands) = self.routes.commands.upgrade() {
                        let responder = Responder::new(self.id, channel, commands);
                        tokio::spawn(async move { handler.on_open(responder).await });
                    }
                }
            }
            Err(error) => {
                let _ = self.session.refuse_start(msgno, error);
            }
        }
    }

    /// Turns one protocol event into whatever the handles are waiting for.
    fn handle_event(
        &mut self,
        event: Event,
        ready: &mut Option<oneshot::Sender<Result<Greeting>>>,
    ) {
        match event {
            Event::GreetingReceived(greeting) => {
                if let Some(sender) = ready.take() {
                    let _ = sender.send(Ok(greeting));
                }
            }
            Event::ChannelOpened { channel, profile } => {
                let (sender, receiver) = mpsc::channel(INBOUND_QUEUE);
                self.routes.inbound.insert(channel, sender);
                if let Some(reply) = self.routes.opens.remove(&channel) {
                    match self.routes.commands.upgrade() {
                        Some(commands) => {
                            let handle = Channel::new(channel, profile, commands, receiver);
                            let _ = reply.send(Ok(handle));
                        }
                        None => {
                            let _ = reply.send(Err(Error::Closed));
                        }
                    }
                }
            }
            Event::StartRefused { channel, error } => {
                if let Some(reply) = self.routes.opens.remove(&channel) {
                    let _ = reply.send(Err(Error::Refused(error)));
                }
            }
            Event::ChannelClosed { channel } => {
                self.routes.inbound.remove(&channel);
                self.served.remove(&channel);
                if let Some(reply) = self.routes.closes.remove(&channel) {
                    let _ = reply.send(Ok(()));
                }
            }
            Event::CloseRefused { channel, error } => {
                if let Some(reply) = self.routes.closes.remove(&channel) {
                    let _ = reply.send(Err(Error::Refused(error)));
                }
            }
            Event::StartRequested {
                channel,
                msgno,
                start,
            } => self.start_requested(channel, msgno, &start),
            Event::CloseRequested { channel, msgno, .. } => {
                // Accepting is the BEEP default action, which is what test_10 checks.
                let _ = self.session.accept_close(channel, msgno);
            }
            Event::SessionClosed => {
                if let Some(reply) = self.routes.session_close.take() {
                    let _ = reply.send(Ok(()));
                }
            }
            Event::MessageReceived { channel, message } => {
                self.deliver(channel, message);
            }
            _ => {}
        }
    }

    /// Routes an incoming message to whoever is waiting for it.
    fn deliver(&mut self, channel: u32, message: vortice_proto::channel::Message) {
        let body = body_of(&message.payload);
        let key = (channel, message.msgno);

        if message.kind != FrameKind::Msg
            && let Some(mut pending) = self.routes.requests.remove(&key)
        {
            match message.kind {
                FrameKind::Rpy => {
                    let _ = pending.reply.send(Ok(Reply::Rpy(body)));
                }
                FrameKind::Err => {
                    let _ = pending.reply.send(Ok(Reply::Err(body)));
                }
                FrameKind::Ans => {
                    pending.answers.push(body);
                    self.routes.requests.insert(key, pending);
                }
                FrameKind::Nul => {
                    let answers = core::mem::take(&mut pending.answers);
                    let _ = pending.reply.send(Ok(Reply::Answers(answers)));
                }
                FrameKind::Msg => unreachable!("guarded above"),
            }
            return;
        }

        if message.kind == FrameKind::Msg
            && let Some(handler) = self.served.get(&channel)
            && let Some(commands) = self.routes.commands.upgrade()
        {
            let handler = Arc::clone(handler);
            let session = self.id;
            let delivered = Message {
                kind: message.kind,
                msgno: message.msgno,
                ansno: message.ansno,
                payload: body,
            };
            // Handlers run as their own task: a slow one must not hold up the session, and
            // BEEP explicitly allows replying to several messages out of order.
            tokio::spawn(async move {
                handler
                    .handle(Responder::new(session, channel, commands), delivered)
                    .await;
            });
            return;
        }

        if let Some(sender) = self.routes.inbound.get(&channel) {
            let delivered = Message {
                kind: message.kind,
                msgno: message.msgno,
                ansno: message.ansno,
                payload: body,
            };
            if sender.try_send(delivered).is_err() {
                tracing::warn!(channel, "dropping a message: nobody is reading the channel");
            }
        }
    }
}

/// What one turn of the driver loop achieved.
enum Progress {
    Command(Option<Command>),
    Read(usize),
    Wrote(usize),
}

/// Prefixes a payload with the empty MIME entity headers BEEP expects.
///
/// LibVortex does the same by default: a payload with no headers still opens with the blank
/// line that separates them from the body, so a peer parsing the payload as MIME finds an
/// empty header section rather than trying to read the body as headers.
fn with_mime(payload: &Bytes) -> Bytes {
    let mut framed = BytesMut::with_capacity(payload.len() + 2);
    framed.extend_from_slice(b"\r\n");
    framed.extend_from_slice(payload);
    framed.freeze()
}

/// Strips the MIME entity headers from an incoming payload, without copying it.
fn body_of(payload: &Bytes) -> Bytes {
    let (_, body) = mime::split(payload);
    payload.slice_ref(body)
}
