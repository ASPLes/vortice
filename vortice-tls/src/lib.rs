// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The BEEP TLS profile, RFC3080 §3.1, over rustls or `native-tls`.
//!
//! BEEP's TLS is not implicit TLS. A session begins in the clear, and either end may then ask
//! to tune it: a channel is started offering `http://iana.org/beep/TLS` with `<ready />`
//! piggybacked on the request, the other end answers `<proceed />` piggybacked on the
//! acceptance, and both then replace the transport with a TLS stream over it. What follows is
//! **a new session** — RFC3080 is explicit that everything learnt before is discarded and the
//! greeting exchange begins again, which is what stops anything negotiated in the clear from
//! carrying over.
//!
//! That last point is the one worth internalising: the greeting a peer sent before TLS proves
//! nothing, and this crate never carries it forward. Profiles a server is only willing to
//! offer under TLS — SASL, most usefully — simply appear in the greeting it sends afterwards.
//!
//! This crate is written entirely against `vortice`'s public API. The one thing the core
//! provides for it is [`Connection::upgrade`], the transport swap; everything else here is
//! ordinary channel work.
//!
//! # Client
//!
//! ```no_run
//! # async fn example() -> vortice_tls::Result<()> {
//! use vortice::{Config, Role};
//!
//! let mut session = vortice::Connection::connect("127.0.0.1:602", Config::new(Role::Initiator))
//!     .await
//!     .map_err(vortice_tls::Error::from)?;
//!
//! // Everything after this point crosses an encrypted transport, on a session that knows
//! // nothing of what was said before it.
//! let greeting = vortice_tls::upgrade(
//!     &mut session,
//!     Config::new(Role::Initiator),
//!     vortice_tls::insecure_client_config(),
//!     "localhost",
//! )
//! .await?;
//! # let _ = greeting;
//! # Ok(())
//! # }
//! ```
//!
//! # Implicit TLS, and sharing a port
//!
//! [`connect`] and [`serve`] run BEEP inside TLS from the first octet, which is what a
//! TLS-terminating proxy produces and what deployments reach for when there is a port to
//! spare. [`looks_like_tls`] tells a handshake from plain BEEP and from an HTTP request, so
//! one port can take all three.
//!
//! # Server
//!
//! [`TlsProfile`] is a [`Handler`] like any other, so a listener offers TLS by registering it:
//!
//! ```no_run
//! # fn example(certificates: Vec<u8>, key: Vec<u8>) -> vortice_tls::Result<()> {
//! use vortice::{Config, Role, Router};
//!
//! let server_config = vortice_tls::server_config(&certificates, &key)?;
//! let router = Router::new().profile(
//!     vortice_tls::PROFILE_URI,
//!     vortice_tls::TlsProfile::new(server_config, Config::new(Role::Listener)),
//! );
//! # let _ = router;
//! # Ok(())
//! # }
//! ```
//!
//! # Which TLS library
//!
//! Two, and neither is the profile's business. The negotiation above is XML on a channel; the
//! only step that involves TLS at all is the swap, and all it asks of a library is to turn a
//! transport into an encrypted one. That is [`backend::Acceptor`] and [`backend::Connector`],
//! one method each.
//!
//! - **`rustls`**, the default feature, and what the interop tests run against.
//! - **`native-tls`**, the platform's own — OpenSSL, Secure Transport, SChannel — in the
//!   `native` module, for a deployment that has already decided what its TLS is.
//!
//! They are not exclusive: both may be on, and a listener on one tunes a client on the other,
//! which `tests/native_tls.rs` checks in both directions. With neither feature everything
//! here still compiles except the two backends, which is what a caller bringing a library of
//! its own builds against.

#![forbid(unsafe_code)]

pub mod backend;
mod error;
mod implicit;
#[cfg(feature = "native-tls")]
pub mod native;
#[cfg(feature = "rustls")]
mod rustls_backend;

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use vortice::{
    BoxedTransport, Config, Connection, ErrorReply, Greeting, Handler, HandlerFuture, Message,
    Peer, Profile, Responder, SessionId, Start, code,
};

use crate::backend::{Acceptor, Connector};

pub use backend::Handshake;
pub use error::{Error, Result};
pub use implicit::{BEEP_ALPN, accept, connect, connect_over, looks_like_tls, serve};
#[cfg(feature = "rustls")]
pub use rustls_backend::{
    acceptor, client_config, insecure_client_config, server_config, with_client_alpn,
    with_server_alpn,
};

/// The profile URI that names this negotiation.
pub const PROFILE_URI: &str = "http://iana.org/beep/TLS";

/// What the initiating peer piggybacks on the channel it starts.
const READY: &str = "<ready />";

/// What the listening peer piggybacks on the acceptance.
const PROCEED: &str = "<proceed />";

/// Tunes a session for TLS and returns the greeting of the session that follows.
///
/// `after` configures the new session — the role must match the one the transport already
/// has, and the greeting is the caller's chance to offer profiles it was not willing to offer
/// in the clear.
///
/// # Errors
///
/// Returns [`Error::NotOffered`] when the peer's greeting does not list the profile,
/// [`Error::Refused`] when it declines the channel, [`Error::NotProceeding`] when it answers
/// something other than `<proceed />`, and [`Error::Handshake`] when TLS itself fails — after
/// which the session is finished, since the transport it ran on is gone.
pub async fn upgrade<'a>(
    session: &'a mut Connection,
    after: Config,
    tls: impl Connector,
    server_name: &str,
) -> Result<&'a Greeting> {
    if !session.peer_greeting().advertises(PROFILE_URI) {
        return Err(Error::NotOffered);
    }

    // The offer and the answer both ride on the channel exchange, so this single round trip
    // is the whole negotiation.
    let channel = session
        .open_channel(Profile::new(PROFILE_URI).with_content(READY))
        .await?;

    match channel.profile().content.as_deref() {
        Some(PROCEED) => {}
        other => {
            return Err(Error::NotProceeding(
                other.unwrap_or("nothing at all").to_owned(),
            ));
        }
    }

    // The swap reports failures as transport errors, which would reach the caller as a session
    // that merely ended. A refused certificate is a different thing to be told, and the most
    // likely failure here, so it is kept aside and reported as itself.
    let handshake_failure: Arc<Mutex<Option<io::Error>>> = Arc::new(Mutex::new(None));
    let failure = Arc::clone(&handshake_failure);
    let name = server_name.to_owned();

    let outcome = session
        .upgrade(after, move |io| async move {
            match tls.connect(&name, io).await {
                Ok(stream) => Ok(Box::pin(stream) as BoxedTransport),
                Err(error) => {
                    let message = error.to_string();
                    if let Ok(mut slot) = failure.lock() {
                        *slot = Some(error);
                    }
                    Err(vortice::Error::Io(io::Error::other(message)))
                }
            }
        })
        .await;

    match outcome {
        Ok(greeting) => Ok(greeting),
        Err(error) => Err(handshake_failure
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
            .map_or_else(|| Error::from(error), Error::Handshake)),
    }
}

/// The listening half of the profile.
///
/// Answers a channel offering TLS with `<proceed />` and then replaces the transport. It
/// declares [`Handler::upgrades_transport`], which is what stops the session reading between
/// the two — see that method for why the gap matters.
#[derive(Clone)]
pub struct TlsProfile {
    acceptor: Arc<dyn Acceptor>,
    after: Config,
    policy: Arc<dyn TlsPolicy>,
}

/// What a listener decides when a peer asks to tune the session.
///
/// This is `vortex_tls_accept_negotiation`'s accept handler, and it exists for the same
/// reasons: a listener may serve TLS to some peers and not others, may need the `serverName`
/// to pick a certificate, and may have to ask something else before it can agree.
///
/// The decision is split in two because the two halves happen at different moments and only
/// one of them can still say no:
///
/// - [`TlsPolicy::accept`] runs on the `<start>`, synchronously, and is the only place a
///   refusal is possible. Refusing writes an `<error>` and leaves the session running in the
///   clear, which is what RFC3080 §3.1 expects of a tuning attempt that is declined.
/// - [`TlsPolicy::proceed`] runs after that, before `<proceed/>` reaches the peer, and may
///   await. It is where work that has to happen before agreeing goes — looking a certificate
///   up, asking a policy server. Returning `false` there means the listener agreed and then
///   could not go through with it: the handshake fails and the session ends, which is the
///   only honest outcome once `<proceed/>` is on the wire.
pub trait TlsPolicy: Send + Sync + 'static {
    /// Whether to tune at all, decided from the `<start>` that asked and from which peer.
    ///
    /// # Errors
    ///
    /// The [`ErrorReply`] to send instead of the acceptance.
    fn accept(&self, session: SessionId, start: &Start) -> std::result::Result<(), ErrorReply> {
        let _ = (session, start);
        Ok(())
    }

    /// Work to do before the acceptance reaches the peer, and a last chance to abandon.
    ///
    /// `false` fails the handshake, and with it the session.
    fn proceed(&self, session: SessionId, server_name: Option<String>) -> TlsDecision {
        let _ = (session, server_name);
        Box::pin(core::future::ready(true))
    }
}

/// What [`TlsPolicy::proceed`] answers with, once it has finished deciding.
pub type TlsDecision = Pin<Box<dyn Future<Output = bool> + Send>>;

/// The policy a [`TlsProfile`] has when none is given: tune with anyone who asks.
///
/// What LibVortex does when `vortex_tls_accept_negotiation` is passed no accept handler.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAll;

impl TlsPolicy for AcceptAll {}

impl core::fmt::Debug for TlsProfile {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `TlsAcceptor` has nothing printable and a configuration is not something to spill
        // into a log, so this says what the value is rather than what it holds.
        formatter.debug_struct("TlsProfile").finish_non_exhaustive()
    }
}

impl TlsProfile {
    /// Serves TLS with `tls`, and runs the session that follows with `after`.
    ///
    /// Tunes with anyone who asks; see [`TlsProfile::with_policy`] for a listener that does
    /// not, and [`TlsProfile::with_acceptor`] for one terminating TLS with something other
    /// than rustls.
    #[cfg(feature = "rustls")]
    #[must_use]
    pub fn new(tls: tokio_rustls::rustls::ServerConfig, after: Config) -> Self {
        Self::with_acceptor(crate::acceptor(tls)).after_tuning(after)
    }

    /// A profile tuning with a backend of the caller's choosing.
    ///
    /// Any [`Acceptor`] will do: the rustls one, the `native-tls` one, or something written
    /// for a TLS library this crate has never heard of. The profile itself is the negotiation
    /// and the swap, neither of which knows what encrypts the transport afterwards.
    #[must_use]
    pub fn with_acceptor(acceptor: impl Acceptor) -> Self {
        Self {
            acceptor: Arc::new(acceptor),
            after: Config::new(vortice::Role::Listener),
            policy: Arc::new(AcceptAll),
        }
    }

    /// The configuration the session that follows the swap runs with.
    ///
    /// A fresh greeting means a fresh offer of profiles, so this is where a listener says what
    /// it is willing to serve once the transport is encrypted.
    #[must_use]
    pub fn after_tuning(mut self, after: Config) -> Self {
        self.after = after;
        self
    }

    /// Puts a [`TlsPolicy`] in charge of who gets tuned.
    #[must_use]
    pub fn with_policy(mut self, policy: impl TlsPolicy) -> Self {
        self.policy = Arc::new(policy);
        self
    }
}

impl Handler for TlsProfile {
    fn handle(&self, _responder: Responder, _message: Message) -> HandlerFuture {
        // Nothing is ever sent on this channel: the negotiation is the channel exchange, and
        // by the time a message could arrive the transport has already been replaced.
        Box::pin(core::future::ready(()))
    }

    fn accept(
        &self,
        peer: Peer<'_>,
        uri: &str,
        start: &Start,
    ) -> std::result::Result<Profile, ErrorReply> {
        let offered = start
            .profiles
            .iter()
            .find(|profile| profile.uri == uri)
            .and_then(|profile| profile.content.as_deref());

        if offered != Some(READY) {
            // LibVortex requires the piggyback too, and refusing here is better than accepting
            // and then swapping a transport the peer is not expecting to change.
            return Err(ErrorReply::new(code::TRANSACTION_FAILED).with_text(
                "the TLS profile expects <ready /> piggybacked on the start",
                None,
            ));
        }
        self.policy.accept(peer.session, start)?;
        Ok(Profile::new(uri).with_content(PROCEED))
    }

    fn upgrades_transport(&self) -> bool {
        true
    }

    fn on_open(&self, responder: Responder) -> HandlerFuture {
        let acceptor = Arc::clone(&self.acceptor);
        let after = self.after.clone();
        let policy = Arc::clone(&self.policy);
        Box::pin(async move {
            // Nothing has reached the peer yet: `<proceed/>` travels with the upgrade below,
            // which is what makes the reply and the swap one indivisible step. So this is the
            // last moment at which the listener can still take its time, or think better of
            // it.
            let server_name = responder.server_name().await.ok().flatten();
            let session = responder.session();
            let outcome = if policy.proceed(session, server_name).await {
                responder
                    .upgrade(after, move |io| async move {
                        acceptor.accept(io).await.map_err(vortice::Error::Io)
                    })
                    .await
            } else {
                // Agreed and then could not go through with it, which is what a listener that
                // fails to build its TLS context does. The peer is already committed to a
                // handshake, so there is nothing to say to it in BEEP: the session ends.
                responder
                    .upgrade(after, move |_io| async move {
                        Err(vortice::Error::Io(std::io::Error::other(
                            "the listener could not go through with the negotiation",
                        )))
                    })
                    .await
            };
            if let Err(error) = outcome {
                tracing::debug!(%error, "TLS negotiation failed");
            }
        })
    }
}
