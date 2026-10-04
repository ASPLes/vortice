// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The profile that carries a mechanism, RFC3080 §4.1.
//!
//! One profile per mechanism, named `http://iana.org/beep/SASL/<MECHANISM>`, so a peer sees in
//! the greeting exactly which ones are on offer and picks by starting a channel.
//!
//! The exchange maps onto the channel like this:
//!
//! - the peer starts the channel, piggybacking `<blob>` with its first move, or nothing at
//!   all for a mechanism where the listener speaks first;
//! - the listener answers on the acceptance, also piggybacked: `<blob status='complete' />`
//!   when one round was enough, `<blob status='continue'>…</blob>` when it was not;
//! - any further rounds are ordinary `MSG` and `RPY` on the open channel.
//!
//! **A failure declines the channel.** There is no `<blob status='failed'>`, which is worth
//! stating because the symmetry invites one: RFC3080 §4.1 has the listener refuse the start,
//! and LibVortex's client agrees — it looks for `<error` in the reply and reports the
//! authentication as failed. A listener that accepted the channel and then said no would
//! leave that client waiting for a reply it is not going to recognise.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vortice::{
    ErrorReply, Handler, HandlerFuture, Message, Profile, Responder, SessionId, Start, code,
};

use crate::blob::{Blob, Status};
use crate::mechanism::{Exchange, Identity, Mechanism, Step};

/// The family every SASL profile URI belongs to.
pub const PROFILE_FAMILY: &str = "http://iana.org/beep/SASL/";

/// The profile URI for a mechanism: `http://iana.org/beep/SASL/PLAIN` and so on.
#[must_use]
pub fn profile_uri(mechanism: &str) -> String {
    format!("{PROFILE_FAMILY}{mechanism}")
}

/// What one channel's exchange is doing between calls into the handler.
enum State {
    /// Waiting for the peer's next blob.
    InFlight(Box<dyn Exchange>),
    /// Finished, and the identity is waiting to be recorded once something can await.
    Settled(Identity),
}

/// Exchanges in flight, keyed by the channel carrying them.
type Exchanges = Arc<Mutex<HashMap<(SessionId, u32), State>>>;

/// Serves one mechanism as a BEEP profile.
///
/// Register one per mechanism on the router, each under its own URI:
///
/// ```no_run
/// # use std::sync::Arc;
/// # use vortice::Router;
/// # fn example(authenticator: Arc<dyn vortice_sasl::Authenticator>) -> Router {
/// use vortice_sasl::{Plain, SaslProfile, profile_uri};
///
/// Router::new().profile(
///     profile_uri("PLAIN"),
///     SaslProfile::new(Plain::new(authenticator)),
/// )
/// # }
/// ```
pub struct SaslProfile {
    mechanism: Arc<dyn Mechanism>,
    /// Only a mechanism that takes more than one round ever leaves anything here between
    /// calls: a one-round exchange is settled in `accept` and recorded in `on_open`, which
    /// always follows it.
    ///
    /// There is no hook for a channel being closed, so an exchange the peer starts and
    /// abandons stays until the profile does. That is bounded by what a peer can open and
    /// costs one small entry each; a close hook on `Handler` would remove even that, and is
    /// worth having before a multi-round mechanism ships.
    exchanges: Exchanges,
}

impl std::fmt::Debug for SaslProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SaslProfile")
            .field("mechanism", &self.mechanism.name())
            .finish_non_exhaustive()
    }
}

impl SaslProfile {
    /// Serves `mechanism`.
    #[must_use]
    pub fn new(mechanism: impl Mechanism) -> Self {
        Self {
            mechanism: Arc::new(mechanism),
            exchanges: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The URI this profile is to be registered under.
    #[must_use]
    pub fn uri(&self) -> String {
        profile_uri(self.mechanism.name())
    }
}

/// What the peer piggybacked on the start, if anything.
fn initial_blob(uri: &str, start: &Start) -> Result<Vec<u8>, ErrorReply> {
    let offered = start
        .profiles
        .iter()
        .find(|profile| profile.uri == uri)
        .and_then(|profile| profile.content.as_deref());

    match offered {
        // A mechanism where the listener speaks first is started with nothing attached.
        None | Some("") => Ok(Vec::new()),
        Some(text) => Blob::from_xml(text)
            .map(|blob| blob.data)
            .map_err(|_| refusal("the piggybacked content is not a SASL blob")),
    }
}

/// The reply that declines a channel, and with it the authentication.
fn refusal(text: &str) -> ErrorReply {
    ErrorReply::new(code::AUTHENTICATION_FAILURE).with_text(text.to_owned(), None)
}

impl Handler for SaslProfile {
    fn accept(
        &self,
        session: SessionId,
        uri: &str,
        start: &Start,
    ) -> std::result::Result<Profile, ErrorReply> {
        let initial = initial_blob(uri, start)?;
        let mut exchange = self.mechanism.begin();

        let (state, content) = match exchange.step(&initial) {
            Step::Complete(identity) => (
                State::Settled(identity),
                Blob::status(Status::Complete).to_xml(),
            ),
            Step::Continue(challenge) => (
                State::InFlight(exchange),
                Blob::with_status(Status::Continue, challenge).to_xml(),
            ),
            Step::Failed(reason) => {
                tracing::debug!(
                    mechanism = self.mechanism.name(),
                    %reason,
                    "SASL exchange refused at the start"
                );
                return Err(refusal(&reason));
            }
        };

        self.exchanges
            .lock()
            .expect("the exchange table is not poisoned")
            .insert((session, start.number), state);
        Ok(Profile::new(uri).with_content(content))
    }

    fn on_open(&self, responder: Responder) -> HandlerFuture {
        let key = (responder.session(), responder.channel());
        let exchanges = Arc::clone(&self.exchanges);

        // An exchange that finished in `accept` has an identity to record, and this is the
        // first moment at which it can be: recording awaits the driver, and `accept` cannot.
        let settled = {
            let mut table = exchanges
                .lock()
                .expect("the exchange table is not poisoned");
            match table.get(&key) {
                Some(State::Settled(_)) => match table.remove(&key) {
                    Some(State::Settled(identity)) => Some(identity),
                    _ => None,
                },
                _ => None,
            }
        };

        Box::pin(async move {
            if let Some(identity) = settled {
                let _ = responder.authenticate(identity.effective()).await;
            }
        })
    }

    fn handle(&self, responder: Responder, message: Message) -> HandlerFuture {
        let key = (responder.session(), responder.channel());
        let name = self.mechanism.name();
        let exchanges = Arc::clone(&self.exchanges);

        Box::pin(async move {
            let in_flight = exchanges
                .lock()
                .expect("the exchange table is not poisoned")
                .remove(&key);

            // Nothing in flight: either the exchange is over or the peer is sending blobs at
            // a profile that is not expecting any.
            let Some(State::InFlight(mut exchange)) = in_flight else {
                let _ = responder
                    .error(message.msgno, Blob::status(Status::Abort).to_xml())
                    .await;
                return;
            };

            let Ok(blob) = Blob::from_xml(&String::from_utf8_lossy(&message.payload)) else {
                let _ = responder
                    .error(message.msgno, Blob::status(Status::Abort).to_xml())
                    .await;
                return;
            };

            if blob.status == Status::Abort {
                tracing::debug!(mechanism = name, "the peer abandoned the exchange");
                let _ = responder
                    .reply(message.msgno, Blob::status(Status::Abort).to_xml())
                    .await;
                return;
            }

            match exchange.step(&blob.data) {
                Step::Complete(identity) => {
                    let _ = responder.authenticate(identity.effective()).await;
                    let _ = responder
                        .reply(message.msgno, Blob::status(Status::Complete).to_xml())
                        .await;
                }
                Step::Continue(challenge) => {
                    exchanges
                        .lock()
                        .expect("the exchange table is not poisoned")
                        .insert(key, State::InFlight(exchange));
                    let _ = responder
                        .reply(
                            message.msgno,
                            Blob::with_status(Status::Continue, challenge).to_xml(),
                        )
                        .await;
                }
                Step::Failed(reason) => {
                    tracing::debug!(mechanism = name, %reason, "SASL exchange refused");
                    let _ = responder
                        .error(message.msgno, Blob::status(Status::Abort).to_xml())
                        .await;
                }
            }
        })
    }
}
