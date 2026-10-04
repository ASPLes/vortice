// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! What a SASL mechanism is, from the listening side.
//!
//! A mechanism is a conversation: the peer sends octets, the listener answers with more
//! octets or with a verdict, and how many rounds that takes is the mechanism's business.
//! [`Mechanism`] names one and starts conversations; [`Exchange`] is one conversation, with
//! whatever state that mechanism needs to remember between rounds.
//!
//! The split matters because a listener registers one [`Mechanism`] and serves many
//! connections with it, while every connection needs its own nonce, its own challenge, its
//! own half-finished state.

use std::fmt::Debug;

/// Where a round of a SASL exchange leaves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Send these octets to the peer and expect another blob back.
    Continue(Vec<u8>),
    /// The peer is who it says it is.
    Complete(Identity),
    /// It is not, or the exchange is malformed. The text is for the log and for the
    /// `<error>` sent back, so it must say nothing a peer could learn from — see
    /// [`Self::Failed`]'s note.
    Failed(String),
}

impl Step {
    /// A refusal with the one message every failure should give.
    ///
    /// Distinguishing "no such user" from "wrong password" tells an unauthenticated peer
    /// which identities exist, which is why every mechanism here answers the same way.
    #[must_use]
    pub fn denied() -> Self {
        Self::Failed("authentication failed".to_owned())
    }
}

/// Who the peer turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Who the peer proved itself to be.
    pub authentication_id: String,
    /// Who it asked to act as, when that is someone else.
    ///
    /// SASL separates the two so that one set of credentials can act for another identity —
    /// an administrator operating on a user's behalf. A mechanism reports what the peer
    /// asked for; whether to allow it is the application's decision, taken in
    /// [`Authenticator`].
    pub authorization_id: Option<String>,
}

impl Identity {
    /// An identity that is only itself.
    #[must_use]
    pub fn new(authentication_id: impl Into<String>) -> Self {
        Self {
            authentication_id: authentication_id.into(),
            authorization_id: None,
        }
    }

    /// The identity the session should be recorded as running under.
    ///
    /// The authorization identity when there is one, since that is who the peer is acting
    /// as, and the authentication identity otherwise.
    #[must_use]
    pub fn effective(&self) -> &str {
        self.authorization_id
            .as_deref()
            .unwrap_or(&self.authentication_id)
    }
}

/// One mechanism a listener offers.
pub trait Mechanism: Debug + Send + Sync + 'static {
    /// The name IANA registered, which is also the last part of the profile URI: `PLAIN`,
    /// `ANONYMOUS`, `CRAM-MD5`.
    fn name(&self) -> &'static str;

    /// Begins a conversation with one peer.
    fn begin(&self) -> Box<dyn Exchange>;
}

/// One conversation with one peer.
pub trait Exchange: Send {
    /// Takes the peer's octets and says what happens next.
    ///
    /// The first call carries whatever the peer piggybacked on the channel start, which for
    /// a mechanism that speaks first — `CRAM-MD5`, where the listener issues the challenge —
    /// is empty.
    fn step(&mut self, blob: &[u8]) -> Step;
}

/// What the application is asked, and the only place it decides anything.
///
/// One method per question, because the mechanisms genuinely differ in what they can ask.
/// `PLAIN` hands over a password to be checked; `CRAM-MD5` cannot, because the password never
/// crosses the wire, so it has to ask for the password itself in order to compute with it.
/// Pretending those are the same question would hide the thing worth knowing: **a listener
/// offering `CRAM-MD5` must be able to recover its users' passwords**, which is a decision
/// about how they are stored, not about which trait method to implement.
///
/// Everything defaults to refusing. A listener grants what it means to grant and nothing by
/// omission.
pub trait Authenticator: Debug + Send + Sync + 'static {
    /// Whether to admit an unauthenticated peer offering `token` as a trace (RFC4505).
    ///
    /// The token is advisory and unverified — an email address by convention, nothing more.
    fn anonymous(&self, token: &str) -> bool {
        let _ = token;
        false
    }

    /// Whether to admit a peer whose identity the transport already established (RFC4422
    /// §A), asking to act as `authorization_id`.
    ///
    /// There is no credential here by design: `EXTERNAL` means "you already know who I am",
    /// and the only honest listener implementation consults what TLS, or the operating
    /// system behind a Unix socket, reported. `None` means the peer asked for whatever
    /// identity the transport says it has.
    fn external(&self, authorization_id: Option<&str>) -> bool {
        let _ = authorization_id;
        false
    }

    /// Whether `password` authenticates `authentication_id` (RFC4616).
    fn plain(
        &self,
        authentication_id: &str,
        authorization_id: Option<&str>,
        password: &str,
    ) -> bool {
        let _ = (authentication_id, authorization_id, password);
        false
    }

    /// The shared secret for an identity, for the mechanisms that must compute with it.
    ///
    /// Returning `Some` here is a statement that the listener holds recoverable passwords.
    /// Nothing else in this crate asks for one.
    fn secret(&self, authentication_id: &str, realm: Option<&str>) -> Option<String> {
        let _ = (authentication_id, realm);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{Identity, Step};

    #[test]
    fn the_effective_identity_is_the_one_being_acted_as() {
        assert_eq!(Identity::new("bob").effective(), "bob");
        assert_eq!(
            Identity {
                authentication_id: "admin".to_owned(),
                authorization_id: Some("bob".to_owned()),
            }
            .effective(),
            "bob"
        );
    }

    /// Every refusal says the same thing, whatever went wrong.
    #[test]
    fn a_refusal_gives_nothing_away() {
        assert_eq!(
            Step::denied(),
            Step::Failed("authentication failed".to_owned())
        );
    }
}
