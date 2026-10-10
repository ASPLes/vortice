// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! `CRAM-MD5`, RFC2195: the listener challenges, the peer answers with a keyed digest.
//!
//! Two rounds. The listener goes first with a string it has never used before, the peer
//! answers `username SP hex(HMAC-MD5(password, challenge))`, and the listener computes the
//! same thing and compares. The password never crosses the wire, which is the whole point,
//! and the listener must hold it in recoverable form, which is the whole cost.
//!
//! # Read this before offering it
//!
//! `CRAM-MD5` is here because the reference implementation has it and deployments use it, not
//! because it is a good choice in 2026. RFC6331 withdrew `DIGEST-MD5`; `CRAM-MD5` was never
//! formally deprecated but is no better off:
//!
//! - **The listener must store recoverable passwords.** [`Authenticator::secret`] exists for
//!   this mechanism and `DIGEST-MD5`, and nothing else in this crate asks for one. A database
//!   of password hashes cannot serve `CRAM-MD5`, and that is a feature of the hashes.
//! - **It authenticates the listener to nobody.** The peer learns nothing about who it is
//!   talking to, so it is only as good as the transport underneath.
//! - **MD5.** HMAC-MD5 has no practical break today, but there is no reason to start new
//!   deployments on it.
//!
//! `SCRAM-SHA-256` answers the first two and replaces MD5. Offer this one for the peers that
//! need it, under TLS, and prefer the other.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use subtle::ConstantTimeEq;

use crate::mechanism::{Authenticator, Context, Exchange, Identity, Mechanism, Step};
use std::sync::Arc;

/// `CRAM-MD5` as a mechanism a listener can offer.
#[derive(Debug)]
pub struct CramMd5 {
    authenticator: Arc<dyn Authenticator>,
    /// What the challenge claims to come from.
    host: String,
}

impl CramMd5 {
    /// Challenges on behalf of `host`, which goes in the challenge after the `@`.
    ///
    /// RFC2195 §2 wants the challenge to look like a message identifier, and the host part is
    /// conventionally the listener's own name. Nothing is checked against it — the peer feeds
    /// the whole string through HMAC and hands it back — so it is a label, not a claim.
    #[must_use]
    pub fn new(authenticator: Arc<dyn Authenticator>, host: impl Into<String>) -> Self {
        Self {
            authenticator,
            host: host.into(),
        }
    }
}

impl Mechanism for CramMd5 {
    fn name(&self) -> &'static str {
        "CRAM-MD5"
    }

    fn begin(&self, context: Context) -> Box<dyn Exchange> {
        Box::new(CramMd5Exchange {
            authenticator: Arc::clone(&self.authenticator),
            context,
            host: self.host.clone(),
            challenge: None,
        })
    }
}

/// One conversation: issue a challenge, then check what comes back against it.
struct CramMd5Exchange {
    authenticator: Arc<dyn Authenticator>,
    context: Context,
    host: String,
    /// Set once the challenge has gone out, which is also how the second round is told from
    /// the first.
    challenge: Option<String>,
}

impl Exchange for CramMd5Exchange {
    fn step(&mut self, blob: &[u8]) -> Step {
        match self.challenge.take() {
            None => {
                let challenge = challenge(&self.host);
                self.challenge = Some(challenge.clone());
                Step::Continue(challenge.into_bytes())
            }
            Some(challenge) => self.verify(&challenge, blob),
        }
    }
}

impl CramMd5Exchange {
    /// Checks `response` against the challenge that was issued.
    fn verify(&self, challenge: &str, response: &[u8]) -> Step {
        let Ok(response) = std::str::from_utf8(response) else {
            return Step::denied();
        };

        // RFC2195 §2: the username, a space, and the digest in lowercase hexadecimal. Split
        // at the *last* space, because a username may contain one and the digest may not.
        let Some((user, digest)) = response.trim_end().rsplit_once(' ') else {
            return Step::denied();
        };

        let Some(secret) = self.authenticator.secret(&self.context, user, None) else {
            // No such user. Computing a digest against a dummy secret anyway would make the
            // timing of the two cases alike; not doing so is a deliberate simplification,
            // since a listener for this mechanism has a password database to protect first.
            return Step::denied();
        };

        let expected = hex(&keyed_digest(secret.as_bytes(), challenge.as_bytes()));

        // Constant time, because this compares a value the peer chose against one derived
        // from a secret, and a comparison that stops at the first wrong octet tells the peer
        // how much of its guess was right.
        if expected.as_bytes().ct_eq(digest.as_bytes()).into() {
            Step::Complete(Identity::new(user))
        } else {
            Step::denied()
        }
    }
}

/// HMAC-MD5 of `message` under `key`, RFC2104.
fn keyed_digest(key: &[u8], message: &[u8]) -> [u8; 16] {
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Lowercase hexadecimal, which is the only form RFC2195 allows in a response.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A challenge that has not been used before: `<random.seconds@host>`.
///
/// RFC2195 §2 asks for a string that is unique to this exchange, since the whole security of
/// the mechanism rests on a digest never being replayable. The clock alone is not enough —
/// two connections in the same second would share one — so the random part is what actually
/// does the work and the timestamp is there because the convention expects one.
fn challenge(host: &str) -> String {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).expect("the operating system has randomness");

    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());

    format!("<{}.{seconds}@{host}>", hex(&random))
}

#[cfg(test)]
mod tests {
    use super::{CramMd5, challenge, hex, keyed_digest};
    use crate::mechanism::{Authenticator, Context, Exchange, Identity, Mechanism, Step};
    use std::sync::Arc;

    /// The credentials the LibVortex regression listener accepts.
    #[derive(Debug)]
    struct Suite;

    impl Authenticator for Suite {
        fn secret(
            &self,
            _context: &Context,
            authentication_id: &str,
            _realm: Option<&str>,
        ) -> Option<String> {
            (authentication_id == "bob").then(|| "secret".to_owned())
        }
    }

    /// This mechanism takes nothing from the context; `test_06a`'s virtual host is exercised
    /// where it decides something, in `tests/sasl.rs`.
    fn exchange(mechanism: &CramMd5) -> Box<dyn Exchange> {
        mechanism.begin(Context::default())
    }

    /// The test vectors of RFC2202 §2, which is where HMAC-MD5's are published.
    #[test]
    fn matches_the_rfc2202_vectors() {
        assert_eq!(
            hex(&keyed_digest(&[0x0b; 16], b"Hi There")),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
        assert_eq!(
            hex(&keyed_digest(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
        assert_eq!(
            hex(&keyed_digest(&[0xaa; 16], &[0xdd; 50])),
            "56be34521d144c88dbb8c733f0e8b3f6"
        );
        // A key longer than the block size, which HMAC hashes first.
        assert_eq!(
            hex(&keyed_digest(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
        );
    }

    #[test]
    fn challenges_then_accepts_the_right_answer() {
        let mechanism = CramMd5::new(Arc::new(Suite), "beep.example.net");
        let mut exchange = exchange(&mechanism);

        let Step::Continue(challenge) = exchange.step(b"") else {
            panic!("the listener speaks first");
        };
        let text = String::from_utf8(challenge.clone()).expect("the challenge is text");
        assert!(
            text.starts_with('<') && text.ends_with("@beep.example.net>"),
            "RFC2195 shape: {text}"
        );

        let response = format!("bob {}", hex(&keyed_digest(b"secret", &challenge)));
        assert_eq!(
            exchange.step(response.as_bytes()),
            Step::Complete(Identity::new("bob"))
        );
    }

    #[test]
    fn refuses_a_wrong_password_an_unknown_user_and_a_malformed_response() {
        let mechanism = CramMd5::new(Arc::new(Suite), "beep.example.net");

        for response in [
            // right shape, wrong secret
            None,
            // no space at all
            Some("bobdeadbeef".to_owned()),
            // a user the listener does not know
            Some(format!("alice {}", hex(&keyed_digest(b"secret", b"x")))),
        ] {
            let mut exchange = exchange(&mechanism);
            let Step::Continue(challenge) = exchange.step(b"") else {
                panic!("the listener speaks first");
            };
            let response = response
                .unwrap_or_else(|| format!("bob {}", hex(&keyed_digest(b"wrong", &challenge))));
            assert_eq!(exchange.step(response.as_bytes()), Step::denied());
        }
    }

    /// The challenge is what stops a digest being replayed, so two of them must differ.
    #[test]
    fn never_issues_the_same_challenge_twice() {
        let first = challenge("host");
        let second = challenge("host");
        assert_ne!(first, second);
    }
}
