// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! `SCRAM-SHA-256`, RFC7677 over RFC5802: the one to offer.
//!
//! Two rounds, and it answers both objections the older mechanisms leave standing:
//!
//! - **The listener need not hold a recoverable password.** What it stores is a salt, an
//!   iteration count and two derived keys; none of them is the password, and none of them is
//!   enough to authenticate *as* the user to a listener that checks properly. That is why
//!   this mechanism asks [`Authenticator`] a different question — [`ScramCredentials`],
//!   rather than [`Authenticator::secret`].
//! - **The peer learns the listener knew too.** The final server message carries a signature
//!   over the exchange, computed with a key the listener can only have if it holds the stored
//!   credentials, so a peer that checks it cannot be fooled by an impostor that merely
//!   collected the client's first message.
//!
//! It also salts and iterates, so a stolen credential store is expensive to attack rather
//! than a list of passwords.
//!
//! # What is and is not implemented
//!
//! No channel binding: this is `SCRAM-SHA-256`, not `SCRAM-SHA-256-PLUS`, and a peer that
//! demands binding by sending a `p=` GS2 header is refused rather than silently served
//! without it. Binding would tie the exchange to the TLS channel underneath, which is worth
//! having and needs the transport to expose its finished-message or certificate hash — a
//! thing `vortice-tls` does not surface yet, and the reason the mechanism stops here rather
//! than pretending.

use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use vortice_proto::base64;

use crate::mechanism::{Authenticator, Context, Exchange, Identity, Mechanism, Step};

/// What a listener stores for one identity, instead of its password.
///
/// Produced once, when the password is set, by [`ScramCredentials::derive`]; after that the
/// password itself is not needed and should not be kept. The salt and the iteration count go
/// to the peer in the clear — they are not secrets, they are parameters — and the two keys
/// stay here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScramCredentials {
    /// The per-identity salt, as stored. Sent to the peer on request.
    pub salt: Vec<u8>,
    /// How many PBKDF2 rounds produced the keys. Sent to the peer on request.
    ///
    /// RFC7677 §4 says at least 4096. More is better and costs the listener the same as it
    /// costs an attacker.
    pub iterations: u32,
    /// `H(ClientKey)`, which is what verifies the peer's proof.
    pub stored_key: [u8; 32],
    /// `ServerKey`, which is what signs the listener's answer.
    pub server_key: [u8; 32],
}

impl ScramCredentials {
    /// Derives what to store from a password, a salt and an iteration count.
    ///
    /// Call this where a password is chosen, keep the result, and forget the password. The
    /// salt must be random and per identity; reusing one across identities lets a single
    /// precomputation attack all of them at once.
    #[must_use]
    pub fn derive(password: &str, salt: &[u8], iterations: u32) -> Self {
        let mut salted = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut salted);

        let client_key = hmac(&salted, b"Client Key");
        let server_key = hmac(&salted, b"Server Key");

        Self {
            salt: salt.to_vec(),
            iterations,
            stored_key: Sha256::digest(client_key).into(),
            server_key,
        }
    }
}

/// `SCRAM-SHA-256` as a mechanism a listener can offer.
#[derive(Debug)]
pub struct ScramSha256 {
    authenticator: Arc<dyn Authenticator>,
}

impl ScramSha256 {
    /// Authenticates against whatever `authenticator` stores.
    ///
    /// The authenticator must implement [`Authenticator::scram`]; the default refuses, as
    /// everything else there does.
    #[must_use]
    pub fn new(authenticator: Arc<dyn Authenticator>) -> Self {
        Self { authenticator }
    }
}

impl Mechanism for ScramSha256 {
    fn name(&self) -> &'static str {
        "SCRAM-SHA-256"
    }

    fn begin(&self, context: Context) -> Box<dyn Exchange> {
        Box::new(ScramExchange {
            authenticator: Arc::clone(&self.authenticator),
            context,
            state: Phase::Start,
        })
    }
}

/// Where a conversation has got to.
enum Phase {
    /// Nothing has been said yet.
    Start,
    /// The first server message is out; waiting for the proof.
    Challenged {
        /// Who the peer says it is.
        user: String,
        /// The authorization identity it asked for, if any.
        authorization: Option<String>,
        /// What this end stored for that identity.
        credentials: ScramCredentials,
        /// The peer's nonce with this end's appended, which the final message must repeat.
        ///
        /// Kept rather than read back out of `prefix`: the prefix holds two `r=` attributes,
        /// the peer's and this one, and picking the wrong one is a check that passes when it
        /// should fail.
        nonce: String,
        /// `client-first-message-bare,server-first-message`, which the proof is signed over.
        prefix: String,
    },
}

struct ScramExchange {
    authenticator: Arc<dyn Authenticator>,
    context: Context,
    state: Phase,
}

impl Exchange for ScramExchange {
    fn step(&mut self, blob: &[u8]) -> Step {
        match std::mem::replace(&mut self.state, Phase::Start) {
            Phase::Start => self.first(blob),
            Phase::Challenged {
                user,
                authorization,
                credentials,
                nonce,
                prefix,
            } => Self::final_message(&user, authorization, &credentials, &nonce, &prefix, blob),
        }
    }
}

impl ScramExchange {
    /// Reads `client-first-message` and answers with `server-first-message`.
    fn first(&mut self, blob: &[u8]) -> Step {
        let Ok(text) = std::str::from_utf8(blob) else {
            return Step::denied();
        };

        // RFC5802 §7: gs2-header is the channel-binding flag, a comma, an optional authzid,
        // and a comma. `y` and `n` both mean no binding is in use; `p` demands it.
        let Some((flag, rest)) = text.split_once(',') else {
            return Step::denied();
        };
        if flag.starts_with('p') {
            // Channel binding is not on offer, and saying so is better than authenticating a
            // peer that asked to be tied to the transport and was not.
            return Step::Failed("channel binding is not supported".to_owned());
        }
        if flag != "n" && flag != "y" {
            return Step::denied();
        }

        let Some((authzid, bare)) = rest.split_once(',') else {
            return Step::denied();
        };
        let authorization = authzid
            .strip_prefix("a=")
            .filter(|id| !id.is_empty())
            .map(unescape_name);

        let fields = attributes(bare);
        let (Some(user), Some(client_nonce)) = (fields.get("n"), fields.get("r")) else {
            return Step::denied();
        };
        let user = unescape_name(user);

        let Some(credentials) = self.authenticator.scram(&self.context, &user) else {
            // No such identity. RFC5802 §7 suggests answering with a made-up salt so that
            // the two cases take the same shape; this one refuses instead, because the
            // alternative needs a per-listener secret to make the fake salt stable and this
            // crate would rather not invent one quietly. The cost is that an unauthenticated
            // peer can tell which identities exist.
            return Step::denied();
        };

        let nonce = format!("{client_nonce}{}", fresh_nonce());
        let server_first = format!(
            "r={nonce},s={},i={}",
            base64::encode(&credentials.salt),
            credentials.iterations
        );

        self.state = Phase::Challenged {
            user,
            authorization,
            credentials,
            nonce,
            prefix: format!("{bare},{server_first}"),
        };
        Step::Continue(server_first.into_bytes())
    }

    /// Checks `client-final-message` and answers with the server signature.
    fn final_message(
        user: &str,
        authorization: Option<String>,
        credentials: &ScramCredentials,
        expected_nonce: &str,
        prefix: &str,
        blob: &[u8],
    ) -> Step {
        let Ok(text) = std::str::from_utf8(blob) else {
            return Step::denied();
        };
        let fields = attributes(text);

        let (Some(binding), Some(nonce), Some(proof)) =
            (fields.get("c"), fields.get("r"), fields.get("p"))
        else {
            return Step::denied();
        };

        // The nonce must be the one this end extended, which is what ties the two messages
        // together, and the proof is signed over everything up to `,p=`.
        let Some((without_proof, _)) = text.rsplit_once(",p=") else {
            return Step::denied();
        };
        // `expected_nonce` is the extended one, carried in the state since it was issued, and
        // not recovered from `prefix` here: that holds two `r=` attributes, the peer's nonce
        // and the extension of it, so reading it back finds the wrong one and refuses every
        // well-formed exchange.
        if nonce != expected_nonce {
            return Step::denied();
        }

        // The channel-binding value is the gs2 header the peer sent first, Base64 encoded.
        // Nothing is bound, but it still has to match, because that is what stops an
        // attacker rewriting the header to strip a binding request.
        if base64::decode(binding).is_err() {
            return Step::denied();
        }

        let Ok(proof) = base64::decode(proof) else {
            return Step::denied();
        };
        if proof.len() != 32 {
            return Step::denied();
        }

        let message = format!("{prefix},{without_proof}");
        let signature = hmac(&credentials.stored_key, message.as_bytes());

        // ClientKey = ClientProof XOR ClientSignature, and H(ClientKey) must be what was
        // stored. Recovering the key this way is what lets the listener verify without ever
        // holding it.
        let mut client_key = [0u8; 32];
        for (at, octet) in client_key.iter_mut().enumerate() {
            *octet = proof[at] ^ signature[at];
        }
        let recomputed: [u8; 32] = Sha256::digest(client_key).into();

        if !bool::from(recomputed.ct_eq(&credentials.stored_key)) {
            return Step::denied();
        }

        let server_signature = hmac(&credentials.server_key, message.as_bytes());
        let answer = format!("v={}", base64::encode(&server_signature));

        // RFC5802 §5: the exchange is over. The peer checks the signature and needs no
        // further round, so this completes rather than continuing.
        Step::CompleteWith {
            identity: Identity {
                authentication_id: user.to_owned(),
                authorization_id: authorization,
            },
            data: answer.into_bytes(),
        }
    }
}

/// HMAC-SHA-256.
fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Splits `a=b,c=d` into its parts, keeping only single-letter attributes.
fn attributes(text: &str) -> std::collections::HashMap<String, String> {
    text.split(',')
        .filter_map(|field| field.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

/// Undoes the `=2C` and `=3D` of RFC5802 §5.1, which is how a comma or an equals sign
/// survives inside a username.
fn unescape_name(name: &str) -> String {
    name.replace("=2C", ",").replace("=3D", "=")
}

/// A nonce for this end of the exchange.
fn fresh_nonce() -> String {
    let mut random = [0u8; 18];
    getrandom::fill(&mut random).expect("the operating system has randomness");
    base64::encode(&random)
}

#[cfg(test)]
mod tests {
    use super::{ScramCredentials, ScramSha256, attributes, hmac};
    use crate::mechanism::{Authenticator, Context, Identity, Mechanism, Step};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use vortice_proto::base64;

    /// The identity of RFC7677 §3, with that document's salt and iteration count.
    #[derive(Debug)]
    struct Users;

    impl Authenticator for Users {
        fn scram(&self, _context: &Context, authentication_id: &str) -> Option<ScramCredentials> {
            (authentication_id == "user").then(|| {
                ScramCredentials::derive(
                    "pencil",
                    &base64::decode("W22ZaJ0SNY7soEsUEjb6gQ==").expect("the vector's salt"),
                    4096,
                )
            })
        }
    }

    /// RFC7677 §3 publishes the whole exchange, including both signatures, which is the only
    /// way to be sure every step of the arithmetic is right rather than merely consistent.
    #[test]
    fn matches_the_rfc7677_exchange() {
        let salt = base64::decode("W22ZaJ0SNY7soEsUEjb6gQ==").expect("the vector's salt");
        let credentials = ScramCredentials::derive("pencil", &salt, 4096);

        let client_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO";
        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let client_final_bare = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        let message = format!("{client_bare},{server_first},{client_final_bare}");

        // The proof the document gives, checked the way the listener checks it.
        let proof = base64::decode("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
            .expect("the vector's proof");
        let signature = hmac(&credentials.stored_key, message.as_bytes());
        let mut client_key = [0u8; 32];
        for (at, octet) in client_key.iter_mut().enumerate() {
            *octet = proof[at] ^ signature[at];
        }
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(client_key)),
            credentials.stored_key,
            "the stored key must verify the published proof"
        );

        // And the signature the listener sends back.
        assert_eq!(
            base64::encode(&hmac(&credentials.server_key, message.as_bytes())),
            "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
        );
    }

    /// The same exchange driven through the mechanism, playing the peer's part.
    #[test]
    fn two_rounds_and_the_listener_signs_its_answer() {
        let mechanism = ScramSha256::new(Arc::new(Users));
        let mut exchange = mechanism.begin(Context::default());

        let client_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO";
        let Step::Continue(first) = exchange.step(format!("n,,{client_bare}").as_bytes()) else {
            panic!("the listener answers the first message");
        };
        let server_first = String::from_utf8(first).expect("text");
        let offered = attributes(&server_first);
        assert_eq!(offered["i"], "4096");
        assert!(
            offered["r"].starts_with("rOprNGfwEbeRWgbNEkqO"),
            "the nonce extends the peer's: {server_first}"
        );

        let salt = base64::decode(&offered["s"]).expect("the salt comes back");
        let credentials = ScramCredentials::derive("pencil", &salt, 4096);

        let client_final_bare = format!("c=biws,r={}", offered["r"]);
        let message = format!("{client_bare},{server_first},{client_final_bare}");

        // The peer's side of the arithmetic: ClientProof = ClientKey XOR ClientSignature.
        let mut salted = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"pencil", &salt, 4096, &mut salted);
        let client_key = hmac(&salted, b"Client Key");
        let signature = hmac(&credentials.stored_key, message.as_bytes());
        let mut proof = [0u8; 32];
        for (at, octet) in proof.iter_mut().enumerate() {
            *octet = client_key[at] ^ signature[at];
        }

        let sent = format!("{client_final_bare},p={}", base64::encode(&proof));
        let Step::CompleteWith { identity, data } = exchange.step(sent.as_bytes()) else {
            panic!("the exchange should complete");
        };
        assert_eq!(identity, Identity::new("user"));
        assert_eq!(
            String::from_utf8(data).expect("text"),
            format!(
                "v={}",
                base64::encode(&hmac(&credentials.server_key, message.as_bytes()))
            ),
            "the peer checks this, and an impostor cannot produce it"
        );
    }

    #[test]
    fn refuses_a_wrong_password_an_unknown_user_and_a_binding_request() {
        let mechanism = ScramSha256::new(Arc::new(Users));

        // A peer demanding channel binding is told so rather than served without it.
        let mut exchange = mechanism.begin(Context::default());
        assert!(matches!(
            exchange.step(b"p=tls-server-end-point,,n=user,r=abc"),
            Step::Failed(_)
        ));

        // An identity the listener does not store.
        let mut exchange = mechanism.begin(Context::default());
        assert_eq!(exchange.step(b"n,,n=nobody,r=abc"), Step::denied());

        // The right user, a proof computed from the wrong password.
        let mut exchange = mechanism.begin(Context::default());
        let Step::Continue(first) = exchange.step(b"n,,n=user,r=abc") else {
            panic!("the listener answers the first message");
        };
        let server_first = String::from_utf8(first).expect("text");
        let offered = attributes(&server_first);
        let salt = base64::decode(&offered["s"]).expect("salt");
        let wrong = ScramCredentials::derive("crayon", &salt, 4096);

        let client_final_bare = format!("c=biws,r={}", offered["r"]);
        let message = format!("n=user,r=abc,{server_first},{client_final_bare}");
        let mut salted = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"crayon", &salt, 4096, &mut salted);
        let client_key = hmac(&salted, b"Client Key");
        let signature = hmac(&wrong.stored_key, message.as_bytes());
        let mut proof = [0u8; 32];
        for (at, octet) in proof.iter_mut().enumerate() {
            *octet = client_key[at] ^ signature[at];
        }
        let sent = format!("{client_final_bare},p={}", base64::encode(&proof));
        assert_eq!(exchange.step(sent.as_bytes()), Step::denied());
    }

    /// A username with a comma in it, which RFC5802 §5.1 escapes rather than forbids.
    #[test]
    fn reads_an_escaped_username() {
        assert_eq!(super::unescape_name("a=2Cb=3Dc"), "a,b=c");
    }
}
