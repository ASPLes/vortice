// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! `DIGEST-MD5`, RFC2831: challenge and response with a nonce from each end.
//!
//! Three rounds. The listener offers a realm and a nonce, the peer answers with a nonce of
//! its own and a digest over both, and the listener answers that with a digest of its own —
//! which is the one thing this mechanism has over `CRAM-MD5`: the peer learns that the
//! listener also knew the password.
//!
//! # Read this before offering it
//!
//! **RFC6331 withdrew this mechanism**, in 2011, and said to use `SCRAM` instead. It is
//! implemented here for one reason: the deployed peers that still speak it, including the
//! reference implementation's own regression suite. Everything the [`crate::CramMd5`] note
//! says applies, and RFC6331 §3 lists more — the realm handling is under-specified, the
//! quoting rules are a reliable source of interoperability failures, and the whole thing is
//! built on MD5.
//!
//! Offer it to reach the peers that need it. Offer `SCRAM-SHA-256` to everything else.
//!
//! # What is and is not implemented
//!
//! `qop=auth` only: authentication, with no security layer over the transport afterwards.
//! `auth-int` and `auth-conf` would have this crate encrypting the session, which is
//! TLS's job and done better there — and which BEEP already has a profile for. A peer that
//! asks for either is refused rather than quietly downgraded.

use std::collections::HashMap;
use std::sync::Arc;

use hmac::digest::Digest;
use md5::Md5;
use subtle::ConstantTimeEq;

use crate::mechanism::{Authenticator, Context, Exchange, Identity, Mechanism, Step};

/// `DIGEST-MD5` as a mechanism a listener can offer.
#[derive(Debug)]
pub struct DigestMd5 {
    authenticator: Arc<dyn Authenticator>,
    /// The realm offered in the challenge, and part of what the digest is computed over.
    realm: String,
}

impl DigestMd5 {
    /// Challenges for `realm`.
    ///
    /// RFC2831 §2.1 lets a listener offer several; one is offered here, because the realm
    /// takes part in the digest and a listener that cannot say which one it meant cannot
    /// check the answer. A peer that names a different one is refused.
    #[must_use]
    pub fn new(authenticator: Arc<dyn Authenticator>, realm: impl Into<String>) -> Self {
        Self {
            authenticator,
            realm: realm.into(),
        }
    }
}

impl Mechanism for DigestMd5 {
    fn name(&self) -> &'static str {
        "DIGEST-MD5"
    }

    fn begin(&self, context: Context) -> Box<dyn Exchange> {
        Box::new(DigestMd5Exchange {
            authenticator: Arc::clone(&self.authenticator),
            context,
            realm: self.realm.clone(),
            state: Phase::Start,
        })
    }
}

/// Where a conversation has got to.
enum Phase {
    /// Nothing sent yet.
    Start,
    /// The challenge is out; waiting for the response.
    Challenged { nonce: String },
    /// The response checked out and `rspauth` is out; waiting for the peer's empty
    /// acknowledgement, after which the exchange is complete.
    Confirmed { identity: Identity },
}

struct DigestMd5Exchange {
    authenticator: Arc<dyn Authenticator>,
    context: Context,
    realm: String,
    state: Phase,
}

impl Exchange for DigestMd5Exchange {
    fn step(&mut self, blob: &[u8]) -> Step {
        match std::mem::replace(&mut self.state, Phase::Start) {
            Phase::Start => {
                let nonce = nonce();
                let challenge = format!(
                    "realm=\"{}\",nonce=\"{nonce}\",qop=\"auth\",charset=utf-8,algorithm=md5-sess",
                    escape(&self.realm)
                );
                self.state = Phase::Challenged { nonce };
                Step::Continue(challenge.into_bytes())
            }
            Phase::Challenged { nonce } => self.check(&nonce, blob),
            // RFC2831 §2.1.3: the peer answers the `rspauth` with an empty response, and
            // that is the end of it.
            Phase::Confirmed { identity } => {
                if blob.is_empty() {
                    Step::Complete(identity)
                } else {
                    Step::denied()
                }
            }
        }
    }
}

impl DigestMd5Exchange {
    /// Checks the peer's response and, if it holds, answers with `rspauth`.
    fn check(&mut self, nonce: &str, response: &[u8]) -> Step {
        let Ok(text) = std::str::from_utf8(response) else {
            return Step::denied();
        };
        let fields = directives(text);

        let (
            Some(username),
            Some(sent_nonce),
            Some(cnonce),
            Some(nc),
            Some(digest_uri),
            Some(sent),
        ) = (
            fields.get("username"),
            fields.get("nonce"),
            fields.get("cnonce"),
            fields.get("nc"),
            fields.get("digest-uri"),
            fields.get("response"),
        )
        else {
            return Step::denied();
        };

        // The nonce must be the one just issued, and the count must be its first use: this
        // exchange's nonce is never offered twice, so anything else is a replay.
        if sent_nonce != nonce || nc != "00000001" {
            return Step::denied();
        }

        // A security layer is not on offer; a peer asking for one gets a refusal rather than
        // an authentication that silently does less than it asked for.
        let qop = fields.get("qop").map_or("auth", String::as_str);
        if qop != "auth" {
            return Step::denied();
        }

        let realm = fields.get("realm").cloned().unwrap_or_default();
        if realm != self.realm {
            return Step::denied();
        }

        let Some(secret) = self
            .authenticator
            .secret(&self.context, username, Some(&self.realm))
        else {
            return Step::denied();
        };

        let authorization = fields.get("authzid").filter(|id| !id.is_empty()).cloned();
        let secret_hash = session_key(
            username,
            &realm,
            &secret,
            nonce,
            cnonce,
            authorization.as_deref(),
        );

        let expected = response_digest(&secret_hash, nonce, nc, cnonce, qop, digest_uri, true);
        if !bool::from(expected.as_bytes().ct_eq(sent.as_bytes())) {
            return Step::denied();
        }

        // The listener proves it knew the password too, which is what the peer checks.
        let rspauth = response_digest(&secret_hash, nonce, nc, cnonce, qop, digest_uri, false);
        self.state = Phase::Confirmed {
            identity: Identity {
                authentication_id: username.clone(),
                authorization_id: authorization,
            },
        };
        Step::Continue(format!("rspauth={rspauth}").into_bytes())
    }
}

/// `A1` of RFC2831 §2.1.2.1, hashed: the part of the digest that holds the password.
///
/// The first hash is over the raw octets and the rest is appended to those octets, not to
/// their hexadecimal — the one place in this mechanism where the difference matters and the
/// usual place an implementation gets it wrong.
fn session_key(
    username: &str,
    realm: &str,
    secret: &str,
    nonce: &str,
    cnonce: &str,
    authorization: Option<&str>,
) -> String {
    let mut inner = Md5::new();
    inner.update(format!("{username}:{realm}:{secret}").as_bytes());
    let inner = inner.finalize();

    let mut outer = Md5::new();
    outer.update(inner);
    outer.update(format!(":{nonce}:{cnonce}").as_bytes());
    if let Some(authorization) = authorization {
        outer.update(format!(":{authorization}").as_bytes());
    }
    hex(&outer.finalize())
}

/// The `response` or `rspauth` value of RFC2831 §2.1.2.1.
///
/// `from_client` picks which `A2` to use: the peer's includes the `AUTHENTICATE:` prefix and
/// the listener's does not, which is the whole of what stops one being replayed as the other.
fn response_digest(
    session_key: &str,
    nonce: &str,
    nc: &str,
    cnonce: &str,
    qop: &str,
    digest_uri: &str,
    from_client: bool,
) -> String {
    let a2 = if from_client {
        format!("AUTHENTICATE:{digest_uri}")
    } else {
        format!(":{digest_uri}")
    };
    let a2 = hex(&Md5::digest(a2.as_bytes()));

    hex(&Md5::digest(
        format!("{session_key}:{nonce}:{nc}:{cnonce}:{qop}:{a2}").as_bytes(),
    ))
}

/// Splits a challenge or response into its directives.
///
/// RFC2831 §2.1 defines them as comma-separated `name=value`, the value optionally quoted
/// with backslash escapes inside. Commas inside a quoted value are part of it, which is why
/// this cannot be a `split(',')`.
fn directives(text: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let mut rest = text.trim();

    while !rest.is_empty() {
        let Some(equals) = rest.find('=') else { break };
        let name = rest[..equals].trim().to_lowercase();
        let mut value = String::new();
        let mut at = equals + 1;
        let bytes = rest.as_bytes();

        if bytes.get(at) == Some(&b'"') {
            at += 1;
            let mut escaped = false;
            while at < bytes.len() {
                let byte = bytes[at];
                at += 1;
                if escaped {
                    value.push(char::from(byte));
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    break;
                } else {
                    value.push(char::from(byte));
                }
            }
        } else {
            while at < bytes.len() && bytes[at] != b',' {
                value.push(char::from(bytes[at]));
                at += 1;
            }
        }

        fields.insert(name, value.trim().to_owned());

        // Past the separator, if there is one.
        rest = rest[at..].trim_start();
        rest = rest.strip_prefix(',').unwrap_or(rest).trim_start();
    }

    fields
}

/// Quotes what goes inside a quoted directive value.
fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A nonce for one exchange, which is what keeps a digest from being replayable.
fn nonce() -> String {
    let mut random = [0u8; 24];
    getrandom::fill(&mut random).expect("the operating system has randomness");
    vortice_proto::base64::encode(&random)
}

#[cfg(test)]
mod tests {
    use super::{DigestMd5, directives, hex, response_digest, session_key};
    use crate::mechanism::{Authenticator, Context, Exchange, Identity, Mechanism, Step};
    use md5::{Digest, Md5};
    use std::sync::Arc;

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
    fn exchange(mechanism: &DigestMd5) -> Box<dyn Exchange> {
        mechanism.begin(Context::default())
    }

    /// The worked example of RFC2831 §4, which is the only published vector for this.
    #[test]
    fn matches_the_rfc2831_example() {
        let key = session_key(
            "chris",
            "elwood.innosoft.com",
            "secret",
            "OA6MG9tEQGm2hh",
            "OA6MHXh6VqTrRk",
            None,
        );
        let response = response_digest(
            &key,
            "OA6MG9tEQGm2hh",
            "00000001",
            "OA6MHXh6VqTrRk",
            "auth",
            "imap/elwood.innosoft.com",
            true,
        );
        assert_eq!(response, "d388dad90d4bbd760a152321f2143af7");

        let rspauth = response_digest(
            &key,
            "OA6MG9tEQGm2hh",
            "00000001",
            "OA6MHXh6VqTrRk",
            "auth",
            "imap/elwood.innosoft.com",
            false,
        );
        assert_eq!(rspauth, "ea40f60335c427b5527b84dbabcdfffd");
    }

    #[test]
    fn reads_the_directives_a_peer_sends() {
        let fields = directives(
            "username=\"bob\",realm=\"example\",nonce=\"abc,def\",nc=00000001,qop=auth,\
             digest-uri=\"beep/host\",response=deadbeef,charset=utf-8",
        );
        assert_eq!(fields["username"], "bob");
        assert_eq!(
            fields["nonce"], "abc,def",
            "a comma inside quotes is content"
        );
        assert_eq!(fields["nc"], "00000001");
        assert_eq!(fields["qop"], "auth");
        assert_eq!(fields["charset"], "utf-8");
    }

    #[test]
    fn reads_a_quoted_value_with_escapes() {
        let fields = directives(r#"realm="a \"quoted\" \\ realm",nc=1"#);
        assert_eq!(fields["realm"], r#"a "quoted" \ realm"#);
        assert_eq!(fields["nc"], "1");
    }

    /// The whole exchange, playing the peer's part with the same arithmetic RFC2831 defines.
    #[test]
    fn three_rounds_and_the_listener_proves_itself_too() {
        let mechanism = DigestMd5::new(Arc::new(Suite), "beep.example.net");
        let mut exchange = exchange(&mechanism);

        let Step::Continue(challenge) = exchange.step(b"") else {
            panic!("the listener speaks first");
        };
        let offered = directives(&String::from_utf8(challenge).expect("text"));
        assert_eq!(offered["realm"], "beep.example.net");
        assert_eq!(offered["qop"], "auth");
        assert_eq!(offered["algorithm"], "md5-sess");

        let nonce = &offered["nonce"];
        let cnonce = "cnonce-of-the-peer";
        let uri = "beep/beep.example.net";
        let key = session_key("bob", "beep.example.net", "secret", nonce, cnonce, None);
        let response = response_digest(&key, nonce, "00000001", cnonce, "auth", uri, true);

        let sent = format!(
            "username=\"bob\",realm=\"beep.example.net\",nonce=\"{nonce}\",cnonce=\"{cnonce}\",\
             nc=00000001,qop=auth,digest-uri=\"{uri}\",response={response},charset=utf-8"
        );

        let Step::Continue(confirmation) = exchange.step(sent.as_bytes()) else {
            panic!("the listener should answer with rspauth");
        };
        let confirmation = String::from_utf8(confirmation).expect("text");
        let expected = response_digest(&key, nonce, "00000001", cnonce, "auth", uri, false);
        assert_eq!(confirmation, format!("rspauth={expected}"));

        assert_eq!(exchange.step(b""), Step::Complete(Identity::new("bob")));
    }

    #[test]
    fn refuses_a_replayed_count_a_foreign_nonce_and_a_security_layer() {
        let mechanism = DigestMd5::new(Arc::new(Suite), "beep.example.net");

        for change in ["nc", "nonce", "qop", "realm", "response"] {
            let mut exchange = exchange(&mechanism);
            let Step::Continue(challenge) = exchange.step(b"") else {
                panic!("the listener speaks first");
            };
            let offered = directives(&String::from_utf8(challenge).expect("text"));
            let nonce = &offered["nonce"];
            let cnonce = "cnonce";
            let uri = "beep/host";
            let key = session_key("bob", "beep.example.net", "secret", nonce, cnonce, None);
            let response = response_digest(&key, nonce, "00000001", cnonce, "auth", uri, true);

            let sent = format!(
                "username=\"bob\",realm=\"{}\",nonce=\"{}\",cnonce=\"{cnonce}\",nc={},qop={},\
                 digest-uri=\"{uri}\",response={}",
                if change == "realm" {
                    "elsewhere"
                } else {
                    "beep.example.net"
                },
                if change == "nonce" {
                    "someone-elses-nonce"
                } else {
                    nonce
                },
                if change == "nc" {
                    "00000002"
                } else {
                    "00000001"
                },
                if change == "qop" { "auth-conf" } else { "auth" },
                if change == "response" {
                    "00000000000000000000000000000000"
                } else {
                    &response
                },
            );
            assert_eq!(exchange.step(sent.as_bytes()), Step::denied(), "{change}");
        }
    }

    /// MD5 itself, so a failure in the vectors above can be told from a failure in the glue.
    #[test]
    fn md5_matches_rfc1321() {
        assert_eq!(hex(&Md5::digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            hex(&Md5::digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }
}
