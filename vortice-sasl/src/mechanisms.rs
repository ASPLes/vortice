// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The mechanisms themselves, one feature each.
//!
//! All three here finish in a single round: the peer's first blob carries everything, and the
//! listener answers `complete` or refuses. The multi-round ones, where the listener speaks
//! first, are the hashing mechanisms.

use std::sync::Arc;

use crate::mechanism::{Authenticator, Exchange, Identity, Mechanism, Step};

/// `ANONYMOUS`, RFC4505: no credential, an optional trace token.
///
/// Worth having for the same reason anonymous FTP was: a service that genuinely serves anyone
/// still benefits from the peer saying who it is, and from the exchange being a SASL exchange
/// like any other rather than an absence of one.
#[cfg(feature = "anonymous")]
#[derive(Debug)]
pub struct Anonymous {
    authenticator: Arc<dyn Authenticator>,
}

#[cfg(feature = "anonymous")]
impl Anonymous {
    /// Admits whoever `authenticator` admits.
    #[must_use]
    pub fn new(authenticator: Arc<dyn Authenticator>) -> Self {
        Self { authenticator }
    }
}

#[cfg(feature = "anonymous")]
impl Mechanism for Anonymous {
    fn name(&self) -> &'static str {
        "ANONYMOUS"
    }

    fn begin(&self) -> Box<dyn Exchange> {
        Box::new(AnonymousExchange {
            authenticator: Arc::clone(&self.authenticator),
        })
    }
}

#[cfg(feature = "anonymous")]
struct AnonymousExchange {
    authenticator: Arc<dyn Authenticator>,
}

#[cfg(feature = "anonymous")]
impl Exchange for AnonymousExchange {
    fn step(&mut self, blob: &[u8]) -> Step {
        // RFC4505 §2: the message is the trace token, UTF-8, and may be absent.
        let Ok(token) = std::str::from_utf8(blob) else {
            return Step::denied();
        };
        if self.authenticator.anonymous(token) {
            Step::Complete(Identity::new(token))
        } else {
            Step::denied()
        }
    }
}

/// `EXTERNAL`, RFC4422 §A: the transport already said who this is.
///
/// The message is an authorization identity or nothing at all; there is no credential,
/// because the point of the mechanism is that one was presented at a lower layer — a client
/// certificate, the peer credentials of a Unix socket. A listener that offers it without
/// consulting that layer is admitting anyone who asks, which is why [`Authenticator::external`]
/// refuses by default.
#[cfg(feature = "external")]
#[derive(Debug)]
pub struct External {
    authenticator: Arc<dyn Authenticator>,
}

#[cfg(feature = "external")]
impl External {
    /// Admits whoever `authenticator` admits.
    #[must_use]
    pub fn new(authenticator: Arc<dyn Authenticator>) -> Self {
        Self { authenticator }
    }
}

#[cfg(feature = "external")]
impl Mechanism for External {
    fn name(&self) -> &'static str {
        "EXTERNAL"
    }

    fn begin(&self) -> Box<dyn Exchange> {
        Box::new(ExternalExchange {
            authenticator: Arc::clone(&self.authenticator),
        })
    }
}

#[cfg(feature = "external")]
struct ExternalExchange {
    authenticator: Arc<dyn Authenticator>,
}

#[cfg(feature = "external")]
impl Exchange for ExternalExchange {
    fn step(&mut self, blob: &[u8]) -> Step {
        let Ok(authorization_id) = std::str::from_utf8(blob) else {
            return Step::denied();
        };
        let asked_for = (!authorization_id.is_empty()).then_some(authorization_id);

        if self.authenticator.external(asked_for) {
            Step::Complete(Identity {
                // There is no authentication identity of its own: the transport's is the
                // only one there is, and the listener knows it by other means.
                authentication_id: authorization_id.to_owned(),
                authorization_id: asked_for.map(ToOwned::to_owned),
            })
        } else {
            Step::denied()
        }
    }
}

/// `PLAIN`, RFC4616: an authorization identity, an authentication identity and a password,
/// separated by NUL octets.
///
/// The password crosses the wire as it was typed, so RFC4616 §1 requires a transport that
/// provides confidentiality. Nothing here can check that — the profile does not know what it
/// is running over — so it is the listener's business to offer `PLAIN` only after tuning, by
/// registering it in the configuration the session takes on afterwards.
#[cfg(feature = "plain")]
#[derive(Debug)]
pub struct Plain {
    authenticator: Arc<dyn Authenticator>,
}

#[cfg(feature = "plain")]
impl Plain {
    /// Admits whoever `authenticator` admits.
    #[must_use]
    pub fn new(authenticator: Arc<dyn Authenticator>) -> Self {
        Self { authenticator }
    }
}

#[cfg(feature = "plain")]
impl Mechanism for Plain {
    fn name(&self) -> &'static str {
        "PLAIN"
    }

    fn begin(&self) -> Box<dyn Exchange> {
        Box::new(PlainExchange {
            authenticator: Arc::clone(&self.authenticator),
        })
    }
}

#[cfg(feature = "plain")]
struct PlainExchange {
    authenticator: Arc<dyn Authenticator>,
}

#[cfg(feature = "plain")]
impl Exchange for PlainExchange {
    fn step(&mut self, blob: &[u8]) -> Step {
        // RFC4616 §2: authzid NUL authcid NUL passwd, and exactly two NULs — a password may
        // not contain one, so a third field is a malformed message rather than a long
        // password.
        let mut fields = blob.split(|octet| *octet == 0);
        let (Some(authorization), Some(authentication), Some(password), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Step::denied();
        };

        let (Ok(authorization), Ok(authentication), Ok(password)) = (
            std::str::from_utf8(authorization),
            std::str::from_utf8(authentication),
            std::str::from_utf8(password),
        ) else {
            return Step::denied();
        };

        let asked_for = (!authorization.is_empty()).then_some(authorization);
        if self
            .authenticator
            .plain(authentication, asked_for, password)
        {
            Step::Complete(Identity {
                authentication_id: authentication.to_owned(),
                authorization_id: asked_for.map(ToOwned::to_owned),
            })
        } else {
            Step::denied()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mechanism::Step;

    /// The credentials the LibVortex regression listener accepts, so that the unit tests and
    /// the interop runs are checking the same thing.
    #[derive(Debug)]
    struct Suite;

    impl Authenticator for Suite {
        fn anonymous(&self, token: &str) -> bool {
            token == "test@aspl.es"
        }

        fn external(&self, authorization_id: Option<&str>) -> bool {
            authorization_id == Some("acinom")
        }

        fn plain(&self, authentication_id: &str, _: Option<&str>, password: &str) -> bool {
            authentication_id == "bob" && password == "secret"
        }
    }

    fn suite() -> Arc<dyn Authenticator> {
        Arc::new(Suite)
    }

    #[cfg(feature = "anonymous")]
    #[test]
    fn anonymous_admits_the_token_it_knows_and_no_other() {
        let mechanism = Anonymous::new(suite());
        assert_eq!(
            mechanism.begin().step(b"test@aspl.es"),
            Step::Complete(Identity::new("test@aspl.es"))
        );
        assert_eq!(mechanism.begin().step(b"test-fail@aspl.es"), Step::denied());
    }

    #[cfg(feature = "external")]
    #[test]
    fn external_admits_the_authorization_identity_it_knows() {
        let mechanism = External::new(suite());
        assert_eq!(
            mechanism.begin().step(b"acinom"),
            Step::Complete(Identity {
                authentication_id: "acinom".to_owned(),
                authorization_id: Some("acinom".to_owned()),
            })
        );
        assert_eq!(mechanism.begin().step(b"acinom1"), Step::denied());
        assert_eq!(mechanism.begin().step(b""), Step::denied());
    }

    #[cfg(feature = "plain")]
    #[test]
    fn plain_reads_the_three_fields_rfc4616_defines() {
        let mechanism = Plain::new(suite());
        assert_eq!(
            mechanism.begin().step(b"\0bob\0secret"),
            Step::Complete(Identity::new("bob"))
        );
        assert_eq!(
            mechanism.begin().step(b"admin\0bob\0secret"),
            Step::Complete(Identity {
                authentication_id: "bob".to_owned(),
                authorization_id: Some("admin".to_owned()),
            })
        );
        assert_eq!(mechanism.begin().step(b"\0bob\0wrong"), Step::denied());
        assert_eq!(mechanism.begin().step(b"\0alice\0secret"), Step::denied());
    }

    /// A password cannot contain a NUL, so anything with more or fewer fields is malformed
    /// rather than a credential to check.
    #[cfg(feature = "plain")]
    #[test]
    fn plain_refuses_a_malformed_message() {
        let mechanism = Plain::new(suite());
        for bad in [
            &b"bob\0secret"[..],
            b"\0bob\0secret\0extra",
            b"",
            b"\0bob\0secret\0",
        ] {
            assert_eq!(mechanism.begin().step(bad), Step::denied(), "{bad:?}");
        }
    }
}
