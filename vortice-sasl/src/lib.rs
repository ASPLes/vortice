// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The BEEP SASL profiles, RFC3080 §4.1, in pure Rust.
//!
//! SASL in BEEP is a family of profiles rather than one: each mechanism is its own profile,
//! `http://iana.org/beep/SASL/PLAIN` and the rest, so what a listener offers is visible in
//! the greeting and a peer chooses by starting the channel it wants. The exchange itself is
//! `<blob>` elements carrying whatever the mechanism has to say, Base64 encoded.
//!
//! ```no_run
//! # use std::sync::Arc;
//! use vortice::{Config, Role, Router, Server};
//! use vortice_sasl::{Authenticator, Context, Plain, SaslProfile, profile_uri};
//!
//! #[derive(Debug)]
//! struct Users;
//!
//! impl Authenticator for Users {
//!     fn plain(
//!         &self,
//!         _context: &Context,
//!         user: &str,
//!         _acting_as: Option<&str>,
//!         password: &str,
//!     ) -> bool {
//!         user == "bob" && password == "secret"
//!     }
//! }
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let users: Arc<dyn Authenticator> = Arc::new(Users);
//! let router = Router::new().profile(
//!     profile_uri("PLAIN"),
//!     SaslProfile::new(Plain::new(Arc::clone(&users))),
//! );
//!
//! let config = Config::new(Role::Listener).with_profile(profile_uri("PLAIN"));
//! let server = Server::bind_with("0.0.0.0:602", config, router).await?;
//! server.serve().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Deciding things
//!
//! Nothing is granted by default. [`Authenticator`] has one method per question a mechanism
//! can ask, each refusing until a listener says otherwise, and the questions differ because
//! the mechanisms do: `PLAIN` hands over a password to be checked, while a mechanism that
//! hashes cannot, and has to ask for the password itself. That asymmetry is in the trait on
//! purpose — it is the difference between a listener that stores password hashes and one
//! that cannot.
//!
//! # What authentication does to a session
//!
//! On success the profile records the identity through
//! [`Responder::authenticate`](vortice::Responder::authenticate), and
//! [`Connection::authenticated`](vortice::Connection::authenticated) reports it from then on.
//! It is deliberately not carried across a transport swap: RFC3080 §3.1 discards what was
//! learnt before tuning, and an identity proved in the clear is exactly that. Authenticate
//! after TLS, which is the order to want anyway.
//!
//! # Mechanisms
//!
//! One feature each, so a deployment links what it offers and nothing else. The default set
//! is the one that needs no recoverable secret in reach of the listener:
//!
//! | Feature | Mechanism | |
//! |---|---|---|
//! | `anonymous` | [`Anonymous`] | RFC4505. No credential; a trace token |
//! | `external` | [`External`] | RFC4422 §A. The transport already said who this is |
//! | `plain` | [`Plain`] | RFC4616. Needs a confidential transport under it |
//!
//! And one that asks more of the listener, so it is not in the default set:
//!
//! | Feature | Mechanism | |
//! |---|---|---|
//! | `cram-md5` | [`CramMd5`] | RFC2195. Two rounds, and the listener must hold recoverable passwords |
//! | `digest-md5` | [`DigestMd5`] | RFC2831, **withdrawn by RFC6331**. Three rounds. For the peers that still speak it |
//!
//! And the one to reach for:
//!
//! | Feature | Mechanism | |
//! |---|---|---|
//! | `scram-sha-256` | [`ScramSha256`] | RFC7677. Salted, iterated, no recoverable password stored, and the listener proves itself too |
//!
//! Pure Rust throughout: GNU SASL is what LibVortex uses and is not a dependency here.

#![forbid(unsafe_code)]

pub mod blob;
#[cfg(feature = "cram-md5")]
mod cram_md5;
#[cfg(feature = "digest-md5")]
mod digest_md5;
mod mechanism;
/// The one-round mechanisms share a module, and it is of no use without one of them.
#[cfg(any(feature = "anonymous", feature = "external", feature = "plain"))]
mod mechanisms;
mod profile;
#[cfg(feature = "scram-sha-256")]
mod scram;

pub use blob::{Blob, Status};
pub use mechanism::{Authenticator, Context, Exchange, Identity, Mechanism, Step};
pub use profile::{PROFILE_FAMILY, SaslProfile, profile_uri};

#[cfg(feature = "anonymous")]
pub use mechanisms::Anonymous;
#[cfg(feature = "external")]
pub use mechanisms::External;
#[cfg(feature = "plain")]
pub use mechanisms::Plain;

#[cfg(feature = "cram-md5")]
pub use cram_md5::CramMd5;
#[cfg(feature = "digest-md5")]
pub use digest_md5::DigestMd5;
#[cfg(feature = "scram-sha-256")]
pub use scram::{ScramCredentials, ScramSha256};
