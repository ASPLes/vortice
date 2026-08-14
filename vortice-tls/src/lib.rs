// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The BEEP TLS profile, RFC3080 §3.1.
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

#![forbid(unsafe_code)]

mod error;
mod implicit;

use std::io;
use std::sync::{Arc, Mutex};

use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use vortice::{
    BoxedTransport, Config, Connection, ErrorReply, Greeting, Handler, HandlerFuture, Message,
    Profile, Responder, Start, code,
};

pub use error::{Error, Result};
pub use implicit::{
    BEEP_ALPN, accept, acceptor, connect, connect_over, looks_like_tls, serve, with_client_alpn,
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
    tls: ClientConfig,
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

    let name = ServerName::try_from(server_name)
        .map_err(|_| Error::Certificate(format!("{server_name:?} is not a valid server name")))?
        .to_owned();
    let connector = TlsConnector::from(Arc::new(tls));

    // The swap reports failures as transport errors, which would reach the caller as a session
    // that merely ended. A refused certificate is a different thing to be told, and the most
    // likely failure here, so it is kept aside and reported as itself.
    let handshake_failure: Arc<Mutex<Option<io::Error>>> = Arc::new(Mutex::new(None));
    let failure = Arc::clone(&handshake_failure);

    let outcome = session
        .upgrade(after, move |io| async move {
            match connector.connect(name, io).await {
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
    acceptor: TlsAcceptor,
    after: Config,
}

impl core::fmt::Debug for TlsProfile {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `TlsAcceptor` has nothing printable and a configuration is not something to spill
        // into a log, so this says what the value is rather than what it holds.
        formatter.debug_struct("TlsProfile").finish_non_exhaustive()
    }
}

impl TlsProfile {
    /// Serves TLS with `tls`, and runs the session that follows with `after`.
    #[must_use]
    pub fn new(tls: ServerConfig, after: Config) -> Self {
        Self {
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            after,
        }
    }
}

impl Handler for TlsProfile {
    fn handle(&self, _responder: Responder, _message: Message) -> HandlerFuture {
        // Nothing is ever sent on this channel: the negotiation is the channel exchange, and
        // by the time a message could arrive the transport has already been replaced.
        Box::pin(core::future::ready(()))
    }

    fn accept(&self, uri: &str, start: &Start) -> std::result::Result<Profile, ErrorReply> {
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
        Ok(Profile::new(uri).with_content(PROCEED))
    }

    fn upgrades_transport(&self) -> bool {
        true
    }

    fn on_open(&self, responder: Responder) -> HandlerFuture {
        let acceptor = self.acceptor.clone();
        let after = self.after.clone();
        Box::pin(async move {
            let outcome = responder
                .upgrade(after, move |io| async move {
                    let stream = acceptor.accept(io).await.map_err(vortice::Error::Io)?;
                    Ok(Box::pin(stream) as BoxedTransport)
                })
                .await;
            if let Err(error) = outcome {
                tracing::debug!(%error, "TLS negotiation failed");
            }
        })
    }
}

/// Builds a server configuration from PEM certificates and a PEM private key.
///
/// # Errors
///
/// Returns [`Error::Certificate`] if either cannot be parsed, or if they do not go together.
pub fn server_config(certificates: &[u8], key: &[u8]) -> Result<ServerConfig> {
    let chain = read_certificates(certificates)?;
    let key = read_key(key)?;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|error| {
            Error::Certificate(format!("certificate and key do not go together: {error}"))
        })
}

/// Builds a client configuration trusting the given PEM certificates and nothing else.
///
/// # Errors
///
/// Returns [`Error::Certificate`] if they cannot be parsed.
pub fn client_config(roots: &[u8]) -> Result<ClientConfig> {
    let mut store = RootCertStore::empty();
    for certificate in read_certificates(roots)? {
        store
            .add(certificate)
            .map_err(|error| Error::Certificate(format!("not a usable root: {error}")))?;
    }
    Ok(ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth())
}

/// Reads a PEM certificate chain.
fn read_certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = io::BufReader::new(pem);
    let chain: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let chain =
        chain.map_err(|error| Error::Certificate(format!("unreadable certificate: {error}")))?;
    if chain.is_empty() {
        return Err(Error::Certificate(
            "no certificate found in the PEM given".to_owned(),
        ));
    }
    Ok(chain)
}

/// Reads a PEM private key in any of the encodings rustls accepts.
fn read_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut reader = io::BufReader::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| Error::Certificate(format!("unreadable private key: {error}")))?
        .ok_or_else(|| Error::Certificate("no private key found in the PEM given".to_owned()))
}

/// A client configuration that accepts any certificate, for tests and for interoperating.
///
/// **This authenticates nothing.** It exists because it is what a great deal of deployed BEEP
/// does — LibVortex verifies no certificate unless asked to, and its regression suite is built
/// on a self-signed one — and because refusing to provide it would only push people to write a
/// worse version. Encryption without authentication still stops passive interception; it does
/// not stop anyone who can sit in the middle. Use [`client_config`] with the roots you expect
/// wherever that matters.
#[must_use]
pub fn insecure_client_config() -> ClientConfig {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(danger::AcceptAnyCertificate))
        .with_no_client_auth();
    config.enable_sni = true;
    config
}

mod danger {
    //! The certificate verifier behind [`super::insecure_client_config`], kept in a module of
    //! its own so that what it does is impossible to import by accident.

    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme};

    /// Accepts every certificate presented, without checking anything at all.
    #[derive(Debug)]
    pub(super) struct AcceptAnyCertificate;

    impl ServerCertVerifier for AcceptAnyCertificate {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &tokio_rustls::rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &tokio_rustls::rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            tokio_rustls::rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
