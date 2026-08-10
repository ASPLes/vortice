// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Tuning a session for TLS, Vortice on both ends.
//!
//! The certificate is generated here rather than shipped, so the test carries no expiry and
//! nothing to rotate.

use std::time::Duration;

use vortice::{Config, Connection, Message, Profile, Responder, Role, Router, Server, code};
use vortice_tls::{PROFILE_URI, TlsProfile};

/// Served both before and after tuning, so each side can be told apart.
const ECHO: &str = "urn:example:echo";

/// Named only in the greeting that follows tuning, which is how the new session is told from
/// the old one.
const AFTER: &str = "urn:example:after-tls";

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .expect("operation timed out")
}

/// A self-signed certificate for `localhost`, and its key, both PEM.
fn certificate() -> (Vec<u8>, Vec<u8>) {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate a certificate");
    (
        issued.cert.pem().into_bytes(),
        issued.signing_key.serialize_pem().into_bytes(),
    )
}

fn echo_handler()
-> impl Fn(Responder, Message) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>>
+ Send
+ Sync
+ 'static {
    |responder: Responder, message: Message| {
        Box::pin(async move {
            let _ = responder.reply(message.msgno, message.payload).await;
        })
    }
}

/// A listener offering TLS, whose greeting only mentions `SECRET` once tuned.
async fn start(certificates: &[u8], key: &[u8]) -> String {
    let tls = vortice_tls::server_config(certificates, key).expect("server configuration");

    // What the session looks like after tuning: the same echo, plus a marker that only the
    // second greeting carries.
    let after = Config::new(Role::Listener)
        .with_profile(ECHO)
        .with_profile(AFTER);

    let router = Router::new()
        .profile(ECHO, echo_handler())
        .profile(PROFILE_URI, TlsProfile::new(tls, after));

    let server = Server::bind_with(
        "127.0.0.1:0",
        Config::new(Role::Listener).with_profile(ECHO),
        router,
    )
    .await
    .expect("bind");
    let address = server.local_addr().expect("local address").to_string();
    tokio::spawn(server.serve());
    address
}

#[tokio::test]
async fn a_session_is_tuned_for_tls_and_carries_on() {
    let (certificates, key) = certificate();
    let address = start(&certificates, &key).await;

    let mut session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect");

    assert!(
        session.peer_greeting().advertises(PROFILE_URI),
        "the listener should offer to tune"
    );
    assert!(
        !session.peer_greeting().advertises(AFTER),
        "and the marker belongs to the greeting that has not been sent yet"
    );

    let greeting = within(vortice_tls::upgrade(
        &mut session,
        Config::new(Role::Initiator),
        vortice_tls::client_config(&certificates).expect("client configuration"),
        "localhost",
    ))
    .await
    .expect("tuning should succeed");

    assert!(
        greeting.advertises(AFTER),
        "the greeting after tuning is a new one, and this is what proves it"
    );

    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open a channel on the tuned session");
    let reply = within(channel.request("over tls")).await.expect("reply");
    assert_eq!(reply.payload(), b"over tls");

    within(session.close()).await.expect("close");
}

/// Fragmentation and `SEQ` pacing across the record layer, which is where a naive transport
/// swap tends to come apart.
#[tokio::test]
async fn a_large_payload_survives_tuning() {
    let (certificates, key) = certificate();
    let address = start(&certificates, &key).await;

    let mut session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect");
    within(vortice_tls::upgrade(
        &mut session,
        Config::new(Role::Initiator),
        vortice_tls::insecure_client_config(),
        "localhost",
    ))
    .await
    .expect("tuning should succeed");

    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open a channel");
    let payload: Vec<u8> = (0..256 * 1024u32)
        .map(|index| (index % 251) as u8)
        .collect();
    let reply = within(channel.request(payload.clone()))
        .await
        .expect("reply");
    assert_eq!(reply.payload(), &payload[..]);
}

/// A client that does not trust the certificate must fail, or [`vortice_tls::client_config`]
/// would be decoration.
#[tokio::test]
async fn an_untrusted_certificate_is_refused() {
    let (certificates, key) = certificate();
    let address = start(&certificates, &key).await;

    // Roots from a different self-signed certificate: correctly formed, and wrong.
    let (other, _) = certificate();

    let mut session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect");

    let error = within(vortice_tls::upgrade(
        &mut session,
        Config::new(Role::Initiator),
        vortice_tls::client_config(&other).expect("client configuration"),
        "localhost",
    ))
    .await
    .expect_err("a certificate signed by nobody we trust must not be accepted");

    assert!(
        matches!(error, vortice_tls::Error::Handshake(_)),
        "expected the handshake to fail, got {error}"
    );
}

#[tokio::test]
async fn a_listener_that_does_not_offer_tls_says_so() {
    let server = Server::bind_with(
        "127.0.0.1:0",
        Config::new(Role::Listener).with_profile(ECHO),
        Router::new().profile(ECHO, echo_handler()),
    )
    .await
    .expect("bind");
    let address = server.local_addr().expect("local address").to_string();
    tokio::spawn(server.serve());

    let mut session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect");

    let error = within(vortice_tls::upgrade(
        &mut session,
        Config::new(Role::Initiator),
        vortice_tls::insecure_client_config(),
        "localhost",
    ))
    .await
    .expect_err("nothing to tune with");
    assert!(
        matches!(error, vortice_tls::Error::NotOffered),
        "got {error}"
    );
}

/// The listener requires `<ready />` on the start, as LibVortex does.
#[tokio::test]
async fn a_start_without_the_piggyback_is_refused() {
    let (certificates, key) = certificate();
    let address = start(&certificates, &key).await;

    let session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect");

    let error = within(session.open_channel(Profile::new(PROFILE_URI)))
        .await
        .expect_err("a bare start on the TLS profile should be refused");

    match error {
        vortice::Error::Refused(reply) => {
            assert_eq!(reply.code, code::TRANSACTION_FAILED);
        }
        other => panic!("expected a refusal, got {other}"),
    }
}
