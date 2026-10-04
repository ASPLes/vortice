// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The same profile over the `native-tls` backend, and over one of each.
//!
//! `tls.rs` already proves the negotiation and the swap work; what is in question here is
//! whether they are really independent of the library underneath. Two tests answer that, and
//! the ones that matter are the crossed pair: a rustls client tuning a `native-tls` listener
//! and the reverse. If the profile had quietly grown a dependency on one library's behaviour —
//! when the handshake starts, how a half-closed stream is reported — those are what would show
//! it, because the two libraries differ in all of that and agree only on the wire.
//!
//! Needs the `native-tls` feature, and so runs under `--all-features` and not by default.

#![cfg(feature = "native-tls")]

use std::time::Duration;

use vortice::{Config, Connection, Message, Profile, Responder, Role, Router, Server};
use vortice_tls::{PROFILE_URI, TlsProfile};

/// Served before and after tuning.
const ECHO: &str = "urn:example:echo";

/// Offered only by the greeting that follows the swap, which is how the new session is told
/// from the old one.
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

/// A listener whose TLS profile terminates with `acceptor`.
async fn start(profile: TlsProfile) -> String {
    let router = Router::new()
        .profile(ECHO, echo_handler())
        .profile(PROFILE_URI, profile);

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

/// What the session offers once the transport is encrypted.
fn after() -> Config {
    Config::new(Role::Listener)
        .with_profile(ECHO)
        .with_profile(AFTER)
}

/// Tunes, checks the greeting is a new one, and echoes something across the record layer.
async fn tune_and_echo(address: &str, connector: impl vortice_tls::backend::Connector) {
    let mut session = within(Connection::connect(address, Config::new(Role::Initiator)))
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
        connector,
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

    // Enough to cross the record layer several times over and to need `SEQ` pacing, which is
    // where a transport swap that only half works tends to come apart.
    let payload = vec![b'n'; 128 * 1024];
    let reply = within(channel.request(payload.clone()))
        .await
        .expect("reply");
    assert_eq!(reply.payload().len(), payload.len());
    assert_eq!(reply.payload(), &payload[..]);

    within(session.close()).await.expect("close");
}

#[tokio::test]
async fn a_session_is_tuned_with_native_tls_on_both_ends() {
    let (certificates, key) = certificate();
    let acceptor = vortice_tls::native::acceptor(&certificates, &key).expect("native acceptor");
    let address = start(TlsProfile::with_acceptor(acceptor).after_tuning(after())).await;

    let connector = vortice_tls::native::connector(&certificates).expect("native connector");
    tune_and_echo(&address, connector).await;
}

/// The point of the exercise: one library at each end, agreeing on the wire.
#[tokio::test]
async fn a_rustls_client_tunes_a_native_tls_listener() {
    let (certificates, key) = certificate();
    let acceptor = vortice_tls::native::acceptor(&certificates, &key).expect("native acceptor");
    let address = start(TlsProfile::with_acceptor(acceptor).after_tuning(after())).await;

    let connector = vortice_tls::client_config(&certificates).expect("rustls client config");
    tune_and_echo(&address, connector).await;
}

#[tokio::test]
async fn a_native_tls_client_tunes_a_rustls_listener() {
    let (certificates, key) = certificate();
    let tls = vortice_tls::server_config(&certificates, &key).expect("rustls server config");
    let address = start(TlsProfile::new(tls, after())).await;

    let connector = vortice_tls::native::connector(&certificates).expect("native connector");
    tune_and_echo(&address, connector).await;
}

/// Implicit TLS — BEEP inside TLS from the first octet, no negotiation — over the same
/// backend, since `connect_over` and `serve` take the backend traits as well.
#[tokio::test]
async fn implicit_tls_runs_over_the_native_backend() {
    let (certificates, key) = certificate();
    let acceptor = vortice_tls::native::acceptor(&certificates, &key).expect("native acceptor");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("local address").to_string();

    tokio::spawn(async move {
        let router = Router::new().profile(ECHO, echo_handler());
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let router = router.clone();
            tokio::spawn(async move {
                let _ = vortice_tls::serve(
                    stream,
                    &acceptor,
                    Config::new(Role::Listener).with_profile(ECHO),
                    router,
                )
                .await;
            });
        }
    });

    let connector = vortice_tls::native::connector(&certificates).expect("native connector");
    let session = within(vortice_tls::connect(
        address.as_str(),
        "localhost",
        connector,
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect inside TLS");

    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open a channel");
    let reply = within(channel.request("inside tls")).await.expect("reply");
    assert_eq!(reply.payload(), b"inside tls");

    within(session.close()).await.expect("close");
}
