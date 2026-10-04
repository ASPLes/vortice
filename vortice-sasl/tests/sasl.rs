// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The profiles on a real listener, driven from a real session.
//!
//! There is no client-side helper yet, which suits this test: it opens the channel by hand
//! with the blob piggybacked, exactly as the wire says to, so what is checked is the wire and
//! not a pair of helpers agreeing with each other.

use std::sync::Arc;
use std::time::Duration;

use vortice::{Config, Connection, Message, Profile, Responder, Role, Router, Server};
use vortice_sasl::{
    Anonymous, Authenticator, Blob, External, Plain, SaslProfile, Status, profile_uri,
};

/// Answers with whoever the session authenticated as, which is the only way to see from the
/// wire that the identity was recorded.
const WHOAMI: &str = "urn:example:whoami";

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .expect("operation timed out")
}

/// The credentials the LibVortex regression listener accepts, so the Rust tests and the
/// interop runs check the same thing.
#[derive(Debug)]
struct Suite;

impl Authenticator for Suite {
    fn anonymous(&self, token: &str) -> bool {
        token == "test@aspl.es"
    }

    fn external(&self, authorization_id: Option<&str>) -> bool {
        authorization_id == Some("acinom")
    }

    fn plain(&self, authentication_id: &str, _acting_as: Option<&str>, password: &str) -> bool {
        authentication_id == "bob" && password == "secret"
    }
}

/// A listener offering the three mechanisms and a way to ask who you are.
async fn start() -> String {
    let users: Arc<dyn Authenticator> = Arc::new(Suite);

    let whoami = |responder: Responder, message: Message| {
        Box::pin(async move {
            let identity = responder.authenticated().await.ok().flatten();
            let _ = responder
                .reply(message.msgno, identity.unwrap_or_default())
                .await;
        }) as std::pin::Pin<Box<dyn Future<Output = ()> + Send>>
    };

    let router = Router::new()
        .profile(WHOAMI, whoami)
        .profile(
            profile_uri("ANONYMOUS"),
            SaslProfile::new(Anonymous::new(Arc::clone(&users))),
        )
        .profile(
            profile_uri("EXTERNAL"),
            SaslProfile::new(External::new(Arc::clone(&users))),
        )
        .profile(
            profile_uri("PLAIN"),
            SaslProfile::new(Plain::new(Arc::clone(&users))),
        );

    let config = Config::new(Role::Listener)
        .with_profile(WHOAMI)
        .with_profile(profile_uri("ANONYMOUS"))
        .with_profile(profile_uri("EXTERNAL"))
        .with_profile(profile_uri("PLAIN"));

    let server = Server::bind_with("127.0.0.1:0", config, router)
        .await
        .expect("bind");
    let address = server.local_addr().expect("local address").to_string();
    tokio::spawn(server.serve());
    address
}

/// Starts the SASL channel for `mechanism`, piggybacking `initial`, and reports the content
/// of the reply — or the refusal.
async fn authenticate(
    session: &Connection,
    mechanism: &str,
    initial: &[u8],
) -> Result<String, vortice::Error> {
    let blob = Blob::new(initial.to_vec()).to_xml();
    let channel = session
        .open_channel(Profile::new(profile_uri(mechanism)).with_content(blob))
        .await?;
    Ok(channel.profile().content.clone().unwrap_or_default())
}

/// Who the listener says we are.
async fn whoami(session: &Connection) -> String {
    let channel = within(session.open_channel(Profile::new(WHOAMI)))
        .await
        .expect("open the whoami channel");
    let reply = within(channel.request("")).await.expect("reply");
    String::from_utf8_lossy(reply.payload()).into_owned()
}

#[tokio::test]
async fn plain_authenticates_and_the_session_remembers() {
    let address = start().await;
    let session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect");

    assert_eq!(
        whoami(&session).await,
        "",
        "nothing is authenticated before the exchange"
    );

    let reply = within(authenticate(&session, "PLAIN", b"\0bob\0secret"))
        .await
        .expect("the listener should accept the channel");
    assert_eq!(reply, Blob::status(Status::Complete).to_xml());

    assert_eq!(whoami(&session).await, "bob");
    within(session.close()).await.expect("close");
}

/// A refusal declines the channel, which is what RFC3080 §4.1 says and what LibVortex's
/// client looks for.
#[tokio::test]
async fn a_wrong_password_is_refused_on_the_channel() {
    let address = start().await;
    let session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect");

    let outcome = within(authenticate(&session, "PLAIN", b"\0bob\0wrong")).await;
    assert!(
        matches!(outcome, Err(vortice::Error::Refused { .. })),
        "expected the channel to be refused, got {outcome:?}"
    );

    assert_eq!(
        whoami(&session).await,
        "",
        "a failed exchange leaves the session as it was"
    );
    within(session.close()).await.expect("close");
}

#[tokio::test]
async fn anonymous_admits_the_token_the_listener_knows() {
    let address = start().await;
    let session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect");

    within(authenticate(&session, "ANONYMOUS", b"test@aspl.es"))
        .await
        .expect("the listener should accept the channel");
    assert_eq!(whoami(&session).await, "test@aspl.es");

    within(session.close()).await.expect("close");
}

#[tokio::test]
async fn external_reports_the_authorization_identity() {
    let address = start().await;
    let session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect");

    within(authenticate(&session, "EXTERNAL", b"acinom"))
        .await
        .expect("the listener should accept the channel");
    assert_eq!(whoami(&session).await, "acinom");

    within(session.close()).await.expect("close");
}

/// The piggyback is the peer's first move and has to be a blob; anything else is refused
/// rather than guessed at.
#[tokio::test]
async fn content_that_is_not_a_blob_is_refused() {
    let address = start().await;
    let session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect");

    let outcome = within(
        session.open_channel(Profile::new(profile_uri("PLAIN")).with_content("<nonsense />")),
    )
    .await;
    assert!(
        matches!(outcome, Err(vortice::Error::Refused { .. })),
        "expected the channel to be refused, got {outcome:?}"
    );

    within(session.close()).await.expect("close");
}
