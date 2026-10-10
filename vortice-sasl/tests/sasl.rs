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
    Anonymous, Authenticator, Blob, Context, External, Plain, SaslProfile, Status, profile_uri,
};

/// Answers with whoever the session authenticated as, which is the only way to see from the
/// wire that the identity was recorded.
const WHOAMI: &str = "urn:example:whoami";

/// The virtual host that has a different user than the default one.
const VIRTUAL_HOST: &str = "test_06a.server";

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
    fn anonymous(&self, _context: &Context, token: &str) -> bool {
        token == "test@aspl.es"
    }

    fn external(&self, _context: &Context, authorization_id: Option<&str>) -> bool {
        authorization_id == Some("acinom")
    }

    fn plain(
        &self,
        context: &Context,
        authentication_id: &str,
        _acting_as: Option<&str>,
        password: &str,
    ) -> bool {
        // One listener, two sets of users, chosen by the virtual host the session named.
        // This is `test_06a`'s shape, and the reason the context reaches here at all.
        if context.server_name.as_deref() == Some(VIRTUAL_HOST) {
            return authentication_id == "12345" && password == "12345";
        }
        authentication_id == "bob" && password == "secret"
    }

    fn secret(
        &self,
        _context: &Context,
        authentication_id: &str,
        _realm: Option<&str>,
    ) -> Option<String> {
        (authentication_id == "bob").then(|| "secret".to_owned())
    }

    /// The same user, stored the way `SCRAM` wants it: a salt, a count and two derived keys,
    /// with the password nowhere in sight. A real listener derives this once, where the
    /// password is chosen, and keeps only the result.
    #[cfg(feature = "scram-sha-256")]
    fn scram(
        &self,
        _context: &Context,
        authentication_id: &str,
    ) -> Option<vortice_sasl::ScramCredentials> {
        (authentication_id == "bob").then(|| {
            vortice_sasl::ScramCredentials::derive("secret", b"a fixed salt, for the test", 4096)
        })
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

    #[cfg(feature = "cram-md5")]
    let router = router.profile(
        profile_uri("CRAM-MD5"),
        SaslProfile::new(vortice_sasl::CramMd5::new(
            Arc::clone(&users),
            "beep.example.net",
        )),
    );

    #[cfg(feature = "scram-sha-256")]
    let router = router.profile(
        profile_uri("SCRAM-SHA-256"),
        SaslProfile::new(vortice_sasl::ScramSha256::new(Arc::clone(&users))),
    );

    let config = Config::new(Role::Listener)
        .with_profile(WHOAMI)
        .with_profile(profile_uri("ANONYMOUS"))
        .with_profile(profile_uri("EXTERNAL"))
        .with_profile(profile_uri("PLAIN"));
    #[cfg(feature = "cram-md5")]
    let config = config.with_profile(profile_uri("CRAM-MD5"));
    #[cfg(feature = "scram-sha-256")]
    let config = config.with_profile(profile_uri("SCRAM-SHA-256"));

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

/// The multi-round path: the listener speaks first, the peer answers, and the verdict comes
/// on the open channel rather than on the acceptance. Everything above finishes in one round,
/// so without this the `Continue` branch of the profile is never exercised.
#[cfg(feature = "cram-md5")]
#[tokio::test]
async fn cram_md5_takes_two_rounds_and_authenticates() {
    use hmac::{Hmac, KeyInit, Mac};
    use md5::Md5;

    let address = start().await;
    let session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect");

    // Nothing is piggybacked: this mechanism has the listener go first.
    let channel = within(session.open_channel(Profile::new(profile_uri("CRAM-MD5"))))
        .await
        .expect("the listener should accept the channel and challenge");

    let offered = channel.profile().content.clone().unwrap_or_default();
    let challenge = Blob::from_xml(&offered).expect("a blob carrying the challenge");
    assert_eq!(challenge.status, Status::Continue);
    assert!(
        !challenge.data.is_empty(),
        "the challenge is what the response is keyed over"
    );

    let mut mac = Hmac::<Md5>::new_from_slice(b"secret").expect("any key length");
    mac.update(&challenge.data);
    let digest = mac.finalize().into_bytes();
    let response = format!(
        "bob {}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );

    let reply = within(channel.request(Blob::new(response.into_bytes()).to_xml()))
        .await
        .expect("the second round");
    assert_eq!(
        String::from_utf8_lossy(reply.payload()),
        Blob::status(Status::Complete).to_xml()
    );

    assert_eq!(whoami(&session).await, "bob");
    within(session.close()).await.expect("close");
}

/// `SCRAM` completes *and* says something in the same blob, which is the one profile path
/// nothing else here takes: `<blob status='complete'>` with content. The content is the
/// server signature, and a peer that does not check it has thrown away half of what this
/// mechanism offers over `CRAM-MD5`.
#[cfg(feature = "scram-sha-256")]
#[tokio::test]
async fn scram_completes_carrying_the_server_signature() {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    use vortice_proto::base64;

    /// HMAC-SHA-256, the peer's half of the arithmetic.
    fn mac(key: &[u8], message: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
        mac.update(message);
        mac.finalize().into_bytes().into()
    }

    let address = start().await;
    let session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator),
    ))
    .await
    .expect("connect");

    // `n,,` is the GS2 header: no channel binding, no authorization identity.
    let bare = "n=bob,r=peer-nonce";
    let channel = within(
        session.open_channel(
            Profile::new(profile_uri("SCRAM-SHA-256"))
                .with_content(Blob::new(format!("n,,{bare}").into_bytes()).to_xml()),
        ),
    )
    .await
    .expect("the listener should accept the channel and answer");

    let first = Blob::from_xml(&channel.profile().content.clone().unwrap_or_default())
        .expect("a blob carrying the first server message");
    assert_eq!(first.status, Status::Continue);
    let server_first = String::from_utf8(first.data).expect("text");

    let field = |name: &str| -> String {
        server_first
            .split(',')
            .find_map(|part| part.strip_prefix(&format!("{name}=")))
            .expect("the attribute is there")
            .to_owned()
    };
    let salt = base64::decode(&field("s")).expect("the salt comes back");
    let nonce = field("r");
    assert!(nonce.starts_with("peer-nonce"), "it extends ours: {nonce}");

    let final_bare = format!("c=biws,r={nonce}");
    let message = format!("{bare},{server_first},{final_bare}");

    let mut salted = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(b"secret", &salt, 4096, &mut salted);
    let client_key = mac(&salted, b"Client Key");
    let stored_key: [u8; 32] = Sha256::digest(client_key).into();
    let signature = mac(&stored_key, message.as_bytes());
    let mut proof = [0u8; 32];
    for (at, octet) in proof.iter_mut().enumerate() {
        *octet = client_key[at] ^ signature[at];
    }

    let sent = format!("{final_bare},p={}", base64::encode(&proof));
    let reply = within(channel.request(Blob::new(sent.into_bytes()).to_xml()))
        .await
        .expect("the second round");

    let last = Blob::from_xml(&String::from_utf8_lossy(reply.payload()))
        .expect("a blob carrying the signature");
    assert_eq!(last.status, Status::Complete);

    let server_key = mac(&salted, b"Server Key");
    assert_eq!(
        String::from_utf8(last.data).expect("text"),
        format!(
            "v={}",
            base64::encode(&mac(&server_key, message.as_bytes()))
        ),
        "the listener has to prove it holds the credentials too"
    );

    assert_eq!(whoami(&session).await, "bob");
    within(session.close()).await.expect("close");
}
