// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The Vortice client against the real `vortex-regression-listener`.
//!
//! This is the phase F3 exit criterion: rather than asserting against another Vortice, the
//! client is put on the wire opposite the C reference implementation and made to do what the
//! regression suite's own tests do.
//!
//! | Test here | LibVortex equivalent |
//! |---|---|
//! | `greets_and_echoes` | `test_01` — connect, greetings, channel create, MSG/RPY, close |
//! | `carries_a_burst_of_small_messages` | `test_02c` — many small messages then close |
//! | `carries_a_message_larger_than_the_window` | `test_03` — messages exceeding the window |
//! | `a_profile_the_listener_does_not_serve_is_refused` | the `/deny` profile of the suite |
//!
//! Requires `VORTICE_LIBVORTEX_TEST_DIR`; without it each test reports itself as skipped.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::{Mutex, MutexGuard};

use vortice::{Config, Connection, Error, Profile, Role};
use vortice_interop::{LibVortex, Listener};

/// Serialises the tests in this binary.
///
/// The regression listener binds fixed ports, so two of these running at once would fight
/// over 44010. Taking a lock rather than letting them race keeps `cargo test` working
/// without `--test-threads=1`, and still gives every test a listener of its own. It is
/// tokio's mutex rather than the standard one because the guard is held across the awaits
/// that make up the test.
async fn exclusive() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().await
}

/// The echo profile every regression listener registers.
const ECHO: &str = "http://iana.org/beep/transient/vortex-regression";

/// A profile the listener deliberately does not register.
const DENY: &str = "http://iana.org/beep/transient/vortex-regression/deny";

/// Starts the C listener, or explains why the test is being skipped.
///
/// The returned guard keeps the other tests in this binary out until it is dropped.
async fn listener() -> Option<(MutexGuard<'static, ()>, LibVortex, Listener)> {
    let guard = exclusive().await;
    let suite = match LibVortex::from_env() {
        Some(suite) if suite.is_built() => suite,
        Some(suite) => {
            eprintln!(
                "SKIPPED: {} does not contain the regression binaries; build LibVortex first",
                suite.test_dir().display()
            );
            return None;
        }
        None => {
            eprintln!("SKIPPED: VORTICE_LIBVORTEX_TEST_DIR is not set");
            return None;
        }
    };
    let running = suite.start_listener().expect("listener should start");
    Some((guard, suite, running))
}

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .expect("operation timed out")
}

/// Opens a session against the running listener, on whichever port its offset puts it.
async fn connect(suite: &LibVortex) -> Connection {
    within(Connection::connect(
        ("127.0.0.1", suite.listener_port()),
        Config::new(Role::Initiator).with_profile(ECHO),
    ))
    .await
    .expect("connect to the regression listener")
}

#[tokio::test]
async fn greets_and_echoes() {
    let Some((_guard, suite, _listener)) = listener().await else {
        return;
    };
    let session = connect(&suite).await;
    assert!(
        session.peer_greeting().advertises(ECHO),
        "the listener should advertise the regression profile, got {:?}",
        session.peer_greeting().profiles()
    );

    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open the echo channel");
    assert_eq!(channel.number(), 1, "the initiator allocates odd numbers");

    let reply = within(channel.request("hola")).await.expect("echo reply");
    assert!(reply.is_ok(), "expected a positive reply, got {reply:?}");
    assert_eq!(reply.payload(), b"hola");

    within(session.close_channel(channel.number()))
        .await
        .expect("close the channel");
    within(session.close()).await.expect("close the session");
}

#[tokio::test]
async fn carries_a_burst_of_small_messages() {
    let Some((_guard, suite, _listener)) = listener().await else {
        return;
    };
    let session = connect(&suite).await;
    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open the echo channel");

    for index in 0..200u32 {
        let payload = format!("message {index}");
        let reply = within(channel.request(payload.clone()))
            .await
            .expect("echo reply");
        assert_eq!(
            reply.payload(),
            payload.as_bytes(),
            "message {index} came back changed"
        );
    }

    within(session.close()).await.expect("close the session");
}

#[tokio::test]
async fn carries_a_message_larger_than_the_window() {
    let Some((_guard, suite, _listener)) = listener().await else {
        return;
    };
    // The default window is 4096 octets, so 64 KiB can only make it across if fragmentation,
    // SEQ pacing and reassembly all work — in both directions, since the echo comes back the
    // same size.
    let session = connect(&suite).await;
    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open the echo channel");

    let payload: Vec<u8> = (0..64 * 1024u32).map(|index| (index % 251) as u8).collect();
    let reply = within(channel.request(payload.clone()))
        .await
        .expect("echo reply");

    assert_eq!(reply.payload().len(), payload.len(), "wrong length echoed");
    assert_eq!(
        reply.payload(),
        &payload[..],
        "the payload came back changed"
    );

    within(session.close()).await.expect("close the session");
}

#[tokio::test]
async fn a_profile_the_listener_does_not_serve_is_refused() {
    let Some((_guard, suite, _listener)) = listener().await else {
        return;
    };
    let session = connect(&suite).await;

    let error = within(session.open_channel(Profile::new(DENY)))
        .await
        .expect_err("the listener does not register that profile");
    assert!(
        matches!(error, Error::Refused(_)),
        "expected a BEEP refusal, got {error}"
    );

    // The session survives a refused channel, which is what the suite's /deny profile checks.
    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("the session should still be usable");
    let reply = within(channel.request("still here")).await.expect("echo");
    assert_eq!(reply.payload(), b"still here");

    within(session.close()).await.expect("close the session");
}
