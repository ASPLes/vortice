// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The real `vortex-regression-client` tuning a Vortice listener for TLS.
//!
//! `test_05` negotiates TLS in band on the suite's ordinary listener port — the profile is
//! offered in the greeting, agreed on a channel, and the transport replaced under a session
//! that then starts again. Afterwards it runs a full request and reply battery over the tuned
//! connection, so what is certified here is the whole path: the negotiation, the swap, the
//! second greeting exchange, and BEEP framing across the TLS record layer.
//!
//! The certificate is the suite's own, `test-certificate.pem`, and that matters for one of
//! these tests: `test_05a2` reads the peer certificate off the tuned connection and compares
//! its MD5 digest against a value written into the C source. Serving anything else — a
//! certificate generated here, which is what this test did while the suite's was a 1024-bit
//! SHA-1 one that expired in 2021 — makes that comparison fail for a reason that has nothing
//! to do with the code under test. The suite's material has since been regenerated (RSA 2048,
//! SHA-256, valid to 2036), so rustls loads it and the pinned digest matches.
//!
//! This test was intermittent for a while, and what it was catching was real: LibVortex's TLS
//! transport never reported what OpenSSL still held decrypted, so a TLS record carrying more
//! than one BEEP frame lost everything past the first. Both ends then waited with empty socket
//! queues. Fixed in `tls/vortex_tls.c`; see §8 of the design decisions.
//!
//! Requires `VORTICE_LIBVORTEX_TEST_DIR`; without it the test reports itself as skipped.

use std::time::Duration;

use vortice::{Config, Role, Router, Server};
use vortice_interop::profiles::regression_router;
use vortice_interop::{LibVortex, SuiteLock};
use vortice_tls::{PROFILE_URI, TlsProfile};

#[path = "common/tls_policy.rs"]
mod tls_policy;

use tls_policy::RegressionTlsPolicy;

#[tokio::test(flavor = "multi_thread")]
async fn the_c_client_tunes_a_vortice_listener_for_tls() {
    let tests = [
        "test_05",
        "test_05a",
        "test_05a1",
        "test_05a2",
        "test_05b",
        "test_05c",
        "test_05d",
    ];
    run_against(100, &tests, |certificate, key, after| {
        let tls = vortice_tls::server_config(certificate, key).expect("server configuration");
        TlsProfile::new(tls, after)
    })
    .await;
}

/// The same negotiation with the platform's TLS underneath, to show the conformance belongs
/// to the profile rather than to rustls.
///
/// Only `test_05` of the family: what the backend can affect is the handshake and the record
/// layer, which that one exercises in full — tune, greet again, then a battery of requests and
/// replies across the encrypted transport. The rest of the family is about refusing, stalling
/// and reading state back, none of which goes anywhere near the TLS library.
#[cfg(feature = "native-tls")]
#[tokio::test(flavor = "multi_thread")]
async fn the_c_client_tunes_a_native_tls_vortice_listener() {
    run_against(150, &["test_05"], |certificate, key, after| {
        let acceptor =
            vortice_tls::native::acceptor(certificate, key).expect("native-tls acceptor");
        TlsProfile::with_acceptor(acceptor).after_tuning(after)
    })
    .await;
}

/// Runs the named tests against a Vortice listener whose TLS profile `build` produces.
///
/// `offset` shifts this run's ports clear of the other interop tests: cargo runs the test
/// binaries of different crates at the same time, and two listeners racing for one port makes
/// both runs meaningless rather than one of them fail.
async fn run_against(
    offset: u16,
    tests: &[&str],
    build: impl FnOnce(&[u8], &[u8], Config) -> TlsProfile,
) {
    // Only one interop test may drive the suite at a time, whichever crate it lives in:
    // three C clients moving tens of megabytes at once make the suite's own timing-sensitive
    // tests fail. Held for the whole test.
    let _suite = SuiteLock::acquire();

    let suite = match LibVortex::from_env() {
        Some(suite) if suite.is_built() => suite,
        Some(suite) => {
            eprintln!(
                "SKIPPED: {} does not contain the regression binaries; build LibVortex first",
                suite.test_dir().display()
            );
            return;
        }
        None => {
            eprintln!("SKIPPED: VORTICE_LIBVORTEX_TEST_DIR is not set");
            return;
        }
    };

    let suite = suite.clone().with_port_offset(suite.port_offset() + offset);

    let port = suite.listener_port();
    assert!(
        LibVortex::port_is_free(port),
        "port {port} is taken; a stray listener would answer for this one"
    );

    // `test_05a2` pins the MD5 digest of this exact certificate, so it has to be this one.
    let certificate = std::fs::read(suite.test_dir().join("test-certificate.pem"))
        .expect("the suite ships test-certificate.pem");
    let key = std::fs::read(suite.test_dir().join("test-private-key.pem"))
        .expect("the suite ships test-private-key.pem");
    // The /5 profile serves files the client names, relative to the working directory.
    std::env::set_current_dir(suite.test_dir()).expect("the suite directory should exist");

    // The session that follows the swap has to offer the same profiles as the one before it:
    // a fresh greeting means a fresh offer, and the client goes on to use them.
    let served: Vec<String> = {
        let mut uris: Vec<String> = regression_router().uris().map(str::to_owned).collect();
        uris.sort_unstable();
        uris
    };
    let mut after = Config::new(Role::Listener);
    for uri in &served {
        after.greeting = after.greeting.clone().with_profile(uri.as_str());
    }

    let router: Router = regression_router().profile(
        PROFILE_URI,
        build(&certificate, &key, after).with_policy(RegressionTlsPolicy::default()),
    );

    let server = Server::bind_with(("0.0.0.0", port), Config::new(Role::Listener), router)
        .await
        .expect("bind the Vortice listener");
    let serving = tokio::spawn(server.serve());

    // `test_05a2` asks the tuned connection for the peer certificate and checks its digest,
    // which is a listener test in everything but name: what it proves is that the certificate
    // the listener presented is the one it was configured with, intact across the swap.
    //
    // `test_05c` tunes with a `serverName` and then asks the listener, over the tuned
    // connection, what name it sees. Answering needs the session to have kept it across the
    // swap — the channel that named it is the one that asked for TLS, and both are gone by
    // the time the question arrives.
    let names: Vec<String> = tests.iter().map(|name| (*name).to_owned()).collect();
    let run = tokio::time::timeout(
        Duration::from_secs(300),
        tokio::task::spawn_blocking(move || {
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            suite.run_client(&names)
        }),
    )
    .await
    .expect("the regression client should finish")
    .expect("the blocking task should not panic")
    .expect("the regression client should be spawnable");

    serving.abort();

    if let Err(error) = run.check(tests) {
        panic!("the C client did not accept the Vortice listener under TLS: {error}");
    }
}
