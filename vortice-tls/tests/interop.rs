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
//! The certificate is generated here rather than taken from the suite. The suite's own
//! (`test-certificate.pem`) is a 1024-bit RSA key signed with SHA-1 that expired in July 2021,
//! and rustls will not load any of those three things — reasonably, since all three are below
//! what it considers usable. Nothing is lost for this test: LibVortex verifies no certificate
//! unless asked to, which is also why its own TLS tests keep passing against material that
//! expired five years ago.
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

#[tokio::test(flavor = "multi_thread")]
async fn the_c_client_tunes_a_vortice_listener_for_tls() {
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

    // Shifted clear of the plain-TCP interop test, which binds the same base port: cargo runs
    // the test binaries of different crates at the same time, and two listeners racing for one
    // port makes both runs meaningless rather than one of them fail.
    let suite = suite.clone().with_port_offset(suite.port_offset() + 100);

    let port = suite.listener_port();
    assert!(
        LibVortex::port_is_free(port),
        "port {port} is taken; a stray listener would answer for this one"
    );

    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate a certificate");
    let tls = vortice_tls::server_config(
        issued.cert.pem().as_bytes(),
        issued.signing_key.serialize_pem().as_bytes(),
    )
    .expect("server configuration");

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

    let router: Router = regression_router().profile(PROFILE_URI, TlsProfile::new(tls, after));

    let server = Server::bind_with(("0.0.0.0", port), Config::new(Role::Listener), router)
        .await
        .expect("bind the Vortice listener");
    let serving = tokio::spawn(server.serve());

    let tests = ["test_05"];
    let run = tokio::time::timeout(
        Duration::from_secs(180),
        tokio::task::spawn_blocking(move || suite.run_client(&tests)),
    )
    .await
    .expect("the regression client should finish")
    .expect("the blocking task should not panic")
    .expect("the regression client should be spawnable");

    serving.abort();

    if let Err(error) = run.check(&tests) {
        panic!("the C client did not accept the Vortice listener under TLS: {error}");
    }
}
