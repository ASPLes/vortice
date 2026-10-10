// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The real `vortex-regression-client` authenticating against Vortice listeners.
//!
//! `test_06` walks all five mechanisms — `ANONYMOUS`, `EXTERNAL`, `PLAIN`, `CRAM-MD5` and
//! `DIGEST-MD5` — with a failing case and a succeeding case for each, and then does the whole
//! thing again against a second listener. That second pass is what the suite calls the
//! unified API: on the C side one handler serves every mechanism instead of five, and it runs
//! on a port of its own. There is nothing to mirror here, because this crate has only ever
//! had one way of doing it, so the second listener is another instance of the first.
//!
//! What this certifies that the unit tests cannot: that the blobs, the challenges and the
//! digests are the ones GNU SASL computes, since that is what the C client authenticates
//! with. An arithmetic error that two implementations of ours would agree on shows up here.
//!
//! Requires `VORTICE_LIBVORTEX_TEST_DIR`; without it the test reports itself as skipped.

#![cfg(all(
    feature = "anonymous",
    feature = "external",
    feature = "plain",
    feature = "cram-md5",
    feature = "digest-md5"
))]

use std::sync::Arc;
use std::time::Duration;

use vortice::{Config, Role, Router, Server};
use vortice_interop::profiles::regression_router;
use vortice_interop::{LibVortex, SuiteLock};
use vortice_sasl::{
    Anonymous, Authenticator, Context, CramMd5, DigestMd5, External, Plain, SaslProfile,
    profile_uri,
};

/// Base port of the suite's second SASL listener, the one `test_06` runs its second pass
/// against.
const UNIFIED_SASL_PORT: u16 = 44011;

/// The credentials `vortex-regression-listener.c` accepts, which is what `test_06` was
/// written against: `test@aspl.es` for `ANONYMOUS`, `acinom` for `EXTERNAL`, and `bob` with
/// the password `secret` for the rest.
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
        // `test_06a` is this branch: it opens the session naming a virtual host and then
        // authenticates a user that exists only there. The C listener's unified handler does
        // the same, keyed on `props->serverName`.
        if context.server_name.as_deref() == Some("test_06a.server") {
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
}

/// The regression profiles, plus every SASL mechanism on offer.
fn router(users: &Arc<dyn Authenticator>) -> Router {
    regression_router()
        .profile(
            profile_uri("ANONYMOUS"),
            SaslProfile::new(Anonymous::new(Arc::clone(users))),
        )
        .profile(
            profile_uri("EXTERNAL"),
            SaslProfile::new(External::new(Arc::clone(users))),
        )
        .profile(
            profile_uri("PLAIN"),
            SaslProfile::new(Plain::new(Arc::clone(users))),
        )
        .profile(
            profile_uri("CRAM-MD5"),
            SaslProfile::new(CramMd5::new(Arc::clone(users), "localhost")),
        )
        .profile(
            profile_uri("DIGEST-MD5"),
            SaslProfile::new(DigestMd5::new(Arc::clone(users), "localhost")),
        )
}

/// A greeting offering everything the router serves.
fn greeting(router: &Router) -> Config {
    let mut uris: Vec<String> = router.uris().map(str::to_owned).collect();
    uris.sort_unstable();

    let mut config = Config::new(Role::Listener);
    for uri in &uris {
        if !config.greeting.advertises(uri.as_str()) {
            config.greeting = config.greeting.clone().with_profile(uri.as_str());
        }
    }
    config
}

#[tokio::test(flavor = "multi_thread")]
async fn the_c_client_authenticates_against_a_vortice_listener() {
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

    // Clear of the other interop tests, which bind the same base ports.
    let suite = suite.clone().with_port_offset(suite.port_offset() + 300);
    let offset = suite.port_offset();

    let main = suite.listener_port();
    let unified = UNIFIED_SASL_PORT + offset;
    for port in [main, unified] {
        assert!(
            LibVortex::port_is_free(port),
            "port {port} is taken; a stray listener would answer for this one"
        );
    }

    // The /5 profile serves files the client names, relative to the working directory.
    std::env::set_current_dir(suite.test_dir()).expect("the suite directory should exist");

    let users: Arc<dyn Authenticator> = Arc::new(Suite);
    let mut serving = Vec::new();
    for port in [main, unified] {
        let router = router(&users);
        let config = greeting(&router);
        let server = Server::bind_with(("0.0.0.0", port), config, router)
            .await
            .expect("bind the Vortice listener");
        serving.push(tokio::spawn(server.serve()));
    }

    // `test_06a` is the one that needs the virtual host: it opens the session naming
    // `test_06a.server` and authenticates a user that exists only under that name, which is
    // why `Context` reaches the authenticator at all.
    let tests = ["test_06", "test_06a"];
    let run = tokio::time::timeout(
        Duration::from_secs(180),
        tokio::task::spawn_blocking(move || suite.run_client(&tests)),
    )
    .await
    .expect("the regression client should finish")
    .expect("the blocking task should not panic")
    .expect("the regression client should be spawnable");

    for handle in serving {
        handle.abort();
    }

    if let Err(error) = run.check(&tests) {
        panic!("the C client did not authenticate against the Vortice listeners: {error}");
    }
}
