// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The real `vortex-regression-client` against a Vortice listener.
//!
//! This is the other half of the phase F4 exit criterion, and the harder direction: instead
//! of Vortice choosing what to send, the C reference implementation drives, and every
//! assertion is one the suite makes about a conforming BEEP listener.
//!
//! The listener runs in-process — a `Server` bound to the port the suite's `--offset-port`
//! puts it on — so there is no second binary to build and keep in step.
//!
//! Requires `VORTICE_LIBVORTEX_TEST_DIR`; without it the test reports itself as skipped.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::{Mutex, MutexGuard};
use vortice::{AlwaysRefuse, Config, Role, Router, Server, code};
use vortice_interop::LibVortex;

/// The echo profile: reply with the same payload.
const ECHO: &str = "http://iana.org/beep/transient/vortex-regression";

/// A second profile with an extended start handler, used for close-action checks.
const ECHO_2: &str = "http://iana.org/beep/transient/vortex-regression/2";

/// Advertised, but every channel start for it is refused.
const DENY_SUPPORTED: &str = "http://iana.org/beep/transient/vortex-regression/deny_supported";

/// Serialises the tests in this binary; the suite binds fixed ports.
async fn exclusive() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().await
}

/// The subset of the regression listener contract these tests need.
///
/// Deliberately absent: the suite's `/deny` profile. `test_02` asks for it and requires the
/// start to fail *because the profile is unknown*, which is a different code from a profile
/// that is registered and refuses.
fn regression_router() -> Router {
    let echo = |responder: vortice::Responder, message: vortice::Message| async move {
        let _ = responder.reply(message.msgno, message.payload).await;
    };
    Router::new()
        .profile(ECHO, echo)
        .profile(ECHO_2, echo)
        .profile(
            DENY_SUPPORTED,
            AlwaysRefuse::with_text(code::SERVICE_NOT_AVAILABLE, "channel refused on purpose"),
        )
}

#[tokio::test(flavor = "multi_thread")]
async fn the_c_client_passes_its_tests_against_a_vortice_listener() {
    let _guard = exclusive().await;
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

    assert!(
        LibVortex::port_is_free(suite.listener_port()),
        "port {} is taken; a stray listener would answer for this one",
        suite.listener_port()
    );

    let server = Server::bind_with(
        ("0.0.0.0", suite.listener_port()),
        Config::new(Role::Listener),
        regression_router(),
    )
    .await
    .expect("bind the Vortice listener");
    let serving = tokio::spawn(server.serve());

    // Tier one of the certification order in the LibVortex map, minus the two that need
    // parts of the listener contract not built yet: test_09 wants close-in-transit, and
    // test_11 wants the suite's /3 profile, whose whole point is replying out of order.
    let tests = ["test_01", "test_02", "test_03", "test_10"];
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
        panic!("the C client did not accept the Vortice listener: {error}");
    }
}
