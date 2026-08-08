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
use vortice::{Config, Role, Server};
use vortice_interop::LibVortex;

#[path = "common/regression_profiles.rs"]
mod regression_profiles;

use regression_profiles::regression_router;

/// Serialises the tests in this binary; the suite binds fixed ports.
async fn exclusive() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().await
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

    // The /5 profile serves files the request names, relative to the working directory, and
    // the suite asks for files that live beside its binaries.
    std::env::set_current_dir(suite.test_dir()).expect("the suite directory should exist");

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
    // Tiers one and two of the certification order in the LibVortex map, plus the ANS/NUL
    // family and the two profiles that push content the moment their channel opens.
    //
    // test_02m is the heavy one — 10000 answers of 4096 octets, about 40 MB — and it has
    // been seen to fail on a machine busy compiling something else. If it fails in CI and
    // nowhere else, suspect the load before the code.
    let tests = [
        "test_01",
        "test_01c",
        "test_02",
        "test_02k",
        "test_02l",
        "test_02l1",
        "test_02m",
        "test_03",
        "test_03b",
        "test_03c",
        "test_04a",
        "test_04ab",
        "test_09",
        "test_10",
        "test_11",
    ];
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
