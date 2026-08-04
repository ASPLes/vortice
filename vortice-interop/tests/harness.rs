// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! End to end check of the harness against a real LibVortex build.
//!
//! This proves the plumbing works — the C listener starts, the C client reaches it, the
//! output is parsed correctly — before any Vortice code is put on either end of the wire.
//!
//! Requires `VORTICE_LIBVORTEX_TEST_DIR` to point at a built LibVortex `test/` directory.
//! Without it the tests report themselves as skipped rather than failing, so that a
//! developer without a LibVortex checkout is not blocked. CI must set the variable.

use vortice_interop::{InteropError, LibVortex};

/// Returns the suite, or `None` after printing why the test is being skipped.
fn suite() -> Option<LibVortex> {
    match LibVortex::from_env() {
        Some(suite) if suite.is_built() => Some(suite),
        Some(suite) => {
            eprintln!(
                "SKIPPED: {} does not contain the regression binaries; build LibVortex first",
                suite.test_dir().display()
            );
            None
        }
        None => {
            eprintln!("SKIPPED: VORTICE_LIBVORTEX_TEST_DIR is not set");
            None
        }
    }
}

#[test]
fn runs_the_c_client_against_the_c_listener() {
    let Some(suite) = suite() else { return };
    let _listener = suite.start_listener().expect("listener should start");

    let run = suite
        .run_client(&["test_01"])
        .expect("client should be spawnable");
    if let Err(error) = run.check(&["test_01"]) {
        panic!("baseline interop run failed: {error}");
    }
}

#[test]
fn detects_a_test_name_the_suite_silently_ignores() {
    let Some(suite) = suite() else { return };
    let _listener = suite.start_listener().expect("listener should start");

    // The suite matches nothing, runs nothing and still prints "All test ok!". The harness
    // has to catch that, otherwise a typo in a test name looks like a passing conformance run.
    let run = suite
        .run_client(&["test_does_not_exist"])
        .expect("client should be spawnable");
    assert!(
        matches!(
            run.check(&["test_does_not_exist"]),
            Err(InteropError::TestNotRun { .. })
        ),
        "harness accepted a run in which no test executed: {}",
        run.stdout
    );
}

#[test]
fn releases_the_listener_port_when_dropped() {
    let Some(suite) = suite() else { return };
    drop(suite.start_listener().expect("listener should start"));
    // Starting again would fail with the port still held.
    let _listener = suite
        .start_listener()
        .expect("port should be free after the previous listener was dropped");
}
