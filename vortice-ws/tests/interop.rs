// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The real `vortex-regression-client` speaking WebSocket to a Vortice listener.
//!
//! This is the phase F5 exit criterion for the WebSocket mechanism, and it is a stronger
//! check than its name suggests. `test_17` opens one WebSocket connection to confirm the
//! transport works, and then reruns a whole sequence of ordinary tests — `test_01` through
//! `test_04ab` — with every connection tunnelled. So what is certified here is not the
//! handshake but the tunnel: framing, fragmentation, flow control, channel management,
//! connection close and the ANS/NUL family, all over WebSocket, driven by the C reference
//! implementation through noPoll.
//!
//! It also pins the interoperability decision the crate documents: noPoll sends BEEP inside
//! WebSocket *text* frames whatever the payload holds, and `test_01a` deliberately sends
//! zeroed binary frames while `test_04ab` sends files. A peer that validated UTF-8 on
//! received text frames, as RFC6455 §5.6 requires, would fail here.
//!
//! Requires `VORTICE_LIBVORTEX_TEST_DIR`; without it the test reports itself as skipped.

use std::time::Duration;

use vortice::{Config, Role};
use vortice_interop::LibVortex;
use vortice_interop::profiles::regression_router;

#[tokio::test(flavor = "multi_thread")]
async fn the_c_client_passes_test_17_against_a_vortice_websocket_listener() {
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

    let port = suite.websocket_port();
    assert!(
        LibVortex::port_is_free(port),
        "port {port} is taken; a stray listener would answer for this one"
    );

    // The suite's file-serving profile resolves the names the client asks for relative to the
    // working directory, and those files live beside its binaries.
    std::env::set_current_dir(suite.test_dir()).expect("the suite directory should exist");

    // Bound on 0.0.0.0 rather than 127.0.0.1: the client resolves `localhost`, which may come
    // back as either family, and a listener on the loopback address alone would miss it.
    let server = vortice_ws::Server::bind_with(
        ("0.0.0.0", port),
        Config::new(Role::Listener),
        regression_router(),
    )
    .await
    .expect("bind the Vortice websocket listener");
    let serving = tokio::spawn(server.serve());

    let tests = ["test_17"];
    let run = tokio::time::timeout(
        Duration::from_secs(300),
        tokio::task::spawn_blocking(move || suite.run_client(&tests)),
    )
    .await
    .expect("the regression client should finish")
    .expect("the blocking task should not panic")
    .expect("the regression client should be spawnable");

    serving.abort();

    if let Err(error) = run.check(&tests) {
        panic!("the C client did not accept the Vortice websocket listener: {error}");
    }
}
