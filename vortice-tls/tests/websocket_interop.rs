// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The suite's WebSocket-over-TLS tests, and its port sharing, against Vortice listeners.
//!
//! `test_18` drives BEEP over `wss`; `test_20` walks one port through plain BEEP, then
//! WebSocket, then WebSocket over TLS, checking each in turn — all three phases, which is the
//! part of phase F5 that had to wait for TLS to exist.
//!
//! `wss` needed no new protocol work: `vortice-ws` serves BEEP over anything that reads and
//! writes, and `vortice-tls` produces such a thing, so the two compose. That they did is the
//! argument for having kept the transports in separate crates.
//!
//! Requires `VORTICE_LIBVORTEX_TEST_DIR`; without it the test reports itself as skipped.

use std::time::Duration;

use vortice_interop::{LibVortex, SuiteLock};

#[path = "common/listeners.rs"]
mod listeners;

#[tokio::test(flavor = "multi_thread")]
async fn the_c_client_passes_its_websocket_tls_tests_against_vortice() {
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

    let _guard = SuiteLock::acquire();

    // Clear of the other interop tests, which bind the same base ports.
    let suite = suite.clone().with_port_offset(suite.port_offset() + 200);
    let offset = suite.port_offset();

    for port in [44013 + offset, 44014 + offset, 44015 + offset] {
        assert!(
            LibVortex::port_is_free(port),
            "port {port} is taken; a stray listener would answer for this one"
        );
    }

    // The file-serving profile resolves names relative to the working directory.
    std::env::set_current_dir(suite.test_dir()).expect("the suite directory should exist");

    listeners::serve_all(offset)
        .await
        .expect("bind the listeners");

    // All four run here: `test_17` is the whole battery over plain WebSocket, `test_18` opens
    // a `wss` session, `test_19` is the battery again over `wss`, and `test_20` walks the
    // shared port through its three phases.
    //
    // `test_19` and `test_20` were out of this list for a long time, because anything that
    // pushed real payload over `wss` lost frames here. What kept them out in the end was this
    // harness: `LibVortex::run_client` ran the libtool wrapper script, which puts the
    // *installed* library directory ahead of everything, so every measurement was made
    // against a noPoll from 2022 — three upstream fixes behind the checkout the run was
    // supposed to be proving things about, including the one for exactly this symptom. Run by
    // hand with `LD_LIBRARY_PATH` pointing at the in-tree `.libs`, all four tests had been
    // passing for some time. The harness now runs the real ELF with that path set; if this
    // test ever starts failing at `test_01a` again, check `ldd` on the client before
    // anything else.
    //
    // The two defects the hunt did find are real and are fixed upstream, and the search for a
    // third — in OpenSSL underneath noPoll — ended in the finding that there was none to look
    // for. Do not reopen it. Measured against OpenSSL 1.1.1, of the three ways a TLS
    // transport can hold octets where `select()` cannot see them:
    //
    //   - Several WebSocket frames inside ONE TLS record. Real, and a genuine defect, but in
    //     noPoll's own event loop (`nopoll_loop_process_data` read a single message per
    //     readable event). Fixed upstream, covered by noPoll's `test_48`. It never affected
    //     this path: LibVortex does not call `nopoll_loop_wait` anywhere. It drives sockets
    //     from `vortex_reader.c` and already drains what noPoll holds, by publishing
    //     `nopoll_conn_read_pending` as the `try_read_pending` connection key and looping on
    //     it in `__vortex_reader_process_socket_pending`.
    //
    //   - Several TLS records inside one TCP segment.
    //   - A record ending mid-WebSocket-header, leaving a partial header in noPoll's
    //     `pending_buf` (which `nopoll_conn_read_pending` deliberately does not report).
    //
    // Neither of the last two stalls, and for the same reason: OpenSSL keeps `read_ahead` off
    // for TLS, so the record layer takes exactly one record off the socket and everything
    // behind it stays in the kernel, where `select()` still sees it. Measured with two real
    // TLS peers, corked into a single segment, after consuming the first record:
    // `SSL_pending()` 0, `SSL_has_pending()` 0, `select()` 1. The same probe with
    // `SSL_CTX_set_read_ahead()` on gives 0, 1, 0 — the stall — but neither noPoll nor
    // LibVortex ever enables it, and noPoll wires the session with `SSL_set_fd()`, with no
    // buffering BIO of its own. (DTLS would enable read_ahead by itself; this is TLS.)
    //
    // Measured on 2026-08-23 against both C trees at HEAD: 20 consecutive runs of all four
    // tests, one failure — and that failure was `test_17`'s `test_04a` losing one ANS frame
    // of 4096, over plain WebSocket. The same loss reproduces over plain BEEP with no
    // WebSocket and no TLS in the path, about three times in 740 runs of `test_04a` against
    // `vortice --example regression-listener`, so it is a separate defect in the ANS/NUL
    // path that these tests inherit rather than anything this file covers. It is `wss`'s
    // problem no more than it is plain TCP's: see `doc/plan-next-steps.md`. It is rare
    // enough that this test will usually pass; a failure here reported as a short block
    // count is that one, not a regression in this file.
    // `test_17a`, `test_18a` and `test_18b` are the packing family, and they are here rather
    // than only in the C suite because a listener is exactly what they exercise: two BEEP
    // frames in one WebSocket frame, the same over TLS, and two WebSocket frames inside one
    // TLS record. The last of those is the shape that cost weeks — see the note above — and
    // it has teeth: against a LibVortex linked with a noPoll that predates the
    // `SSL_pending()` fix it fails, reporting one reply where two were due.
    let tests = [
        "test_17", "test_17a", "test_18", "test_18a", "test_18b", "test_19", "test_20",
    ];
    let run = tokio::time::timeout(
        Duration::from_secs(300),
        tokio::task::spawn_blocking(move || suite.run_client(&tests)),
    )
    .await
    .expect("the regression client should finish")
    .expect("the blocking task should not panic")
    .expect("the regression client should be spawnable");

    if let Err(error) = run.check(&tests) {
        panic!("the C client did not accept the Vortice listeners: {error}");
    }
}
