// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The listener behaviour the suite's `test_05a` and `test_05d` drive from the wire.
//!
//! Shared by the interop test and by `examples/tls-regression-listener.rs`, so that what CI
//! checks is exactly what a developer gets running it by hand.

#![allow(dead_code, unreachable_pub)]

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use vortice::{ErrorReply, SessionId, Start, code};
use vortice_tls::{TlsDecision, TlsPolicy};

/// How long a peer naming [`SLOW_SERVER_NAME`] is left waiting.
///
/// What `regression_tls_handle_query` waits in `vortex-regression-listener.c`. `test_05d`
/// tries timeouts from twenty microseconds to three seconds and expects every one of them to
/// expire, so anything comfortably above the largest will do.
pub const SLOW_NEGOTIATION: Duration = Duration::from_secs(10);

/// The virtual host that makes this listener answer late.
pub const SLOW_SERVER_NAME: &str = "test-05-d.server";

/// The Rust half of `regression_tls_handle_query`.
///
/// Three outcomes, the same three the C listener has:
///
/// - a peer that opened a `/block-tls` channel gets its next tuning **refused**, and the
///   session carries on in the clear — that is `test_05a`'s first half;
/// - that same connection gets its *following* attempt accepted and then **broken**, which is
///   what the C listener simulates by making its SSL context creation return NULL, and what
///   `test_05a` checks by requiring the connection to be gone afterwards;
/// - a peer naming [`SLOW_SERVER_NAME`] is left waiting, so a client with a short timeout
///   gives up on a listener that has not answered. That is `test_05d`.
#[derive(Debug, Default)]
pub struct RegressionTlsPolicy {
    /// Sessions refused once, to be broken on their next attempt.
    armed: Mutex<HashSet<SessionId>>,
}

impl TlsPolicy for RegressionTlsPolicy {
    fn accept(&self, session: SessionId, _start: &Start) -> Result<(), ErrorReply> {
        if vortice_interop::profiles::take_block_tls() {
            // Refused, and remembered: this is where the C listener arms a failure for the
            // next attempt on this same connection.
            self.armed
                .lock()
                .expect("the armed set is not poisoned")
                .insert(session);
            return Err(ErrorReply::new(code::TRANSACTION_FAILED)
                .with_text("TLS blocked for this connection on purpose", None));
        }
        Ok(())
    }

    fn proceed(&self, session: SessionId, server_name: Option<String>) -> TlsDecision {
        let armed = self
            .armed
            .lock()
            .expect("the armed set is not poisoned")
            .remove(&session);
        Box::pin(async move {
            if armed {
                return false;
            }
            if server_name.as_deref() == Some(SLOW_SERVER_NAME) {
                tokio::time::sleep(SLOW_NEGOTIATION).await;
            }
            true
        })
    }
}
