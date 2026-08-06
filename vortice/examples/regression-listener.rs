// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! A Vortice listener speaking the LibVortex regression suite's profile contract.
//!
//! It exists so the C `vortex-regression-client` can be pointed at Vortice instead of at
//! `vortex-regression-listener`, which is the direction that proves the listener side
//! conforms rather than merely that the client interoperates.
//!
//! ```sh
//! cargo run -p vortice --example regression-listener -- --offset-port=1000
//! cd ~/programas/libvortex-1.1/test
//! ./vortex-regression-client --offset-port=1000 --run-test=test_01,test_03,test_10
//! ```
//!
//! The profile set is the subset the first tier of the certification order needs. Note what
//! is deliberately missing: the suite's `/deny` profile is *not* registered, because
//! `test_02` requires a start for it to fail on the grounds that the profile is unknown.

use vortice::{AlwaysRefuse, Config, Message, Responder, Role, Router, Server, code};

const BASE_PORT: u16 = 44010;

const ECHO: &str = "http://iana.org/beep/transient/vortex-regression";
const ECHO_2: &str = "http://iana.org/beep/transient/vortex-regression/2";
const ECHO_3: &str = "http://iana.org/beep/transient/vortex-regression/3";
const DENY_SUPPORTED: &str = "http://iana.org/beep/transient/vortex-regression/deny_supported";

/// The profiles this listener serves.
#[must_use]
pub fn regression_router() -> Router {
    let echo = |responder: Responder, message: Message| async move {
        if std::env::var_os("VORTICE_TRACE").is_some() {
            eprintln!(
                "[msg] channel={} msgno={} len={}",
                responder.channel(),
                message.msgno,
                message.payload.len()
            );
        }
        let _ = responder.reply(message.msgno, message.payload).await;
    };
    Router::new()
        .profile(ECHO, echo)
        .profile(ECHO_2, echo)
        .profile(ECHO_3, echo)
        .profile(
            DENY_SUPPORTED,
            AlwaysRefuse::with_text(code::SERVICE_NOT_AVAILABLE, "channel refused on purpose"),
        )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let offset: u16 = std::env::args()
        .find_map(|arg| arg.strip_prefix("--offset-port=").map(str::to_owned))
        .map_or(Ok(0), |value| value.parse())?;
    let port = BASE_PORT + offset;

    let server = Server::bind_with(
        ("0.0.0.0", port),
        Config::new(Role::Listener),
        regression_router(),
    )
    .await?;

    println!("Vortice regression listener on port {port} (offset {offset})");
    server.serve().await?;
    Ok(())
}
