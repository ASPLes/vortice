// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! A Vortice WebSocket listener speaking the LibVortex regression suite's profile contract.
//!
//! The WebSocket counterpart of `vortice/examples/regression-listener.rs`, on the port the
//! suite's `test_17` connects to. It serves the same profiles, from the same module, so the
//! two transports are compared on equal terms.
//!
//! ```sh
//! cd ~/programas/libvortex-1.1/test          # the /5 profile serves files by name
//! cargo run -p vortice-ws --example ws-regression-listener -- --offset-port=1000
//! ./vortex-regression-client --offset-port=1000 --run-test=test_17
//! ```
//!
//! With `--shared` it binds the suite's port-sharing port instead, taking plain BEEP and
//! WebSocket on the one port, which is what `test_20` exercises.

use vortice::{Config, Role};
use vortice_interop::profiles::regression_router;

/// Base port the suite's WebSocket listener uses, before any offset.
const BASE_PORT: u16 = 44013;

/// Base port the suite's port-sharing listener uses, before any offset.
const SHARING_PORT: u16 = 44015;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let offset: u16 = std::env::args()
        .find_map(|arg| arg.strip_prefix("--offset-port=").map(str::to_owned))
        .map_or(Ok(0), |value| value.parse())?;
    let shared = std::env::args().any(|arg| arg == "--shared");
    let port = if shared { SHARING_PORT } else { BASE_PORT } + offset;

    let mut server = vortice_ws::Server::bind_with(
        ("0.0.0.0", port),
        Config::new(Role::Listener),
        regression_router(),
    )
    .await?;
    if shared {
        server = server.with_plain_beep();
    }

    println!(
        "Vortice websocket regression listener on port {port} (offset {offset}, shared {shared})"
    );
    server.serve().await?;
    Ok(())
}
