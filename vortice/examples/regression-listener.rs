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
//! cd ~/programas/libvortex-1.1/test          # the /5 profile serves files by name
//! cargo run -p vortice --example regression-listener -- --offset-port=1000
//! ./vortex-regression-client --offset-port=1000 --run-test=test_01,test_11
//! ```
//!
//! The profiles themselves live in the integration test's shared module, so this binary and
//! CI serve exactly the same thing.

use vortice::{Config, Role, Server};
use vortice_interop::profiles::regression_router;

/// Base port the suite's main listener uses, before any offset.
const BASE_PORT: u16 = 44010;

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
