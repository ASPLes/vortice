// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The suite's WebSocket listeners, plain and over TLS, plus the three-way shared port.
//!
//! ```sh
//! cd ~/programas/libvortex-1.1/test
//! cargo run -p vortice-tls --example tls-ws-regression-listener -- --offset-port=1200
//! ./vortex-regression-client --offset-port=1200 --run-test=test_17,test_18,test_19,test_20
//! ```

#[path = "../tests/common/listeners.rs"]
mod listeners;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let offset: u16 = std::env::args()
        .find_map(|arg| arg.strip_prefix("--offset-port=").map(str::to_owned))
        .map_or(Ok(0), |value| value.parse())?;

    listeners::serve_all(offset).await?;
    println!(
        "Vortice listeners: ws {}, wss {}, shared {}",
        44013 + offset,
        44014 + offset,
        44015 + offset
    );
    std::future::pending::<()>().await;
    Ok(())
}
