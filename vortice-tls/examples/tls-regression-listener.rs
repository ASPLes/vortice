// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! A Vortice regression listener that also offers the BEEP TLS profile.
//!
//! The same profile contract as `vortice/examples/regression-listener`, plus
//! `http://iana.org/beep/TLS`, so the C client's `test_05` can tune the session and carry on.
//!
//! ```sh
//! cd ~/programas/libvortex-1.1/test
//! cargo run -p vortice-tls --example tls-regression-listener -- --offset-port=1000
//! ./vortex-regression-client --offset-port=1000 --run-test=test_05
//! ```

use vortice::{Config, Role, Server};
use vortice_interop::profiles::regression_router;
use vortice_tls::{PROFILE_URI, TlsProfile};

/// Base port the suite's main listener uses, before any offset.
const BASE_PORT: u16 = 44010;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vortice=debug,vortice_tls=debug".into()),
        )
        .init();

    let offset: u16 = std::env::args()
        .find_map(|arg| arg.strip_prefix("--offset-port=").map(str::to_owned))
        .map_or(Ok(0), |value| value.parse())?;
    let port = BASE_PORT + offset;

    // Generated rather than read from the suite: its own certificate is a 1024-bit RSA key
    // signed with SHA-1 that expired in 2021, none of which rustls will load.
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let tls = vortice_tls::server_config(
        issued.cert.pem().as_bytes(),
        issued.signing_key.serialize_pem().as_bytes(),
    )?;

    // The session after tuning starts again from nothing, so it has to offer the profiles the
    // client is about to use.
    let mut after = Config::new(Role::Listener);
    let mut uris: Vec<String> = regression_router().uris().map(str::to_owned).collect();
    uris.sort_unstable();
    for uri in &uris {
        after.greeting = after.greeting.clone().with_profile(uri.as_str());
    }

    let router = regression_router().profile(PROFILE_URI, TlsProfile::new(tls, after));

    let server = Server::bind_with(("0.0.0.0", port), Config::new(Role::Listener), router).await?;
    println!("Vortice TLS regression listener on port {port} (offset {offset})");
    server.serve().await?;
    Ok(())
}
