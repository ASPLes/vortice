// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Answering an upgrade request and running BEEP over what comes back.

use http::HeaderMap;
use http::header::{CONNECTION, UPGRADE};
use hyper::upgrade::OnUpgrade;
use vortice::{Config, Connection, Router};

use crate::error::Result;
use crate::{UPGRADE_TOKEN, error::Error};

/// Whether a request's headers ask to upgrade to BEEP.
///
/// Both halves are required and both are matched case-insensitively, since HTTP field values
/// are not case sensitive and `Connection` is a comma separated list that may carry more than
/// `upgrade` alone.
#[must_use]
pub fn is_beep_upgrade(headers: &HeaderMap) -> bool {
    let connection_asks = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));

    let upgrade_names_beep = headers
        .get_all(UPGRADE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(UPGRADE_TOKEN));

    connection_asks && upgrade_names_beep
}

/// Runs a BEEP session over a connection hyper has upgraded.
///
/// Returns once the session ends. The upgraded stream already replays whatever hyper had
/// read past the request, so nothing is lost between the `101` and the greeting.
///
/// # Errors
///
/// Returns [`Error::Io`] if the upgrade never completes, and [`Error::Session`] if the
/// greeting exchange fails.
pub async fn serve_upgraded(on_upgrade: OnUpgrade, config: Config, router: Router) -> Result<()> {
    let upgraded = on_upgrade
        .await
        .map_err(|error| Error::Io(std::io::Error::other(format!("upgrade failed: {error}"))))?;
    let io = hyper_util::rt::TokioIo::new(upgraded);

    let connection = Connection::serve_io(io, config, router).await?;
    // Holding the handle is what keeps the session alive: dropping it would close it.
    connection.closed().await;
    Ok(())
}

#[cfg(feature = "axum")]
pub use self::extractor::BeepUpgrade;

#[cfg(feature = "axum")]
mod extractor {
    use axum::extract::FromRequestParts;
    use axum::response::{IntoResponse, Response};
    use http::{StatusCode, request::Parts};
    use hyper::upgrade::OnUpgrade;
    use vortice::{Config, Router};

    use super::{is_beep_upgrade, serve_upgraded};
    use crate::UPGRADE_TOKEN;

    /// An axum extractor for a BEEP upgrade request.
    ///
    /// Structurally the same thing as `axum::extract::ws::WebSocketUpgrade`: it validates the
    /// headers, takes the pending upgrade out of the request, and answers `101` while handing
    /// the socket to a callback.
    #[derive(Debug)]
    pub struct BeepUpgrade {
        on_upgrade: OnUpgrade,
    }

    /// Why a request could not be treated as a BEEP upgrade.
    #[derive(Debug, Clone, Copy)]
    pub struct NotAnUpgrade {
        reason: &'static str,
    }

    impl IntoResponse for NotAnUpgrade {
        fn into_response(self) -> Response {
            (StatusCode::BAD_REQUEST, self.reason).into_response()
        }
    }

    impl<S: Send + Sync> FromRequestParts<S> for BeepUpgrade {
        type Rejection = NotAnUpgrade;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            if !is_beep_upgrade(&parts.headers) {
                return Err(NotAnUpgrade {
                    reason: "expected Connection: Upgrade and Upgrade: BEEP",
                });
            }
            // Taking it rather than cloning is deliberate: only one place may drive an
            // upgrade, and leaving it behind would let a second extractor try.
            let on_upgrade = parts.extensions.remove::<OnUpgrade>().ok_or(NotAnUpgrade {
                reason: "this connection cannot be upgraded",
            })?;
            Ok(Self { on_upgrade })
        }
    }

    impl BeepUpgrade {
        /// Answers `101` and serves `router` over the upgraded connection.
        ///
        /// The response has to be returned to axum: the upgrade only happens once axum has
        /// written it, so the session task starts by waiting for that.
        #[must_use]
        pub fn serve(self, config: Config, router: Router) -> Response {
            self.on_upgrade(|on_upgrade| async move {
                // A session that ends badly is the caller's business; `on_upgrade` exists
                // for callers that want to observe it.
                let _ = serve_upgraded(on_upgrade, config, router).await;
            })
        }

        /// Answers `101` and hands the pending upgrade to a callback.
        ///
        /// Use this when the session needs more setting up than [`BeepUpgrade::serve`] does.
        #[must_use]
        pub fn on_upgrade<F, Fut>(self, callback: F) -> Response
        where
            F: FnOnce(OnUpgrade) -> Fut + Send + 'static,
            Fut: Future<Output = ()> + Send + 'static,
        {
            tokio::spawn(callback(self.on_upgrade));

            Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(http::header::CONNECTION, "upgrade")
                .header(http::header::UPGRADE, UPGRADE_TOKEN)
                .body(axum::body::Body::empty())
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}
