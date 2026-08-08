// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Errors from the upgrade handshake.

use std::fmt;
use std::io;

/// Anything that can go wrong reaching BEEP through an HTTP upgrade.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The transport failed.
    Io(io::Error),

    /// The BEEP session itself failed, once the upgrade had completed.
    Session(vortice::Error),

    /// The peer answered something other than `101 Switching Protocols`.
    NotUpgraded {
        /// The status it answered with, if the response could be parsed at all.
        status: Option<u16>,
    },

    /// The response was not a response.
    MalformedResponse {
        /// What was expected at the point the parse failed.
        reason: &'static str,
    },

    /// The peer's `101` did not name BEEP in its `Upgrade` header.
    ///
    /// Continuing would mean speaking BEEP at something that agreed to speak
    /// something else.
    WrongProtocol,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "transport error: {error}"),
            Self::Session(error) => write!(f, "session error: {error}"),
            Self::NotUpgraded {
                status: Some(status),
            } => write!(f, "expected 101 Switching Protocols, got {status}"),
            Self::NotUpgraded { status: None } => {
                f.write_str("expected 101 Switching Protocols, got an unreadable status")
            }
            Self::MalformedResponse { reason } => write!(f, "malformed HTTP response: {reason}"),
            Self::WrongProtocol => {
                write!(
                    f,
                    "the peer upgraded to something other than {}",
                    crate::UPGRADE_TOKEN
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Session(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<vortice::Error> for Error {
    fn from(error: vortice::Error) -> Self {
        Self::Session(error)
    }
}

/// Shorthand for the results this crate returns.
pub type Result<T> = std::result::Result<T, Error>;
