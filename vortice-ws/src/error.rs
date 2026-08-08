// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! What can go wrong carrying BEEP over WebSocket.

use core::fmt;

use crate::frame::ProtocolError;

/// The result of a WebSocket transport operation.
pub type Result<T> = core::result::Result<T, Error>;

/// Why a BEEP session over WebSocket could not be established or kept.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The transport underneath failed.
    Io(std::io::Error),
    /// The BEEP session itself failed, once the transport was up.
    Session(vortice::Error),
    /// The opening HTTP exchange was not a valid WebSocket handshake.
    Handshake {
        /// What was wrong with it.
        reason: &'static str,
    },
    /// The server answered the handshake with something other than `101`.
    NotUpgraded {
        /// The status it gave, absent if the status line could not be read.
        status: Option<u16>,
    },
    /// The peer's framing is one RFC6455 does not allow.
    Protocol(ProtocolError),
    /// The operating system had no randomness for a masking key or a handshake nonce.
    ///
    /// RFC6455 §5.3 requires masking keys to be unpredictable, so there is no fallback here
    /// worth having: a predictable key would be worse than a refused connection.
    Entropy,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "websocket transport failed: {error}"),
            Self::Session(error) => write!(formatter, "beep session failed: {error}"),
            Self::Handshake { reason } => write!(formatter, "websocket handshake failed: {reason}"),
            Self::NotUpgraded { status: Some(code) } => {
                write!(formatter, "server answered {code} instead of 101")
            }
            Self::NotUpgraded { status: None } => {
                write!(formatter, "the server's answer had no readable status")
            }
            Self::Protocol(error) => write!(formatter, "websocket framing error: {error}"),
            Self::Entropy => write!(
                formatter,
                "the operating system had no randomness for a websocket masking key"
            ),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Handshake { .. } | Self::NotUpgraded { .. } | Self::Entropy => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<vortice::Error> for Error {
    fn from(error: vortice::Error) -> Self {
        Self::Session(error)
    }
}

impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}
