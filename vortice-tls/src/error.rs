// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! What can go wrong negotiating TLS on a BEEP session.

use core::fmt;

/// The result of a TLS negotiation.
pub type Result<T> = core::result::Result<T, Error>;

/// Why a BEEP session could not be tuned for TLS.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The peer does not offer the TLS profile in its greeting.
    NotOffered,
    /// The peer refused the channel that carries the negotiation.
    Refused(vortice::ErrorReply),
    /// The peer answered the offer with something other than `<proceed />`.
    ///
    /// RFC3080 §3.1 allows an `<error/>` here, which is a peer declining to tune rather than
    /// a failure of the session.
    NotProceeding(String),
    /// The TLS handshake itself failed.
    Handshake(std::io::Error),
    /// The session failed, before or after the handshake.
    Session(vortice::Error),
    /// A certificate or key could not be read.
    Certificate(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOffered => write!(
                formatter,
                "the peer's greeting does not offer the TLS profile"
            ),
            Self::Refused(error) => {
                write!(formatter, "the peer refused the TLS channel: {error:?}")
            }
            Self::NotProceeding(answer) => {
                write!(
                    formatter,
                    "the peer answered {answer:?} instead of proceeding"
                )
            }
            Self::Handshake(error) => write!(formatter, "the TLS handshake failed: {error}"),
            Self::Session(error) => write!(formatter, "beep session failed: {error}"),
            Self::Certificate(reason) => write!(formatter, "{reason}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Handshake(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::NotOffered | Self::Refused(_) | Self::NotProceeding(_) | Self::Certificate(_) => {
                None
            }
        }
    }
}

impl From<vortice::Error> for Error {
    fn from(error: vortice::Error) -> Self {
        match error {
            vortice::Error::Refused(reply) => Self::Refused(reply),
            other => Self::Session(other),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Handshake(error)
    }
}
