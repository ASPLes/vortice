// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Errors surfaced by the async layer.

use std::fmt;
use std::io;

use vortice_proto::management::ErrorReply;

/// Anything that can go wrong on a session.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The transport failed.
    Io(io::Error),

    /// The peer violated the protocol. Fatal: the session is closed.
    Protocol(vortice_proto::Error),

    /// The peer refused a request, with the code and text it gave.
    Refused(ErrorReply),

    /// The session ended before the operation could finish.
    ///
    /// Either the peer closed it, the transport died, or the driver task was dropped.
    Closed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "transport error: {error}"),
            Self::Protocol(error) => write!(f, "protocol error: {error}"),
            Self::Refused(reply) => match &reply.text {
                Some(text) => write!(f, "peer refused with code {}: {text}", reply.code),
                None => write!(f, "peer refused with code {}", reply.code),
            },
            Self::Closed => f.write_str("the session is closed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Refused(_) | Self::Closed => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<vortice_proto::Error> for Error {
    fn from(error: vortice_proto::Error) -> Self {
        Self::Protocol(error)
    }
}

/// Shorthand for the results this crate returns.
pub type Result<T> = std::result::Result<T, Error>;
