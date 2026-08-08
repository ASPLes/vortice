// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Asking an HTTP server to upgrade to BEEP.

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use vortice::{Config, Connection, Rewind};

use crate::UPGRADE_TOKEN;
use crate::error::{Error, Result};

/// Largest response head accepted, so a peer that never sends a blank line cannot make the
/// client read for ever.
const MAX_HEAD: usize = 16 * 1024;

/// Connects to `address`, upgrades `path` to BEEP and completes the greeting exchange.
///
/// The request is written by hand rather than through an HTTP client. An upgrade is one
/// request with no body whose whole purpose is to stop being HTTP, so a client that manages
/// connection pools, redirects and keep-alive has nothing to contribute and a great deal to
/// get in the way of.
///
/// ```no_run
/// # async fn example() -> vortice_http::Result<()> {
/// use vortice::{Config, Role};
///
/// let session = vortice_http::connect(
///     "127.0.0.1:8080",
///     "127.0.0.1:8080",
///     "/beep",
///     Config::new(Role::Initiator),
/// )
/// .await?;
/// # let _ = session;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`Error::NotUpgraded`] when the server answers anything but `101`,
/// [`Error::WrongProtocol`] when it upgrades to something that is not BEEP, and
/// [`Error::Session`] when the greeting exchange fails.
pub async fn connect(
    address: impl ToSocketAddrs,
    host: &str,
    path: &str,
    config: Config,
) -> Result<Connection> {
    let mut stream = TcpStream::connect(address).await?;
    stream.set_nodelay(true)?;

    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: {UPGRADE_TOKEN}\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let leftover = read_switching_protocols(&mut stream).await?;

    // Whatever arrived past the blank line is already BEEP: the server may well have sent
    // its greeting in the same segment as the 101.
    let io = Rewind::new(leftover, stream);
    Ok(Connection::from_io(io, config).await?)
}

/// Reads the response head, checks it is a BEEP upgrade, and returns what came after it.
async fn read_switching_protocols(stream: &mut TcpStream) -> Result<Bytes> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];

    let body_at = loop {
        if let Some(at) = find_blank_line(&head) {
            break at;
        }
        if head.len() > MAX_HEAD {
            return Err(Error::MalformedResponse {
                reason: "no blank line ending the response head",
            });
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(Error::MalformedResponse {
                reason: "connection closed before the response head was complete",
            });
        }
        head.extend_from_slice(&chunk[..read]);
    };

    let (head, rest) = head.split_at(body_at);
    let rest = Bytes::copy_from_slice(rest);

    let text = core::str::from_utf8(head).map_err(|_| Error::MalformedResponse {
        reason: "the response head is not text",
    })?;
    let mut lines = text.split("\r\n");

    let status_line = lines.next().ok_or(Error::MalformedResponse {
        reason: "empty response",
    })?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok());
    if status != Some(101) {
        return Err(Error::NotUpgraded { status });
    }

    let names_beep = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("upgrade"))
        .flat_map(|(_, value)| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(UPGRADE_TOKEN));
    if !names_beep {
        return Err(Error::WrongProtocol);
    }

    Ok(rest)
}

/// The offset just past the `CRLF CRLF` that ends a response head.
fn find_blank_line(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

#[cfg(test)]
mod tests {
    use super::find_blank_line;

    #[test]
    fn finds_the_end_of_a_response_head() {
        assert_eq!(find_blank_line(b"HTTP/1.1 101\r\n\r\n"), Some(16));
        assert_eq!(find_blank_line(b"HTTP/1.1 101\r\n\r\nRPY 0 0"), Some(16));
    }

    #[test]
    fn reports_an_incomplete_head() {
        assert_eq!(find_blank_line(b"HTTP/1.1 101\r\n"), None);
        assert_eq!(find_blank_line(b""), None);
    }
}
