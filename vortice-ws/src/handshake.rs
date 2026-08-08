// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The opening HTTP exchange of RFC6455 §4.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::digest::{base64, sha1};
use crate::error::{Error, Result};

/// The constant RFC6455 §1.3 appends to the client key before hashing.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Largest handshake head accepted, so a peer that never sends a blank line cannot make us
/// read for ever.
const MAX_HEAD: usize = 16 * 1024;

/// The value of `Sec-WebSocket-Accept` answering a given `Sec-WebSocket-Key`.
///
/// ```
/// // The worked example of RFC6455 §1.3.
/// assert_eq!(
///     vortice_ws::accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
///     "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
/// );
/// ```
#[must_use]
pub fn accept_key(client_key: &str) -> String {
    let mut salted = String::with_capacity(client_key.len() + GUID.len());
    salted.push_str(client_key);
    salted.push_str(GUID);
    base64(&sha1(salted.as_bytes()))
}

/// Sixteen unpredictable octets, Base64 encoded, for `Sec-WebSocket-Key`.
///
/// # Errors
///
/// Returns [`Error::Entropy`] if the operating system has no randomness to give.
pub(crate) fn client_key() -> Result<String> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| Error::Entropy)?;
    Ok(base64(&nonce))
}

/// What a peer asked for in its handshake request.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    /// The `Sec-WebSocket-Key` to answer.
    pub(crate) key: String,
}

/// The request a client sends to open a WebSocket.
pub(crate) fn request(path: &str, host: &str, key: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    )
}

/// The `101` a server answers a valid request with.
pub(crate) fn response(key: &str) -> String {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        accept_key(key)
    )
}

/// Checks a client's request and pulls out what answering it needs.
pub(crate) fn parse_request(head: &str) -> Result<Request> {
    let mut lines = head.split("\r\n");

    let request_line = lines.next().unwrap_or_default();
    if !request_line
        .split_whitespace()
        .next()
        .is_some_and(|method| method == "GET")
    {
        return Err(Error::Handshake {
            reason: "a websocket handshake must be a GET",
        });
    }

    let headers: Vec<(&str, &str)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim(), value.trim()))
        .collect();

    /// Whether a header's comma separated value contains a token.
    fn names(headers: &[(&str, &str)], header: &str, token: &str) -> bool {
        headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(header))
            .flat_map(|(_, value)| value.split(','))
            .any(|candidate| candidate.trim().eq_ignore_ascii_case(token))
    }

    if !names(&headers, "upgrade", "websocket") {
        return Err(Error::Handshake {
            reason: "the request does not ask to upgrade to websocket",
        });
    }
    if !names(&headers, "connection", "upgrade") {
        return Err(Error::Handshake {
            reason: "the request is missing Connection: Upgrade",
        });
    }
    if !names(&headers, "sec-websocket-version", "13") {
        // Answering a version we do not speak with a session would be worse than refusing:
        // §4.4 says to name the versions we do support instead.
        return Err(Error::Handshake {
            reason: "only websocket version 13 is supported",
        });
    }

    let key = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-key"))
        .map(|(_, value)| (*value).to_owned())
        .ok_or(Error::Handshake {
            reason: "the request is missing Sec-WebSocket-Key",
        })?;

    Ok(Request { key })
}

/// Checks the server's answer against the key we sent.
pub(crate) fn parse_response(head: &str, sent_key: &str) -> Result<()> {
    let mut lines = head.split("\r\n");

    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok());
    if status != Some(101) {
        return Err(Error::NotUpgraded { status });
    }

    let expected = accept_key(sent_key);
    let accepted = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("sec-websocket-accept"))
        .any(|(_, value)| value.trim() == expected);

    if accepted {
        Ok(())
    } else {
        // A `101` whose accept key does not match means something on the path answered a
        // handshake it did not understand, which is exactly what the key exists to catch.
        Err(Error::Handshake {
            reason: "the server's Sec-WebSocket-Accept does not answer our key",
        })
    }
}

/// Reads up to and including the blank line ending an HTTP head.
///
/// Returns the head as text and whatever was read past it, which belongs to the peer's first
/// frame and must not be dropped.
pub(crate) async fn read_head<T: AsyncRead + Unpin>(
    io: &mut T,
    seed: BytesMut,
) -> Result<(String, Bytes)> {
    let mut buffer = seed;
    let mut chunk = [0u8; 1024];

    let end = loop {
        if let Some(at) = find_blank_line(&buffer) {
            break at;
        }
        if buffer.len() > MAX_HEAD {
            return Err(Error::Handshake {
                reason: "no blank line ending the handshake head",
            });
        }
        let read = io.read(&mut chunk).await?;
        if read == 0 {
            return Err(Error::Handshake {
                reason: "the connection closed before the handshake head was complete",
            });
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let head = buffer.split_to(end);
    let head = core::str::from_utf8(&head)
        .map_err(|_| Error::Handshake {
            reason: "the handshake head is not text",
        })?
        .to_owned();

    Ok((head, buffer.freeze()))
}

/// The offset just past the `CRLF CRLF` that ends an HTTP head.
fn find_blank_line(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

#[cfg(test)]
mod tests {
    use super::{accept_key, find_blank_line, parse_request, parse_response, request, response};
    use crate::error::Error;

    #[test]
    fn answers_the_rfc6455_worked_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn accepts_a_well_formed_request() {
        let head = request("/beep", "example.com:8080", "dGhlIHNhbXBsZSBub25jZQ==");
        let parsed = parse_request(&head).expect("a valid handshake");
        assert_eq!(parsed.key, "dGhlIHNhbXBsZSBub25jZQ==");
    }

    /// Field names and the tokens in them are case insensitive, and `Connection` is a list.
    #[test]
    fn accepts_the_spellings_a_peer_may_use() {
        let head = "GET / HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    UPGRADE: WebSocket\r\n\
                    Connection: keep-alive, Upgrade\r\n\
                    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                    Sec-WebSocket-Version: 13\r\n";
        assert!(parse_request(head).is_ok());
    }

    #[test]
    fn refuses_a_request_that_is_missing_a_piece() {
        let complete = "GET / HTTP/1.1\r\n\
                        Upgrade: websocket\r\n\
                        Connection: Upgrade\r\n\
                        Sec-WebSocket-Key: k\r\n\
                        Sec-WebSocket-Version: 13\r\n";

        for dropped in ["Upgrade:", "Connection:", "Sec-WebSocket-Key:"] {
            let head: String = complete
                .split("\r\n")
                .filter(|line| !line.starts_with(dropped))
                .collect::<Vec<_>>()
                .join("\r\n");
            assert!(
                matches!(parse_request(&head), Err(Error::Handshake { .. })),
                "a request without {dropped} should be refused"
            );
        }
    }

    #[test]
    fn refuses_a_version_it_does_not_speak() {
        let head = "GET / HTTP/1.1\r\n\
                    Upgrade: websocket\r\n\
                    Connection: Upgrade\r\n\
                    Sec-WebSocket-Key: k\r\n\
                    Sec-WebSocket-Version: 8\r\n";
        assert!(matches!(parse_request(head), Err(Error::Handshake { .. })));
    }

    #[test]
    fn refuses_a_method_other_than_get() {
        let head = "POST / HTTP/1.1\r\nUpgrade: websocket\r\n";
        assert!(matches!(parse_request(head), Err(Error::Handshake { .. })));
    }

    #[test]
    fn a_response_answers_its_own_request() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        assert!(parse_response(&response(key), key).is_ok());
    }

    #[test]
    fn refuses_a_response_answering_a_different_key() {
        let answer = response("c29tZSBvdGhlciBrZXk=");
        assert!(matches!(
            parse_response(&answer, "dGhlIHNhbXBsZSBub25jZQ=="),
            Err(Error::Handshake { .. })
        ));
    }

    #[test]
    fn reports_a_status_that_is_not_a_switch() {
        let answer = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n";
        assert!(matches!(
            parse_response(answer, "k"),
            Err(Error::NotUpgraded { status: Some(404) })
        ));
    }

    #[test]
    fn finds_the_end_of_a_head() {
        assert_eq!(find_blank_line(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(find_blank_line(b"GET / HTTP/1.1\r\n"), None);
    }
}
