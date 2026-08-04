// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Minimal MIME splitting for BEEP payloads.
//!
//! A BEEP payload is MIME: entity headers, a blank line, then the body. This module does
//! only what channel-management messages need — separate the two halves and look a header
//! up. Full MIME handling (multi-line headers, parameter parsing, transfer encodings,
//! everything LibVortex `test_01d` exercises in its seven sub-cases) belongs to a later
//! phase and to a layer above this one.
//!
//! Both LibVortex defaults are reproduced here: a payload with no headers is all body, and
//! `Content-Type` defaults to [`DEFAULT_CONTENT_TYPE`], which is why LibVortex omits the
//! header entirely when it would carry that value.

/// The `Content-Type` entity header name.
pub const CONTENT_TYPE: &str = "Content-Type";

/// The content type assumed when no `Content-Type` header is present.
pub const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

/// The content type BEEP channel-management messages use.
pub const BEEP_XML: &str = "application/beep+xml";

/// Splits a payload into its entity headers and its body.
///
/// Three shapes are recognised, matching what LibVortex produces:
///
/// - `headers CRLF CRLF body` — the normal case, headers are returned without the blank line;
/// - `CRLF body` — MIME enabled but no headers to emit, so the payload opens with the blank line;
/// - anything else — no MIME structure at all, the whole payload is the body.
///
/// ```
/// use vortice_proto::mime;
///
/// let (headers, body) = mime::split(b"Content-Type: application/beep+xml\r\n\r\n<greeting />");
/// assert_eq!(headers, b"Content-Type: application/beep+xml");
/// assert_eq!(body, b"<greeting />");
///
/// assert_eq!(mime::split(b"\r\nraw"), (&b""[..], &b"raw"[..]));
/// assert_eq!(mime::split(b"raw"), (&b""[..], &b"raw"[..]));
/// ```
#[must_use]
pub fn split(payload: &[u8]) -> (&[u8], &[u8]) {
    if let Some(body) = payload.strip_prefix(b"\r\n") {
        return (&[], body);
    }
    match find_subslice(payload, b"\r\n\r\n") {
        Some(i) => (&payload[..i], &payload[i + 4..]),
        None => (&[], payload),
    }
}

/// Looks a header up by name, case-insensitively, returning its trimmed value.
///
/// `headers` is the first half of a [`split`] result.
///
/// ```
/// use vortice_proto::mime;
///
/// let headers = b"Content-Type: application/beep+xml\r\nContent-Transfer-Encoding: binary";
/// assert_eq!(mime::header(headers, "content-type"), Some(&b"application/beep+xml"[..]));
/// assert_eq!(mime::header(headers, "X-Absent"), None);
/// ```
#[must_use]
pub fn header<'a>(headers: &'a [u8], name: &str) -> Option<&'a [u8]> {
    for line in split_lines(headers) {
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (found, value) = line.split_at(colon);
        if found.eq_ignore_ascii_case(name.as_bytes()) {
            return Some(trim(&value[1..]));
        }
    }
    None
}

/// The content type of a payload, falling back to [`DEFAULT_CONTENT_TYPE`].
///
/// This mirrors `vortex_frame_get_content_type`, which never returns an absent value.
#[must_use]
pub fn content_type(payload: &[u8]) -> &[u8] {
    let (headers, _) = split(payload);
    header(headers, CONTENT_TYPE).unwrap_or(DEFAULT_CONTENT_TYPE.as_bytes())
}

fn split_lines(headers: &[u8]) -> impl Iterator<Item = &[u8]> {
    headers
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
}

fn trim(mut value: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = value {
        if first.is_ascii_whitespace() {
            value = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = value {
        if last.is_ascii_whitespace() {
            value = rest;
        } else {
            break;
        }
    }
    value
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_headers_from_body() {
        let (headers, body) = split(b"Content-Type: application/beep+xml\r\n\r\n<greeting />");
        assert_eq!(headers, b"Content-Type: application/beep+xml");
        assert_eq!(body, b"<greeting />");
    }

    #[test]
    fn treats_a_leading_blank_line_as_empty_headers() {
        assert_eq!(split(b"\r\npayload"), (&b""[..], &b"payload"[..]));
        assert_eq!(split(b"\r\n"), (&b""[..], &b""[..]));
    }

    #[test]
    fn treats_a_payload_without_mime_structure_as_all_body() {
        assert_eq!(split(b"just bytes"), (&b""[..], &b"just bytes"[..]));
        assert_eq!(split(b""), (&b""[..], &b""[..]));
    }

    #[test]
    fn keeps_crlf_pairs_inside_the_body() {
        let (headers, body) = split(b"A: b\r\n\r\nfirst\r\n\r\nsecond");
        assert_eq!(headers, b"A: b");
        assert_eq!(body, b"first\r\n\r\nsecond");
    }

    #[test]
    fn finds_headers_case_insensitively() {
        let headers = b"Content-Type: application/beep+xml\r\nContent-Transfer-Encoding: binary";
        assert_eq!(
            header(headers, "content-type"),
            Some(&b"application/beep+xml"[..])
        );
        assert_eq!(
            header(headers, "CONTENT-TRANSFER-ENCODING"),
            Some(&b"binary"[..])
        );
        assert_eq!(header(headers, "Content"), None);
    }

    #[test]
    fn defaults_the_content_type_the_way_libvortex_does() {
        assert_eq!(
            content_type(b"raw payload"),
            DEFAULT_CONTENT_TYPE.as_bytes()
        );
        assert_eq!(
            content_type(b"Content-Type: application/beep+xml\r\n\r\n<greeting />"),
            BEEP_XML.as_bytes()
        );
    }
}
