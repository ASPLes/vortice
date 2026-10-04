// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The `<blob>` element the SASL profiles exchange, RFC3080 §4.1.
//!
//! The whole wire format of these profiles is this one element. Everything a mechanism has to
//! say travels inside it, Base64 encoded, and the `status` attribute says what the exchange
//! is doing rather than what the mechanism said:
//!
//! ```text
//! <blob>aW5pdGlhbA==</blob>                 the client's first move, piggybacked on the start
//! <blob status='continue'>Y2hhbGw=</blob>   the server wants another round
//! <blob status='complete' />                it is satisfied
//! <blob status='abort' />                   either end is giving up
//! ```
//!
//! Written by hand rather than through the XML writer in `vortice-proto`, because what
//! LibVortex emits and accepts is this exact shape and nothing broader: a single element, an
//! attribute in single quotes, and content that is either absent — in which case the element
//! is self-closing — or Base64. Reading is correspondingly forgiving about whitespace and
//! quoting and strict about everything else.

use vortice_proto::base64;

/// Where an exchange has got to, from the `status` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// No attribute at all, which is what a client's blob carries.
    None,
    /// Another round is expected.
    Continue,
    /// The exchange succeeded.
    Complete,
    /// The sender is abandoning the exchange.
    Abort,
}

impl Status {
    /// The attribute value, or `None` when there is no attribute to write.
    const fn attribute(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Continue => Some("continue"),
            Self::Complete => Some("complete"),
            Self::Abort => Some("abort"),
        }
    }

    /// The status an attribute value names.
    fn parse(value: &str) -> Option<Self> {
        match value {
            "continue" => Some(Self::Continue),
            "complete" => Some(Self::Complete),
            "abort" => Some(Self::Abort),
            _ => None,
        }
    }
}

/// One `<blob>`: a status and whatever octets the mechanism is carrying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    /// What the exchange is doing.
    pub status: Status,
    /// The mechanism's own data, already decoded.
    pub data: Vec<u8>,
}

impl Blob {
    /// A blob carrying `data` and no status, which is what a client sends.
    #[must_use]
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self {
            status: Status::None,
            data: data.into(),
        }
    }

    /// A blob carrying `status` and nothing else.
    #[must_use]
    pub const fn status(status: Status) -> Self {
        Self {
            status,
            data: Vec::new(),
        }
    }

    /// A blob carrying both.
    #[must_use]
    pub fn with_status(status: Status, data: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            data: data.into(),
        }
    }

    /// Renders the element, Base64 encoding the data.
    #[must_use]
    pub fn to_xml(&self) -> String {
        let mut out = String::from("<blob");
        if let Some(status) = self.status.attribute() {
            out.push_str(" status='");
            out.push_str(status);
            out.push('\'');
        }
        if self.data.is_empty() {
            out.push_str(" />");
        } else {
            out.push('>');
            out.push_str(&base64::encode(&self.data));
            out.push_str("</blob>");
        }
        out
    }

    /// Reads an element a peer sent.
    ///
    /// # Errors
    ///
    /// Returns [`NotABlob`] when the text is not a single `<blob>` element, when its status is
    /// not one RFC3080 defines, or when its content is not Base64.
    pub fn from_xml(text: &str) -> Result<Self, NotABlob> {
        let text = text.trim();
        let rest = text.strip_prefix("<blob").ok_or(NotABlob)?;

        // Up to the end of the open tag: either `/>` or `>`.
        let (head, body) = match rest.find('>') {
            Some(at) => (&rest[..at], &rest[at + 1..]),
            None => return Err(NotABlob),
        };
        let self_closing = head.trim_end().ends_with('/');
        let head = head.trim_end().trim_end_matches('/');

        let status = match attribute(head, "status") {
            Some(value) => Status::parse(&value).ok_or(NotABlob)?,
            None => Status::None,
        };

        if self_closing {
            if !body.trim().is_empty() {
                return Err(NotABlob);
            }
            return Ok(Self {
                status,
                data: Vec::new(),
            });
        }

        let content = body.strip_suffix("</blob>").ok_or(NotABlob)?;
        let data = base64::decode(content.trim()).map_err(|_| NotABlob)?;
        Ok(Self { status, data })
    }
}

/// What [`Blob::from_xml`] reports for anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotABlob;

impl core::fmt::Display for NotABlob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("not a SASL <blob> element")
    }
}

impl core::error::Error for NotABlob {}

/// The value of `name` in an open tag, accepting either kind of quote.
fn attribute(head: &str, name: &str) -> Option<String> {
    let at = head.find(name)?;
    let rest = head[at + name.len()..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let quote = rest.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let rest = &rest[quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::{Blob, NotABlob, Status};

    /// Verbatim from `__build_blob_reply` in `sasl/vortex_sasl.c`: this is the shape the
    /// reference implementation writes, and what it will be reading back.
    #[test]
    fn writes_what_libvortex_writes() {
        assert_eq!(
            Blob::new(b"initial".to_vec()).to_xml(),
            "<blob>aW5pdGlhbA==</blob>"
        );
        assert_eq!(
            Blob::status(Status::Complete).to_xml(),
            "<blob status='complete' />"
        );
        assert_eq!(
            Blob::with_status(Status::Continue, b"chall".to_vec()).to_xml(),
            "<blob status='continue'>Y2hhbGw=</blob>"
        );
        assert_eq!(Blob::status(Status::None).to_xml(), "<blob />");
    }

    #[test]
    fn reads_back_what_it_writes() {
        for blob in [
            Blob::new(b"initial".to_vec()),
            Blob::status(Status::Complete),
            Blob::status(Status::Abort),
            Blob::with_status(Status::Continue, b"chall".to_vec()),
            Blob::status(Status::None),
        ] {
            assert_eq!(Blob::from_xml(&blob.to_xml()), Ok(blob));
        }
    }

    /// A peer is not obliged to write it the way this crate does.
    #[test]
    fn reads_the_variations_a_peer_may_send() {
        assert_eq!(
            Blob::from_xml("<blob status=\"complete\"/>").expect("double quotes"),
            Blob::status(Status::Complete)
        );
        assert_eq!(
            Blob::from_xml("  <blob>Zm9v</blob>\r\n").expect("surrounding whitespace"),
            Blob::new(b"foo".to_vec())
        );
        assert_eq!(
            Blob::from_xml("<blob status = 'continue' >Zm9v</blob>").expect("spaced attribute"),
            Blob::with_status(Status::Continue, b"foo".to_vec())
        );
    }

    #[test]
    fn refuses_what_is_not_a_blob() {
        for bad in [
            "<error code='535'>nope</error>",
            "<blob status='maybe' />",
            "<blob>not base64!</blob>",
            "<blob>Zm9v",
            "<blob />trailing",
            "",
        ] {
            assert_eq!(Blob::from_xml(bad), Err(NotABlob), "{bad:?}");
        }
    }
}
