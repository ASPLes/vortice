// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The greeting exchange on channel 0.
//!
//! Both peers announce themselves immediately after the transport is established, each
//! sending an `RPY` on channel 0 with message number 0 and sequence number 0, carrying
//! `Content-Type: application/beep+xml` and a `<greeting>` element listing the profiles it
//! is willing to serve.
//!
//! The wire layout produced by [`Greeting::to_payload`] is byte-for-byte the one
//! `__vortex_greetings_build_message` produces, so a capture taken from either
//! implementation can be replayed against the other.
//!
//! ```text
//! Content-Type: application/beep+xml
//!
//! <greeting>
//!    <profile uri='http://iana.org/beep/transient/vortex-regression' />
//! </greeting>
//! ```

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use bytes::Bytes;

use crate::error::Error;
use crate::frame::{DataFrame, FrameKind};
use crate::{mime, xml};

/// The channel every greeting is exchanged on.
pub const GREETING_CHANNEL: u32 = 0;

/// The profiles a peer advertises, plus the optional negotiation attributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Greeting {
    profiles: Vec<String>,
    features: Option<String>,
    localize: Option<String>,
}

impl Greeting {
    /// An empty greeting, advertising no profiles.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Advertises one more profile URI.
    #[must_use]
    pub fn with_profile(mut self, uri: impl Into<String>) -> Self {
        self.profiles.push(uri.into());
        self
    }

    /// Sets the `features` attribute, listing optional feature tokens.
    #[must_use]
    pub fn with_features(mut self, features: impl Into<String>) -> Self {
        self.features = Some(features.into());
        self
    }

    /// Sets the `localize` attribute, listing preferred language tags.
    #[must_use]
    pub fn with_localize(mut self, localize: impl Into<String>) -> Self {
        self.localize = Some(localize.into());
        self
    }

    /// The advertised profile URIs, in the order they appeared.
    #[must_use]
    pub fn profiles(&self) -> &[String] {
        &self.profiles
    }

    /// Whether a given profile URI is advertised.
    #[must_use]
    pub fn advertises(&self, uri: &str) -> bool {
        self.profiles.iter().any(|profile| profile == uri)
    }

    /// The `features` attribute, if any.
    #[must_use]
    pub fn features(&self) -> Option<&str> {
        self.features.as_deref()
    }

    /// The `localize` attribute, if any.
    #[must_use]
    pub fn localize(&self) -> Option<&str> {
        self.localize.as_deref()
    }

    /// Renders the greeting as a BEEP payload, MIME headers included.
    #[must_use]
    pub fn to_payload(&self) -> Bytes {
        let mut out = String::new();
        out.push_str(mime::CONTENT_TYPE);
        out.push_str(": ");
        out.push_str(mime::BEEP_XML);
        out.push_str("\r\n\r\n<greeting");
        if let Some(features) = &self.features {
            push_attr(&mut out, "features", features);
        }
        if let Some(localize) = &self.localize {
            push_attr(&mut out, "localize", localize);
        }
        if self.profiles.is_empty() {
            out.push_str(" />\r\n");
        } else {
            out.push_str(">\r\n");
            for uri in &self.profiles {
                out.push_str("   <profile uri='");
                xml::escape(&mut out, uri);
                out.push_str("' />\r\n");
            }
            out.push_str("</greeting>\r\n");
        }
        Bytes::from(out)
    }

    /// Builds the frame that carries this greeting, at the given sequence number.
    ///
    /// The sequence number is zero for the greeting itself; the parameter exists because a
    /// session that has already sent octets on channel 0 must continue from where it was.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FrameTooLarge`] if the rendered greeting exceeds the maximum frame
    /// size, which requires an implausible number of advertised profiles.
    pub fn to_frame(&self, seqno: u32) -> Result<DataFrame, Error> {
        DataFrame::new(
            FrameKind::Rpy,
            GREETING_CHANNEL,
            0,
            seqno,
            self.to_payload(),
        )
    }

    /// Parses a greeting from a BEEP payload, MIME headers included.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotBeepXml`] when the payload does not declare
    /// `Content-Type: application/beep+xml`, which LibVortex treats as fatal, and
    /// [`Error::UnexpectedElement`] when the root element is not `<greeting>`.
    pub fn from_payload(payload: &[u8]) -> Result<Self, Error> {
        let (headers, body) = mime::split(payload);
        let content_type = mime::header(headers, mime::CONTENT_TYPE).ok_or(Error::NotBeepXml)?;
        if !content_type.eq_ignore_ascii_case(mime::BEEP_XML.as_bytes()) {
            return Err(Error::NotBeepXml);
        }

        let root = xml::parse(body)?;
        if root.name != "greeting" {
            return Err(Error::UnexpectedElement);
        }
        Ok(Self {
            profiles: root
                .children_named("profile")
                .filter_map(|child| child.attr("uri"))
                .map(ToOwned::to_owned)
                .collect(),
            features: root.attr("features").map(ToOwned::to_owned),
            localize: root.attr("localize").map(ToOwned::to_owned),
        })
    }

    /// Parses a greeting from the frame that carried it, validating the frame shape.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAGreeting`] unless the frame is a complete `RPY` on channel 0
    /// with message number 0 and sequence number 0, the checks LibVortex performs in
    /// `vortex_greetings.c` before looking at the payload at all. Otherwise as
    /// [`Greeting::from_payload`].
    pub fn from_frame(frame: &DataFrame) -> Result<Self, Error> {
        if frame.kind() != FrameKind::Rpy {
            return Err(Error::NotAGreeting {
                reason: "expected an RPY frame",
            });
        }
        if frame.channel() != GREETING_CHANNEL {
            return Err(Error::NotAGreeting {
                reason: "expected channel 0",
            });
        }
        if frame.msgno() != 0 {
            return Err(Error::NotAGreeting {
                reason: "expected message number 0",
            });
        }
        if frame.seqno() != 0 {
            return Err(Error::NotAGreeting {
                reason: "expected sequence number 0",
            });
        }
        if frame.more() {
            return Err(Error::NotAGreeting {
                reason: "expected a complete frame",
            });
        }
        Self::from_payload(frame.payload())
    }
}

fn push_attr(out: &mut String, name: &str, value: &str) {
    out.push(' ');
    out.push_str(name);
    out.push_str("='");
    xml::escape(out, value);
    out.push('\'');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decoder;
    use bytes::BytesMut;

    #[test]
    fn renders_an_empty_greeting_the_way_libvortex_does() {
        let payload = Greeting::new().to_payload();
        assert_eq!(
            &payload[..],
            b"Content-Type: application/beep+xml\r\n\r\n<greeting />\r\n"
        );
    }

    #[test]
    fn renders_advertised_profiles_the_way_libvortex_does() {
        let payload = Greeting::new()
            .with_profile("urn:example:one")
            .with_profile("urn:example:two")
            .to_payload();
        assert_eq!(
            &payload[..],
            b"Content-Type: application/beep+xml\r\n\r\n\
              <greeting>\r\n   <profile uri='urn:example:one' />\r\n\
              \x20  <profile uri='urn:example:two' />\r\n</greeting>\r\n"
        );
    }

    #[test]
    fn renders_the_negotiation_attributes_in_libvortex_order() {
        let payload = Greeting::new()
            .with_features("x-foo")
            .with_localize("es-ES")
            .to_payload();
        assert_eq!(
            &payload[..],
            b"Content-Type: application/beep+xml\r\n\r\n\
              <greeting features='x-foo' localize='es-ES' />\r\n"
        );
    }

    #[test]
    fn round_trips_through_a_frame_and_the_decoder() {
        let greeting = Greeting::new()
            .with_profile("http://iana.org/beep/transient/vortex-regression")
            .with_profile("http://iana.org/beep/transient/vortex-regression/zero")
            .with_localize("es-ES");

        let mut buf = BytesMut::new();
        greeting.to_frame(0).unwrap().encode(&mut buf);

        let frame = Decoder::new().decode(&mut buf).unwrap().unwrap();
        let parsed = Greeting::from_frame(frame.as_data().unwrap()).unwrap();
        assert_eq!(parsed, greeting);
        assert!(parsed.advertises("http://iana.org/beep/transient/vortex-regression/zero"));
        assert!(!parsed.advertises("urn:absent"));
    }

    #[test]
    fn parses_a_greeting_produced_by_libvortex() {
        // Exactly the octets __vortex_greetings_build_message emits for one profile.
        let payload = b"Content-Type: application/beep+xml\r\n\r\n\
                        <greeting>\r\n   <profile uri='urn:example:echo' />\r\n</greeting>\r\n";
        let greeting = Greeting::from_payload(payload).unwrap();
        assert_eq!(greeting.profiles(), ["urn:example:echo"]);
        assert_eq!(greeting.features(), None);
    }

    #[test]
    fn parses_a_greeting_with_no_profiles() {
        let payload = b"Content-Type: application/beep+xml\r\n\r\n<greeting />\r\n";
        assert!(
            Greeting::from_payload(payload)
                .unwrap()
                .profiles()
                .is_empty()
        );
    }

    #[test]
    fn escapes_markup_in_profile_uris() {
        let greeting = Greeting::new().with_profile("urn:a&b<c>'d\"");
        let parsed = Greeting::from_payload(&greeting.to_payload()).unwrap();
        assert_eq!(parsed.profiles(), ["urn:a&b<c>'d\""]);
    }

    #[test]
    fn rejects_a_payload_that_is_not_beep_xml() {
        assert_eq!(
            Greeting::from_payload(b"<greeting />").unwrap_err(),
            Error::NotBeepXml
        );
        assert_eq!(
            Greeting::from_payload(b"Content-Type: text/plain\r\n\r\n<greeting />").unwrap_err(),
            Error::NotBeepXml
        );
    }

    #[test]
    fn accepts_the_content_type_in_any_case() {
        let payload = b"content-type: Application/BEEP+XML\r\n\r\n<greeting />";
        assert!(Greeting::from_payload(payload).is_ok());
    }

    #[test]
    fn rejects_a_root_element_that_is_not_a_greeting() {
        let payload = b"Content-Type: application/beep+xml\r\n\r\n<error code='550' />";
        assert_eq!(
            Greeting::from_payload(payload).unwrap_err(),
            Error::UnexpectedElement
        );
    }

    #[test]
    fn rejects_frames_that_do_not_have_the_greeting_shape() {
        let payload = Greeting::new().to_payload();
        let cases: [(DataFrame, &str); 4] = [
            (
                DataFrame::new(FrameKind::Msg, 0, 0, 0, payload.clone()).unwrap(),
                "expected an RPY frame",
            ),
            (
                DataFrame::new(FrameKind::Rpy, 1, 0, 0, payload.clone()).unwrap(),
                "expected channel 0",
            ),
            (
                DataFrame::new(FrameKind::Rpy, 0, 1, 0, payload.clone()).unwrap(),
                "expected message number 0",
            ),
            (
                DataFrame::new(FrameKind::Rpy, 0, 0, 1, payload.clone()).unwrap(),
                "expected sequence number 0",
            ),
        ];
        for (frame, reason) in cases {
            assert_eq!(
                Greeting::from_frame(&frame).unwrap_err(),
                Error::NotAGreeting { reason }
            );
        }

        let partial = DataFrame::new(FrameKind::Rpy, 0, 0, 0, payload)
            .unwrap()
            .with_more(true);
        assert_eq!(
            Greeting::from_frame(&partial).unwrap_err(),
            Error::NotAGreeting {
                reason: "expected a complete frame"
            }
        );
    }
}
