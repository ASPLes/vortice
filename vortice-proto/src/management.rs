// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Channel-management messages: the `<start>`, `<close>`, `<profile>`, `<ok>` and `<error>`
//! elements BEEP exchanges on channel 0 (RFC3080 §2.3.1).
//!
//! Four exchanges make up the whole vocabulary:
//!
//! | Request | Positive reply | Negative reply |
//! |---|---|---|
//! | `<start>` | `<profile>` | `<error>` |
//! | `<close>` | `<ok />` | `<error>` |
//!
//! All of them travel as `application/beep+xml` payloads: `<start>` and `<close>` in a
//! `MSG`, the positive replies in an `RPY`, and `<error>` in an `ERR`. Enforcing that
//! pairing is the session layer's job; this module only reads and writes the elements.
//!
//! # Cosmetic divergence from LibVortex
//!
//! The rendering follows `vortex_frame_factory.c` — same attribute order, same three space
//! indent on profile lines, the same `CDATA` wrapper for piggybacked content — with one
//! exception. The C format strings leave stray double spaces before a self-closing bracket
//! when the optional `xml:lang` attribute is present (`xml:lang='es-ES'  />`) and a space
//! before the opening bracket of an element with content (`<error code='550' >`). Vortice
//! renders those cleanly. The difference is whitespace between attributes, which XML does
//! not distinguish, and the parser here accepts either spelling.

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use bytes::Bytes;

use crate::error::Error;
use crate::{mime, xml};

/// The reply codes RFC3080 §8 defines for `<error>` and `<close>`.
pub mod code {
    /// Service not available.
    pub const SERVICE_NOT_AVAILABLE: u32 = 421;
    /// Requested action not taken.
    pub const ACTION_NOT_TAKEN: u32 = 450;
    /// Requested action aborted.
    pub const ACTION_ABORTED: u32 = 451;
    /// Temporary authentication failure.
    pub const TEMPORARY_AUTH_FAILURE: u32 = 454;
    /// General syntax error.
    pub const GENERAL_SYNTAX_ERROR: u32 = 500;
    /// Syntax error in parameters.
    pub const SYNTAX_ERROR_IN_PARAMETERS: u32 = 501;
    /// Parameter not implemented.
    pub const PARAMETER_NOT_IMPLEMENTED: u32 = 504;
    /// Authentication required.
    pub const AUTHENTICATION_REQUIRED: u32 = 530;
    /// Authentication mechanism insufficient.
    pub const AUTH_MECHANISM_INSUFFICIENT: u32 = 534;
    /// Authentication failure.
    pub const AUTHENTICATION_FAILURE: u32 = 535;
    /// Action not authorised for user.
    pub const ACTION_NOT_AUTHORISED: u32 = 537;
    /// Authentication mechanism requires encryption.
    pub const AUTH_REQUIRES_ENCRYPTION: u32 = 538;
    /// Requested action not taken, most commonly a refused channel start.
    pub const REQUESTED_ACTION_NOT_TAKEN: u32 = 550;
    /// Parameter invalid.
    pub const PARAMETER_INVALID: u32 = 553;
    /// Transaction failed.
    pub const TRANSACTION_FAILED: u32 = 554;
    /// Success, the code a `<close>` normally carries.
    pub const SUCCESS: u32 = 200;
}

/// How the content piggybacked on a profile element is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encoding {
    /// Carried literally, the default when the attribute is absent.
    #[default]
    None,
    /// Base64, announced with `encoding='base64'`.
    ///
    /// Exercised by LibVortex `test_01t`.
    Base64,
}

impl Encoding {
    fn parse(value: Option<&str>) -> Result<Self, Error> {
        match value {
            None | Some("none") => Ok(Self::None),
            Some("base64") => Ok(Self::Base64),
            Some(_) => Err(Error::Xml {
                reason: "encoding must be 'none' or 'base64'",
            }),
        }
    }
}

/// A profile offered in a `<start>`, or confirmed in the reply to one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The profile URI.
    pub uri: String,
    /// How [`Profile::content`] is encoded.
    pub encoding: Encoding,
    /// Content piggybacked on the channel creation, if any.
    pub content: Option<String>,
}

impl Profile {
    /// A profile offered with no piggybacked content.
    #[must_use]
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            encoding: Encoding::None,
            content: None,
        }
    }

    /// Attaches literal content to piggyback on the exchange.
    #[must_use]
    pub fn with_content(mut self, content: impl Into<String>) -> Self {
        self.content = Some(content.into());
        self
    }

    /// Attaches base64 content, announced with `encoding='base64'`.
    #[must_use]
    pub fn with_base64_content(mut self, content: impl Into<String>) -> Self {
        self.content = Some(content.into());
        self.encoding = Encoding::Base64;
        self
    }

    fn parse(element: &xml::Element<'_>) -> Result<Self, Error> {
        let uri = element.attr("uri").ok_or(Error::Xml {
            reason: "profile element without a uri attribute",
        })?;
        Ok(Self {
            uri: uri.to_owned(),
            encoding: Encoding::parse(element.attr("encoding"))?,
            content: if element.text.is_empty() {
                None
            } else {
                Some(element.text.clone())
            },
        })
    }

    fn render(&self, out: &mut String) {
        out.push_str("<profile uri='");
        xml::escape(out, &self.uri);
        out.push('\'');
        if self.encoding == Encoding::Base64 {
            out.push_str(" encoding='base64'");
        }
        match &self.content {
            None => out.push_str(" />"),
            Some(content) => {
                out.push_str("><![CDATA[");
                out.push_str(content);
                out.push_str("]]></profile>");
            }
        }
    }
}

/// A request to create a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Start {
    /// The channel number being requested. Odd for the initiating peer, even for the
    /// listening one.
    pub number: u32,
    /// The virtual host the channel is for, carried in greetings afterwards.
    ///
    /// Exercised by LibVortex `test_01g` and `test_08`.
    pub server_name: Option<String>,
    /// The profiles offered, in order of preference.
    pub profiles: Vec<Profile>,
}

impl Start {
    /// A start requesting `number` with a single profile offered.
    #[must_use]
    pub fn new(number: u32, profile: Profile) -> Self {
        Self {
            number,
            server_name: None,
            profiles: alloc::vec![profile],
        }
    }

    /// Sets the `serverName` attribute.
    #[must_use]
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// Offers one more profile.
    #[must_use]
    pub fn offering(mut self, profile: Profile) -> Self {
        self.profiles.push(profile);
        self
    }
}

/// A request to close a channel, or the whole session when the number is zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Close {
    /// The channel to close; zero closes the session.
    pub number: u32,
    /// The reply code explaining why, normally [`code::SUCCESS`].
    pub code: u32,
    /// Language of [`Close::text`].
    pub lang: Option<String>,
    /// Human readable explanation.
    pub text: Option<String>,
}

impl Close {
    /// A successful close of the given channel.
    #[must_use]
    pub fn new(number: u32) -> Self {
        Self {
            number,
            code: code::SUCCESS,
            lang: None,
            text: None,
        }
    }

    /// Sets the reply code.
    #[must_use]
    pub fn with_code(mut self, code: u32) -> Self {
        self.code = code;
        self
    }

    /// Attaches an explanation, optionally tagged with a language.
    #[must_use]
    pub fn with_text(mut self, text: impl Into<String>, lang: Option<String>) -> Self {
        self.text = Some(text.into());
        self.lang = lang;
        self
    }
}

/// A refusal, sent in an `ERR` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorReply {
    /// The reply code, one of the constants in [`code`].
    pub code: u32,
    /// Language of [`ErrorReply::text`].
    pub lang: Option<String>,
    /// Human readable explanation.
    pub text: Option<String>,
}

impl ErrorReply {
    /// A refusal carrying just a code.
    #[must_use]
    pub fn new(code: u32) -> Self {
        Self {
            code,
            lang: None,
            text: None,
        }
    }

    /// Attaches an explanation, optionally tagged with a language.
    #[must_use]
    pub fn with_text(mut self, text: impl Into<String>, lang: Option<String>) -> Self {
        self.text = Some(text.into());
        self.lang = lang;
        self
    }
}

/// Any channel-management message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// `<start>` — asking for a channel.
    Start(Start),
    /// `<close>` — asking to close a channel or the session.
    Close(Close),
    /// `<profile>` — a start accepted.
    Profile(Profile),
    /// `<ok />` — a close accepted.
    Ok,
    /// `<error>` — a request refused.
    Error(ErrorReply),
}

impl Message {
    /// Parses a channel-management message from a BEEP payload, MIME headers included.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotBeepXml`] when the payload does not declare
    /// `Content-Type: application/beep+xml`, [`Error::UnexpectedElement`] when the root is
    /// not one of the five known elements, and [`Error::Xml`] when a required attribute is
    /// missing or malformed.
    pub fn from_payload(payload: &[u8]) -> Result<Self, Error> {
        let (headers, body) = mime::split(payload);
        let content_type = mime::header(headers, mime::CONTENT_TYPE).ok_or(Error::NotBeepXml)?;
        if !content_type.eq_ignore_ascii_case(mime::BEEP_XML.as_bytes()) {
            return Err(Error::NotBeepXml);
        }
        Self::from_xml(body)
    }

    /// Parses a channel-management message from the XML alone, without MIME headers.
    ///
    /// # Errors
    ///
    /// As [`Message::from_payload`], minus the content type check.
    pub fn from_xml(body: &[u8]) -> Result<Self, Error> {
        let root = xml::parse(body)?;
        match root.name {
            "start" => Ok(Self::Start(Start {
                number: attr_u32(&root, "number")?,
                server_name: root.attr("serverName").map(ToOwned::to_owned),
                profiles: root
                    .children_named("profile")
                    .map(Profile::parse)
                    .collect::<Result<Vec<_>, _>>()?,
            })),
            "close" => Ok(Self::Close(Close {
                number: attr_u32(&root, "number")?,
                code: attr_u32(&root, "code")?,
                lang: root.attr("xml:lang").map(ToOwned::to_owned),
                text: text_of(&root),
            })),
            "profile" => Ok(Self::Profile(Profile::parse(&root)?)),
            "ok" => Ok(Self::Ok),
            "error" => Ok(Self::Error(ErrorReply {
                code: attr_u32(&root, "code")?,
                lang: root.attr("xml:lang").map(ToOwned::to_owned),
                text: text_of(&root),
            })),
            _ => Err(Error::UnexpectedElement),
        }
    }

    /// Renders the message as a BEEP payload, MIME headers included.
    #[must_use]
    pub fn to_payload(&self) -> Bytes {
        let mut out = String::new();
        out.push_str(mime::CONTENT_TYPE);
        out.push_str(": ");
        out.push_str(mime::BEEP_XML);
        out.push_str("\r\n\r\n");
        self.render(&mut out);
        Bytes::from(out)
    }

    fn render(&self, out: &mut String) {
        match self {
            Self::Start(start) => {
                out.push_str("<start number='");
                push_u32(out, start.number);
                out.push('\'');
                if let Some(name) = &start.server_name {
                    out.push_str(" serverName='");
                    xml::escape(out, name);
                    out.push('\'');
                }
                out.push_str(">\r\n");
                for profile in &start.profiles {
                    out.push_str("   ");
                    profile.render(out);
                    out.push_str("\r\n");
                }
                out.push_str("</start>\r\n");
            }
            Self::Close(close) => {
                out.push_str("<close number='");
                push_u32(out, close.number);
                out.push_str("' code='");
                push_u32(out, close.code);
                out.push('\'');
                render_lang_and_text(out, close.lang.as_deref(), close.text.as_deref(), "close");
            }
            Self::Profile(profile) => {
                profile.render(out);
                out.push_str("\r\n");
            }
            Self::Ok => out.push_str("<ok />"),
            Self::Error(error) => {
                out.push_str("<error code='");
                push_u32(out, error.code);
                out.push('\'');
                render_lang_and_text(out, error.lang.as_deref(), error.text.as_deref(), "error");
            }
        }
    }
}

/// Renders the optional `xml:lang` attribute and the optional text body shared by `<close>`
/// and `<error>`.
fn render_lang_and_text(out: &mut String, lang: Option<&str>, text: Option<&str>, tag: &str) {
    if let Some(lang) = lang {
        out.push_str(" xml:lang='");
        xml::escape(out, lang);
        out.push('\'');
    }
    match text {
        None => out.push_str(" />\r\n"),
        Some(text) => {
            out.push('>');
            xml::escape(out, text);
            out.push_str("</");
            out.push_str(tag);
            out.push_str(">\r\n");
        }
    }
}

fn text_of(element: &xml::Element<'_>) -> Option<String> {
    let trimmed = element.text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn attr_u32(element: &xml::Element<'_>, name: &'static str) -> Result<u32, Error> {
    let raw = element
        .attr(name)
        .ok_or(Error::MissingField { field: name })?;
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidDigit { field: name });
    }
    raw.parse().map_err(|_| Error::ValueOutOfRange {
        field: name,
        max: u32::MAX,
    })
}

fn push_u32(out: &mut String, mut value: u32) {
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + u8::try_from(value % 10).unwrap_or(b'0');
        value /= 10;
        if value == 0 {
            break;
        }
    }
    out.push_str(core::str::from_utf8(&buf[i..]).unwrap_or("0"));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strips the MIME headers so tests can compare the XML alone.
    fn xml_of(message: &Message) -> String {
        let payload = message.to_payload();
        let (_, body) = mime::split(&payload);
        String::from_utf8(body.to_vec()).unwrap()
    }

    fn round_trip(message: &Message) -> Message {
        Message::from_payload(&message.to_payload()).unwrap()
    }

    #[test]
    fn renders_a_start_the_way_libvortex_does() {
        let message = Message::Start(Start::new(1, Profile::new("urn:example:echo")));
        assert_eq!(
            xml_of(&message),
            "<start number='1'>\r\n   <profile uri='urn:example:echo' />\r\n</start>\r\n"
        );
    }

    #[test]
    fn renders_a_start_with_a_server_name() {
        let message = Message::Start(
            Start::new(3, Profile::new("urn:example:echo")).with_server_name("beep.example.com"),
        );
        assert_eq!(
            xml_of(&message),
            "<start number='3' serverName='beep.example.com'>\r\n   \
             <profile uri='urn:example:echo' />\r\n</start>\r\n"
        );
    }

    #[test]
    fn renders_piggybacked_content_inside_cdata() {
        let message = Message::Start(Start::new(
            1,
            Profile::new("urn:example:echo").with_content("hello"),
        ));
        assert_eq!(
            xml_of(&message),
            "<start number='1'>\r\n   \
             <profile uri='urn:example:echo'><![CDATA[hello]]></profile>\r\n</start>\r\n"
        );
    }

    #[test]
    fn renders_the_base64_encoding_attribute() {
        // test_01t checks the profile content encoding in the start reply.
        let message =
            Message::Profile(Profile::new("urn:example:echo").with_base64_content("aGk="));
        assert_eq!(
            xml_of(&message),
            "<profile uri='urn:example:echo' encoding='base64'><![CDATA[aGk=]]></profile>\r\n"
        );
    }

    #[test]
    fn renders_close_ok_and_error() {
        assert_eq!(
            xml_of(&Message::Close(Close::new(1))),
            "<close number='1' code='200' />\r\n"
        );
        assert_eq!(xml_of(&Message::Ok), "<ok />");
        assert_eq!(
            xml_of(&Message::Error(ErrorReply::new(
                code::REQUESTED_ACTION_NOT_TAKEN
            ))),
            "<error code='550' />\r\n"
        );
    }

    #[test]
    fn renders_text_and_language() {
        let message = Message::Error(
            ErrorReply::new(550).with_text("profile not supported", Some("en-US".into())),
        );
        assert_eq!(
            xml_of(&message),
            "<error code='550' xml:lang='en-US'>profile not supported</error>\r\n"
        );
    }

    #[test]
    fn round_trips_every_message() {
        let messages = [
            Message::Start(Start::new(1, Profile::new("urn:a"))),
            Message::Start(
                Start::new(2, Profile::new("urn:a").with_content("data"))
                    .with_server_name("host")
                    .offering(Profile::new("urn:b").with_base64_content("aGk=")),
            ),
            Message::Close(Close::new(0).with_code(200)),
            Message::Close(Close::new(7).with_text("done", Some("es-ES".into()))),
            Message::Profile(Profile::new("urn:a")),
            Message::Profile(Profile::new("urn:a").with_content("piggyback")),
            Message::Ok,
            Message::Error(ErrorReply::new(421)),
            Message::Error(ErrorReply::new(550).with_text("nope", None)),
        ];
        for message in messages {
            assert_eq!(
                round_trip(&message),
                message,
                "round trip changed the message"
            );
        }
    }

    #[test]
    fn parses_what_libvortex_emits_with_its_extra_whitespace() {
        // The C format strings leave a double space before a self-closing bracket when
        // xml:lang is present, and a space before the bracket of an element with content.
        let cases: [(&[u8], Message); 3] = [
            (
                b"<close number='1' code='200' xml:lang='es-ES'  />\r\n",
                Message::Close(Close {
                    number: 1,
                    code: 200,
                    lang: Some("es-ES".into()),
                    text: None,
                }),
            ),
            (
                b"<error code='550' >boom</error>\r\n",
                Message::Error(ErrorReply {
                    code: 550,
                    lang: None,
                    text: Some("boom".into()),
                }),
            ),
            (
                b"<profile uri='urn:a' ><![CDATA[c]]></profile>\r\n",
                Message::Profile(Profile {
                    uri: "urn:a".into(),
                    encoding: Encoding::None,
                    content: Some("c".into()),
                }),
            ),
        ];
        for (raw, expected) in cases {
            assert_eq!(Message::from_xml(raw).unwrap(), expected);
        }
    }

    #[test]
    fn accepts_a_start_offering_several_profiles() {
        let raw = b"<start number='1'>\r\n   <profile uri='urn:a' />\r\n   \
                    <profile uri='urn:b' />\r\n</start>\r\n";
        let Message::Start(start) = Message::from_xml(raw).unwrap() else {
            panic!("expected a start");
        };
        assert_eq!(start.profiles.len(), 2);
        assert_eq!(start.profiles[1].uri, "urn:b");
    }

    #[test]
    fn escapes_markup_in_attributes_and_text() {
        let message =
            Message::Start(Start::new(1, Profile::new("urn:a&b<c>")).with_server_name("h'ost\""));
        let Message::Start(parsed) = round_trip(&message) else {
            panic!("expected a start");
        };
        assert_eq!(parsed.profiles[0].uri, "urn:a&b<c>");
        assert_eq!(parsed.server_name.as_deref(), Some("h'ost\""));
    }

    #[test]
    fn rejects_a_payload_that_is_not_beep_xml() {
        assert_eq!(
            Message::from_payload(b"<ok />").unwrap_err(),
            Error::NotBeepXml
        );
    }

    #[test]
    fn rejects_an_unknown_root_element() {
        assert_eq!(
            Message::from_xml(b"<greeting />").unwrap_err(),
            Error::UnexpectedElement
        );
    }

    #[test]
    fn rejects_missing_and_malformed_attributes() {
        assert_eq!(
            Message::from_xml(b"<start />").unwrap_err(),
            Error::MissingField { field: "number" }
        );
        assert_eq!(
            Message::from_xml(b"<close number='1' />").unwrap_err(),
            Error::MissingField { field: "code" }
        );
        assert_eq!(
            Message::from_xml(b"<error code='abc' />").unwrap_err(),
            Error::InvalidDigit { field: "code" }
        );
        assert_eq!(
            Message::from_xml(b"<start number='1'><profile /></start>").unwrap_err(),
            Error::Xml {
                reason: "profile element without a uri attribute"
            }
        );
        assert_eq!(
            Message::from_xml(b"<profile uri='u' encoding='rot13' />").unwrap_err(),
            Error::Xml {
                reason: "encoding must be 'none' or 'base64'"
            }
        );
    }

    #[test]
    fn treats_an_absent_encoding_as_none() {
        let Message::Profile(profile) = Message::from_xml(b"<profile uri='u' />").unwrap() else {
            panic!("expected a profile");
        };
        assert_eq!(profile.encoding, Encoding::None);
        assert_eq!(Encoding::default(), Encoding::None);
    }
}
