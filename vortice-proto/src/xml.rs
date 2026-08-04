// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! A minimal XML reader for BEEP channel-management messages.
//!
//! BEEP carries `<greeting>`, `<start>`, `<close>`, `<ok>` and `<error>` on channel 0. The
//! grammar involved is tiny and fixed by RFC3080, so this module implements exactly that
//! subset rather than pulling in a general XML parser: it stays `no_std`, it allocates only
//! for the element tree, and it is small enough to fuzz meaningfully.
//!
//! What is supported: elements, attributes with either quote style, self-closing elements,
//! character data, `CDATA` sections, comments, the XML declaration, a `DOCTYPE` declaration,
//! and the five predefined entities plus numeric character references. What is not:
//! namespaces, processing instructions inside content, and entity declarations. None of
//! those appear in BEEP channel management.
//!
//! `CDATA` is not optional here: LibVortex wraps piggybacked profile content in it
//! unconditionally, so a start message carrying content cannot be read without it.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

/// Deepest element nesting accepted, a guard against hostile input.
const MAX_DEPTH: usize = 32;

/// Longest entity reference accepted, e.g. `&#x10FFFF;`.
const MAX_ENTITY_LEN: usize = 12;

/// Opening delimiter of a CDATA section.
const CDATA_OPEN: &[u8] = b"<![CDATA[";

/// Closing delimiter of a CDATA section.
const CDATA_CLOSE: &[u8] = b"]]>";

/// A parsed XML element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Element<'a> {
    pub(crate) name: &'a str,
    pub(crate) attrs: Vec<(&'a str, Cow<'a, str>)>,
    pub(crate) children: Vec<Element<'a>>,
    pub(crate) text: String,
}

impl<'a> Element<'a> {
    /// The value of an attribute, or `None` when it is absent.
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_ref())
    }

    /// The direct children with the given element name.
    pub(crate) fn children_named<'s>(
        &'s self,
        name: &'s str,
    ) -> impl Iterator<Item = &'s Element<'a>> {
        self.children.iter().filter(move |child| child.name == name)
    }
}

/// Escapes the characters that cannot appear literally in element text or in a quoted
/// attribute value.
///
/// LibVortex writes profile URIs and error text unescaped, relying on them never containing
/// these characters. Vortice escapes them so that an unusual or hostile value cannot inject
/// markup into a channel-management message.
pub(crate) fn escape(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
}

/// Parses a document holding exactly one root element.
pub(crate) fn parse(input: &[u8]) -> Result<Element<'_>, Error> {
    let src = core::str::from_utf8(input).map_err(|_| Error::NotUtf8)?;
    let mut parser = Parser { src, i: 0 };
    parser.skip_prolog()?;
    let root = parser.parse_element(0)?;
    parser.skip_prolog()?;
    if parser.i < parser.src.len() {
        return Err(Error::Xml {
            reason: "trailing content after the root element",
        });
    }
    Ok(root)
}

struct Parser<'a> {
    src: &'a str,
    i: usize,
}

impl<'a> Parser<'a> {
    fn bytes(&self) -> &'a [u8] {
        self.src.as_bytes()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes().get(self.i).copied()
    }

    fn starts_with(&self, pat: &[u8]) -> bool {
        self.bytes()[self.i..].starts_with(pat)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.i += 1;
        }
    }

    /// Skips whitespace, comments, the XML declaration and a `DOCTYPE` declaration.
    fn skip_prolog(&mut self) -> Result<(), Error> {
        loop {
            self.skip_ws();
            if self.starts_with(b"<?") {
                self.skip_past(b"?>")?;
            } else if self.starts_with(b"<!--") {
                self.skip_past(b"-->")?;
            } else if self.starts_with(b"<!") {
                self.skip_past(b">")?;
            } else {
                return Ok(());
            }
        }
    }

    fn skip_past(&mut self, pat: &[u8]) -> Result<(), Error> {
        let rest = &self.bytes()[self.i..];
        let at = (0..rest.len().saturating_sub(pat.len() - 1))
            .find(|&i| rest[i..].starts_with(pat))
            .ok_or(Error::Xml {
                reason: "unterminated declaration or comment",
            })?;
        self.i += at + pat.len();
        Ok(())
    }

    fn expect(&mut self, byte: u8, reason: &'static str) -> Result<(), Error> {
        if self.peek() != Some(byte) {
            return Err(Error::Xml { reason });
        }
        self.i += 1;
        Ok(())
    }

    fn read_name(&mut self) -> Result<&'a str, Error> {
        let start = self.i;
        while let Some(byte) = self.peek() {
            if matches!(
                byte,
                b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>' | b'=' | b'<'
            ) {
                break;
            }
            self.i += 1;
        }
        if start == self.i {
            return Err(Error::Xml {
                reason: "expected an element or attribute name",
            });
        }
        Ok(&self.src[start..self.i])
    }

    fn parse_element(&mut self, depth: usize) -> Result<Element<'a>, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Xml {
                reason: "element nesting too deep",
            });
        }
        self.expect(b'<', "expected an element")?;
        let name = self.read_name()?;
        let mut element = Element {
            name,
            attrs: Vec::new(),
            children: Vec::new(),
            text: String::new(),
        };

        loop {
            self.skip_ws();
            match self.peek() {
                Some(b'/') => {
                    self.i += 1;
                    self.expect(b'>', "expected '>' closing an empty element")?;
                    return Ok(element);
                }
                Some(b'>') => {
                    self.i += 1;
                    break;
                }
                Some(_) => {
                    let key = self.read_name()?;
                    self.skip_ws();
                    self.expect(b'=', "expected '=' after an attribute name")?;
                    self.skip_ws();
                    let value = self.read_attr_value()?;
                    element.attrs.push((key, value));
                }
                None => {
                    return Err(Error::Xml {
                        reason: "unterminated start tag",
                    });
                }
            }
        }

        self.parse_content(&mut element, depth)?;
        Ok(element)
    }

    fn read_attr_value(&mut self) -> Result<Cow<'a, str>, Error> {
        let quote = match self.peek() {
            Some(q @ (b'"' | b'\'')) => q,
            _ => {
                return Err(Error::Xml {
                    reason: "attribute value must be quoted",
                });
            }
        };
        self.i += 1;
        let start = self.i;
        while let Some(byte) = self.peek() {
            if byte == quote {
                let raw = &self.src[start..self.i];
                self.i += 1;
                return decode_entities(raw);
            }
            self.i += 1;
        }
        Err(Error::Xml {
            reason: "unterminated attribute value",
        })
    }

    fn parse_content(&mut self, element: &mut Element<'a>, depth: usize) -> Result<(), Error> {
        loop {
            if self.starts_with(b"</") {
                self.i += 2;
                let closing = self.read_name()?;
                self.skip_ws();
                self.expect(b'>', "expected '>' closing an end tag")?;
                if closing != element.name {
                    return Err(Error::Xml {
                        reason: "end tag does not match its start tag",
                    });
                }
                return Ok(());
            }
            if self.starts_with(b"<!--") {
                self.skip_past(b"-->")?;
                continue;
            }
            if self.starts_with(CDATA_OPEN) {
                // LibVortex wraps piggybacked profile content in CDATA, so this is not an
                // optional nicety: `vortex_frame_get_start_message` emits it unconditionally
                // whenever a start carries content.
                self.i += CDATA_OPEN.len();
                let start = self.i;
                self.skip_past(CDATA_CLOSE)?;
                let end = self.i - CDATA_CLOSE.len();
                element.text.push_str(&self.src[start..end]);
                continue;
            }
            match self.peek() {
                Some(b'<') => element.children.push(self.parse_element(depth + 1)?),
                Some(_) => {
                    let start = self.i;
                    while !matches!(self.peek(), Some(b'<') | None) {
                        self.i += 1;
                    }
                    element
                        .text
                        .push_str(&decode_entities(&self.src[start..self.i])?);
                }
                None => {
                    return Err(Error::Xml {
                        reason: "unterminated element content",
                    });
                }
            }
        }
    }
}

/// Expands the predefined entities and numeric character references.
fn decode_entities(raw: &str) -> Result<Cow<'_, str>, Error> {
    if !raw.contains('&') {
        return Ok(Cow::Borrowed(raw));
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 1..];
        let end = tail
            .as_bytes()
            .iter()
            .take(MAX_ENTITY_LEN)
            .position(|&b| b == b';')
            .ok_or(Error::Xml {
                reason: "unterminated entity reference",
            })?;
        let name = &tail[..end];
        match name {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => out.push(decode_numeric_reference(name)?),
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    Ok(Cow::Owned(out))
}

fn decode_numeric_reference(name: &str) -> Result<char, Error> {
    let invalid = Error::Xml {
        reason: "unsupported entity reference",
    };
    let digits = name.strip_prefix('#').ok_or(invalid.clone())?;
    let value = match digits.strip_prefix(['x', 'X']) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => digits.parse::<u32>(),
    }
    .map_err(|_| invalid.clone())?;
    char::from_u32(value).ok_or(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_empty_element() {
        let root = parse(b"<greeting />").unwrap();
        assert_eq!(root.name, "greeting");
        assert!(root.attrs.is_empty());
        assert!(root.children.is_empty());
    }

    #[test]
    fn parses_attributes_with_either_quote_style() {
        let root = parse(b"<greeting features='x' localize=\"es-ES\" />").unwrap();
        assert_eq!(root.attr("features"), Some("x"));
        assert_eq!(root.attr("localize"), Some("es-ES"));
        assert_eq!(root.attr("absent"), None);
    }

    #[test]
    fn parses_children_the_way_libvortex_lays_a_greeting_out() {
        let doc =
            b"<greeting>\r\n   <profile uri='a' />\r\n   <profile uri='b' />\r\n</greeting>\r\n";
        let root = parse(doc).unwrap();
        let uris: Vec<_> = root
            .children_named("profile")
            .filter_map(|child| child.attr("uri"))
            .collect();
        assert_eq!(uris, ["a", "b"]);
    }

    #[test]
    fn parses_element_text() {
        let root = parse(b"<error code='550'>still working</error>").unwrap();
        assert_eq!(root.attr("code"), Some("550"));
        assert_eq!(root.text, "still working");
    }

    #[test]
    fn skips_the_declaration_comments_and_doctype() {
        let doc = b"<?xml version='1.0'?><!-- hi --><!DOCTYPE greeting><greeting /><!-- bye -->";
        assert_eq!(parse(doc).unwrap().name, "greeting");
    }

    #[test]
    fn expands_predefined_and_numeric_entities() {
        let root = parse(b"<profile uri='a&amp;b&#66;&#x43;' />").unwrap();
        assert_eq!(root.attr("uri"), Some("a&bBC"));
        assert_eq!(parse(b"<e>&lt;&gt;&quot;&apos;</e>").unwrap().text, "<>\"'");
    }

    #[test]
    fn borrows_attribute_values_that_need_no_expansion() {
        let root = parse(b"<profile uri='plain' />").unwrap();
        assert!(matches!(root.attrs[0].1, Cow::Borrowed(_)));
    }

    #[test]
    fn reads_cdata_sections_verbatim() {
        // Exactly how LibVortex piggybacks profile content on a start message.
        let root = parse(b"<profile uri='u'><![CDATA[<not markup> & raw]]></profile>").unwrap();
        assert_eq!(root.text, "<not markup> & raw");
        assert!(root.children.is_empty());
    }

    #[test]
    fn joins_cdata_with_surrounding_text() {
        let root = parse(b"<e>before<![CDATA[ raw ]]>after</e>").unwrap();
        assert_eq!(root.text, "before raw after");
    }

    #[test]
    fn accepts_an_empty_cdata_section() {
        assert_eq!(parse(b"<e><![CDATA[]]></e>").unwrap().text, "");
    }

    #[test]
    fn rejects_an_unterminated_cdata_section() {
        assert!(parse(b"<e><![CDATA[ never closed</e>").is_err());
    }

    #[test]
    fn rejects_mismatched_tags() {
        assert!(parse(b"<greeting></profile>").is_err());
    }

    #[test]
    fn rejects_unterminated_input() {
        assert!(parse(b"<greeting").is_err());
        assert!(parse(b"<greeting>").is_err());
        assert!(parse(b"<greeting uri='x").is_err());
        assert!(parse(b"<!-- unterminated").is_err());
        assert!(parse(b"<e>&amp").is_err());
    }

    #[test]
    fn rejects_content_after_the_root_element() {
        assert!(parse(b"<greeting /><greeting />").is_err());
    }

    #[test]
    fn rejects_unquoted_attribute_values() {
        assert!(parse(b"<profile uri=plain />").is_err());
    }

    #[test]
    fn rejects_deeply_nested_documents() {
        let mut doc = Vec::new();
        for _ in 0..MAX_DEPTH + 2 {
            doc.extend_from_slice(b"<e>");
        }
        for _ in 0..MAX_DEPTH + 2 {
            doc.extend_from_slice(b"</e>");
        }
        assert!(parse(&doc).is_err());
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(parse(b"<e>\xff</e>").unwrap_err(), Error::NotUtf8);
    }
}
