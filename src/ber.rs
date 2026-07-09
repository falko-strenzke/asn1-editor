// Copyright 2026 Falko Strenzke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! BER/DER TLV parser and encoder.
//!
//! The parser works on raw tag/length/value structure without any schema
//! knowledge, keeping absolute file offsets and header lengths so that the
//! output can be compared 1:1 against Peter Gutmann's `dumpasn1`.
//!
//! The "encapsulates" heuristic (nested ASN.1 inside primitive OCTET STRING
//! / BIT STRING values) replicates `checkEncapsulate()` from dumpasn1.c.

use std::fmt;

/// Maximum nesting depth accepted by the parser (guards against stack
/// exhaustion on hostile inputs).
const MAX_DEPTH: usize = 100;

/// Universal tag numbers used by name/value formatting.
pub const TAG_BOOLEAN: u32 = 1;
pub const TAG_INTEGER: u32 = 2;
pub const TAG_BIT_STRING: u32 = 3;
pub const TAG_OCTET_STRING: u32 = 4;
pub const TAG_NULL: u32 = 5;
pub const TAG_OID: u32 = 6;
pub const TAG_ENUMERATED: u32 = 10;
pub const TAG_UTF8_STRING: u32 = 12;
pub const TAG_SEQUENCE: u32 = 16;
pub const TAG_SET: u32 = 17;
pub const TAG_UTC_TIME: u32 = 23;
pub const TAG_GENERALIZED_TIME: u32 = 24;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

/// One parsed TLV item. Constructed nodes carry their children;
/// primitive nodes carry the raw content octets in `value` (for BIT STRING
/// this includes the leading unused-bits octet). Primitive OCTET STRING /
/// BIT STRING values that pass the dumpasn1 encapsulation heuristic
/// additionally carry the parsed inner items in `children` with
/// `encapsulates` set.
#[derive(Clone, Debug)]
pub struct Node {
    pub class: Class,
    pub tag: u32,
    pub constructed: bool,
    /// Parsed from an indefinite-length (BER) encoding. Re-encoding always
    /// produces definite lengths.
    pub indefinite: bool,
    /// Absolute offset of the first identifier octet in the decoded input.
    pub offset: usize,
    /// Number of identifier + length octets.
    pub header_len: usize,
    /// Number of content octets (excluding end-of-contents octets).
    pub content_len: usize,
    /// Content octets of primitive nodes; empty for constructed nodes.
    pub value: Vec<u8>,
    pub children: Vec<Node>,
    pub encapsulates: bool,
    /// UI state: whether the node is expanded in the tree view.
    pub expanded: bool,
}

/// Type label using dumpasn1's naming, for any class/tag combination.
pub fn type_name_of(class: Class, tag: u32) -> String {
    match class {
        Class::Universal => universal_tag_name(tag).to_string(),
        Class::Application => format!("[APPLICATION {}]", tag),
        Class::ContextSpecific => format!("[{}]", tag),
        Class::Private => format!("[PRIVATE {}]", tag),
    }
}

/// Encode just the identifier octets of a tag (used for previews).
pub fn identifier_octets(class: Class, tag: u32, constructed: bool) -> Vec<u8> {
    let mut out = Vec::new();
    write_identifier(class, tag, constructed, &mut out);
    out
}

impl Node {
    /// Type label using dumpasn1's naming.
    pub fn type_name(&self) -> String {
        type_name_of(self.class, self.tag)
    }

    pub fn is_universal(&self, tag: u32) -> bool {
        self.class == Class::Universal && self.tag == tag
    }

    /// Content octets as they would be encoded right now. For constructed
    /// and encapsulating nodes this is derived from the children, so edits
    /// deeper in the tree are reflected.
    pub fn content_octets(&self) -> Vec<u8> {
        if self.constructed {
            encode_forest(&self.children)
        } else if self.encapsulates {
            let mut out = Vec::new();
            if self.is_universal(TAG_BIT_STRING) {
                // Preserve the unused-bits octet in front of the nested items.
                out.push(self.value.first().copied().unwrap_or(0));
            }
            out.extend_from_slice(&encode_forest(&self.children));
            out
        } else {
            self.value.clone()
        }
    }

    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }
}

pub fn universal_tag_name(tag: u32) -> &'static str {
    match tag {
        0 => "End-of-contents octets",
        1 => "BOOLEAN",
        2 => "INTEGER",
        3 => "BIT STRING",
        4 => "OCTET STRING",
        5 => "NULL",
        6 => "OBJECT IDENTIFIER",
        7 => "ObjectDescriptor",
        8 => "EXTERNAL",
        9 => "REAL",
        10 => "ENUMERATED",
        11 => "EMBEDDED PDV",
        12 => "UTF8String",
        16 => "SEQUENCE",
        17 => "SET",
        18 => "NumericString",
        19 => "PrintableString",
        20 => "TeletexString",
        21 => "VideotexString",
        22 => "IA5String",
        23 => "UTCTime",
        24 => "GeneralizedTime",
        25 => "GraphicString",
        26 => "VisibleString",
        27 => "GeneralString",
        28 => "UniversalString",
        30 => "BMPString",
        _ => "Unknown (Reserved)",
    }
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub offset: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "offset {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for ParseError {}

fn err<T>(offset: usize, message: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError { offset, message: message.into() })
}

struct Header {
    class: Class,
    tag: u32,
    constructed: bool,
    indefinite: bool,
    header_len: usize,
    content_len: usize,
}

/// Decode identifier and length octets at the start of `data`. `abs` is the
/// absolute offset of `data[0]`, used only for error reporting.
fn parse_header(data: &[u8], abs: usize) -> Result<Header, ParseError> {
    let b0 = match data.first() {
        Some(&b) => b,
        None => return err(abs, "unexpected end of data"),
    };
    if b0 == 0x00 {
        return err(abs, "zero tag octet (end-of-contents outside indefinite length)");
    }
    let class = match b0 >> 6 {
        0 => Class::Universal,
        1 => Class::Application,
        2 => Class::ContextSpecific,
        _ => Class::Private,
    };
    let constructed = b0 & 0x20 != 0;
    let mut idx = 1usize;
    let mut tag = (b0 & 0x1F) as u32;
    if tag == 0x1F {
        // High tag number, base-128 with continuation bit.
        tag = 0;
        loop {
            let b = match data.get(idx) {
                Some(&b) => b,
                None => return err(abs + idx, "truncated high tag number"),
            };
            idx += 1;
            tag = (tag << 7) | (b & 0x7F) as u32;
            if b & 0x80 == 0 {
                break;
            }
            if idx > 5 {
                return err(abs, "tag number too large");
            }
        }
    }
    let lb = match data.get(idx) {
        Some(&b) => b,
        None => return err(abs + idx, "missing length octet"),
    };
    idx += 1;
    let (content_len, indefinite) = if lb < 0x80 {
        (lb as usize, false)
    } else if lb == 0x80 {
        (0, true)
    } else {
        let n = (lb & 0x7F) as usize;
        if n > 8 {
            return err(abs + idx - 1, format!("unsupported length-of-length {}", n));
        }
        let mut len: u64 = 0;
        for i in 0..n {
            let b = match data.get(idx + i) {
                Some(&b) => b,
                None => return err(abs + idx + i, "truncated length field"),
            };
            len = (len << 8) | b as u64;
        }
        idx += n;
        if len > usize::MAX as u64 {
            return err(abs, "length overflow");
        }
        (len as usize, false)
    };
    Ok(Header { class, tag, constructed, indefinite, header_len: idx, content_len })
}

/// Parse a sequence of TLV items filling `data` completely. `abs` is the
/// absolute offset of `data[0]`.
pub fn parse_forest(data: &[u8], abs: usize) -> Result<Vec<Node>, ParseError> {
    parse_forest_depth(data, abs, 0)
}

fn parse_forest_depth(data: &[u8], abs: usize, depth: usize) -> Result<Vec<Node>, ParseError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let (node, used) = parse_node(&data[pos..], abs + pos, depth)?;
        out.push(node);
        pos += used;
    }
    Ok(out)
}

/// Parse a single node at the start of `data`; returns the node and the
/// number of bytes consumed.
fn parse_node(data: &[u8], abs: usize, depth: usize) -> Result<(Node, usize), ParseError> {
    if depth > MAX_DEPTH {
        return err(abs, "maximum nesting depth exceeded");
    }
    let h = parse_header(data, abs)?;
    let mut node = Node {
        class: h.class,
        tag: h.tag,
        constructed: h.constructed,
        indefinite: h.indefinite,
        offset: abs,
        header_len: h.header_len,
        content_len: h.content_len,
        value: Vec::new(),
        children: Vec::new(),
        encapsulates: false,
        expanded: true,
    };

    if h.indefinite {
        if !h.constructed {
            return err(abs, "indefinite length on primitive encoding");
        }
        let mut pos = h.header_len;
        loop {
            if pos + 2 <= data.len() && data[pos] == 0x00 && data[pos + 1] == 0x00 {
                pos += 2;
                break;
            }
            if pos >= data.len() {
                return err(abs, "missing end-of-contents octets");
            }
            let (child, used) = parse_node(&data[pos..], abs + pos, depth + 1)?;
            node.children.push(child);
            pos += used;
        }
        node.content_len = pos - h.header_len - 2;
        return Ok((node, pos));
    }

    let end = h.header_len + h.content_len;
    if end > data.len() {
        return err(abs, format!("length {} exceeds available data", h.content_len));
    }
    let content = &data[h.header_len..end];

    if h.constructed {
        node.children = parse_forest_depth(content, abs + h.header_len, depth + 1)?;
        return Ok((node, end));
    }

    node.value = content.to_vec();

    // dumpasn1-compatible encapsulation heuristic for primitive
    // OCTET STRING and BIT STRING values.
    if node.is_universal(TAG_OCTET_STRING) && check_encapsulate(content) {
        if let Ok(children) = parse_forest_depth(content, abs + h.header_len, depth + 1) {
            node.encapsulates = true;
            node.children = children;
        }
    } else if node.is_universal(TAG_BIT_STRING) && content.len() >= 2 {
        // dumpasn1 skips the unused-bits octet, dumps contents of up to 4
        // bytes as bit flags, and only then considers encapsulation.
        let rem = &content[1..];
        if rem.len() > 4 && check_encapsulate(rem) {
            if let Ok(children) = parse_forest_depth(rem, abs + h.header_len + 1, depth + 1) {
                node.encapsulates = true;
                node.children = children;
            }
        }
    }

    Ok((node, end))
}

/// Port of dumpasn1's `checkEncapsulate()`: does `content` look like a
/// single nested ASN.1 item filling the buffer exactly?
fn check_encapsulate(content: &[u8]) -> bool {
    if content.len() < 2 {
        return false;
    }
    let h = match parse_header(content, 0) {
        Ok(h) => h,
        Err(_) => return false,
    };
    // Only standard tag classes are considered.
    if h.class != Class::Universal && h.class != Class::ContextSpecific {
        return false;
    }
    if h.indefinite {
        // dumpasn1 special-cases indefinite-length nested SEQUENCEs; accept
        // if the whole buffer parses as exactly one item.
        if !(h.class == Class::Universal && h.tag == TAG_SEQUENCE) {
            return false;
        }
        return matches!(parse_forest(content, 0), Ok(f) if f.len() == 1);
    }
    // The nested item must fill the value exactly.
    if h.header_len + h.content_len != content.len() {
        return false;
    }
    // Tag must look vaguely valid.
    if h.tag == 0 || h.tag > 0x31 {
        return false;
    }
    // Primitive items are accepted as-is; constructed items only when they
    // are SEQUENCEs or SETs (avoids false positives on string types whose
    // first byte happens to look like a constructed tag).
    if !h.constructed {
        return true;
    }
    h.tag == TAG_SEQUENCE || h.tag == TAG_SET
}

fn write_identifier(class: Class, tag: u32, constructed: bool, out: &mut Vec<u8>) {
    let class_bits = match class {
        Class::Universal => 0x00,
        Class::Application => 0x40,
        Class::ContextSpecific => 0x80,
        Class::Private => 0xC0,
    };
    let form = if constructed { 0x20 } else { 0x00 };
    if tag < 0x1F {
        out.push(class_bits | form | tag as u8);
    } else {
        out.push(class_bits | form | 0x1F);
        let mut groups = Vec::new();
        let mut t = tag;
        loop {
            groups.push((t & 0x7F) as u8);
            t >>= 7;
            if t == 0 {
                break;
            }
        }
        groups.reverse();
        let last = groups.len() - 1;
        for (i, g) in groups.iter().enumerate() {
            out.push(if i == last { *g } else { g | 0x80 });
        }
    }
}

fn write_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let sig = &bytes[skip..];
        out.push(0x80 | sig.len() as u8);
        out.extend_from_slice(sig);
    }
}

/// Encode a node as DER (definite, minimal lengths).
pub fn encode_node(node: &Node) -> Vec<u8> {
    let content = node.content_octets();
    let mut out = Vec::with_capacity(content.len() + 8);
    write_identifier(node.class, node.tag, node.constructed, &mut out);
    write_length(content.len(), &mut out);
    out.extend_from_slice(&content);
    out
}

pub fn encode_forest(nodes: &[Node]) -> Vec<u8> {
    let mut out = Vec::new();
    for n in nodes {
        out.extend_from_slice(&encode_node(n));
    }
    out
}

// ---------------------------------------------------------------------------
// Shared value decoding helpers (used by the dump formatter and the TUI).
// ---------------------------------------------------------------------------

/// Two's-complement big-endian integer, if it fits in i128.
pub fn decode_integer(bytes: &[u8]) -> Option<i128> {
    if bytes.is_empty() || bytes.len() > 16 {
        return None;
    }
    let mut v: i128 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        v = (v << 8) | b as i128;
    }
    Some(v)
}

/// Decode OBJECT IDENTIFIER content octets into arc values.
pub fn oid_arcs(bytes: &[u8]) -> Option<Vec<u64>> {
    if bytes.is_empty() {
        return None;
    }
    let mut arcs = Vec::new();
    let mut sub: u64 = 0;
    let mut first = true;
    for (i, &b) in bytes.iter().enumerate() {
        sub = sub.checked_mul(128)?.checked_add((b & 0x7F) as u64)?;
        if b & 0x80 != 0 {
            if i == bytes.len() - 1 {
                return None; // truncated sub-identifier
            }
            continue;
        }
        if first {
            let (a0, a1) = if sub < 40 {
                (0, sub)
            } else if sub < 80 {
                (1, sub - 40)
            } else {
                (2, sub - 80)
            };
            arcs.push(a0);
            arcs.push(a1);
            first = false;
        } else {
            arcs.push(sub);
        }
        sub = 0;
    }
    Some(arcs)
}

pub fn is_printable_ascii(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&b| (0x20..=0x7E).contains(&b))
}

/// Format UTCTime / GeneralizedTime content the way dumpasn1 does
/// ("DD/MM/YYYY HH:MM:SS GMT"). Returns None for non-Zulu or malformed
/// values.
pub fn format_time(bytes: &[u8], generalized: bool) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    let digits = s.strip_suffix('Z')?;
    let need = if generalized { 14 } else { 12 };
    if digits.len() != need || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let num = |r: std::ops::Range<usize>| digits[r].parse::<u32>().unwrap();
    let (year, rest) = if generalized {
        (num(0..4), 4)
    } else {
        let yy = num(0..2);
        (if yy < 50 { 2000 + yy } else { 1900 + yy }, 2)
    };
    Some(format!(
        "{:02}/{:02}/{:04} {:02}:{:02}:{:02} GMT",
        num(rest + 2..rest + 4), // day
        num(rest..rest + 2),     // month
        year,
        num(rest + 4..rest + 6),
        num(rest + 6..rest + 8),
        num(rest + 8..rest + 10),
    ))
}

pub fn hex_pairs(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_sequence() {
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        let data = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let forest = parse_forest(&data, 0).unwrap();
        assert_eq!(forest.len(), 1);
        let seq = &forest[0];
        assert!(seq.is_universal(TAG_SEQUENCE));
        assert!(seq.constructed);
        assert_eq!(seq.offset, 0);
        assert_eq!(seq.header_len, 2);
        assert_eq!(seq.content_len, 6);
        assert_eq!(seq.children.len(), 2);
        assert_eq!(seq.children[1].offset, 5);
        assert_eq!(seq.children[1].value, vec![0x02]);
    }

    #[test]
    fn roundtrip_der() {
        // SEQUENCE { INTEGER 42, OCTET STRING AA BB, BOOLEAN TRUE }
        let data = [
            0x30, 0x0A, 0x02, 0x01, 0x2A, 0x04, 0x02, 0xAA, 0xBB, 0x01, 0x01, 0xFF,
        ];
        let forest = parse_forest(&data, 0).unwrap();
        assert_eq!(encode_forest(&forest), data);
    }

    #[test]
    fn octet_string_encapsulation() {
        // OCTET STRING { INTEGER 0x1234 } — inner item fills content exactly.
        let data = [0x04, 0x04, 0x02, 0x02, 0x12, 0x34];
        let forest = parse_forest(&data, 0).unwrap();
        let os = &forest[0];
        assert!(os.encapsulates);
        assert_eq!(os.children.len(), 1);
        assert_eq!(os.children[0].offset, 2);
        assert!(os.children[0].is_universal(TAG_INTEGER));
        assert_eq!(encode_forest(&forest), data);
    }

    #[test]
    fn octet_string_no_encapsulation_on_trailing_bytes() {
        // Inner item does not fill the value exactly -> plain OCTET STRING.
        let data = [0x04, 0x05, 0x02, 0x02, 0x12, 0x34, 0x00];
        let forest = parse_forest(&data, 0).unwrap();
        assert!(!forest[0].encapsulates);
        assert_eq!(encode_forest(&forest), data);
    }

    #[test]
    fn bit_string_encapsulation_skips_unused_bits_octet() {
        // BIT STRING, 0 unused bits, encapsulating SEQUENCE { INTEGER 1 }.
        let data = [0x03, 0x06, 0x00, 0x30, 0x03, 0x02, 0x01, 0x01];
        let forest = parse_forest(&data, 0).unwrap();
        let bs = &forest[0];
        assert!(bs.encapsulates);
        assert_eq!(bs.children[0].offset, 3);
        assert_eq!(encode_forest(&forest), data);
    }

    #[test]
    fn short_bit_string_is_not_encapsulating() {
        // Remaining content of <= 4 bytes is treated as bit flags by
        // dumpasn1, never as encapsulated data.
        let data = [0x03, 0x05, 0x00, 0x30, 0x02, 0x05, 0x00];
        let forest = parse_forest(&data, 0).unwrap();
        assert!(!forest[0].encapsulates);
    }

    #[test]
    fn indefinite_length_parses_and_normalizes() {
        // SEQUENCE (indefinite) { NULL } EOC
        let data = [0x30, 0x80, 0x05, 0x00, 0x00, 0x00];
        let forest = parse_forest(&data, 0).unwrap();
        let seq = &forest[0];
        assert!(seq.indefinite);
        assert_eq!(seq.content_len, 2);
        // Re-encoding uses definite lengths.
        assert_eq!(encode_forest(&forest), [0x30, 0x02, 0x05, 0x00]);
    }

    #[test]
    fn high_tag_number_roundtrip() {
        // [APPLICATION 1000] (primitive) with 1 content byte.
        let mut data = Vec::new();
        write_identifier(Class::Application, 1000, false, &mut data);
        data.push(0x01);
        data.push(0xAB);
        let forest = parse_forest(&data, 0).unwrap();
        assert_eq!(forest[0].tag, 1000);
        assert_eq!(forest[0].class, Class::Application);
        assert_eq!(encode_forest(&forest), data);
    }

    #[test]
    fn long_length_roundtrip() {
        let mut data = vec![0x04, 0x81, 0x80];
        data.extend(std::iter::repeat_n(0xEE, 0x80));
        let forest = parse_forest(&data, 0).unwrap();
        assert_eq!(forest[0].content_len, 0x80);
        assert_eq!(encode_forest(&forest), data);
    }

    #[test]
    fn trailing_garbage_is_an_error() {
        let data = [0x05, 0x00, 0x00];
        let e = parse_forest(&data, 0).unwrap_err();
        assert_eq!(e.offset, 2);
    }

    #[test]
    fn oid_decoding() {
        // 2.5.4.3 (commonName)
        assert_eq!(oid_arcs(&[0x55, 0x04, 0x03]), Some(vec![2, 5, 4, 3]));
        // 1.2.840.113549
        assert_eq!(
            oid_arcs(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]),
            Some(vec![1, 2, 840, 113549])
        );
    }

    #[test]
    fn integer_decoding() {
        assert_eq!(decode_integer(&[0x02]), Some(2));
        assert_eq!(decode_integer(&[0xFF]), Some(-1));
        assert_eq!(decode_integer(&[0x00, 0xFF]), Some(255));
        assert_eq!(decode_integer(&[0x01, 0x00, 0x01]), Some(65537));
    }

    #[test]
    fn time_formatting() {
        assert_eq!(
            format_time(b"260709115028Z", false).as_deref(),
            Some("09/07/2026 11:50:28 GMT")
        );
        assert_eq!(
            format_time(b"20260709115028Z", true).as_deref(),
            Some("09/07/2026 11:50:28 GMT")
        );
    }
}
