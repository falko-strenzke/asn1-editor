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

//! dumpasn1-style text output.
//!
//! The structural fields (offset, length, type name, nesting) match
//! dumpasn1's output exactly; value rendering (integers, strings, times,
//! hex dumps) is a close approximation. The compatibility test in
//! `tests/dumpasn1_compat.rs` compares the structural fields against the
//! real dumpasn1 binary.

use crate::ber::{
    self, Node, TAG_BIT_STRING, TAG_BOOLEAN, TAG_ENUMERATED, TAG_GENERALIZED_TIME, TAG_INTEGER,
    TAG_NULL, TAG_OCTET_STRING, TAG_OID, TAG_UTC_TIME,
};

/// Bytes of hex shown before dumpasn1 prints "[ Another N bytes skipped ]".
const HEX_DISPLAY_LIMIT: usize = 128;

/// A minimal built-in OID name table (dumpasn1 loads a much larger one from
/// dumpasn1.cfg; names are cosmetic and not part of the structure check).
const OID_NAMES: &[(&[u64], &str)] = &[
    (&[1, 2, 840, 10045, 2, 1], "ecPublicKey"),
    (&[1, 2, 840, 10045, 3, 1, 7], "prime256v1"),
    (&[1, 2, 840, 10045, 4, 3, 2], "ecdsaWithSHA256"),
    (&[1, 2, 840, 113549, 1, 1, 1], "rsaEncryption"),
    (&[1, 2, 840, 113549, 1, 1, 11], "sha256WithRSAEncryption"),
    (&[1, 2, 840, 113549, 1, 7, 1], "data"),
    (&[1, 2, 840, 113549, 1, 7, 2], "signedData"),
    (&[1, 2, 840, 113549, 1, 9, 1], "emailAddress"),
    (&[2, 5, 4, 3], "commonName"),
    (&[2, 5, 4, 6], "countryName"),
    (&[2, 5, 4, 7], "localityName"),
    (&[2, 5, 4, 8], "stateOrProvinceName"),
    (&[2, 5, 4, 10], "organizationName"),
    (&[2, 5, 4, 11], "organizationalUnitName"),
    (&[2, 5, 29, 14], "subjectKeyIdentifier"),
    (&[2, 5, 29, 15], "keyUsage"),
    (&[2, 5, 29, 17], "subjectAltName"),
    (&[2, 5, 29, 19], "basicConstraints"),
    (&[2, 5, 29, 20], "cRLNumber"),
    (&[2, 5, 29, 31], "cRLDistributionPoints"),
    (&[2, 5, 29, 35], "authorityKeyIdentifier"),
    (&[2, 5, 29, 37], "extKeyUsage"),
];

pub fn dump(roots: &[Node], total_len: usize) -> String {
    let width = std::cmp::max(3, total_len.to_string().len());
    let mut out = String::new();
    for node in roots {
        dump_node(node, 0, width, &mut out);
    }
    out
}

fn blank_prefix(width: usize) -> String {
    format!("{:>w$} {:>w$}: ", "", "", w = width)
}

fn dump_node(node: &Node, depth: usize, width: usize, out: &mut String) {
    let len_field = if node.indefinite {
        "NDEF".to_string()
    } else {
        node.content_len.to_string()
    };
    let prefix = format!("{:>w$} {:>w$}: ", node.offset, len_field, w = width);
    let indent = "  ".repeat(depth);
    let name = node.type_name();

    if node.constructed || node.encapsulates {
        let mut annotation = String::new();
        if node.encapsulates && node.is_universal(TAG_BIT_STRING) {
            let unused = node.value.first().copied().unwrap_or(0);
            if unused != 0 {
                annotation = format!(" {} unused bit{}", unused, plural(unused as usize));
            }
        }
        // dumpasn1 prints zero-length constructed items as "NAME {}".
        if node.children.is_empty() && node.content_len == 0 && !node.indefinite {
            out.push_str(&format!("{prefix}{indent}{name} {{}}\n"));
            return;
        }
        let opener = if node.encapsulates { ", encapsulates {" } else { " {" };
        out.push_str(&format!("{prefix}{indent}{name}{annotation}{opener}\n"));
        for child in &node.children {
            dump_node(child, depth + 1, width, out);
        }
        out.push_str(&format!("{}{}  }}\n", blank_prefix(width), indent));
    } else {
        out.push_str(&format!("{prefix}{indent}{name}"));
        write_primitive_value(node, depth, width, out);
        out.push('\n');
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Append the value part of a primitive node's line (and possibly hex
/// continuation lines, which carry the blank offset/length prefix).
fn write_primitive_value(node: &Node, depth: usize, width: usize, out: &mut String) {
    let v = &node.value;
    if node.class != ber::Class::Universal {
        // Implicitly tagged content: show text if printable, hex otherwise.
        write_text_or_hex(v, depth, width, out);
        return;
    }
    match node.tag {
        TAG_BOOLEAN => {
            let s = if v.first().copied().unwrap_or(0) == 0 { "FALSE" } else { "TRUE" };
            out.push_str(&format!(" {}", s));
        }
        TAG_INTEGER | TAG_ENUMERATED => {
            if v.len() <= 8 {
                if let Some(i) = ber::decode_integer(v) {
                    out.push_str(&format!(" {}", i));
                    return;
                }
            }
            write_hex(v, depth, width, out);
        }
        TAG_BIT_STRING => {
            let unused = v.first().copied().unwrap_or(0);
            if unused != 0 {
                out.push_str(&format!(" {} unused bit{}", unused, plural(unused as usize)));
            }
            match v.len() {
                0 => {}
                1 => out.push_str(" (no bits set)"),
                _ => write_hex(&v[1..], depth, width, out),
            }
        }
        TAG_OCTET_STRING => write_text_or_hex(v, depth, width, out),
        TAG_NULL => {}
        TAG_OID => match ber::oid_arcs(v) {
            Some(arcs) => {
                let text = arcs
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                match OID_NAMES.iter().find(|(a, _)| *a == arcs.as_slice()) {
                    Some((_, name)) => {
                        // dumpasn1 moves "name (arcs)" to a continuation
                        // line when it would wrap an 80-column display.
                        if (2 * width + 3) + 2 * depth + 18 + name.len() + 2 + text.len() >= 80 {
                            out.push_str(&format!(
                                "\n{}{}{} ({})",
                                blank_prefix(width),
                                "  ".repeat(depth + 1),
                                name,
                                text
                            ));
                        } else {
                            out.push_str(&format!(" {} ({})", name, text));
                        }
                    }
                    None => out.push_str(&format!(" '{}'", text)),
                }
            }
            None => write_hex(v, depth, width, out),
        },
        TAG_UTC_TIME | TAG_GENERALIZED_TIME => {
            match ber::format_time(v, node.tag == TAG_GENERALIZED_TIME) {
                Some(t) => out.push_str(&format!(" {}", t)),
                None => write_text_or_hex(v, depth, width, out),
            }
        }
        // String types and everything else.
        _ => write_text_or_hex(v, depth, width, out),
    }
}

fn write_text_or_hex(v: &[u8], depth: usize, width: usize, out: &mut String) {
    if v.is_empty() {
        return;
    }
    if ber::is_printable_ascii(v) {
        out.push_str(&format!(" '{}'", String::from_utf8_lossy(v)));
    } else {
        write_hex(v, depth, width, out);
    }
}

/// Hex rendering following dumpasn1's dumpHex(): the value goes on the same
/// line when prefix + indent + hex fit in an 80-column display, otherwise it
/// becomes an indented block of 16 bytes per line, capped at 128 bytes
/// (unless less than one extra line would remain).
fn write_hex(v: &[u8], depth: usize, width: usize, out: &mut String) {
    if (2 * width + 5) + 2 * depth + 3 * v.len() < 80 {
        out.push_str(&format!(" {}", ber::hex_pairs(v)));
        return;
    }
    // dumpasn1 caps the indentation of hex blocks (adjustLevel) so deeply
    // nested values do not run off an 80-column display.
    let display_len = (2 * width + 5) + v.len().min(16) * 3;
    let level = depth.min(80usize.saturating_sub(display_len) / 2);
    let indent = "  ".repeat(level + 1);
    let shown = if v.len() < HEX_DISPLAY_LIMIT + 16 { v.len() } else { HEX_DISPLAY_LIMIT };
    for chunk in v[..shown].chunks(16) {
        out.push_str(&format!("\n{}{}{}", blank_prefix(width), indent, ber::hex_pairs(chunk)));
    }
    if shown < v.len() {
        // dumpasn1 indents this marker by doIndent(level + 5).
        out.push_str(&format!(
            "\n{}{}[ Another {} bytes skipped ]",
            blank_prefix(width),
            "  ".repeat(level + 5),
            v.len() - shown
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::parse_forest;

    #[test]
    fn dump_format_matches_dumpasn1_layout() {
        // SEQUENCE { INTEGER 2, NULL }
        let data = [0x30, 0x05, 0x02, 0x01, 0x02, 0x05, 0x00];
        let forest = parse_forest(&data, 0).unwrap();
        let text = dump(&forest, data.len());
        let expected = concat!(
            "  0   5: SEQUENCE {\n",
            "  2   1:   INTEGER 2\n",
            "  5   0:   NULL\n",
            "       :   }\n",
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn dump_encapsulated_octet_string() {
        let data = [0x04, 0x04, 0x02, 0x02, 0x12, 0x34];
        let forest = parse_forest(&data, 0).unwrap();
        let text = dump(&forest, data.len());
        assert!(text.starts_with("  0   4: OCTET STRING, encapsulates {\n"));
        assert!(text.contains("  2   2:   INTEGER 4660\n"));
    }
}
