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

//! Structural decoding, human-readable interpretation and re-encoding of the
//! X.509 `KeyUsage` certificate extension (RFC 5280 §4.2.1.3,
//! `id-ce-keyUsage` = 2.5.29.15):
//!
//! ```text
//! KeyUsage ::= BIT STRING {
//!     digitalSignature (0), nonRepudiation   (1), keyEncipherment (2),
//!     dataEncipherment (3), keyAgreement     (4), keyCertSign     (5),
//!     cRLSign          (6), encipherOnly     (7), decipherOnly    (8) }
//! ```
//!
//! Like [`super::basic_constraints`], the functions walk a `ber::Node`
//! positionally and operate on the outer `Extension` SEQUENCE
//! (`{ extnID, critical?, extnValue }`) — the node the user selects in the
//! tree — so one node drives both the content-pane interpretation and the
//! "As Key Usage" structured editor.

use crate::ber::{self, Node};

/// `id-ce-keyUsage`.
pub const EXTN_OID: &[u64] = &[2, 5, 29, 15];

/// Number of defined `KeyUsage` bits (positions 0..=8).
pub const NUM_BITS: usize = 9;

/// The nine `KeyUsage` bits in bit-position order: name and the usage each
/// permits when set.
pub const BITS: [(&str, &str); NUM_BITS] = [
    (
        "digitalSignature",
        "verify signatures other than on certificates and CRLs (entity authentication, signed data)",
    ),
    ("nonRepudiation", "verify non-repudiation (content commitment) signatures"),
    ("keyEncipherment", "encipher private or secret keys (e.g. RSA key transport)"),
    ("dataEncipherment", "encipher raw user data directly"),
    ("keyAgreement", "perform key agreement (e.g. ECDH)"),
    ("keyCertSign", "verify signatures on certificates (requires cA = TRUE in Basic Constraints)"),
    ("cRLSign", "verify signatures on CRLs"),
    ("encipherOnly", "restrict key agreement to enciphering only (only meaningful with keyAgreement)"),
    ("decipherOnly", "restrict key agreement to deciphering only (only meaningful with keyAgreement)"),
];

/// The decoded `KeyUsage` extension.
pub struct KeyUsage {
    /// One flag per defined bit, in bit-position order (see [`BITS`]).
    pub bits: [bool; NUM_BITS],
    /// Whether the enclosing `Extension` is marked critical.
    pub critical: bool,
}

/// If `node` is an X.509 `Extension` SEQUENCE carrying KeyUsage, return the
/// index of its `extnValue` OCTET STRING child. The node must be a constructed
/// SEQUENCE whose first child is the KeyUsage `extnID` OID and whose last child
/// is a primitive OCTET STRING.
pub fn value_index(node: &Node) -> Option<usize> {
    if !node.constructed || !node.is_universal(ber::TAG_SEQUENCE) {
        return None;
    }
    let first = node.children.first()?;
    if !first.is_universal(ber::TAG_OID) || ber::oid_arcs(&first.value)? != EXTN_OID {
        return None;
    }
    let last = node.children.len().checked_sub(1)?;
    let extn_value = &node.children[last];
    if last == 0 || extn_value.constructed || !extn_value.is_universal(ber::TAG_OCTET_STRING) {
        return None;
    }
    Some(last)
}

/// The inner `KeyUsage` BIT STRING carried by an `extnValue` OCTET STRING —
/// either the child the parser's encapsulation heuristic already decoded
/// (DESIGN.md §5) or, failing that, parsed from the raw value.
fn inner_bit_string(extn_value: &Node) -> Option<Node> {
    let bs = if extn_value.encapsulates {
        extn_value.children.first().cloned()
    } else {
        ber::parse_forest(&extn_value.value, 0).ok()?.into_iter().next()
    }?;
    bs.is_universal(ber::TAG_BIT_STRING).then_some(bs)
}

/// Decode the KeyUsage flags from the outer `Extension` SEQUENCE, or `None` if
/// `node` is not a KeyUsage extension.
pub fn parse(node: &Node) -> Option<KeyUsage> {
    let idx = value_index(node)?;
    let bs = inner_bit_string(&node.children[idx])?;
    let bits = decode_bits(&bs.value);
    // `critical` is a field of the enclosing Extension, not of the inner value:
    // Extension ::= { extnID, critical BOOLEAN DEFAULT FALSE, extnValue }.
    let critical = node.children.len() >= 3
        && node.children[1].is_universal(ber::TAG_BOOLEAN)
        && node.children[1].value.first().copied().unwrap_or(0) != 0;
    Some(KeyUsage { bits, critical })
}

/// Decode a BIT STRING's content octets (`[unused-bit count, bit octets…]`)
/// into the nine named flags. Bits are numbered from the most-significant bit
/// of the first octet; out-of-range positions read as clear.
fn decode_bits(value: &[u8]) -> [bool; NUM_BITS] {
    let octets = value.get(1..).unwrap_or(&[]);
    let mut bits = [false; NUM_BITS];
    for (i, b) in bits.iter_mut().enumerate() {
        let mask = 0x80u8 >> (i % 8);
        *b = octets.get(i / 8).is_some_and(|&o| o & mask != 0);
    }
    bits
}

/// Plain-language interpretation of the extension, one line per set usage, for
/// the content pane.
pub fn describe(ku: &KeyUsage) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(if ku.critical {
        "Marked critical — a relying party that cannot process this extension must reject the certificate.".to_string()
    } else {
        "Not marked critical.".to_string()
    });
    if ku.bits.iter().any(|&b| b) {
        lines.push("Permitted key usages:".to_string());
        for (i, &on) in ku.bits.iter().enumerate() {
            if on {
                let (name, meaning) = BITS[i];
                lines.push(format!("• {name}: {meaning}"));
            }
        }
    } else {
        lines.push(
            "No key-usage bits are set — RFC 5280 requires at least one bit to be set.".to_string(),
        );
    }
    lines
}

/// Encode the nine flags as a complete DER BIT STRING (the content of an
/// `extnValue` OCTET STRING). Following DER, trailing zero bits are trimmed, so
/// the length depends on the highest set bit; no bits set yields an empty BIT
/// STRING.
pub fn encode_der(bits: &[bool; NUM_BITS]) -> Vec<u8> {
    let content = match (0..NUM_BITS).rev().find(|&i| bits[i]) {
        None => vec![0x00], // empty BIT STRING, zero unused bits
        Some(highest) => {
            let nbits = highest + 1;
            let nbytes = nbits.div_ceil(8);
            let mut data = vec![0u8; nbytes];
            for (i, &on) in bits.iter().enumerate() {
                if on {
                    data[i / 8] |= 0x80 >> (i % 8);
                }
            }
            let mut c = Vec::with_capacity(nbytes + 1);
            c.push((nbytes * 8 - nbits) as u8); // unused bits
            c.extend_from_slice(&data);
            c
        }
    };
    let mut out = Vec::with_capacity(content.len() + 2);
    out.push(ber::TAG_BIT_STRING as u8); // primitive BIT STRING
    out.extend_from_slice(&ber::length_octets(content.len()));
    out.extend_from_slice(&content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn extension_node(cert_rel: &str) -> Node {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(cert_rel);
        let der = std::fs::read(&path).unwrap_or_else(|_| panic!("read {cert_rel}"));
        let roots = ber::parse_forest(&der, 0).expect("parse cert");
        find_ku_extension(&roots).unwrap_or_else(|| panic!("no KeyUsage in {cert_rel}"))
    }

    /// Depth-first search for the first KeyUsage Extension SEQUENCE.
    fn find_ku_extension(nodes: &[Node]) -> Option<Node> {
        for n in nodes {
            if value_index(n).is_some() {
                return Some(n.clone());
            }
            if let Some(found) = find_ku_extension(&n.children) {
                return Some(found);
            }
        }
        None
    }

    fn set_names(ku: &KeyUsage) -> Vec<&'static str> {
        ku.bits
            .iter()
            .enumerate()
            .filter(|(_, &b)| b)
            .map(|(i, _)| BITS[i].0)
            .collect()
    }

    #[test]
    fn parses_ca_cert_sign_and_crl_sign() {
        let ku = parse(&extension_node("testdata/chain/root_ca.der")).expect("key usage");
        assert!(ku.critical);
        assert_eq!(set_names(&ku), ["keyCertSign", "cRLSign"]);
    }

    #[test]
    fn parses_leaf_digital_signature_only() {
        let ku = parse(&extension_node("testdata/chain/server.der")).expect("key usage");
        assert!(ku.critical);
        assert_eq!(set_names(&ku), ["digitalSignature"]);
    }

    #[test]
    fn non_key_usage_node_is_none() {
        let der = [0x02, 0x01, 0x05]; // a bare INTEGER
        let roots = ber::parse_forest(&der, 0).unwrap();
        assert!(value_index(&roots[0]).is_none());
        assert!(parse(&roots[0]).is_none());
    }

    #[test]
    fn encode_matches_known_bit_patterns() {
        // digitalSignature (bit 0): 7 unused bits, 0x80.
        let mut ds = [false; NUM_BITS];
        ds[0] = true;
        assert_eq!(encode_der(&ds), [0x03, 0x02, 0x07, 0x80]);
        // keyCertSign (5) + cRLSign (6): 1 unused bit, 0x06.
        let mut ca = [false; NUM_BITS];
        ca[5] = true;
        ca[6] = true;
        assert_eq!(encode_der(&ca), [0x03, 0x02, 0x01, 0x06]);
        // decipherOnly (8) is the only two-octet case: 7 unused bits, 0x00 0x80.
        let mut dec = [false; NUM_BITS];
        dec[8] = true;
        assert_eq!(encode_der(&dec), [0x03, 0x03, 0x07, 0x00, 0x80]);
        // No bits set: empty BIT STRING.
        assert_eq!(encode_der(&[false; NUM_BITS]), [0x03, 0x01, 0x00]);
    }

    #[test]
    fn encode_round_trips_through_parse() {
        let patterns: [[bool; NUM_BITS]; 3] = [
            {
                let mut b = [false; NUM_BITS];
                b[0] = true;
                b[2] = true;
                b
            },
            {
                let mut b = [false; NUM_BITS];
                b[5] = true;
                b[6] = true;
                b
            },
            {
                let mut b = [false; NUM_BITS];
                b[4] = true;
                b[8] = true;
                b
            },
        ];
        for bits in patterns {
            let bs = encode_der(&bits);
            // Wrap in a minimal Extension SEQUENCE to parse it back.
            let mut ext_content = Vec::new();
            ext_content.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x0F]); // OID 2.5.29.15
            ext_content.push(0x04); // extnValue OCTET STRING
            ext_content.extend_from_slice(&ber::length_octets(bs.len()));
            ext_content.extend_from_slice(&bs);
            let mut ext = vec![0x30];
            ext.extend_from_slice(&ber::length_octets(ext_content.len()));
            ext.extend_from_slice(&ext_content);

            let roots = ber::parse_forest(&ext, 0).unwrap();
            let ku = parse(&roots[0]).expect("round-trip parse");
            assert_eq!(ku.bits, bits);
        }
    }
}
