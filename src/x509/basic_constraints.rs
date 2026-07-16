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
//! X.509 `BasicConstraints` certificate extension (RFC 5280 §4.2.1.9,
//! `id-ce-basicConstraints` = 2.5.29.19):
//!
//! ```text
//! BasicConstraints ::= SEQUENCE {
//!     cA                      BOOLEAN DEFAULT FALSE,
//!     pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
//! ```
//!
//! The functions here walk a `ber::Node` positionally, like `x509.rs`. They
//! operate on the outer `Extension` SEQUENCE (`{ extnID, critical?, extnValue }`)
//! so the same node the user selects in the tree drives both the content-pane
//! interpretation and the "As Basic Constraints" structured editor.

use crate::ber::{self, Node};

/// `id-ce-basicConstraints`.
pub const EXTN_OID: &[u64] = &[2, 5, 29, 19];

/// The decoded fields of a BasicConstraints extension.
pub struct BasicConstraints {
    /// The `cA` boolean (DEFAULT FALSE).
    pub ca: bool,
    /// Whether the enclosing `Extension` is marked critical.
    pub critical: bool,
    /// `pathLenConstraint` as a decimal string, if present.
    pub path_len: Option<String>,
}

/// If `node` is an X.509 `Extension` SEQUENCE carrying BasicConstraints,
/// return the index of its `extnValue` OCTET STRING child. The node must be a
/// constructed SEQUENCE whose first child is the BasicConstraints `extnID` OID
/// and whose last child is a primitive OCTET STRING.
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

/// The inner `BasicConstraints` SEQUENCE carried by an `extnValue` OCTET
/// STRING — either the child the parser's encapsulation heuristic already
/// decoded (DESIGN.md §5) or, failing that, parsed from the raw value.
fn inner_sequence(extn_value: &Node) -> Option<Node> {
    let seq = if extn_value.encapsulates {
        extn_value.children.first().cloned()
    } else {
        ber::parse_forest(&extn_value.value, 0).ok()?.into_iter().next()
    }?;
    seq.is_universal(ber::TAG_SEQUENCE).then_some(seq)
}

/// Decode the BasicConstraints fields from the outer `Extension` SEQUENCE, or
/// `None` if `node` is not a BasicConstraints extension.
pub fn parse(node: &Node) -> Option<BasicConstraints> {
    let idx = value_index(node)?;
    let seq = inner_sequence(&node.children[idx])?;
    let mut ca = false;
    let mut path_len = None;
    for child in &seq.children {
        if child.is_universal(ber::TAG_BOOLEAN) {
            ca = child.value.first().copied().unwrap_or(0) != 0;
        } else if child.is_universal(ber::TAG_INTEGER) {
            path_len = ber::integer_decimal(&child.value);
        }
    }
    // `critical` is a field of the enclosing Extension, not of the inner
    // value: Extension ::= { extnID, critical BOOLEAN DEFAULT FALSE, extnValue }.
    let critical = node.children.len() >= 3
        && node.children[1].is_universal(ber::TAG_BOOLEAN)
        && node.children[1].value.first().copied().unwrap_or(0) != 0;
    Some(BasicConstraints { ca, critical, path_len })
}

/// Plain-language interpretation of the extension, one sentence per line, for
/// the content pane.
pub fn describe(bc: &BasicConstraints) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(if bc.critical {
        "Marked critical — a relying party that cannot process this extension must reject the certificate.".to_string()
    } else {
        "Not marked critical.".to_string()
    });
    if bc.ca {
        lines.push(
            "cA = TRUE: a CA certificate — its public key may be used to verify signatures on other certificates."
                .to_string(),
        );
        match &bc.path_len {
            Some(n) => {
                let plural = if n == "1" { "" } else { "s" };
                lines.push(format!(
                    "pathLenConstraint = {n}: at most {n} intermediate CA certificate{plural} may follow this one before an end-entity certificate.",
                ));
            }
            None => lines.push(
                "pathLenConstraint absent: no limit on the number of subordinate CA certificates below this one."
                    .to_string(),
            ),
        }
    } else {
        lines.push(
            "cA = FALSE: an end-entity certificate — its public key must not be used to verify certificate signatures."
                .to_string(),
        );
        if bc.path_len.is_some() {
            lines.push(
                "pathLenConstraint is present but has no meaning while cA is FALSE.".to_string(),
            );
        }
    }
    lines
}

/// Encode a fresh `BasicConstraints` value as a complete DER SEQUENCE (the
/// content of an `extnValue` OCTET STRING). `cA = FALSE` is omitted (DER
/// DEFAULT) and `pathLenConstraint` is emitted only when `cA` is asserted,
/// as required by RFC 5280 §4.2.1.9.
pub fn encode_der(ca: bool, path_len: Option<u32>) -> Vec<u8> {
    let mut content = Vec::new();
    if ca {
        content.extend_from_slice(&[ber::TAG_BOOLEAN as u8, 0x01, 0xFF]);
    }
    if let (true, Some(n)) = (ca, path_len) {
        let int = ber::encode_integer(i128::from(n));
        content.push(ber::TAG_INTEGER as u8);
        content.extend_from_slice(&ber::length_octets(int.len()));
        content.extend_from_slice(&int);
    }
    let mut out = Vec::with_capacity(content.len() + 2);
    out.push((ber::TAG_SEQUENCE as u8) | 0x20); // constructed SEQUENCE
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
        find_bc_extension(&roots).unwrap_or_else(|| panic!("no BasicConstraints in {cert_rel}"))
    }

    /// Depth-first search for the first BasicConstraints Extension SEQUENCE.
    fn find_bc_extension(nodes: &[Node]) -> Option<Node> {
        for n in nodes {
            if value_index(n).is_some() {
                return Some(n.clone());
            }
            if let Some(found) = find_bc_extension(&n.children) {
                return Some(found);
            }
        }
        None
    }

    #[test]
    fn parses_ca_true_without_path_len() {
        let node = extension_node("testdata/chain/root_ca.der");
        let bc = parse(&node).expect("basic constraints");
        assert!(bc.ca);
        assert!(bc.critical);
        assert_eq!(bc.path_len, None);
    }

    #[test]
    fn parses_ca_true_with_path_len_zero() {
        let node = extension_node("testdata/chain/intermediate_ca.der");
        let bc = parse(&node).expect("basic constraints");
        assert!(bc.ca);
        assert_eq!(bc.path_len.as_deref(), Some("0"));
    }

    #[test]
    fn parses_end_entity_ca_false() {
        let node = extension_node("testdata/chain/server.der");
        let bc = parse(&node).expect("basic constraints");
        assert!(!bc.ca);
    }

    #[test]
    fn non_basic_constraints_node_is_none() {
        // A bare INTEGER is not an Extension SEQUENCE.
        let der = [0x02, 0x01, 0x05];
        let roots = ber::parse_forest(&der, 0).unwrap();
        assert!(value_index(&roots[0]).is_none());
        assert!(parse(&roots[0]).is_none());
    }

    #[test]
    fn encode_round_trips_through_parse() {
        for (ca, path_len) in [(true, None), (true, Some(0)), (true, Some(3)), (false, None)] {
            let der = encode_der(ca, path_len);
            // Wrap the value in a minimal Extension SEQUENCE to parse it back.
            let mut ext_content = Vec::new();
            // extnID OID 2.5.29.19
            ext_content.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x13]);
            // extnValue OCTET STRING wrapping the BasicConstraints DER
            ext_content.push(0x04);
            ext_content.extend_from_slice(&ber::length_octets(der.len()));
            ext_content.extend_from_slice(&der);
            let mut ext = vec![0x30];
            ext.extend_from_slice(&ber::length_octets(ext_content.len()));
            ext.extend_from_slice(&ext_content);

            let roots = ber::parse_forest(&ext, 0).unwrap();
            let bc = parse(&roots[0]).expect("round-trip parse");
            assert_eq!(bc.ca, ca);
            // pathLenConstraint is emitted only when cA is asserted.
            let expected = if ca { path_len.map(|n| n.to_string()) } else { None };
            assert_eq!(bc.path_len, expected);
        }
    }
}
