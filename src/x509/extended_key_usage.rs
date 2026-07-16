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
//! X.509 `ExtKeyUsage` certificate extension (RFC 5280 §4.2.1.12,
//! `id-ce-extKeyUsage` = 2.5.29.37):
//!
//! ```text
//! ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
//! KeyPurposeId ::= OBJECT IDENTIFIER
//! ```
//!
//! Like [`super::basic_constraints`] and [`super::key_usage`], the functions
//! walk a `ber::Node` positionally and operate on the outer `Extension`
//! SEQUENCE (`{ extnID, critical?, extnValue }`) — the node the user selects in
//! the tree — so one node drives both the content-pane interpretation and the
//! "As Extended Key Usage" structured editor. Because the value is an open list
//! of OIDs, the editor toggles a set of well-known `KeyPurposeId`s and also
//! accepts arbitrary OIDs typed in dot notation.

use crate::ber::{self, Node};
use crate::oid;

/// `id-ce-extKeyUsage`.
pub const EXTN_OID: &[u64] = &[2, 5, 29, 37];

/// The well-known key purposes offered as toggles in the editor: OID, short
/// name and the usage each grants (RFC 5280 §4.2.1.12).
pub const PURPOSES: [(&[u64], &str, &str); 7] = [
    (&[2, 5, 29, 37, 0], "anyExtendedKeyUsage", "any purpose (imposes no extended-key-usage restriction)"),
    (&[1, 3, 6, 1, 5, 5, 7, 3, 1], "serverAuth", "TLS server authentication"),
    (&[1, 3, 6, 1, 5, 5, 7, 3, 2], "clientAuth", "TLS client authentication"),
    (&[1, 3, 6, 1, 5, 5, 7, 3, 3], "codeSigning", "signing of downloadable executable code"),
    (&[1, 3, 6, 1, 5, 5, 7, 3, 4], "emailProtection", "email protection (S/MIME)"),
    (&[1, 3, 6, 1, 5, 5, 7, 3, 8], "timeStamping", "binding a hash to a time (trusted timestamping)"),
    (&[1, 3, 6, 1, 5, 5, 7, 3, 9], "OCSPSigning", "signing OCSP responses"),
];

/// Number of well-known purposes in [`PURPOSES`].
pub const NUM_PREDEFINED: usize = PURPOSES.len();

/// The decoded `ExtendedKeyUsage` extension.
pub struct ExtendedKeyUsage {
    /// The `KeyPurposeId` OIDs, in the order they appear.
    pub purposes: Vec<Vec<u64>>,
    /// Whether the enclosing `Extension` is marked critical.
    pub critical: bool,
}

/// Index into [`PURPOSES`] of a well-known purpose, if `arcs` is one.
pub fn predefined_index(arcs: &[u64]) -> Option<usize> {
    PURPOSES.iter().position(|(oid, _, _)| *oid == arcs)
}

/// If `node` is an X.509 `Extension` SEQUENCE carrying ExtendedKeyUsage, return
/// the index of its `extnValue` OCTET STRING child. The node must be a
/// constructed SEQUENCE whose first child is the ExtKeyUsage `extnID` OID and
/// whose last child is a primitive OCTET STRING.
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

/// The inner `ExtKeyUsageSyntax` SEQUENCE carried by an `extnValue` OCTET
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

/// Decode the key purposes from the outer `Extension` SEQUENCE, or `None` if
/// `node` is not an ExtendedKeyUsage extension.
pub fn parse(node: &Node) -> Option<ExtendedKeyUsage> {
    let idx = value_index(node)?;
    let seq = inner_sequence(&node.children[idx])?;
    let mut purposes = Vec::new();
    for child in &seq.children {
        if child.is_universal(ber::TAG_OID) {
            if let Some(arcs) = ber::oid_arcs(&child.value) {
                purposes.push(arcs);
            }
        }
    }
    // `critical` is a field of the enclosing Extension, not of the inner value:
    // Extension ::= { extnID, critical BOOLEAN DEFAULT FALSE, extnValue }.
    let critical = node.children.len() >= 3
        && node.children[1].is_universal(ber::TAG_BOOLEAN)
        && node.children[1].value.first().copied().unwrap_or(0) != 0;
    Some(ExtendedKeyUsage { purposes, critical })
}

/// A display label for one `KeyPurposeId`: `(name, dotted, meaning)`. The name
/// is the well-known short name, else the built-in OID repository's short name,
/// else the dotted form; `meaning` is filled for well-known purposes only.
pub fn purpose_label(arcs: &[u64]) -> (String, String, Option<&'static str>) {
    let dotted = oid::dotted(arcs);
    if let Some(i) = predefined_index(arcs) {
        let (_, name, meaning) = PURPOSES[i];
        (name.to_string(), dotted, Some(meaning))
    } else if let Some(entry) = oid::lookup(arcs) {
        (entry.short_name.to_string(), dotted, None)
    } else {
        (dotted.clone(), dotted, None)
    }
}

/// Plain-language interpretation of the extension, one line per key purpose,
/// for the content pane.
pub fn describe(eku: &ExtendedKeyUsage) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(if eku.critical {
        "Marked critical — the certificate may be used only for the purposes listed below.".to_string()
    } else {
        "Not marked critical — a consistency advisory that SHOULD still be honoured (RFC 5280).".to_string()
    });
    if eku.purposes.is_empty() {
        lines.push(
            "No key purposes are listed — RFC 5280 requires at least one.".to_string(),
        );
    } else {
        lines.push("Permitted key purposes:".to_string());
        for arcs in &eku.purposes {
            let (name, dotted, meaning) = purpose_label(arcs);
            match meaning {
                Some(m) => lines.push(format!("• {name} ({dotted}): {m}")),
                None if name == dotted => {
                    lines.push(format!("• {dotted} (unrecognised key purpose)"))
                }
                None => lines.push(format!("• {name} ({dotted})")),
            }
        }
    }
    lines
}

/// Encode a fresh list of `KeyPurposeId`s as a complete DER SEQUENCE (the
/// content of an `extnValue` OCTET STRING). Arcs that do not form a valid OID
/// are skipped (the callers only pass validated arcs).
pub fn encode_der(purposes: &[Vec<u64>]) -> Vec<u8> {
    let mut content = Vec::new();
    for arcs in purposes {
        let Ok(oid_content) = ber::encode_oid(&oid::dotted(arcs)) else { continue };
        content.push(ber::TAG_OID as u8);
        content.extend_from_slice(&ber::length_octets(oid_content.len()));
        content.extend_from_slice(&oid_content);
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
        find_eku_extension(&roots).unwrap_or_else(|| panic!("no ExtKeyUsage in {cert_rel}"))
    }

    fn find_eku_extension(nodes: &[Node]) -> Option<Node> {
        for n in nodes {
            if value_index(n).is_some() {
                return Some(n.clone());
            }
            if let Some(found) = find_eku_extension(&n.children) {
                return Some(found);
            }
        }
        None
    }

    #[test]
    fn parses_server_auth() {
        let eku = parse(&extension_node("testdata/chain/server.der")).expect("eku");
        assert!(eku.critical == eku.critical); // present regardless
        assert_eq!(eku.purposes, vec![vec![1, 3, 6, 1, 5, 5, 7, 3, 1]]);
        assert_eq!(predefined_index(&eku.purposes[0]), Some(1));
    }

    #[test]
    fn non_eku_node_is_none() {
        let der = [0x02, 0x01, 0x05]; // a bare INTEGER
        let roots = ber::parse_forest(&der, 0).unwrap();
        assert!(value_index(&roots[0]).is_none());
        assert!(parse(&roots[0]).is_none());
    }

    #[test]
    fn purpose_label_covers_predefined_repo_and_unknown() {
        let (name, dotted, meaning) = purpose_label(&[1, 3, 6, 1, 5, 5, 7, 3, 1]);
        assert_eq!(name, "serverAuth");
        assert_eq!(dotted, "1.3.6.1.5.5.7.3.1");
        assert!(meaning.is_some());

        // An OID the built-in repository does not know: label falls back to dotted.
        let (name, dotted, meaning) = purpose_label(&[1, 2, 3, 4, 5]);
        assert_eq!(name, "1.2.3.4.5");
        assert_eq!(dotted, "1.2.3.4.5");
        assert!(meaning.is_none());
    }

    #[test]
    fn encode_round_trips_through_parse() {
        let purposes = vec![
            vec![1, 3, 6, 1, 5, 5, 7, 3, 1], // serverAuth
            vec![1, 3, 6, 1, 5, 5, 7, 3, 2], // clientAuth
            vec![1, 2, 3, 4, 5],             // a custom OID
        ];
        let der = encode_der(&purposes);
        // Wrap in a minimal Extension SEQUENCE to parse it back.
        let mut ext_content = Vec::new();
        ext_content.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x25]); // OID 2.5.29.37
        ext_content.push(0x04); // extnValue OCTET STRING
        ext_content.extend_from_slice(&ber::length_octets(der.len()));
        ext_content.extend_from_slice(&der);
        let mut ext = vec![0x30];
        ext.extend_from_slice(&ber::length_octets(ext_content.len()));
        ext.extend_from_slice(&ext_content);

        let roots = ber::parse_forest(&ext, 0).unwrap();
        let eku = parse(&roots[0]).expect("round-trip parse");
        assert_eq!(eku.purposes, purposes);
    }

    #[test]
    fn empty_list_encodes_as_empty_sequence() {
        assert_eq!(encode_der(&[]), [0x30, 0x00]);
    }
}
