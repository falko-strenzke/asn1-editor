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

//! Structural decoding and read-only password decryption of PKCS#12 `PFX`
//! containers (RFC 7292). Unlike the single, editable encrypted region of an
//! `EncryptedPrivateKeyInfo` (`pkcs8.rs`), a PKCS#12 file can hold several
//! independently password-encrypted regions — one or more `EncryptedData`
//! content blobs (typically the certificates) and one or more
//! `PKCS8ShroudedKeyBag`s (the private keys). This module locates each such
//! region in the outer parse tree and, given the password, decrypts it.
//!
//! Scope: the password-based encryption must be **PBES2** (PBKDF2 +
//! AES-128/256-CBC), which is what current OpenSSL and comparable tools
//! emit by default. The legacy `pbeWithSHAAnd*` schemes use the RFC 7292
//! Appendix B key-derivation, which `aws-lc-rs` does not expose; those are
//! reported as unsupported. Decryption is **read-only**: the PKCS#12
//! integrity `MacData` also relies on the RFC 7292 KDF, so an edited
//! container could not be re-MAC'd into a valid file. The revealed subtrees
//! are therefore never re-encrypted or written back.

use crate::ber::{self, Class, Node, TAG_INTEGER, TAG_OCTET_STRING, TAG_SEQUENCE};
use crate::pkcs8::{oid_of, Pbes2};

const OID_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const OID_ENCRYPTED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 6];
const OID_SHROUDED_KEY_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 2];

/// What a decryptable region contains, for the reveal's header text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind {
    /// An `EncryptedData` content blob (typically the certificate bags).
    EncryptedContent,
    /// A `PKCS8ShroudedKeyBag` — an `EncryptedPrivateKeyInfo` private key.
    ShroudedKey,
}

impl RegionKind {
    pub fn label(self) -> &'static str {
        match self {
            RegionKind::EncryptedContent => "encrypted PKCS#12 content",
            RegionKind::ShroudedKey => "encrypted private key",
        }
    }
}

/// One password-encrypted region found inside a PKCS#12 container.
pub struct Region {
    /// Path of the ciphertext-bearing node in the *outer* document forest
    /// (the `encryptedContent [0]` blob or the shrouded key's `encryptedData`
    /// OCTET STRING). The reveal hangs below this node.
    pub cipher_path: Vec<usize>,
    pub kind: RegionKind,
    pbes2: Pbes2,
    ciphertext: Vec<u8>,
}

impl Region {
    /// PBKDF2-derive the key, AES-CBC decrypt, strip PKCS#7 padding, and
    /// confirm the plaintext is a single ASN.1 SEQUENCE (a `SafeContents`
    /// or a `PrivateKeyInfo`) — the wrong-password signal.
    pub fn decrypt(&self, password: &[u8]) -> Result<Vec<u8>, String> {
        let plain = self.pbes2.decrypt(password, &self.ciphertext)?;
        match ber::parse_forest(&plain, 0) {
            Ok(roots) if roots.len() == 1 && roots[0].is_universal(TAG_SEQUENCE) => Ok(plain),
            _ => Err("decryption failed (wrong password?)".to_string()),
        }
    }
}

/// A decoded PKCS#12 `PFX` with the encrypted regions this tool can decrypt.
pub struct Pkcs12 {
    pub regions: Vec<Region>,
}

/// Try to decode `roots` as a PKCS#12 `PFX`.
///
/// * `Ok(None)` — not a PKCS#12 container at all (the common case).
/// * `Err(msg)` — it *is* a PKCS#12, but nothing in it can be decrypted
///   (no encrypted content, or every encrypted region uses an unsupported
///   scheme); `msg` explains what.
/// * `Ok(Some(_))` — a PKCS#12 with at least one supported PBES2 region.
pub fn parse(roots: &[Node]) -> Result<Option<Pkcs12>, String> {
    // PFX ::= SEQUENCE { version INTEGER(v3), authSafe ContentInfo,
    //   macData MacData OPTIONAL }
    let Some(root) = roots.first() else { return Ok(None) };
    if roots.len() != 1 || !root.constructed || !root.is_universal(TAG_SEQUENCE) {
        return Ok(None);
    }
    if root.children.len() < 2 || root.children.len() > 3 {
        return Ok(None);
    }
    let version = &root.children[0];
    if version.constructed
        || !version.is_universal(TAG_INTEGER)
        || ber::decode_integer(&version.value) != Some(3)
    {
        return Ok(None);
    }
    // authSafe is a ContentInfo carrying id-data whose content OCTET STRING
    // encapsulates the AuthenticatedSafe.
    let auth_safe = &root.children[1];
    let Some((data_oid, content)) = content_info(auth_safe) else { return Ok(None) };
    if data_oid != OID_DATA {
        return Ok(None);
    }
    // content is an OCTET STRING encapsulating AuthenticatedSafe (SEQUENCE OF
    // ContentInfo). Path so far: [0, 1, 1, 0] (authSafe → content [0] → OS).
    let Some(auth_safe_seq) = encapsulated_seq(content) else { return Ok(None) };

    // It is a PFX; from here, an absence of supported regions is an error.
    let mut regions = Vec::new();
    let mut unsupported: Option<String> = None;
    // auth_safe_seq path is [0, 1, 1, 0, 0]; iterate its ContentInfo children.
    let base = vec![0usize, 1, 1, 0, 0];
    for (j, ci) in auth_safe_seq.children.iter().enumerate() {
        let mut ci_path = base.clone();
        ci_path.push(j);
        collect_content_info(ci, &ci_path, &mut regions, &mut unsupported);
    }

    if regions.is_empty() {
        return Err(unsupported.unwrap_or_else(|| {
            "PKCS#12 contains no password-encrypted content".to_string()
        }));
    }
    Ok(Some(Pkcs12 { regions }))
}

/// One ContentInfo of the AuthenticatedSafe. Either an `EncryptedData`
/// (a directly encrypted region) or plaintext `data` whose SafeContents may
/// hold shrouded key bags.
fn collect_content_info(
    ci: &Node,
    ci_path: &[usize],
    regions: &mut Vec<Region>,
    unsupported: &mut Option<String>,
) {
    let Some((oid, content)) = content_info(ci) else { return };
    if oid == OID_ENCRYPTED_DATA {
        // content [0] EXPLICIT holds EncryptedData ::= SEQUENCE { version,
        //   encryptedContentInfo SEQUENCE { contentType, algorithm,
        //   encryptedContent [0] IMPLICIT OCTET STRING } }.
        let Some(enc_data) = as_sequence(content) else { return };
        let Some(eci) = enc_data.children.get(1).and_then(as_sequence) else { return };
        let Some(alg) = eci.children.get(1) else { return };
        let Some(cipher_node) = eci.children.get(2) else { return };
        // encryptedContent is [0] IMPLICIT (context, primitive) — its value
        // is the ciphertext.
        if cipher_node.class != Class::ContextSpecific || cipher_node.constructed {
            return;
        }
        // cipher_path: ci → content [0] (child 1) → EncryptedData (child 0)
        //   → encryptedContentInfo (child 1) → encryptedContent (child 2).
        let cipher_path = extend(ci_path, &[1, 0, 1, 2]);
        push_region(
            alg,
            cipher_node.value.clone(),
            cipher_path,
            RegionKind::EncryptedContent,
            regions,
            unsupported,
        );
    } else if oid == OID_DATA {
        // content [0] EXPLICIT holds an OCTET STRING encapsulating a
        // SafeContents (SEQUENCE OF SafeBag).
        let Some(safe_contents) = encapsulated_seq(content) else { return };
        // safe_contents path: ci → content [0] (child 1) → OS (child 0)
        //   → SafeContents (child 0).
        let sc_path = extend(ci_path, &[1, 0, 0]);
        for (k, bag) in safe_contents.children.iter().enumerate() {
            let mut bag_path = sc_path.clone();
            bag_path.push(k);
            collect_safe_bag(bag, &bag_path, regions, unsupported);
        }
    }
}

/// A SafeBag; a `PKCS8ShroudedKeyBag` is a decryptable region.
fn collect_safe_bag(
    bag: &Node,
    bag_path: &[usize],
    regions: &mut Vec<Region>,
    unsupported: &mut Option<String>,
) {
    // SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT,
    //   bagAttributes SET OPTIONAL }
    let Some(seq) = as_sequence(bag) else { return };
    let Some(bag_id) = seq.children.first().and_then(oid_of) else { return };
    if bag_id != OID_SHROUDED_KEY_BAG {
        return;
    }
    // bagValue [0] EXPLICIT holds an EncryptedPrivateKeyInfo ::= SEQUENCE {
    //   encryptionAlgorithm, encryptedData OCTET STRING }.
    let Some(epki) = seq.children.get(1).and_then(explicit_0_child).and_then(as_sequence) else {
        return;
    };
    let Some(alg) = epki.children.first() else { return };
    let Some(cipher_node) = epki.children.get(1) else { return };
    if cipher_node.constructed || !cipher_node.is_universal(TAG_OCTET_STRING) {
        return;
    }
    // cipher_path: bag → bagValue [0] (child 1) → EncryptedPrivateKeyInfo
    //   (child 0) → encryptedData (child 1).
    let cipher_path = extend(bag_path, &[1, 0, 1]);
    push_region(
        alg,
        cipher_node.value.clone(),
        cipher_path,
        RegionKind::ShroudedKey,
        regions,
        unsupported,
    );
}

/// Decode a PBES2 `AlgorithmIdentifier`; on success record a region, else
/// remember the unsupported reason (only the first is kept, for the status).
fn push_region(
    alg: &Node,
    ciphertext: Vec<u8>,
    cipher_path: Vec<usize>,
    kind: RegionKind,
    regions: &mut Vec<Region>,
    unsupported: &mut Option<String>,
) {
    match Pbes2::from_algorithm_identifier(alg) {
        Ok(Some(pbes2)) => regions.push(Region { cipher_path, kind, pbes2, ciphertext }),
        Ok(None) => {
            unsupported.get_or_insert_with(|| {
                "PKCS#12 uses an unsupported (non-PBES2) encryption scheme".to_string()
            });
        }
        Err(msg) => {
            unsupported.get_or_insert(msg);
        }
    }
}

/// A ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT }.
/// Returns the content-type OID and the inner content node (the child of the
/// EXPLICIT `[0]`).
fn content_info(node: &Node) -> Option<(Vec<u64>, &Node)> {
    let seq = as_sequence(node)?;
    let oid = seq.children.first().and_then(oid_of)?;
    let content = seq.children.get(1).and_then(explicit_0_child)?;
    Some((oid, content))
}

fn as_sequence(node: &Node) -> Option<&Node> {
    (node.constructed && node.is_universal(TAG_SEQUENCE)).then_some(node)
}

/// The single child of an EXPLICIT context `[0]` (constructed) node.
fn explicit_0_child(node: &Node) -> Option<&Node> {
    if node.class == Class::ContextSpecific && node.tag == 0 && node.constructed {
        node.children.first()
    } else {
        None
    }
}

/// If `node` is an OCTET STRING encapsulating exactly one SEQUENCE, return it.
fn encapsulated_seq(node: &Node) -> Option<&Node> {
    if node.constructed || !node.is_universal(TAG_OCTET_STRING) || !node.encapsulates {
        return None;
    }
    node.children.first().and_then(as_sequence)
}

fn extend(base: &[usize], tail: &[usize]) -> Vec<usize> {
    let mut v = base.to_vec();
    v.extend_from_slice(tail);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input;
    use std::path::Path;

    fn parse_file(rel: &str) -> Vec<Node> {
        let raw = std::fs::read(Path::new(rel)).unwrap();
        let (der, _) = input::load(&raw).unwrap();
        ber::parse_forest(&der, 0).unwrap()
    }

    fn node_at<'a>(roots: &'a [Node], path: &[usize]) -> &'a Node {
        let (&first, rest) = path.split_first().unwrap();
        let mut node = &roots[first];
        for &index in rest {
            node = &node.children[index];
        }
        node
    }

    #[test]
    fn finds_both_encrypted_regions() {
        let roots = parse_file("testdata/pkcs12.der");
        let p12 = parse(&roots).unwrap().expect("supported PKCS#12");
        assert_eq!(p12.regions.len(), 2);
        // One certificate-content region and one shrouded key region.
        let kinds: Vec<_> = p12.regions.iter().map(|r| r.kind).collect();
        assert!(kinds.contains(&RegionKind::EncryptedContent));
        assert!(kinds.contains(&RegionKind::ShroudedKey));
        // Every recorded cipher_path really points at the ciphertext bytes.
        for region in &p12.regions {
            let node = node_at(&roots, &region.cipher_path);
            assert_eq!(node.value, region.ciphertext);
            assert!(!region.ciphertext.is_empty());
        }
    }

    #[test]
    fn decrypts_regions_with_correct_password() {
        let roots = parse_file("testdata/pkcs12.der");
        let p12 = parse(&roots).unwrap().unwrap();
        for region in &p12.regions {
            let plain = region.decrypt(b"asn1editor").expect("correct password decrypts");
            let inner = ber::parse_forest(&plain, 0).unwrap();
            assert_eq!(inner.len(), 1);
            assert!(inner[0].is_universal(TAG_SEQUENCE));
        }
        // The shrouded key decrypts to a PrivateKeyInfo (version INTEGER +
        // algorithm SEQUENCE + privateKey OCTET STRING).
        let key = p12.regions.iter().find(|r| r.kind == RegionKind::ShroudedKey).unwrap();
        let plain = key.decrypt(b"asn1editor").unwrap();
        let inner = ber::parse_forest(&plain, 0).unwrap();
        assert!(inner[0].children.len() >= 3);
        assert!(inner[0].children[0].is_universal(TAG_INTEGER));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let roots = parse_file("testdata/pkcs12.der");
        let p12 = parse(&roots).unwrap().unwrap();
        for region in &p12.regions {
            assert!(region.decrypt(b"not the password").is_err());
            assert!(region.decrypt(b"").is_err());
        }
    }

    #[test]
    fn non_pkcs12_files_are_not_pfx() {
        assert!(parse(&parse_file("testdata/enc_pkcs8.der")).unwrap().is_none());
        assert!(parse(&parse_file("testdata/private_key_pkcs8.der")).unwrap().is_none());
        assert!(parse(&parse_file("testdata/cert_ec.der")).unwrap().is_none());
        assert!(parse(&parse_file("testdata/pkcs7.der")).unwrap().is_none());
    }
}
