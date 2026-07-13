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

//! Structural decoding of X.509 `Certificate` and `CertificateList` (CRL)
//! shapes (RFC 5280 §4.1/§5.1) directly over `ber::Node`, plus a recursive
//! directory scan collecting candidate CA certificates. No cryptographic
//! knowledge lives here (see `verify.rs`); this module only knows ASN.1
//! structure, the same way `dump.rs` interprets universal tags for
//! display. Independent of `spec.rs` — works with or without the RFC 5280
//! spec files installed.

use std::path::{Path, PathBuf};

use crate::ber::{
    self, Class, Node, TAG_BIT_STRING, TAG_GENERALIZED_TIME, TAG_OCTET_STRING, TAG_OID,
    TAG_SEQUENCE, TAG_UTC_TIME,
};
use crate::input;

const CN_OID: &[u64] = &[2, 5, 4, 3];
const ORGANIZATION_OID: &[u64] = &[2, 5, 4, 10];
const SUBJECT_KEY_ID_OID: &[u64] = &[2, 5, 29, 14];
const AUTHORITY_KEY_ID_OID: &[u64] = &[2, 5, 29, 35];

/// Real-world certs/CRLs are always tiny; files larger than this are
/// skipped unread during a directory scan (keeps scanning e.g. a
/// `target/` or `.git/` directory cheap).
const MAX_SCAN_FILE_SIZE: u64 = 1024 * 1024;
const MAX_SCAN_DEPTH: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Certificate,
    Crl,
}

/// Everything needed to verify one signed object's signature, extracted
/// from a document that structurally matches `Certificate` or
/// `CertificateList`.
pub struct Signable {
    pub kind: Kind,
    /// Raw DER bytes of the signed `tbsCertificate`/`tbsCertList` (header
    /// + content), exactly as they appear in the document's own encoding
    /// — this is the message the signature covers.
    pub tbs: Vec<u8>,
    /// `signatureAlgorithm.algorithm` OID arcs.
    pub sig_alg: Vec<u64>,
    /// The outer `signature` BIT STRING content, unused-bits octet stripped.
    pub signature: Vec<u8>,
    /// Raw DER encoding of the `issuer` Name (header + content).
    pub issuer: Vec<u8>,
    /// Raw DER encoding of the `subject` Name. Certificate only.
    pub subject: Option<Vec<u8>>,
    /// `subjectPublicKeyInfo.algorithm.algorithm` OID arcs. Certificate only.
    pub pubkey_alg: Option<Vec<u64>>,
    /// `subjectPublicKey` BIT STRING content, unused-bits octet stripped.
    /// Certificate only.
    pub pubkey: Option<Vec<u8>>,
    /// `authorityKeyIdentifier` extension's `keyIdentifier`, if present.
    pub aki_key_id: Option<Vec<u8>>,
    /// `subjectKeyIdentifier` extension value, if present. Certificate only.
    pub ski: Option<Vec<u8>>,
    /// Short display string for the subject, e.g. "CN=Test CA". Certificate only.
    pub subject_summary: Option<String>,
}

/// A Certificate found while scanning a directory, kept as a candidate
/// issuer for other certs/CRLs. Only the fields needed for issuer
/// matching + verification are retained, not the parsed tree.
pub struct CaCandidate {
    pub path: PathBuf,
    pub subject: Vec<u8>,
    pub subject_summary: String,
    pub ski: Option<Vec<u8>>,
    pub pubkey_alg: Vec<u64>,
    pub pubkey: Vec<u8>,
}

/// Try to structurally decode `roots` (the parsed forest of a single
/// document) as a `Certificate` or `CertificateList`. Returns `None` for
/// the (overwhelming majority of) documents that are neither — this is
/// not an error, most files in a directory aren't signed objects.
pub fn parse_signable(roots: &[Node], der: &[u8]) -> Option<Signable> {
    if roots.len() != 1 {
        return None;
    }
    let root = &roots[0];
    if !root.constructed || !root.is_universal(TAG_SEQUENCE) || root.children.len() != 3 {
        return None;
    }
    let sig_alg = alg_oid(&root.children[1])?;
    let sig_node = &root.children[2];
    if sig_node.constructed || !sig_node.is_universal(TAG_BIT_STRING) {
        return None;
    }
    let signature = strip_unused_bits(&sig_node.value);
    let tbs_node = &root.children[0];
    if !tbs_node.constructed {
        return None;
    }
    let tbs = der_span(der, tbs_node);

    try_certificate(tbs_node, der, tbs.clone(), sig_alg.clone(), signature.clone())
        .or_else(|| try_crl(tbs_node, der, tbs, sig_alg, signature))
}

fn alg_oid(node: &Node) -> Option<Vec<u64>> {
    if !node.constructed || !node.is_universal(TAG_SEQUENCE) {
        return None;
    }
    let first = node.children.first()?;
    if first.constructed || !first.is_universal(TAG_OID) {
        return None;
    }
    ber::oid_arcs(&first.value)
}

fn strip_unused_bits(bit_string_value: &[u8]) -> Vec<u8> {
    bit_string_value.get(1..).unwrap_or(&[]).to_vec()
}

fn der_span(der: &[u8], node: &Node) -> Vec<u8> {
    der[node.offset..node.offset + node.header_len + node.content_len].to_vec()
}

/// `TBSCertificate ::= SEQUENCE { [0] Version DEFAULT v1, serialNumber,
/// signature, issuer, validity, subject, subjectPublicKeyInfo,
/// issuerUniqueID? [1], subjectUniqueID? [2], extensions? [3] }` — fields
/// are matched by fixed position (skipping the optional leading version),
/// not by generic structural matching (see DESIGN.md).
fn try_certificate(
    tbs_node: &Node,
    der: &[u8],
    tbs: Vec<u8>,
    sig_alg: Vec<u64>,
    signature: Vec<u8>,
) -> Option<Signable> {
    let children = &tbs_node.children;
    let mut i = 0;
    if children
        .first()
        .is_some_and(|c| c.class == Class::ContextSpecific && c.tag == 0 && c.constructed)
    {
        i = 1;
    }
    // serialNumber, signature(AlgorithmIdentifier), issuer, validity, subject, spki
    if children.len() < i + 6 {
        return None;
    }
    let issuer_node = &children[i + 2];
    let validity_node = &children[i + 3];
    let subject_node = &children[i + 4];
    let spki_node = &children[i + 5];
    if !issuer_node.constructed || !issuer_node.is_universal(TAG_SEQUENCE) {
        return None;
    }
    if !validity_node.constructed || !validity_node.is_universal(TAG_SEQUENCE) {
        return None;
    }
    if !subject_node.constructed || !subject_node.is_universal(TAG_SEQUENCE) {
        return None;
    }
    if !spki_node.constructed || !spki_node.is_universal(TAG_SEQUENCE) || spki_node.children.len() != 2 {
        return None;
    }
    let pubkey_alg = alg_oid(&spki_node.children[0])?;
    let pubkey_node = &spki_node.children[1];
    if pubkey_node.constructed || !pubkey_node.is_universal(TAG_BIT_STRING) {
        return None;
    }
    let pubkey = strip_unused_bits(&pubkey_node.value);

    let mut aki_key_id = None;
    let mut ski = None;
    for c in &children[(i + 6).min(children.len())..] {
        if c.class == Class::ContextSpecific && c.tag == 3 && c.constructed {
            let (a, s) = extract_aki_ski(c);
            aki_key_id = a;
            ski = s;
        }
    }

    Some(Signable {
        kind: Kind::Certificate,
        tbs,
        sig_alg,
        signature,
        issuer: der_span(der, issuer_node),
        subject: Some(der_span(der, subject_node)),
        pubkey_alg: Some(pubkey_alg),
        pubkey: Some(pubkey),
        aki_key_id,
        ski,
        subject_summary: Some(dn_summary(subject_node)),
    })
}

/// `TBSCertList ::= SEQUENCE { version? INTEGER, signature, issuer,
/// thisUpdate, nextUpdate?, revokedCertificates?, crlExtensions? [0] }`.
/// `thisUpdate` being a *primitive* Time (vs. Certificate's constructed
/// `validity` SEQUENCE at the same position) is what disambiguates a CRL
/// shape from a Certificate shape.
fn try_crl(
    tbs_node: &Node,
    der: &[u8],
    tbs: Vec<u8>,
    sig_alg: Vec<u64>,
    signature: Vec<u8>,
) -> Option<Signable> {
    let children = &tbs_node.children;
    let mut i = 0;
    if children.first().is_some_and(|c| !c.constructed && c.is_universal(ber::TAG_INTEGER)) {
        i = 1;
    }
    // signature(AlgorithmIdentifier), issuer, thisUpdate
    if children.len() < i + 3 {
        return None;
    }
    let issuer_node = &children[i + 1];
    let this_update = &children[i + 2];
    if !issuer_node.constructed || !issuer_node.is_universal(TAG_SEQUENCE) {
        return None;
    }
    if this_update.constructed
        || !(this_update.is_universal(TAG_UTC_TIME) || this_update.is_universal(TAG_GENERALIZED_TIME))
    {
        return None;
    }

    let mut aki_key_id = None;
    for c in &children[(i + 3).min(children.len())..] {
        if c.class == Class::ContextSpecific && c.tag == 0 && c.constructed {
            let (a, _s) = extract_aki_ski(c);
            aki_key_id = a;
        }
    }

    Some(Signable {
        kind: Kind::Crl,
        tbs,
        sig_alg,
        signature,
        issuer: der_span(der, issuer_node),
        subject: None,
        pubkey_alg: None,
        pubkey: None,
        aki_key_id,
        ski: None,
        subject_summary: None,
    })
}

/// `ext_container` is the EXPLICIT `[3]`/`[0]` context-tag node wrapping
/// `Extensions ::= SEQUENCE OF Extension`; each `Extension ::= SEQUENCE {
/// extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }`.
/// Relies on the parser's own encapsulation heuristic having already
/// decoded `extnValue`'s nested ASN.1 (DESIGN.md §5) — if it didn't (e.g.
/// a malformed extension), the key identifier is simply reported absent.
fn extract_aki_ski(ext_container: &Node) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let mut aki = None;
    let mut ski = None;
    let Some(extensions_seq) = ext_container.children.first() else { return (None, None) };
    for ext in &extensions_seq.children {
        if ext.children.len() < 2 {
            continue;
        }
        let Some(oid_node) = ext.children.first() else { continue };
        if oid_node.constructed || !oid_node.is_universal(TAG_OID) {
            continue;
        }
        let Some(oid) = ber::oid_arcs(&oid_node.value) else { continue };
        let Some(extn_value) = ext.children.last() else { continue };
        if extn_value.constructed || !extn_value.is_universal(TAG_OCTET_STRING) || !extn_value.encapsulates {
            continue;
        }
        if oid == SUBJECT_KEY_ID_OID {
            if let Some(inner) = extn_value.children.first() {
                if !inner.constructed {
                    ski = Some(inner.value.clone());
                }
            }
        } else if oid == AUTHORITY_KEY_ID_OID {
            if let Some(seq) = extn_value.children.first() {
                for f in &seq.children {
                    if f.class == Class::ContextSpecific && f.tag == 0 && !f.constructed {
                        aki = Some(f.value.clone());
                    }
                }
            }
        }
    }
    (aki, ski)
}

/// Short display string for a `Name` (RDNSequence): the first
/// `commonName`, else the first `organizationName`, else a neutral
/// placeholder.
fn dn_summary(name: &Node) -> String {
    find_attr(name, CN_OID)
        .map(|v| format!("CN={}", v))
        .or_else(|| find_attr(name, ORGANIZATION_OID).map(|v| format!("O={}", v)))
        .unwrap_or_else(|| "<unnamed subject>".to_string())
}

fn find_attr(rdn_sequence: &Node, oid: &[u64]) -> Option<String> {
    for rdn in &rdn_sequence.children {
        for atv in &rdn.children {
            if atv.children.len() != 2 {
                continue;
            }
            let oid_node = &atv.children[0];
            if oid_node.constructed || !oid_node.is_universal(TAG_OID) {
                continue;
            }
            if ber::oid_arcs(&oid_node.value).as_deref() != Some(oid) {
                continue;
            }
            let value_node = &atv.children[1];
            if !value_node.constructed {
                return Some(String::from_utf8_lossy(&value_node.value).into_owned());
            }
        }
    }
    None
}

/// A signed object (Certificate or CRL) found while scanning a directory,
/// paired with the file it came from. This is the raw material for both
/// the candidate-issuer index and the cross-file relation graph
/// (`verify::relations_for`).
pub struct SignableFile {
    pub path: PathBuf,
    pub signable: Signable,
}

/// Recursively scan `root` for files that decode as a signed object
/// (Certificate or CRL). Symlinks (to files or directories) are not
/// followed, which also rules out symlink cycles. Most files in a
/// directory are neither; parse failures and files that don't
/// structurally match are silently skipped, not errors.
pub fn scan_dir_signables(root: &Path) -> Vec<SignableFile> {
    let mut out = Vec::new();
    scan_dir_rec(root, 0, &mut out);
    out
}

/// The subset of scanned files that are Certificates, as candidate
/// issuers for signature verification (only certs can sign; CRLs cannot).
pub fn cert_candidates(files: &[SignableFile]) -> Vec<CaCandidate> {
    files.iter().filter_map(candidate_from).collect()
}

/// Convenience wrapper: scan `root` and keep only the certificate
/// candidates. Equivalent to `cert_candidates(&scan_dir_signables(root))`.
pub fn scan_dir(root: &Path) -> Vec<CaCandidate> {
    cert_candidates(&scan_dir_signables(root))
}

fn candidate_from(file: &SignableFile) -> Option<CaCandidate> {
    let s = &file.signable;
    if s.kind != Kind::Certificate {
        return None;
    }
    Some(CaCandidate {
        path: file.path.clone(),
        subject: s.subject.clone()?,
        subject_summary: s.subject_summary.clone().unwrap_or_default(),
        ski: s.ski.clone(),
        pubkey_alg: s.pubkey_alg.clone()?,
        pubkey: s.pubkey.clone()?,
    })
}

fn scan_dir_rec(dir: &Path, depth: usize, out: &mut Vec<SignableFile>) {
    if depth > MAX_SCAN_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.filter_map(|e| e.ok()) {
        let Ok(file_type) = entry.file_type() else { continue };
        let path = entry.path();
        if file_type.is_dir() {
            scan_dir_rec(&path, depth + 1, out);
        } else if file_type.is_file() {
            if let Some(file) = scan_file(&path) {
                out.push(file);
            }
        }
    }
}

fn scan_file(path: &Path) -> Option<SignableFile> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_SCAN_FILE_SIZE {
        return None;
    }
    let raw = std::fs::read(path).ok()?;
    let (der, _container) = input::load(&raw).ok()?;
    let roots = ber::parse_forest(&der, 0).ok()?;
    let signable = parse_signable(&roots, &der)?;
    Some(SignableFile { path: path.to_path_buf(), signable })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("asn1-editor-x509-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn parse_der(path: &Path) -> (Vec<u8>, Vec<Node>) {
        let raw = std::fs::read(path).unwrap();
        let (der, _) = input::load(&raw).unwrap();
        let roots = ber::parse_forest(&der, 0).unwrap();
        (der, roots)
    }

    #[test]
    fn recognizes_ec_certificate() {
        let (der, roots) = parse_der(Path::new("testdata/cert_ec.der"));
        let signable = parse_signable(&roots, &der).expect("should decode as a Certificate");
        assert_eq!(signable.kind, Kind::Certificate);
        assert_eq!(signable.sig_alg, [1, 2, 840, 10045, 4, 3, 2]); // ecdsa-with-SHA256
        assert!(signable.subject.is_some());
        assert!(signable.pubkey.is_some());
        assert_eq!(signable.pubkey_alg.as_deref(), Some([1u64, 2, 840, 10045, 2, 1].as_slice()));
        assert!(signable.subject_summary.unwrap().contains("CN="));
        assert!(!signable.tbs.is_empty());
        assert!(signable.tbs.len() < der.len());
    }

    #[test]
    fn recognizes_rsa_certificate_and_crl() {
        let (der, roots) = parse_der(Path::new("testdata/cert_rsa.der"));
        let signable = parse_signable(&roots, &der).unwrap();
        assert_eq!(signable.kind, Kind::Certificate);
        assert_eq!(signable.sig_alg, [1, 2, 840, 113549, 1, 1, 11]); // sha256WithRSAEncryption

        let (der, roots) = parse_der(Path::new("testdata/crl.der"));
        let signable = parse_signable(&roots, &der).unwrap();
        assert_eq!(signable.kind, Kind::Crl);
        assert!(signable.subject.is_none());
        assert!(signable.pubkey.is_none());
    }

    #[test]
    fn non_signable_document_is_none() {
        let (der, roots) = parse_der(Path::new("testdata/ec_key.der"));
        assert!(parse_signable(&roots, &der).is_none());
    }

    #[test]
    fn scan_dir_finds_certificates_recursively() {
        let dir = tmp_dir("scan");
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::copy("testdata/cert_ec.der", dir.join("a.der")).unwrap();
        std::fs::copy("testdata/cert_rsa.der", dir.join("sub/b.der")).unwrap();
        std::fs::copy("testdata/ec_key.der", dir.join("not-a-cert.der")).unwrap();
        std::fs::write(dir.join("garbage.txt"), b"not asn.1 at all").unwrap();

        let found = scan_dir(&dir);
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|c| c.path.ends_with("a.der")));
        assert!(found.iter().any(|c| c.path.ends_with("sub/b.der")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_dir_skips_oversized_files() {
        let dir = tmp_dir("oversize");
        std::fs::write(dir.join("big.der"), vec![0u8; (MAX_SCAN_FILE_SIZE + 1) as usize]).unwrap();
        assert!(scan_dir(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_dir_signables_includes_crls_but_candidates_are_certs_only() {
        // The bundled chain/ folder: 4 certs (root, intermediate, server,
        // server_bad_signature) + 2 CRLs (root, intermediate).
        let signables = scan_dir_signables(Path::new("testdata/chain"));
        assert_eq!(signables.len(), 6);
        assert_eq!(signables.iter().filter(|s| s.signable.kind == Kind::Crl).count(), 2);
        // Only the certificates become candidate issuers.
        let candidates = cert_candidates(&signables);
        assert_eq!(candidates.len(), 4);
        assert!(candidates.iter().all(|c| !c.pubkey.is_empty()));
    }
}
