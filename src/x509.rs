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

pub mod basic_constraints;
pub mod extended_key_usage;
pub mod key_usage;

use crate::ber::{
    self, Class, Node, TAG_BIT_STRING, TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_OCTET_STRING,
    TAG_OID, TAG_SEQUENCE, TAG_UTC_TIME,
};
use crate::input;

const CN_OID: &[u64] = &[2, 5, 4, 3];
const ORGANIZATION_OID: &[u64] = &[2, 5, 4, 10];
const SUBJECT_KEY_ID_OID: &[u64] = &[2, 5, 29, 14];
const AUTHORITY_KEY_ID_OID: &[u64] = &[2, 5, 29, 35];
const EC_PUBLIC_KEY_OID: &[u64] = &[1, 2, 840, 10045, 2, 1];
const RSA_ENCRYPTION_OID: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];

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
#[derive(Clone)]
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
    /// `serialNumber` INTEGER content octets. Certificate only. Together
    /// with `issuer` this is what a CMS `IssuerAndSerialNumber` signer
    /// identifier points at.
    pub serial: Option<Vec<u8>>,
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

    let serial_node = &children[i];
    if serial_node.constructed || !serial_node.is_universal(ber::TAG_INTEGER) {
        return None;
    }

    Some(Signable {
        kind: Kind::Certificate,
        tbs,
        sig_alg,
        signature,
        issuer: der_span(der, issuer_node),
        serial: Some(serial_node.value.clone()),
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
        serial: None,
        subject: None,
        pubkey_alg: None,
        pubkey: None,
        aki_key_id,
        ski: None,
        subject_summary: None,
    })
}

/// `ext_container` is the EXPLICIT `[3]`/`[0]` context-tag node wrapping
/// `id-signedData` (RFC 5652): the ContentInfo content type of a CMS
/// signed message.
const ID_SIGNED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];
/// PKCS#9 `messageDigest` signed-attribute OID.
const ID_MESSAGE_DIGEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 4];

/// Everything needed to verify the (first) signature of a CMS `SignedData`
/// message, extracted structurally like [`Signable`]. Only signers
/// identified by `IssuerAndSerialNumber` are handled (the RFC 5652 v1
/// SignerInfo shape openssl emits); a `subjectKeyIdentifier` sid is skipped.
#[derive(Clone)]
pub struct CmsSigned {
    /// Raw DER of the sid's `issuer` Name (header + content).
    pub issuer: Vec<u8>,
    /// The sid's `serialNumber` INTEGER content octets.
    pub serial: Vec<u8>,
    /// `digestAlgorithm.algorithm` OID arcs.
    pub digest_alg: Vec<u64>,
    /// `signatureAlgorithm.algorithm` OID arcs.
    pub sig_alg: Vec<u64>,
    /// The `signature` OCTET STRING content.
    pub signature: Vec<u8>,
    /// When `signedAttrs` is present: its DER re-encoded with the explicit
    /// `SET OF` tag (0x31) — the exact message the signature covers
    /// (RFC 5652 §5.4).
    pub signed_attrs: Option<Vec<u8>>,
    /// The `messageDigest` signed attribute's OCTET STRING content, when
    /// signedAttrs carries one — must equal digest(eContent).
    pub message_digest: Option<Vec<u8>>,
    /// The `eContent` OCTET STRING content octets, when attached.
    pub econtent: Option<Vec<u8>>,
    /// Tree path (in the parsed forest) of the SignerInfo `signature` OCTET
    /// STRING — where re-signing installs the new signature.
    pub signature_path: Vec<usize>,
    /// Tree path of the `messageDigest` attribute value OCTET STRING, when
    /// present — where re-signing installs the recomputed content digest.
    pub message_digest_path: Option<Vec<usize>>,
}

/// Try to structurally decode `roots` as a CMS `ContentInfo` carrying
/// `SignedData` with at least one `IssuerAndSerialNumber`-identified signer.
/// `None` for any other document — not an error.
pub fn parse_cms_signed(roots: &[Node], der: &[u8]) -> Option<CmsSigned> {
    if roots.len() != 1 {
        return None;
    }
    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ... }
    let root = &roots[0];
    if !root.constructed || !root.is_universal(TAG_SEQUENCE) || root.children.len() != 2 {
        return None;
    }
    let ct = &root.children[0];
    if ct.constructed || !ct.is_universal(TAG_OID) || ber::oid_arcs(&ct.value)? != ID_SIGNED_DATA {
        return None;
    }
    let wrapper = &root.children[1];
    if !(wrapper.class == Class::ContextSpecific && wrapper.tag == 0 && wrapper.constructed) {
        return None;
    }
    // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
    //   certificates [0]?, crls [1]?, signerInfos SET }
    let sd = wrapper.children.first()?;
    if !sd.constructed || !sd.is_universal(TAG_SEQUENCE) || sd.children.len() < 4 {
        return None;
    }
    // EncapsulatedContentInfo ::= SEQUENCE { eContentType OID,
    //   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
    let eci = &sd.children[2];
    if !eci.constructed || !eci.is_universal(TAG_SEQUENCE) {
        return None;
    }
    let econtent = eci.children.iter().find_map(|c| {
        if c.class == Class::ContextSpecific && c.tag == 0 && c.constructed {
            let os = c.children.first()?;
            (os.is_universal(TAG_OCTET_STRING)).then(|| os.content_octets())
        } else {
            None
        }
    });
    // signerInfos is the last child.
    let si_set_idx = sd.children.len() - 1;
    let signer_infos = &sd.children[si_set_idx];
    if !signer_infos.constructed || !signer_infos.is_universal(ber::TAG_SET) {
        return None;
    }
    // First SignerInfo whose sid is an IssuerAndSerialNumber. Tree paths are
    // built relative to the fixed prefix root[0] → content[1] → SignedData[0]
    // → signerInfos → the i-th SignerInfo.
    for (i, si) in signer_infos.children.iter().enumerate() {
        let base = vec![0, 1, 0, si_set_idx, i];
        if let Some(mut parsed) = try_signer_info(si, der, &base) {
            parsed.econtent = econtent;
            return Some(parsed);
        }
    }
    None
}

/// `SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm,
/// signedAttrs [0] IMPLICIT OPTIONAL, signatureAlgorithm, signature,
/// unsignedAttrs [1] IMPLICIT OPTIONAL }` with
/// `sid = IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber }`.
fn try_signer_info(si: &Node, der: &[u8], base: &[usize]) -> Option<CmsSigned> {
    if !si.constructed || !si.is_universal(TAG_SEQUENCE) || si.children.len() < 5 {
        return None;
    }
    let sid = &si.children[1];
    if !sid.constructed || !sid.is_universal(TAG_SEQUENCE) || sid.children.len() != 2 {
        return None; // a [0] subjectKeyIdentifier sid is not handled
    }
    let issuer_node = &sid.children[0];
    let serial_node = &sid.children[1];
    if !issuer_node.constructed || !issuer_node.is_universal(TAG_SEQUENCE) {
        return None;
    }
    if serial_node.constructed || !serial_node.is_universal(ber::TAG_INTEGER) {
        return None;
    }
    let digest_alg = alg_oid(&si.children[2])?;
    let child_path = |i: usize| -> Vec<usize> { base.iter().copied().chain([i]).collect() };

    // Optional signedAttrs [0] IMPLICIT SET OF Attribute.
    let mut idx = 3;
    let mut signed_attrs = None;
    let mut message_digest = None;
    let mut message_digest_path = None;
    let attrs = &si.children[3];
    if attrs.class == Class::ContextSpecific && attrs.tag == 0 && attrs.constructed {
        // The signature covers the DER with the explicit SET OF tag (0x31)
        // in place of the [0] — rebuild it from the attribute encodings.
        let content = attrs.content_octets();
        let mut set = Vec::with_capacity(content.len() + 4);
        set.push(0x31);
        set.extend_from_slice(&ber::length_octets(content.len()));
        set.extend_from_slice(&content);
        signed_attrs = Some(set);
        for (j, attr) in attrs.children.iter().enumerate() {
            let Some(oid) = attr.children.first() else { continue };
            if !oid.is_universal(TAG_OID) || ber::oid_arcs(&oid.value).as_deref() != Some(ID_MESSAGE_DIGEST) {
                continue;
            }
            let Some(values) = attr.children.get(1) else { continue };
            let Some(os) = values.children.first() else { continue };
            if os.is_universal(TAG_OCTET_STRING) {
                message_digest = Some(os.content_octets());
                // signedAttrs [0] is child 3; attribute j; value SET child 1;
                // OCTET STRING child 0.
                message_digest_path = Some(base.iter().copied().chain([3, j, 1, 0]).collect());
            }
        }
        idx = 4;
    }
    if si.children.len() < idx + 2 {
        return None;
    }
    let sig_alg = alg_oid(&si.children[idx])?;
    let sig_node = &si.children[idx + 1];
    if sig_node.constructed || !sig_node.is_universal(TAG_OCTET_STRING) {
        return None;
    }
    Some(CmsSigned {
        issuer: der_span(der, issuer_node),
        serial: serial_node.value.clone(),
        digest_alg,
        sig_alg,
        signature: sig_node.value.clone(),
        signed_attrs,
        message_digest,
        econtent: None, // filled in by the caller
        signature_path: child_path(idx + 1),
        message_digest_path,
    })
}

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

/// A CMS `SignedData` file found in the directory scan, kept so its
/// signer→message relation arrow can be drawn in the browser. Carries the
/// raw DER for the OpenSSL half of `verify::verify_cms`.
pub struct CmsFile {
    pub path: PathBuf,
    pub cms: CmsSigned,
    pub der: Vec<u8>,
}

/// Recursively scan `root` for CMS signed messages, with the same depth and
/// size caps as [`scan_dir_signables`]. Certificates/CRLs and unparseable
/// files are skipped.
pub fn scan_dir_cms(root: &Path) -> Vec<CmsFile> {
    let mut out = Vec::new();
    scan_cms_rec(root, 0, &mut out);
    out
}

fn scan_cms_rec(dir: &Path, depth: usize, out: &mut Vec<CmsFile>) {
    if depth > MAX_SCAN_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.filter_map(|e| e.ok()) {
        let Ok(file_type) = entry.file_type() else { continue };
        let path = entry.path();
        if file_type.is_dir() {
            scan_cms_rec(&path, depth + 1, out);
        } else if file_type.is_file() {
            if let Some(file) = scan_cms_file(&path) {
                out.push(file);
            }
        }
    }
}

fn scan_cms_file(path: &Path) -> Option<CmsFile> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_SCAN_FILE_SIZE {
        return None;
    }
    let raw = std::fs::read(path).ok()?;
    let (der, _container) = input::load(&raw).ok()?;
    let roots = ber::parse_forest(&der, 0).ok()?;
    let cms = parse_cms_signed(&roots, &der)?;
    Some(CmsFile { path: path.to_path_buf(), cms, der })
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

// --------------------------------------------------------------------------
// Public-key identity: telling whether a private key and a certificate
// belong to the same key pair. This is structural only — the public key a
// private key embeds (EC keys carry the point; RSA keys carry the modulus
// and exponent) is compared with the certificate's `subjectPublicKey`. No
// point multiplication or other crypto happens here.
// --------------------------------------------------------------------------

/// A canonical identity of a public key, reduced to its minimal value bytes
/// so a key and the certificate carrying it compare equal regardless of the
/// container each was extracted from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PublicKeyId {
    /// An elliptic-curve public point (`subjectPublicKey` / `ECPrivateKey`'s
    /// `publicKey`, unused-bits octet stripped). Curve identity is implied by
    /// the point's length and value.
    Ec(Vec<u8>),
    /// RSA modulus and public exponent (the two INTEGERs of `RSAPublicKey` /
    /// `RSAPrivateKey`), by their DER content octets.
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    /// Any other algorithm: the algorithm OID plus the raw public-key bytes
    /// (only usable when the key explicitly carries a public part, e.g. a
    /// v2 `OneAsymmetricKey`).
    Other { alg: Vec<u64>, key: Vec<u8> },
}

/// Build a [`PublicKeyId`] from a `subjectPublicKeyInfo`'s algorithm OID and
/// (unused-bits-stripped) `subjectPublicKey` bytes — the form both
/// [`Signable`] and [`CaCandidate`] already store.
pub fn public_key_id(alg: &[u64], pubkey: &[u8]) -> Option<PublicKeyId> {
    if alg == EC_PUBLIC_KEY_OID {
        Some(PublicKeyId::Ec(pubkey.to_vec()))
    } else if alg == RSA_ENCRYPTION_OID {
        // subjectPublicKey is the DER of RSAPublicKey ::= SEQUENCE {
        //   modulus INTEGER, publicExponent INTEGER }.
        let roots = ber::parse_forest(pubkey, 0).ok()?;
        let node = roots.first()?;
        if !node.constructed || !node.is_universal(TAG_SEQUENCE) || node.children.len() < 2 {
            return None;
        }
        Some(PublicKeyId::Rsa {
            modulus: int_content(&node.children[0])?,
            exponent: int_content(&node.children[1])?,
        })
    } else {
        Some(PublicKeyId::Other { alg: alg.to_vec(), key: pubkey.to_vec() })
    }
}

/// The public-key identity of a certificate `Signable` (returns `None` for
/// CRLs, which carry no key).
pub fn public_key_id_of_signable(s: &Signable) -> Option<PublicKeyId> {
    public_key_id(s.pubkey_alg.as_deref()?, s.pubkey.as_deref()?)
}

/// The public-key identity a *private* key corresponds to, extracted
/// structurally from a plaintext `PrivateKeyInfo` (PKCS#8 / RFC 5958) or a
/// SEC1 `ECPrivateKey`. `None` when the shape is neither, or when the public
/// part cannot be recovered without deriving it (e.g. an EC key stored
/// without its optional `publicKey`).
pub fn public_key_id_of_private_key(roots: &[Node]) -> Option<PublicKeyId> {
    if roots.len() != 1 {
        return None;
    }
    let root = &roots[0];
    if !root.constructed || !root.is_universal(TAG_SEQUENCE) || root.children.len() < 2 {
        return None;
    }
    // Distinguish the two shapes by the second element: a SEC1 `ECPrivateKey`
    // has the private-key OCTET STRING there; a PKCS#8 `PrivateKeyInfo` has
    // the `privateKeyAlgorithm` SEQUENCE.
    let second = &root.children[1];
    if !second.constructed && second.is_universal(TAG_OCTET_STRING) {
        return ec_point_of_ec_private_key(root).map(PublicKeyId::Ec);
    }
    if !(second.constructed && second.is_universal(TAG_SEQUENCE)) {
        return None;
    }
    // PKCS#8 PrivateKeyInfo.
    let alg = alg_oid(second)?;
    let private_key = root.children.get(2)?;
    if private_key.constructed || !private_key.is_universal(TAG_OCTET_STRING) {
        return None;
    }
    // The privateKey OCTET STRING encapsulates the algorithm-specific key.
    let inner = private_key.children.first();
    if alg == EC_PUBLIC_KEY_OID {
        if let Some(point) = inner.and_then(ec_point_of_ec_private_key) {
            return Some(PublicKeyId::Ec(point));
        }
        // A v2 OneAsymmetricKey may instead carry the point in an outer [1].
        return context_bitstring(&root.children, 1).map(PublicKeyId::Ec);
    }
    if alg == RSA_ENCRYPTION_OID {
        // RSAPrivateKey ::= SEQUENCE { version, modulus, publicExponent, ... }
        let rsa = inner?;
        if !rsa.constructed || !rsa.is_universal(TAG_SEQUENCE) || rsa.children.len() < 3 {
            return None;
        }
        return Some(PublicKeyId::Rsa {
            modulus: int_content(&rsa.children[1])?,
            exponent: int_content(&rsa.children[2])?,
        });
    }
    // Other algorithms are matchable only if an explicit public key is
    // present (a v2 OneAsymmetricKey `publicKey [1]`).
    context_bitstring(&root.children, 1).map(|key| PublicKeyId::Other { alg, key })
}

/// The EC public point of a SEC1 `ECPrivateKey ::= SEQUENCE { version,
/// privateKey, [0] parameters?, [1] publicKey? }` — its optional `[1]
/// publicKey` BIT STRING, unused-bits octet stripped.
fn ec_point_of_ec_private_key(ec: &Node) -> Option<Vec<u8>> {
    if !ec.constructed || !ec.is_universal(TAG_SEQUENCE) {
        return None;
    }
    context_bitstring(&ec.children, 1)
}

/// The content of a `[tag] EXPLICIT` context node wrapping a BIT STRING,
/// unused-bits octet stripped.
fn context_bitstring(children: &[Node], tag: u32) -> Option<Vec<u8>> {
    let node = children
        .iter()
        .find(|c| c.class == Class::ContextSpecific && c.tag == tag && c.constructed)?;
    let bs = node.children.first()?;
    if bs.constructed || !bs.is_universal(TAG_BIT_STRING) {
        return None;
    }
    Some(strip_unused_bits(&bs.value))
}

fn int_content(node: &Node) -> Option<Vec<u8>> {
    (!node.constructed && node.is_universal(TAG_INTEGER)).then(|| node.value.clone())
}

/// Return the DER of a PKCS#8 `PrivateKeyInfo` for the private key in
/// `roots`, the form `aws-lc-rs`'s `from_pkcs8` signing constructors want. A
/// PKCS#8 key is returned re-encoded as-is; a bare SEC1 `ECPrivateKey` is
/// wrapped (its curve moved into the `privateKeyAlgorithm`). `None` for
/// anything else (an encrypted key must be decrypted first).
pub fn to_pkcs8_der(roots: &[Node]) -> Option<Vec<u8>> {
    if roots.len() != 1 {
        return None;
    }
    let root = &roots[0];
    if !root.constructed || !root.is_universal(TAG_SEQUENCE) || root.children.len() < 2 {
        return None;
    }
    let second = &root.children[1];
    if second.constructed && second.is_universal(TAG_SEQUENCE) {
        // Already a PKCS#8 PrivateKeyInfo.
        return Some(ber::encode_forest(roots));
    }
    if !second.constructed && second.is_universal(TAG_OCTET_STRING) {
        return wrap_sec1_as_pkcs8(root);
    }
    None
}

/// Wrap a SEC1 `ECPrivateKey` into a PKCS#8 `PrivateKeyInfo`: move the curve
/// from the inner `[0] parameters` into the outer `privateKeyAlgorithm` and
/// drop it from the inner key (the RFC 5958 canonical form).
fn wrap_sec1_as_pkcs8(ec: &Node) -> Option<Vec<u8>> {
    let curve = ec
        .children
        .iter()
        .find(|c| c.class == Class::ContextSpecific && c.tag == 0 && c.constructed)
        .and_then(|c| c.children.first())
        .filter(|o| !o.constructed && o.is_universal(TAG_OID))?
        .clone();
    let mut inner = ec.clone();
    inner
        .children
        .retain(|c| !(c.class == Class::ContextSpecific && c.tag == 0 && c.constructed));

    let algorithm = universal_seq(vec![
        universal_primitive(TAG_OID, ber::encode_oid("1.2.840.10045.2.1").ok()?), // ecPublicKey
        curve,
    ]);
    let pkcs8 = universal_seq(vec![
        universal_primitive(TAG_INTEGER, vec![0]),               // version v1
        algorithm,                                               // privateKeyAlgorithm
        universal_primitive(TAG_OCTET_STRING, ber::encode_node(&inner)), // privateKey
    ]);
    Some(ber::encode_forest(&[pkcs8]))
}

fn universal_primitive(tag: u32, value: Vec<u8>) -> Node {
    Node {
        class: Class::Universal,
        tag,
        constructed: false,
        indefinite: false,
        offset: 0,
        header_len: 0,
        content_len: 0,
        value,
        children: Vec::new(),
        encapsulates: false,
        expanded: false,
    }
}

fn universal_seq(children: Vec<Node>) -> Node {
    Node {
        class: Class::Universal,
        tag: TAG_SEQUENCE,
        constructed: true,
        indefinite: false,
        offset: 0,
        header_len: 0,
        content_len: 0,
        value: Vec::new(),
        children,
        encapsulates: false,
        expanded: false,
    }
}

/// A private-key file found while scanning a directory, reduced to the
/// public-key identity it corresponds to — the raw material for the
/// key↔certificate links in `verify::key_links_for`.
pub struct KeyFile {
    pub path: PathBuf,
    pub key: PublicKeyId,
}

/// Recursively scan `root` for files that structurally decode as a *plaintext*
/// private key (SEC1 `ECPrivateKey` or PKCS#8 `PrivateKeyInfo`), returning
/// their paths. Recognition is by *shape* — it does **not** require the public
/// key to be recoverable from the private key, because ML-DSA/SLH-DSA PKCS#8
/// keys carry no embedded public key; the caller derives the public-key
/// identity (with crypto help where the structure alone is not enough).
/// Encrypted keys and PKCS#12 containers are excluded — their key becomes known
/// only after a password is supplied, handled in `app.rs`. Same traversal rules
/// as [`scan_dir_signables`] (no symlinks, size/depth caps).
pub fn scan_dir_private_key_paths(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    scan_key_paths_rec(root, 0, &mut out);
    out
}

fn scan_key_paths_rec(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_SCAN_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.filter_map(|e| e.ok()) {
        let Ok(file_type) = entry.file_type() else { continue };
        let path = entry.path();
        if file_type.is_dir() {
            scan_key_paths_rec(&path, depth + 1, out);
        } else if file_type.is_file() && is_private_key_file(&path) {
            out.push(path);
        }
    }
}

fn is_private_key_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else { return false };
    if meta.len() > MAX_SCAN_FILE_SIZE {
        return false;
    }
    let Ok(raw) = std::fs::read(path) else { return false };
    let Ok((der, _container)) = input::load(&raw) else { return false };
    let Ok(roots) = ber::parse_forest(&der, 0) else { return false };
    is_plaintext_private_key(&roots)
}

/// Whether `roots` structurally decodes as a plaintext private key — a SEC1
/// `ECPrivateKey` (`SEQUENCE { version INTEGER, privateKey OCTET STRING, … }`)
/// or a PKCS#8 `PrivateKeyInfo` / `OneAsymmetricKey` (`SEQUENCE { version
/// INTEGER, privateKeyAlgorithm SEQUENCE { OID, … }, privateKey OCTET STRING,
/// … }`) — *without* requiring the public key to be recoverable. A leading
/// version INTEGER distinguishes both shapes from a certificate (leading
/// `tbsCertificate` SEQUENCE) and an `EncryptedPrivateKeyInfo` (leading
/// `AlgorithmIdentifier` SEQUENCE).
pub fn is_plaintext_private_key(roots: &[Node]) -> bool {
    if roots.len() != 1 {
        return false;
    }
    let root = &roots[0];
    if !root.constructed || !root.is_universal(TAG_SEQUENCE) || root.children.len() < 2 {
        return false;
    }
    let version = &root.children[0];
    if version.constructed || !version.is_universal(TAG_INTEGER) {
        return false;
    }
    let second = &root.children[1];
    // SEC1 ECPrivateKey: the second element is the privateKey OCTET STRING.
    if !second.constructed && second.is_universal(TAG_OCTET_STRING) {
        return true;
    }
    // PKCS#8: privateKeyAlgorithm SEQUENCE { OID, … }, then privateKey OCTET STRING.
    let alg_is_seq_with_oid = second.constructed
        && second.is_universal(TAG_SEQUENCE)
        && second.children.first().is_some_and(|c| !c.constructed && c.is_universal(TAG_OID));
    alg_is_seq_with_oid
        && root
            .children
            .get(2)
            .is_some_and(|pk| !pk.constructed && pk.is_universal(TAG_OCTET_STRING))
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

    fn cert_key_id(rel: &str) -> PublicKeyId {
        let (der, roots) = parse_der(&Path::new("testdata/keylink").join(rel));
        let signable = parse_signable(&roots, &der).expect("a certificate");
        public_key_id_of_signable(&signable).expect("cert public key")
    }

    fn priv_key_id(rel: &str) -> Option<PublicKeyId> {
        let (_der, roots) = parse_der(&Path::new("testdata/keylink").join(rel));
        public_key_id_of_private_key(&roots)
    }

    #[test]
    fn ec_private_keys_public_matches_its_certificate() {
        let cert = cert_key_id("cert_ec.der");
        assert!(matches!(cert, PublicKeyId::Ec(_)));
        // Both the PKCS#8-wrapped and the bare SEC1 form recover the same
        // point, and it equals the certificate's subjectPublicKey.
        for key in ["key_ec_pkcs8.der", "key_ec_sec1.der"] {
            assert_eq!(priv_key_id(key).unwrap(), cert, "{}", key);
        }
    }

    #[test]
    fn rsa_private_keys_public_matches_its_certificate() {
        let cert = cert_key_id("cert_rsa.der");
        assert!(matches!(cert, PublicKeyId::Rsa { .. }));
        assert_eq!(priv_key_id("key_rsa_pkcs8.der").unwrap(), cert);
    }

    #[test]
    fn unrelated_key_and_cert_do_not_match() {
        let ec_cert = cert_key_id("cert_ec.der");
        // A different algorithm's key never matches.
        assert_ne!(priv_key_id("key_rsa_pkcs8.der").unwrap(), ec_cert);
        // A different EC key (the unrelated committed sample) does not match.
        if let Some(other) = priv_key_id("../ec_key.der") {
            assert_ne!(other, ec_cert);
        }
    }

    #[test]
    fn scan_dir_private_key_paths_finds_plaintext_keys_only() {
        let paths = scan_dir_private_key_paths(Path::new("testdata/keylink"));
        let names: std::collections::BTreeSet<String> = paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains("key_ec_pkcs8.der"));
        assert!(names.contains("key_ec_sec1.der"));
        assert!(names.contains("key_rsa_pkcs8.der"));
        // Encrypted keys, PKCS#12 containers, and certificates are not
        // plaintext private keys.
        assert!(!names.contains("key_ec_enc.der"));
        assert!(!names.contains("key_ec.p12"));
        assert!(!names.contains("cert_ec.der"));
    }

    #[test]
    fn certificate_and_encrypted_key_are_not_plaintext_private_keys() {
        for f in ["testdata/cert_ec.der", "testdata/cert_rsa.der", "testdata/enc_pkcs8.der", "testdata/pkcs12.der"] {
            let (_der, roots) = parse_der(Path::new(f));
            assert!(!is_plaintext_private_key(&roots), "{} misdetected as a private key", f);
        }
        for f in ["testdata/private_key_pkcs8.der", "testdata/ec_key.der"] {
            let (_der, roots) = parse_der(Path::new(f));
            assert!(is_plaintext_private_key(&roots), "{} not detected as a private key", f);
        }
    }

    #[test]
    fn parse_cms_signed_extracts_the_signer_info() {
        let (der, roots) = parse_der(Path::new("testdata/cms_signed.der"));
        let cms = parse_cms_signed(&roots, &der).expect("CMS fixture parses");
        // sid = issuer + serial of keylink/cert_ec.der (the signer).
        let (signer_der, signer_roots) = parse_der(Path::new("testdata/keylink/cert_ec.der"));
        let signer = parse_signable(&signer_roots, &signer_der).unwrap();
        assert_eq!(cms.issuer, signer.issuer);
        assert_eq!(Some(cms.serial.as_slice()), signer.serial.as_deref());
        assert_eq!(cms.sig_alg, [1, 2, 840, 10045, 4, 3, 2], "ecdsa-with-SHA256");
        assert_eq!(cms.digest_alg, [2, 16, 840, 1, 101, 3, 4, 2, 1], "sha256");
        assert!(!cms.signature.is_empty());
        // openssl signs with attributes; the re-tagged SET and the digest
        // attribute and the attached content are all present.
        assert!(cms.signed_attrs.as_ref().is_some_and(|s| s[0] == 0x31));
        assert_eq!(cms.message_digest.as_ref().map(|d| d.len()), Some(32));
        assert!(cms
            .econtent
            .as_deref()
            .is_some_and(|c| c.starts_with(b"asn1-editor CMS test message")));
        // A certificate is not a CMS message.
        let (cder, croots) = parse_der(Path::new("testdata/cert_ec.der"));
        assert!(parse_cms_signed(&croots, &cder).is_none());
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
