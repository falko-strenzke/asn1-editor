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

//! Cryptographic signature verification, layered on top of the purely
//! structural `x509.rs`. This is the only module that knows about
//! `aws-lc-rs`; a future CMS `SignerInfo` decoder could call
//! `verify_against` with the same `(tbs bytes, sig alg OID, signature
//! bytes)` shape it already takes from `x509::Signable`.
//!
//! Algorithm coverage: RSA PKCS#1 v1.5 (SHA-1/256/384/512), ECDSA
//! (P-256/SHA-256, P-384/SHA-384), Ed25519. RSA-PSS and post-quantum
//! algorithms (ML-DSA/SLH-DSA) are not implemented yet; `aws-lc-rs` was
//! chosen over `ring` specifically because it is the more likely of the
//! two to gain PQ verification support later.

use std::path::{Path, PathBuf};

use aws_lc_rs::signature;

use crate::x509::{self, CaCandidate, PublicKeyId, Signable, SignableFile};

const SHA1_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 5];
const SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
const SHA384_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 12];
const SHA512_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 13];
const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const ECDSA_WITH_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
const ED25519_OID: &[u64] = &[1, 3, 101, 112];

pub enum SignatureStatus {
    Verified { issuer_path: PathBuf, issuer_summary: String, self_signed: bool },
    Invalid { issuer_path: PathBuf, issuer_summary: String },
    IssuerNotFound,
    UnsupportedAlgorithm(String),
}

fn algorithm_for(oid: &[u64]) -> Option<&'static dyn signature::VerificationAlgorithm> {
    if oid == SHA1_WITH_RSA {
        Some(&signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY)
    } else if oid == SHA256_WITH_RSA {
        Some(&signature::RSA_PKCS1_2048_8192_SHA256)
    } else if oid == SHA384_WITH_RSA {
        Some(&signature::RSA_PKCS1_2048_8192_SHA384)
    } else if oid == SHA512_WITH_RSA {
        Some(&signature::RSA_PKCS1_2048_8192_SHA512)
    } else if oid == ECDSA_WITH_SHA256 {
        Some(&signature::ECDSA_P256_SHA256_ASN1)
    } else if oid == ECDSA_WITH_SHA384 {
        Some(&signature::ECDSA_P384_SHA384_ASN1)
    } else if oid == ED25519_OID {
        Some(&signature::ED25519)
    } else {
        None
    }
}

fn oid_string(oid: &[u64]) -> String {
    oid.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".")
}

/// Find a candidate issuer for `signable` in `index` (an
/// `authorityKeyIdentifier`/`subjectKeyIdentifier` match is preferred
/// over issuer/subject DN byte-equality when both AKI and at least one
/// candidate's SKI are present), then verify the signature against it.
/// With several byte-equal-DN candidates, the first one whose signature
/// actually verifies wins; if none do, the status reports `Invalid`
/// against the first candidate.
pub fn verify_against(index: &[CaCandidate], signable: &Signable) -> SignatureStatus {
    let by_key_id: Vec<&CaCandidate> = signable
        .aki_key_id
        .as_ref()
        .map(|aki| index.iter().filter(|c| c.ski.as_ref() == Some(aki)).collect())
        .unwrap_or_default();
    let candidates: Vec<&CaCandidate> = if !by_key_id.is_empty() {
        by_key_id
    } else {
        index.iter().filter(|c| c.subject == signable.issuer).collect()
    };
    let Some(first) = candidates.first() else {
        return SignatureStatus::IssuerNotFound;
    };
    let Some(alg) = algorithm_for(&signable.sig_alg) else {
        return SignatureStatus::UnsupportedAlgorithm(oid_string(&signable.sig_alg));
    };
    for candidate in &candidates {
        let public_key = signature::UnparsedPublicKey::new(alg, &candidate.pubkey);
        if public_key.verify(&signable.tbs, &signable.signature).is_ok() {
            return SignatureStatus::Verified {
                issuer_path: candidate.path.clone(),
                issuer_summary: candidate.subject_summary.clone(),
                self_signed: signable.subject.as_ref() == Some(&candidate.subject),
            };
        }
    }
    SignatureStatus::Invalid {
        issuer_path: first.path.clone(),
        issuer_summary: first.subject_summary.clone(),
    }
}

/// One cryptographic relation between the selected file and another file
/// in the browser's scanned tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationEdge {
    /// Path of the other file (the signer, for an incoming edge; the
    /// signed object, for an outgoing edge).
    pub other: PathBuf,
    /// True when the signature cryptographically verifies; false when the
    /// issuance is only *claimed* (an issuer is present but its signature
    /// does not verify) — rendered in red.
    pub verified: bool,
}

/// The cryptographic relations of one selected file to the others in the
/// scanned tree: who signed it (incoming) and what it signed (outgoing).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileRelations {
    /// The file whose signature covers the selected file, if that signer
    /// is present in the tree. A self-signed object has no incoming edge
    /// (the signer is itself — no separate file to point from).
    pub signed_by: Option<RelationEdge>,
    /// The files the selected file signed (only non-empty when the
    /// selected file is a CA certificate present as an issuer in the tree).
    pub signs: Vec<RelationEdge>,
    /// Files linked to the selected file by a shared key pair: a private-key
    /// file and the certificate carrying its public key. The relation is
    /// undirected (a key is not "signed by" a cert) — no arrowhead is drawn.
    /// Deduplicated; a file is never linked to itself.
    pub key_links: Vec<PathBuf>,
}

/// Undirected key↔certificate links touching `selected`.
///
/// `key_bearers` pairs each private-key-bearing file with the public key it
/// corresponds to — plaintext key files from the directory scan, plus (added
/// by the caller) any currently-open encrypted key or PKCS#12 whose password
/// has been supplied. `certs` pairs each certificate file with its public
/// key. A link is drawn between a key-bearing file and a certificate file
/// that share the same public key; a file is never linked to itself. Pure
/// logic, no I/O — the two input lists are assembled by the caller.
pub fn key_links_for(
    key_bearers: &[(PathBuf, PublicKeyId)],
    certs: &[(PathBuf, PublicKeyId)],
    selected: &Path,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let add = |path: &Path, out: &mut Vec<PathBuf>| {
        if path != selected && !out.iter().any(|q| q == path) {
            out.push(path.to_path_buf());
        }
    };
    // The selected file bears a private key → link the certificates for it.
    for (kp, kid) in key_bearers {
        if kp.as_path() == selected {
            for (cp, cid) in certs {
                if cid == kid {
                    add(cp, &mut out);
                }
            }
        }
    }
    // The selected file is a certificate → link the private keys for it.
    for (cp, cid) in certs {
        if cp.as_path() == selected {
            for (kp, kid) in key_bearers {
                if kid == cid {
                    add(kp, &mut out);
                }
            }
        }
    }
    out
}

/// Is this certificate cryptographically self-signed — issuer equal to its
/// own subject and the signature verifying under its own public key? Such
/// a certificate's issuance edge would only ever point at itself (or at
/// another *copy* of the same certificate, e.g. the same root stored as
/// both .der and .pem), so the relation graph draws nothing for it.
fn is_self_signed(s: &Signable) -> bool {
    let (Some(subject), Some(pubkey)) = (&s.subject, &s.pubkey) else {
        return false; // CRLs and cert-less shapes cannot be self-signed
    };
    if *subject != s.issuer {
        return false;
    }
    let Some(alg) = algorithm_for(&s.sig_alg) else { return false };
    signature::UnparsedPublicKey::new(alg, pubkey)
        .verify(&s.tbs, &s.signature)
        .is_ok()
}

/// Compute the signer/signed relations of `selected` against every other
/// signed object in `signables`. Pure logic (no rendering): for each
/// scanned file it resolves the single issuer `verify_against` would pick,
/// then reads off the edges touching `selected`. Self-signed certificates
/// contribute no issuance edge at all — neither to themselves nor between
/// duplicate copies of the same certificate in different files. `signs`
/// order follows scan order and is therefore not guaranteed stable —
/// callers that care should sort.
pub fn relations_for(signables: &[SignableFile], selected: &Path) -> FileRelations {
    let candidates = x509::cert_candidates(signables);
    let mut relations = FileRelations::default();
    for file in signables {
        if is_self_signed(&file.signable) {
            continue; // no incoming/outgoing arrows for self-signed certs
        }
        let (issuer_path, verified) = match verify_against(&candidates, &file.signable) {
            SignatureStatus::Verified { issuer_path, .. } => (issuer_path, true),
            SignatureStatus::Invalid { issuer_path, .. } => (issuer_path, false),
            // No identifiable single issuer in the tree — no edge.
            SignatureStatus::IssuerNotFound | SignatureStatus::UnsupportedAlgorithm(_) => continue,
        };
        if issuer_path == file.path {
            // Not cryptographically self-signed (or it would have been
            // skipped above), but the resolver still landed on the file
            // itself — never draw an arrow from a file to itself.
            continue;
        }
        if file.path == selected {
            relations.signed_by = Some(RelationEdge { other: issuer_path.clone(), verified });
        }
        if issuer_path == selected {
            relations.signs.push(RelationEdge { other: file.path.clone(), verified });
        }
    }
    relations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ber, input, x509};
    use std::path::Path;

    fn scan_and_verify(dir: &Path, file: &str) -> SignatureStatus {
        let index = x509::scan_dir(dir);
        let raw = std::fs::read(dir.join(file)).unwrap();
        let (der, _) = input::load(&raw).unwrap();
        let roots = ber::parse_forest(&der, 0).unwrap();
        let signable = x509::parse_signable(&roots, &der).unwrap();
        verify_against(&index, &signable)
    }

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("asn1-editor-verify-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ------------------------------------------------------------------
    // Relation-graph logic over the committed testdata/chain hierarchy:
    //   root_ca (self-signed)
    //     ├── intermediate_ca
    //     │     ├── server                 (valid leaf)
    //     │     ├── server_bad_signature   (leaf, signature corrupted)
    //     │     └── intermediate_crl
    //     └── root_crl
    // These need no openssl — the files are part of the repo.
    // ------------------------------------------------------------------

    fn chain_relations(file: &str) -> FileRelations {
        let dir = Path::new("testdata/chain");
        let signables = x509::scan_dir_signables(dir);
        relations_for(&signables, &dir.join(file))
    }

    fn signer(rel: &FileRelations) -> Option<(String, bool)> {
        rel.signed_by
            .as_ref()
            .map(|e| (e.other.file_name().unwrap().to_string_lossy().into_owned(), e.verified))
    }

    fn signs(rel: &FileRelations) -> std::collections::BTreeMap<String, bool> {
        rel.signs
            .iter()
            .map(|e| (e.other.file_name().unwrap().to_string_lossy().into_owned(), e.verified))
            .collect()
    }

    #[test]
    fn valid_leaf_points_back_to_its_intermediate() {
        let rel = chain_relations("server.der");
        assert_eq!(signer(&rel), Some(("intermediate_ca.der".to_string(), true)));
        assert!(rel.signs.is_empty());
    }

    #[test]
    fn broken_leaf_shows_claimed_issuer_as_unverified() {
        let rel = chain_relations("server_bad_signature.der");
        // Issuer is still identified (AKI/DN match), but marked unverified.
        assert_eq!(signer(&rel), Some(("intermediate_ca.der".to_string(), false)));
        assert!(rel.signs.is_empty());
    }

    #[test]
    fn intermediate_is_signed_by_root_and_signs_its_children() {
        let rel = chain_relations("intermediate_ca.der");
        assert_eq!(signer(&rel), Some(("root_ca.der".to_string(), true)));
        let signed = signs(&rel);
        assert_eq!(
            signed,
            std::collections::BTreeMap::from([
                ("server.der".to_string(), true),
                ("server_bad_signature.der".to_string(), false),
                ("intermediate_crl.der".to_string(), true),
            ])
        );
        // The intermediate does not point back at its own issuer or itself.
        assert!(!signed.contains_key("root_ca.der"));
        assert!(!signed.contains_key("intermediate_ca.der"));
    }

    #[test]
    fn self_signed_root_has_no_incoming_edge_but_signs_children() {
        let rel = chain_relations("root_ca.der");
        assert_eq!(signer(&rel), None, "a self-signed root has no separate signer");
        let signed = signs(&rel);
        assert_eq!(
            signed,
            std::collections::BTreeMap::from([
                ("intermediate_ca.der".to_string(), true),
                ("root_crl.der".to_string(), true),
            ])
        );
        assert!(!signed.contains_key("root_ca.der"), "no self-edge");
    }

    #[test]
    fn duplicated_self_signed_cert_gets_no_arrows() {
        // testdata/ holds the same self-signed EC certificate twice, as
        // cert_ec.der and cert_ec.pem. Neither copy may point at the
        // other: self-signed certificates have no issuance arrows at all.
        let dir = Path::new("testdata");
        let signables = x509::scan_dir_signables(dir);
        for file in ["cert_ec.der", "cert_ec.pem", "cert_rsa.der"] {
            let rel = relations_for(&signables, &dir.join(file));
            assert_eq!(rel.signed_by, None, "{} must have no incoming arrow", file);
            assert!(rel.signs.is_empty(), "{} must have no outgoing arrows", file);
        }
    }

    #[test]
    fn crls_are_signed_by_their_issuing_ca() {
        assert_eq!(
            signer(&chain_relations("root_crl.der")),
            Some(("root_ca.der".to_string(), true))
        );
        assert!(chain_relations("root_crl.der").signs.is_empty());
        assert_eq!(
            signer(&chain_relations("intermediate_crl.der")),
            Some(("intermediate_ca.der".to_string(), true))
        );
        assert!(chain_relations("intermediate_crl.der").signs.is_empty());
    }

    fn openssl_available() -> bool {
        std::process::Command::new("openssl").arg("version").output().is_ok()
    }

    fn run_openssl(args: &[&str]) {
        let status = std::process::Command::new("openssl").args(args).status().unwrap();
        assert!(status.success(), "openssl {:?} failed", args);
    }

    #[test]
    fn self_signed_root_verifies() {
        if !openssl_available() {
            eprintln!("skipping: openssl not installed");
            return;
        }
        let dir = tmp_dir("selfsigned");
        let key = dir.join("ca.key");
        let cert = dir.join("ca.der");
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", key.to_str().unwrap()]);
        run_openssl(&[
            "req", "-x509", "-new", "-key", key.to_str().unwrap(),
            "-out", cert.to_str().unwrap(), "-outform", "DER",
            "-days", "365", "-subj", "/CN=Test Root",
        ]);

        match scan_and_verify(&dir, "ca.der") {
            SignatureStatus::Verified { self_signed, .. } => assert!(self_signed),
            other => panic!("expected Verified, got a different status ({})", debug_kind(&other)),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaf_signed_by_ca_verifies_and_tamper_is_detected() {
        if !openssl_available() {
            eprintln!("skipping: openssl not installed");
            return;
        }
        let dir = tmp_dir("chain");
        let ca_key = dir.join("ca.key");
        let ca_cert = dir.join("ca.der");
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", ca_key.to_str().unwrap()]);
        run_openssl(&[
            "req", "-x509", "-new", "-key", ca_key.to_str().unwrap(),
            "-out", ca_cert.to_str().unwrap(), "-outform", "DER",
            "-days", "365", "-subj", "/CN=Test CA",
        ]);

        let leaf_key = dir.join("leaf.key");
        let csr = dir.join("leaf.csr");
        let leaf_cert = dir.join("leaf.der");
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", leaf_key.to_str().unwrap()]);
        run_openssl(&[
            "req", "-new", "-key", leaf_key.to_str().unwrap(),
            "-out", csr.to_str().unwrap(), "-subj", "/CN=Leaf",
        ]);
        let ca_pem = dir.join("ca.pem");
        run_openssl(&["x509", "-inform", "DER", "-in", ca_cert.to_str().unwrap(), "-out", ca_pem.to_str().unwrap()]);
        run_openssl(&[
            "x509", "-req", "-in", csr.to_str().unwrap(),
            "-CA", ca_pem.to_str().unwrap(), "-CAkey", ca_key.to_str().unwrap(), "-CAcreateserial",
            "-out", leaf_cert.to_str().unwrap(), "-outform", "DER", "-days", "365",
        ]);

        match scan_and_verify(&dir, "leaf.der") {
            SignatureStatus::Verified { self_signed, .. } => assert!(!self_signed),
            other => panic!("expected Verified, got a different status ({})", debug_kind(&other)),
        }

        // Flip a byte in the leaf's signature and confirm verification fails.
        let mut bytes = std::fs::read(&leaf_cert).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&leaf_cert, &bytes).unwrap();
        let index = x509::scan_dir(&dir);
        let roots = ber::parse_forest(&bytes, 0).unwrap();
        let signable = x509::parse_signable(&roots, &bytes);
        // A flipped last byte may break DER parsing outright (also an
        // acceptable outcome) or parse but fail to verify.
        if let Some(signable) = signable {
            match verify_against(&index, &signable) {
                SignatureStatus::Invalid { .. } => {}
                other => panic!("expected Invalid after tampering, got {}", debug_kind(&other)),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unrelated_ca_is_not_found() {
        if !openssl_available() {
            eprintln!("skipping: openssl not installed");
            return;
        }
        // Build a leaf signed by "CA A" in a scratch area outside the test
        // directory, so its real issuer is never in the scanned index.
        let scratch = tmp_dir("nomatch-scratch");
        let ca_key = scratch.join("ca.key");
        let ca_cert = scratch.join("ca.pem");
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", ca_key.to_str().unwrap()]);
        run_openssl(&[
            "req", "-x509", "-new", "-key", ca_key.to_str().unwrap(),
            "-out", ca_cert.to_str().unwrap(), "-subj", "/CN=CA A", "-days", "365",
        ]);
        let leaf_key = scratch.join("leaf.key");
        let csr = scratch.join("leaf.csr");
        let leaf_cert = scratch.join("leaf.der");
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", leaf_key.to_str().unwrap()]);
        run_openssl(&["req", "-new", "-key", leaf_key.to_str().unwrap(), "-out", csr.to_str().unwrap(), "-subj", "/CN=Leaf"]);
        run_openssl(&[
            "x509", "-req", "-in", csr.to_str().unwrap(),
            "-CA", ca_cert.to_str().unwrap(), "-CAkey", ca_key.to_str().unwrap(), "-CAcreateserial",
            "-out", leaf_cert.to_str().unwrap(), "-outform", "DER", "-days", "365",
        ]);

        // The actual scan directory only has an unrelated CA B (different
        // subject) plus the leaf — CA A is nowhere in it.
        let dir = tmp_dir("nomatch");
        let other_ca_key = dir.join("cab.key");
        let other_ca_cert = dir.join("cab.der");
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", other_ca_key.to_str().unwrap()]);
        run_openssl(&[
            "req", "-x509", "-new", "-key", other_ca_key.to_str().unwrap(),
            "-out", other_ca_cert.to_str().unwrap(), "-outform", "DER",
            "-days", "365", "-subj", "/CN=CA B",
        ]);
        std::fs::copy(&leaf_cert, dir.join("leaf.der")).unwrap();

        match scan_and_verify(&dir, "leaf.der") {
            SignatureStatus::IssuerNotFound => {}
            other => panic!("expected IssuerNotFound, got {}", debug_kind(&other)),
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&scratch);
    }

    fn debug_kind(s: &SignatureStatus) -> &'static str {
        match s {
            SignatureStatus::Verified { .. } => "Verified",
            SignatureStatus::Invalid { .. } => "Invalid",
            SignatureStatus::IssuerNotFound => "IssuerNotFound",
            SignatureStatus::UnsupportedAlgorithm(_) => "UnsupportedAlgorithm",
        }
    }

    #[test]
    fn key_links_connect_a_key_and_its_certificate_both_ways() {
        let ec = PublicKeyId::Ec(vec![1, 2, 3]);
        let other = PublicKeyId::Ec(vec![9, 9, 9]);
        let keys = vec![
            (PathBuf::from("key.der"), ec.clone()),
            (PathBuf::from("other_key.der"), other.clone()),
        ];
        let certs = vec![
            (PathBuf::from("cert.pem"), ec.clone()),
            (PathBuf::from("unrelated.pem"), other),
        ];
        // From the key's side: link to its matching certificate only.
        assert_eq!(
            key_links_for(&keys, &certs, Path::new("key.der")),
            vec![PathBuf::from("cert.pem")]
        );
        // From the certificate's side: link back to the matching key only.
        assert_eq!(
            key_links_for(&keys, &certs, Path::new("cert.pem")),
            vec![PathBuf::from("key.der")]
        );
        // A file that shares no key with any other: nothing.
        assert!(key_links_for(&keys, &certs, Path::new("nobody")).is_empty());
    }

    #[test]
    fn key_links_dedup_and_never_point_at_the_file_itself() {
        let ec = PublicKeyId::Ec(vec![1]);
        // The same key in two cert files (plus a duplicate path): a key links
        // to each distinct certificate file once.
        let keys = vec![(PathBuf::from("k"), ec.clone())];
        let certs = vec![
            (PathBuf::from("c1"), ec.clone()),
            (PathBuf::from("c1"), ec.clone()),
            (PathBuf::from("c2"), ec.clone()),
        ];
        assert_eq!(
            key_links_for(&keys, &certs, Path::new("k")),
            vec![PathBuf::from("c1"), PathBuf::from("c2")]
        );
        // A file that is somehow both a bearer and a cert for the same key
        // never links to itself.
        let same = vec![(PathBuf::from("both"), ec.clone())];
        assert!(key_links_for(&same, &same, Path::new("both")).is_empty());
    }
}
