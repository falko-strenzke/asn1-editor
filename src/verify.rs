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

use std::path::PathBuf;

use aws_lc_rs::signature;

use crate::x509::{CaCandidate, Signable};

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
}
