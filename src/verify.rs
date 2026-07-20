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

//! Cryptographic signature verification and generation, layered on top of the
//! purely structural `x509.rs`. A future CMS `SignerInfo` decoder could call
//! `verify_against` with the same `(tbs bytes, sig alg OID, signature bytes)`
//! shape it already takes from `x509::Signable`.
//!
//! Two backends: classical algorithms use `aws-lc-rs` — RSA PKCS#1 v1.5
//! (SHA-1/256/384/512), ECDSA (P-256/SHA-256, P-384/SHA-384), Ed25519 — with
//! an OpenSSL fallback for RSA moduli outside `aws-lc-rs`'s parameter ranges
//! (the deliberately weak 512/768/1024-bit sizes the key generator offers) —
//! while
//! the post-quantum FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) algorithms use the
//! `openssl` crate (OpenSSL 3.5+), which covers both families; `aws-lc-rs` has
//! ML-DSA but not SLH-DSA, so OpenSSL is used uniformly for the pair. The PQ
//! signatures are "pure" (the message is signed directly, no external digest),
//! matching the LAMPS X.509 profiles: OpenSSL's one-shot `Signer`/`Verifier`
//! without a digest.

use std::path::{Path, PathBuf};

use aws_lc_rs::signature;

use crate::ber;
use crate::x509::{self, CaCandidate, PublicKeyId, Signable, SignableFile};

const RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
const SHA1_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 5];
const SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
const SHA384_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 12];
const SHA512_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 13];
const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const ECDSA_WITH_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
const ED25519_OID: &[u64] = &[1, 3, 101, 112];

/// The pure ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) signature-algorithm OIDs,
/// all under the NIST arc `2.16.840.1.101.3.4.3.{17..=31}`: ML-DSA-44/65/87
/// (17–19) and the twelve SLH-DSA parameter sets (20–31).
const PQ_SIG_ARCS: &[u64] = &[17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];

/// Whether `sig_alg` is one of the pure ML-DSA/SLH-DSA OIDs, which are handled
/// by the OpenSSL backend rather than `aws-lc-rs`.
fn is_pq(sig_alg: &[u64]) -> bool {
    matches!(sig_alg, [2, 16, 840, 1, 101, 3, 4, 3, arc] if PQ_SIG_ARCS.contains(arc))
}

/// Whether `sig_alg` is the XMSS OID, handled by the Botan backend
/// (`xmss.rs`) — the only backend implementing the stateful hash-based
/// schemes.
fn is_xmss(sig_alg: &[u64]) -> bool {
    crate::xmss::is_xmss_oid(sig_alg)
}

/// Whether signing with `sig_alg` mutates the private key — the caller must
/// persist the updated key [`sign_stateful`] returns. True for XMSS (each
/// signature consumes a one-time-signature index); false for every stateless
/// algorithm.
pub fn is_stateful(sig_alg: &[u64]) -> bool {
    is_xmss(sig_alg)
}

#[derive(Debug)]
pub enum SignatureStatus {
    Verified { issuer_path: PathBuf, issuer_summary: String, self_signed: bool },
    Invalid { issuer_path: PathBuf, issuer_summary: String },
    IssuerNotFound,
    UnsupportedAlgorithm(String),
}

impl SignatureStatus {
    /// The identified issuer/signer certificate's file, when one was found
    /// (whether or not the signature verified) — the certificate whose path
    /// is validated for a CRL or CMS message (§9d).
    pub fn issuer_path(&self) -> Option<&Path> {
        match self {
            SignatureStatus::Verified { issuer_path, .. }
            | SignatureStatus::Invalid { issuer_path, .. } => Some(issuer_path),
            SignatureStatus::IssuerNotFound | SignatureStatus::UnsupportedAlgorithm(_) => None,
        }
    }
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

/// Whether `pkcs8_key` is a *usable* private key — it loads for one of the
/// supported algorithms, which for an EC key also confirms the private scalar
/// is consistent with the key's embedded public key. A key whose scalar has
/// been corrupted (but whose structure and public key remain) fails here even
/// though it still parses structurally, so the key↔certificate link and the
/// re-sign key search can drop it.
pub fn private_key_usable(pkcs8_key: &[u8]) -> bool {
    signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_key)
        .is_ok()
        || signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            pkcs8_key,
        )
        .is_ok()
        || signature::RsaKeyPair::from_pkcs8(pkcs8_key).is_ok()
        // An RSA key outside aws-lc-rs's modulus range (e.g. the deliberately
        // weak 512/768-bit sizes) is validated by OpenSSL instead.
        || (pkcs8_alg_arcs(pkcs8_key).as_deref() == Some(RSA_ENCRYPTION)
            && rsa_private_key_usable(pkcs8_key))
        || signature::Ed25519KeyPair::from_pkcs8(pkcs8_key).is_ok()
        // A post-quantum key (ML-DSA/SLH-DSA) loads via OpenSSL, not aws-lc-rs.
        || (pkcs8_is_pq(pkcs8_key)
            && openssl::pkey::PKey::private_key_from_pkcs8(pkcs8_key).is_ok())
        // An XMSS key loads via the Botan backend.
        || (pkcs8_alg_arcs(pkcs8_key).as_deref().is_some_and(is_xmss)
            && crate::xmss::key_usable(pkcs8_key))
}

/// Whether `pkcs8_key` is a consistent RSA private key according to OpenSSL
/// (`RSA_check_key`, which validates the primes against the modulus — the
/// small-key counterpart of `RsaKeyPair::from_pkcs8`'s checks).
fn rsa_private_key_usable(pkcs8_key: &[u8]) -> bool {
    openssl::pkey::PKey::private_key_from_pkcs8(pkcs8_key)
        .ok()
        .and_then(|key| key.rsa().ok())
        .is_some_and(|rsa| rsa.check_key().unwrap_or(false))
}

/// The `privateKeyAlgorithm` OID arcs of a PKCS#8 `PrivateKeyInfo`.
pub(crate) fn pkcs8_alg_arcs(pkcs8_key: &[u8]) -> Option<Vec<u64>> {
    let roots = ber::parse_forest(pkcs8_key, 0).ok()?;
    roots
        .first()
        .and_then(|r| r.children.get(1)) // privateKeyAlgorithm
        .and_then(|a| a.children.first()) // algorithm OID
        .and_then(|o| ber::oid_arcs(&o.value))
}

/// Whether a PKCS#8 `PrivateKeyInfo`'s `privateKeyAlgorithm` is a pure
/// ML-DSA/SLH-DSA OID. Used to gate the OpenSSL usability check so classical
/// keys keep their stricter `aws-lc-rs` validation (which also catches a
/// corrupted EC scalar).
fn pkcs8_is_pq(pkcs8_key: &[u8]) -> bool {
    pkcs8_alg_arcs(pkcs8_key).as_deref().is_some_and(is_pq)
}

/// Whether a PKCS#8 `PrivateKeyInfo`'s `privateKeyAlgorithm` is the XMSS OID,
/// so it must go through the Botan backend rather than OpenSSL/`aws-lc-rs`.
pub fn pkcs8_is_xmss(pkcs8_key: &[u8]) -> bool {
    pkcs8_alg_arcs(pkcs8_key).as_deref().is_some_and(is_xmss)
}

/// Whether `signature` is a valid `sig_alg` signature over `tbs` under the
/// public key `pubkey` (a `subjectPublicKey`, unused-bits octet stripped).
/// Used by re-signing to confirm a freshly generated signature actually
/// matches the issuer certificate before committing to it.
pub fn verify_signature(sig_alg: &[u64], pubkey: &[u8], tbs: &[u8], signature: &[u8]) -> bool {
    if is_pq(sig_alg) {
        return pq_verify(sig_alg, pubkey, tbs, signature);
    }
    if is_xmss(sig_alg) {
        return crate::xmss::verify(pubkey, tbs, signature);
    }
    let ok = match algorithm_for(sig_alg) {
        Some(alg) => signature::UnparsedPublicKey::new(alg, pubkey).verify(tbs, signature).is_ok(),
        None => false,
    };
    // aws-lc-rs refuses RSA moduli outside its parameter ranges (SHA-2 needs
    // ≥ 2048 bits); retry with OpenSSL so signatures under the weak RSA key
    // sizes the key generator offers still verify.
    ok || rsa_openssl_verify(sig_alg, pubkey, tbs, signature)
}

/// Map an RSA X.509 signature-algorithm OID to the message digest used by the
/// OpenSSL small-modulus fallback.
fn rsa_openssl_digest(sig_alg: &[u64]) -> Option<openssl::hash::MessageDigest> {
    use openssl::hash::MessageDigest;
    if sig_alg == SHA1_WITH_RSA {
        Some(MessageDigest::sha1())
    } else if sig_alg == SHA256_WITH_RSA {
        Some(MessageDigest::sha256())
    } else if sig_alg == SHA384_WITH_RSA {
        Some(MessageDigest::sha384())
    } else if sig_alg == SHA512_WITH_RSA {
        Some(MessageDigest::sha512())
    } else {
        None
    }
}

/// Verify an RSA PKCS#1 v1.5 signature with OpenSSL. `pubkey` is the raw
/// `subjectPublicKey` bytes, i.e. a PKCS#1 `RSAPublicKey` DER. Returns false
/// for non-RSA algorithms.
fn rsa_openssl_verify(sig_alg: &[u64], pubkey: &[u8], tbs: &[u8], signature: &[u8]) -> bool {
    let Some(digest) = rsa_openssl_digest(sig_alg) else { return false };
    let Ok(rsa) = openssl::rsa::Rsa::public_key_from_der_pkcs1(pubkey) else { return false };
    let Ok(key) = openssl::pkey::PKey::from_rsa(rsa) else { return false };
    let Ok(mut verifier) = openssl::sign::Verifier::new(digest, &key) else { return false };
    verifier.verify_oneshot(signature, tbs).unwrap_or(false)
}

/// Sign with an RSA private key through OpenSSL (PKCS#1 v1.5) — the fallback
/// for moduli `aws-lc-rs` refuses to load.
fn rsa_openssl_sign(sig_alg: &[u64], pkcs8_key: &[u8], tbs: &[u8]) -> Result<Vec<u8>, String> {
    let digest = rsa_openssl_digest(sig_alg)
        .ok_or_else(|| "unsupported RSA signature algorithm".to_string())?;
    let key = openssl::pkey::PKey::private_key_from_pkcs8(pkcs8_key)
        .map_err(|_| "the signing key is not a usable RSA key".to_string())?;
    if key.rsa().is_err() {
        return Err("the signing key is not a usable RSA key".to_string());
    }
    let mut signer = openssl::sign::Signer::new(digest, &key)
        .map_err(|e| format!("RSA signer init failed: {}", e))?;
    signer.sign_oneshot_to_vec(tbs).map_err(|e| format!("RSA signing failed: {}", e))
}

/// Verify a pure ML-DSA/SLH-DSA signature with OpenSSL. `pubkey` is the raw
/// `subjectPublicKey` bytes, so the `SubjectPublicKeyInfo` is rebuilt around
/// them before loading — OpenSSL parses a whole SPKI, not the bare key.
fn pq_verify(sig_alg: &[u64], pubkey: &[u8], tbs: &[u8], signature: &[u8]) -> bool {
    let Some(spki) = spki_der(sig_alg, pubkey) else { return false };
    let Ok(key) = openssl::pkey::PKey::public_key_from_der(&spki) else { return false };
    let Ok(mut verifier) = openssl::sign::Verifier::new_without_digest(&key) else {
        return false;
    };
    verifier.verify_oneshot(signature, tbs).unwrap_or(false)
}

/// Sign `tbs` with a pure ML-DSA/SLH-DSA private key (PKCS#8) via OpenSSL's
/// one-shot signer (no external digest). The algorithm is determined by the
/// key itself; `sig_alg` only selects this backend.
fn pq_sign(pkcs8_key: &[u8], tbs: &[u8]) -> Result<Vec<u8>, String> {
    let key = openssl::pkey::PKey::private_key_from_pkcs8(pkcs8_key)
        .map_err(|_| "the signing key is not a usable ML-DSA/SLH-DSA key".to_string())?;
    let mut signer = openssl::sign::Signer::new_without_digest(&key)
        .map_err(|e| format!("post-quantum signer init failed: {}", e))?;
    signer.sign_oneshot_to_vec(tbs).map_err(|e| format!("post-quantum signing failed: {}", e))
}

/// Build a `SubjectPublicKeyInfo` DER — `SEQUENCE { SEQUENCE { OID },
/// subjectPublicKey BIT STRING }` — for a pure ML-DSA/SLH-DSA algorithm
/// (parameters absent) and raw public-key bytes.
fn spki_der(sig_alg: &[u64], pubkey: &[u8]) -> Option<Vec<u8>> {
    let dotted = sig_alg.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".");
    let oid = ber::univ(ber::TAG_OID, false, ber::encode_oid(&dotted).ok()?);
    let alg_id = ber::univ_seq(vec![oid]);
    let mut bit_value = Vec::with_capacity(pubkey.len() + 1);
    bit_value.push(0); // unused-bits octet
    bit_value.extend_from_slice(pubkey);
    let bit_string = ber::univ(ber::TAG_BIT_STRING, false, bit_value);
    Some(ber::encode_node(&ber::univ_seq(vec![alg_id, bit_string])))
}

/// Whether `sign` can generate a signature for this signature-algorithm OID.
/// (A subset of what `algorithm_for` can *verify* — `aws-lc-rs` does not sign
/// with the legacy SHA-1 RSA algorithm.)
pub fn signing_supported(sig_alg: &[u64]) -> bool {
    is_pq(sig_alg)
        || is_xmss(sig_alg)
        || [
            SHA256_WITH_RSA,
            SHA384_WITH_RSA,
            SHA512_WITH_RSA,
            ECDSA_WITH_SHA256,
            ECDSA_WITH_SHA384,
            ED25519_OID,
        ]
        .contains(&sig_alg)
}

/// Generate a signature over `tbs` (the DER of a `tbsCertificate` /
/// `tbsCertList`) with the private key `pkcs8_key` (a PKCS#8 `PrivateKeyInfo`)
/// for the X.509 signature algorithm `sig_alg`. The returned bytes go
/// straight into the object's outer `signature` BIT STRING (after the
/// unused-bits octet). Errors if the key and algorithm disagree (e.g. an RSA
/// key for an ECDSA algorithm) or the algorithm is unsupported for signing.
pub fn sign(sig_alg: &[u64], pkcs8_key: &[u8], tbs: &[u8]) -> Result<Vec<u8>, String> {
    sign_stateful(sig_alg, pkcs8_key, tbs).map(|(sig, _)| sig)
}

/// Like [`sign`], but for a stateful algorithm (XMSS) also returns the
/// updated private key, which the caller should persist: each XMSS signature
/// consumes a one-time-signature index. (Within one process Botan's index
/// registry prevents reuse even from stale bytes, so callers that cannot
/// persist — e.g. the speculative signing in the re-sign dialog — may drop
/// it; the serialized index is what protects across program runs.) For the
/// stateless algorithms the second component is `None`.
pub fn sign_stateful(
    sig_alg: &[u64],
    pkcs8_key: &[u8],
    tbs: &[u8],
) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
    if is_xmss(sig_alg) {
        let (sig, updated) = crate::xmss::sign(pkcs8_key, tbs)?;
        return Ok((sig, Some(updated)));
    }
    sign_stateless(sig_alg, pkcs8_key, tbs).map(|sig| (sig, None))
}

fn sign_stateless(sig_alg: &[u64], pkcs8_key: &[u8], tbs: &[u8]) -> Result<Vec<u8>, String> {
    if is_pq(sig_alg) {
        return pq_sign(pkcs8_key, tbs);
    }
    let rng = aws_lc_rs::rand::SystemRandom::new();

    let rsa_padding: Option<&'static dyn signature::RsaEncoding> = if sig_alg == SHA256_WITH_RSA {
        Some(&signature::RSA_PKCS1_SHA256)
    } else if sig_alg == SHA384_WITH_RSA {
        Some(&signature::RSA_PKCS1_SHA384)
    } else if sig_alg == SHA512_WITH_RSA {
        Some(&signature::RSA_PKCS1_SHA512)
    } else {
        None
    };
    if let Some(padding) = rsa_padding {
        // A modulus outside aws-lc-rs's range (e.g. a weak 512/768-bit key)
        // fails to load; those sign through the OpenSSL fallback instead.
        let Ok(key) = signature::RsaKeyPair::from_pkcs8(pkcs8_key) else {
            return rsa_openssl_sign(sig_alg, pkcs8_key, tbs);
        };
        let mut sig = vec![0u8; key.public_modulus_len()];
        key.sign(padding, &rng, tbs, &mut sig)
            .map_err(|_| "RSA signing failed".to_string())?;
        return Ok(sig);
    }

    let ecdsa_alg: Option<&'static signature::EcdsaSigningAlgorithm> = if sig_alg == ECDSA_WITH_SHA256
    {
        Some(&signature::ECDSA_P256_SHA256_ASN1_SIGNING)
    } else if sig_alg == ECDSA_WITH_SHA384 {
        Some(&signature::ECDSA_P384_SHA384_ASN1_SIGNING)
    } else {
        None
    };
    if let Some(alg) = ecdsa_alg {
        let key = signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8_key)
            .map_err(|_| "the signing key is not a usable ECDSA key for this curve".to_string())?;
        let sig = key.sign(&rng, tbs).map_err(|_| "ECDSA signing failed".to_string())?;
        return Ok(sig.as_ref().to_vec());
    }

    if sig_alg == ED25519_OID {
        let key = signature::Ed25519KeyPair::from_pkcs8(pkcs8_key)
            .map_err(|_| "the signing key is not a usable Ed25519 key".to_string())?;
        return Ok(key.sign(tbs).as_ref().to_vec());
    }

    Err(format!("re-signing is not supported for algorithm {}", oid_string(sig_alg)))
}

/// Find a candidate issuer for `signable` in `index` (an
/// `authorityKeyIdentifier`/`subjectKeyIdentifier` match is preferred
/// over issuer/subject DN byte-equality when both AKI and at least one
/// candidate's SKI are present), then verify the signature against it.
/// With several byte-equal-DN candidates, the first one whose signature
/// actually verifies wins; if none do, the status reports `Invalid`
/// against the first candidate.
/// The certificates in `index` that *claim* to be `signable`'s issuer —
/// matched on `authorityKeyIdentifier`/`subjectKeyIdentifier` when present,
/// else on issuer/subject DN byte-equality — **without** checking the
/// signature. `verify_against` narrows these to the one that actually
/// verifies; re-signing (`sign`) needs the claimed issuer even when the
/// current signature does not verify (the whole reason to re-sign).
pub fn claimed_issuers<'a>(index: &'a [CaCandidate], signable: &Signable) -> Vec<&'a CaCandidate> {
    let by_key_id: Vec<&CaCandidate> = signable
        .aki_key_id
        .as_ref()
        .map(|aki| index.iter().filter(|c| c.ski.as_ref() == Some(aki)).collect())
        .unwrap_or_default();
    if by_key_id.is_empty() {
        index.iter().filter(|c| c.subject == signable.issuer).collect()
    } else {
        by_key_id
    }
}

/// Verify a CMS `SignedData` message (RFC 5652) against the certificates
/// found in the directory scan. The signer certificate is identified by the
/// SignerInfo's `IssuerAndSerialNumber`; if none of the scanned certificates
/// carries that issuer + serial, the result is `IssuerNotFound`. Otherwise
/// the signature is checked twice, like a certificate's (§9): a raw check
/// with our own primitives (signature over the re-tagged `signedAttrs` SET —
/// or the `eContent` when no attributes are signed — plus the
/// `messageDigest` attribute against digest(eContent)), and an independent
/// `CMS_verify` through the OpenSSL bindings pinned to the identified
/// signer certificate (chain building disabled — path validation is §9d's
/// job). `Verified` only when both agree.
pub fn verify_cms(files: &[SignableFile], cms: &x509::CmsSigned, cms_der: &[u8]) -> SignatureStatus {
    let signer = files.iter().find(|f| {
        f.signable.kind == x509::Kind::Certificate
            && f.signable.issuer == cms.issuer
            && f.signable.serial.as_deref() == Some(cms.serial.as_slice())
    });
    let Some(signer) = signer else {
        return SignatureStatus::IssuerNotFound;
    };
    let summary = signer.signable.subject_summary.clone().unwrap_or_default();
    if !is_pq(&cms.sig_alg) && !is_xmss(&cms.sig_alg) && algorithm_for(&cms.sig_alg).is_none() {
        return SignatureStatus::UnsupportedAlgorithm(oid_string(&cms.sig_alg));
    }
    let raw_ok = cms_raw_verify(cms, &signer.signable);
    let openssl_ok = cms_openssl_verify(cms_der, &signer.path);
    if raw_ok && openssl_ok {
        SignatureStatus::Verified {
            issuer_path: signer.path.clone(),
            issuer_summary: summary,
            self_signed: false,
        }
    } else {
        SignatureStatus::Invalid { issuer_path: signer.path.clone(), issuer_summary: summary }
    }
}

/// The raw half of CMS verification: the SignerInfo signature over the
/// message RFC 5652 §5.4 prescribes, plus — when attributes are signed —
/// the `messageDigest` attribute against the digest of the attached content.
fn cms_raw_verify(cms: &x509::CmsSigned, signer: &Signable) -> bool {
    let Some(pubkey) = signer.pubkey.as_deref() else { return false };
    let message: &[u8] = match (&cms.signed_attrs, &cms.econtent) {
        (Some(set), _) => set,
        (None, Some(content)) => content,
        (None, None) => return false, // detached content is not supported
    };
    if !verify_signature(&cms.sig_alg, pubkey, message, &cms.signature) {
        return false;
    }
    // With signed attributes, the content is covered indirectly: the
    // messageDigest attribute must hash the attached eContent.
    if cms.signed_attrs.is_some() {
        let (Some(expected), Some(content)) = (&cms.message_digest, &cms.econtent) else {
            return false;
        };
        let Some(alg) = digest_for(&cms.digest_alg) else { return false };
        if aws_lc_rs::digest::digest(alg, content).as_ref() != expected.as_slice() {
            return false;
        }
    }
    true
}

/// Digest `content` with the CMS `digestAlgorithm` — the recomputed
/// `messageDigest` attribute value re-signing installs. `None` for an
/// unsupported digest algorithm.
pub fn cms_message_digest(digest_alg: &[u64], content: &[u8]) -> Option<Vec<u8>> {
    let alg = digest_for(digest_alg)?;
    Some(aws_lc_rs::digest::digest(alg, content).as_ref().to_vec())
}

/// Map a CMS `digestAlgorithm` OID to the aws-lc-rs digest.
fn digest_for(oid: &[u64]) -> Option<&'static aws_lc_rs::digest::Algorithm> {
    match oid {
        [2, 16, 840, 1, 101, 3, 4, 2, 1] => Some(&aws_lc_rs::digest::SHA256),
        [2, 16, 840, 1, 101, 3, 4, 2, 2] => Some(&aws_lc_rs::digest::SHA384),
        [2, 16, 840, 1, 101, 3, 4, 2, 3] => Some(&aws_lc_rs::digest::SHA512),
        _ => None,
    }
}

/// The OpenSSL half of CMS verification: `CMS_verify` against exactly the
/// identified signer certificate (read from disk), with chain verification
/// disabled and embedded certificates ignored (`NOINTERN`), so the result
/// reflects this signature under that certificate — nothing else.
fn cms_openssl_verify(cms_der: &[u8], signer_path: &Path) -> bool {
    use openssl::cms::{CMSOptions, CmsContentInfo};
    let Ok(raw) = std::fs::read(signer_path) else { return false };
    let Ok((cert_der, _)) = crate::input::load(&raw) else { return false };
    let Ok(cert) = openssl::x509::X509::from_der(&cert_der) else { return false };
    let Ok(mut certs) = openssl::stack::Stack::new() else { return false };
    if certs.push(cert).is_err() {
        return false;
    }
    let Ok(mut cms) = CmsContentInfo::from_der(cms_der) else { return false };
    cms.verify(
        Some(&certs),
        None,
        None,
        None,
        CMSOptions::NOINTERN | CMSOptions::NO_SIGNER_CERT_VERIFY,
    )
    .is_ok()
}

pub fn verify_against(index: &[CaCandidate], signable: &Signable) -> SignatureStatus {
    let candidates = claimed_issuers(index, signable);
    let Some(first) = candidates.first() else {
        return SignatureStatus::IssuerNotFound;
    };
    if !is_pq(&signable.sig_alg)
        && !is_xmss(&signable.sig_alg)
        && algorithm_for(&signable.sig_alg).is_none()
    {
        return SignatureStatus::UnsupportedAlgorithm(oid_string(&signable.sig_alg));
    }
    for candidate in &candidates {
        if verify_signature(&signable.sig_alg, &candidate.pubkey, &signable.tbs, &signable.signature)
        {
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
    verify_signature(&s.sig_alg, pubkey, &s.tbs, &s.signature)
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

/// Extend `relations` with signer→message edges for CMS signed messages: the
/// signer certificate is resolved by the SignerInfo's issuer + serial among
/// `signables` (only certificates can sign), and the edge is colored by
/// whether the signature verifies — exactly like a certificate's issuance
/// edge. No edge when the signer certificate is not present in the tree.
pub fn cms_relations(
    signables: &[x509::SignableFile],
    cms_files: &[x509::CmsFile],
    selected: &Path,
    relations: &mut FileRelations,
) {
    for file in cms_files {
        let (signer_path, verified) = match verify_cms(signables, &file.cms, &file.der) {
            SignatureStatus::Verified { issuer_path, .. } => (issuer_path, true),
            SignatureStatus::Invalid { issuer_path, .. } => (issuer_path, false),
            SignatureStatus::IssuerNotFound | SignatureStatus::UnsupportedAlgorithm(_) => continue,
        };
        if signer_path == file.path {
            continue; // never an arrow from a file to itself
        }
        if file.path == selected {
            relations.signed_by = Some(RelationEdge { other: signer_path.clone(), verified });
        }
        if signer_path == selected {
            relations.signs.push(RelationEdge { other: file.path.clone(), verified });
        }
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

    // ---- CMS signed-message verification -----------------------------------

    /// The committed CMS fixture, parsed, plus its raw DER.
    fn cms_fixture() -> (x509::CmsSigned, Vec<u8>) {
        let der = std::fs::read("testdata/cms_signed.der").unwrap();
        let roots = ber::parse_forest(&der, 0).unwrap();
        let cms = x509::parse_cms_signed(&roots, &der).expect("CMS fixture parses");
        (cms, der)
    }

    #[test]
    fn cms_message_verifies_against_the_scanned_signer() {
        // The signer (keylink/cert_ec.der) is found by issuer + serial in the
        // recursive scan of testdata/, and both verification halves pass.
        let signables = x509::scan_dir_signables(Path::new("testdata"));
        let (cms, der) = cms_fixture();
        match verify_cms(&signables, &cms, &der) {
            SignatureStatus::Verified { issuer_path, issuer_summary, self_signed } => {
                assert!(issuer_path.ends_with("keylink/cert_ec.der"), "{issuer_path:?}");
                assert!(!issuer_summary.is_empty());
                assert!(!self_signed);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn cms_message_with_tampered_signature_is_invalid() {
        let signables = x509::scan_dir_signables(Path::new("testdata"));
        let (mut cms, der) = cms_fixture();
        *cms.signature.last_mut().unwrap() ^= 0x01;
        assert!(matches!(verify_cms(&signables, &cms, &der), SignatureStatus::Invalid { .. }));
    }

    #[test]
    fn cms_message_with_tampered_content_fails_the_digest_check() {
        // The signature over signedAttrs still verifies, but the messageDigest
        // attribute no longer hashes the (tampered) eContent.
        let signables = x509::scan_dir_signables(Path::new("testdata"));
        let (mut cms, der) = cms_fixture();
        cms.econtent.as_mut().unwrap()[0] ^= 0x01;
        assert!(matches!(verify_cms(&signables, &cms, &der), SignatureStatus::Invalid { .. }));
    }

    #[test]
    fn cms_openssl_half_rejects_a_tampered_message() {
        // The in-memory struct stays pristine (the raw half passes); only the
        // DER handed to OpenSSL is tampered — CMS_verify must catch it.
        let signables = x509::scan_dir_signables(Path::new("testdata"));
        let (cms, mut der) = cms_fixture();
        let at = der
            .windows(8)
            .position(|w| w == b"CMS test")
            .expect("payload text in the fixture");
        der[at] ^= 0x01;
        assert!(matches!(verify_cms(&signables, &cms, &der), SignatureStatus::Invalid { .. }));
    }

    #[test]
    fn cms_relations_link_signer_certificate_to_the_message() {
        let signables = x509::scan_dir_signables(Path::new("testdata"));
        let cms_files = x509::scan_dir_cms(Path::new("testdata"));
        let cms_path = Path::new("testdata/cms_signed.der");
        let signer = Path::new("testdata/keylink/cert_ec.der");

        // Selecting the CMS message: an incoming (verified) edge from the signer.
        let mut r = FileRelations::default();
        cms_relations(&signables, &cms_files, cms_path, &mut r);
        let edge = r.signed_by.expect("CMS message shows its signer");
        assert!(edge.other.ends_with("keylink/cert_ec.der"));
        assert!(edge.verified);

        // Selecting the signer certificate: an outgoing edge to the message.
        let mut r = FileRelations::default();
        cms_relations(&signables, &cms_files, signer, &mut r);
        assert!(r.signs.iter().any(|e| e.other == cms_path && e.verified));
    }

    #[test]
    fn cms_relations_are_red_when_the_signature_is_broken() {
        // A CMS file whose signer is present but whose signature does not
        // verify still gets an edge — colored broken (red).
        let signables = x509::scan_dir_signables(Path::new("testdata"));
        let mut cms_files = x509::scan_dir_cms(Path::new("testdata"));
        // Corrupt the message content of every CMS snapshot in place.
        for f in &mut cms_files {
            if let Some(c) = f.cms.econtent.as_mut() {
                c[0] ^= 0x01;
            }
        }
        let cms_path = Path::new("testdata/cms_signed.der");
        let mut r = FileRelations::default();
        cms_relations(&signables, &cms_files, cms_path, &mut r);
        let edge = r.signed_by.expect("a claimed-but-broken signer still gets an edge");
        assert!(!edge.verified, "broken signature → red edge");
    }

    #[test]
    fn cms_relations_absent_without_the_signer() {
        // testdata/chain has no CMS files and not the signer either.
        let signables = x509::scan_dir_signables(Path::new("testdata/chain"));
        let cms_files = x509::scan_dir_cms(Path::new("testdata"));
        let mut r = FileRelations::default();
        cms_relations(&signables, &cms_files, Path::new("testdata/cms_signed.der"), &mut r);
        assert!(r.signed_by.is_none() && r.signs.is_empty());
    }

    #[test]
    fn cms_message_without_its_signer_is_issuer_not_found() {
        // testdata/chain does not contain the signer certificate.
        let signables = x509::scan_dir_signables(Path::new("testdata/chain"));
        let (cms, der) = cms_fixture();
        assert!(matches!(verify_cms(&signables, &cms, &der), SignatureStatus::IssuerNotFound));
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

    /// Build a self-signed certificate for the OpenSSL `algorithm` and confirm
    /// our parser + verifier accept its signature — the real end-to-end path
    /// for a post-quantum signature we did not generate ourselves.
    fn assert_self_signed_pq_verifies(algorithm: &str, tag: &str) {
        if !openssl_available() {
            eprintln!("skipping: openssl not installed");
            return;
        }
        let dir = tmp_dir(tag);
        let key = dir.join("ca.key");
        let cert = dir.join("ca.der");
        run_openssl(&["genpkey", "-algorithm", algorithm, "-out", key.to_str().unwrap()]);
        run_openssl(&[
            "req", "-x509", "-new", "-key", key.to_str().unwrap(),
            "-out", cert.to_str().unwrap(), "-outform", "DER",
            "-days", "365", "-subj", "/CN=PQ Root",
        ]);
        match scan_and_verify(&dir, "ca.der") {
            SignatureStatus::Verified { self_signed, .. } => assert!(self_signed),
            other => panic!("{}: expected Verified, got {}", algorithm, debug_kind(&other)),
        }
        // Flipping a signature byte must break verification.
        let mut bytes = std::fs::read(&cert).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&cert, &bytes).unwrap();
        let roots = ber::parse_forest(&bytes, 0).unwrap();
        if let Some(s) = x509::parse_signable(&roots, &bytes) {
            let index = x509::scan_dir(&dir);
            assert!(
                matches!(verify_against(&index, &s), SignatureStatus::Invalid { .. }),
                "{}: tampered signature must not verify",
                algorithm
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ml_dsa_self_signed_certificate_verifies() {
        assert_self_signed_pq_verifies("ML-DSA-44", "mldsa-cert");
    }

    #[test]
    fn slh_dsa_self_signed_certificate_verifies() {
        // A fast (`f`) SLH-DSA set keeps signing time reasonable.
        assert_self_signed_pq_verifies("SLH-DSA-SHA2-128f", "slhdsa-cert");
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
    fn sign_produces_a_signature_the_verifier_accepts() {
        use crate::{ber, input};
        // The self-signed EC certificate is verified by its own key, so
        // signing its tbs with that key must produce an acceptable signature.
        let (cert_der, _) = input::load(&std::fs::read("testdata/keylink/cert_ec.der").unwrap()).unwrap();
        let cert_roots = ber::parse_forest(&cert_der, 0).unwrap();
        let signable = x509::parse_signable(&cert_roots, &cert_der).unwrap();
        let (key_der, _) = input::load(&std::fs::read("testdata/keylink/key_ec_pkcs8.der").unwrap()).unwrap();

        assert!(signing_supported(&signable.sig_alg));
        let sig = sign(&signable.sig_alg, &key_der, &signable.tbs).expect("signing succeeds");

        let alg = algorithm_for(&signable.sig_alg).unwrap();
        let pubkey = signature::UnparsedPublicKey::new(alg, signable.pubkey.as_ref().unwrap());
        assert!(pubkey.verify(&signable.tbs, &sig).is_ok(), "new signature must verify");
        assert!(pubkey.verify(b"tampered", &sig).is_err(), "signature is bound to the tbs");
    }

    #[test]
    fn sign_with_a_sec1_key_after_wrapping_to_pkcs8() {
        use crate::{ber, input};
        let (cert_der, _) = input::load(&std::fs::read("testdata/keylink/cert_ec.der").unwrap()).unwrap();
        let signable =
            x509::parse_signable(&ber::parse_forest(&cert_der, 0).unwrap(), &cert_der).unwrap();
        // The bare SEC1 form of the same key, normalized to PKCS#8, signs and
        // verifies just like the PKCS#8 file.
        let (sec1_der, _) = input::load(&std::fs::read("testdata/keylink/key_ec_sec1.der").unwrap()).unwrap();
        let pkcs8 = x509::to_pkcs8_der(&ber::parse_forest(&sec1_der, 0).unwrap())
            .expect("SEC1 wraps to PKCS#8");
        let sig = sign(&signable.sig_alg, &pkcs8, &signable.tbs).unwrap();
        let alg = algorithm_for(&signable.sig_alg).unwrap();
        let pubkey = signature::UnparsedPublicKey::new(alg, signable.pubkey.as_ref().unwrap());
        assert!(pubkey.verify(&signable.tbs, &sig).is_ok());
    }

    #[test]
    fn sign_rejects_a_key_of_the_wrong_type() {
        use crate::{ber, input};
        let (cert_der, _) = input::load(&std::fs::read("testdata/keylink/cert_ec.der").unwrap()).unwrap();
        let cert_roots = ber::parse_forest(&cert_der, 0).unwrap();
        let signable = x509::parse_signable(&cert_roots, &cert_der).unwrap();
        // An RSA key cannot produce an ECDSA signature.
        let (rsa_key, _) = input::load(&std::fs::read("testdata/keylink/key_rsa_pkcs8.der").unwrap()).unwrap();
        assert!(sign(&signable.sig_alg, &rsa_key, &signable.tbs).is_err());
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
