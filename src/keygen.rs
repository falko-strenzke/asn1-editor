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

//! Private-key generation for the public-key modification flow (`app.rs`).
//!
//! Keys are generated with the `openssl` crate (already a dependency for
//! path validation and the PKCS#12 MAC): OpenSSL produces the private key,
//! its plaintext PKCS#8 `PrivateKeyInfo` (fed to `verify::sign`, which loads
//! it with `aws-lc-rs`), its `SubjectPublicKeyInfo` (spliced into the
//! certificate being rekeyed), and — for a password-protected key — an
//! encrypted PKCS#8 in the same PBES2/PBKDF2/AES-256-CBC form our own
//! `pkcs8.rs` can later decrypt.
//!
//! The supported algorithms are those `verify` can both *sign* with and
//! *verify*: classically, RSA with SHA-256 (2048/4096-bit keys), ECDSA on
//! P-256 (SHA-256) and P-384 (SHA-384), and Ed25519; and, post-quantum, the
//! FIPS 204 ML-DSA (44/65/87) and FIPS 205 SLH-DSA (all twelve parameter sets)
//! families. The post-quantum keys are generated with OpenSSL by algorithm
//! name (`EVP_PKEY_CTX_new_from_name`, via raw `openssl-sys` FFI, since the
//! safe crate lacks SLH-DSA), then handled by the same PKCS#8/SPKI code paths.

use std::ffi::CString;
use std::ptr;

use foreign_types::ForeignType;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::symm::Cipher;

use crate::ber::{self, Class, Node, TAG_NULL, TAG_OID, TAG_SEQUENCE};

/// A signature algorithm the program can generate a key for and sign with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    RsaSha256_2048,
    RsaSha256_4096,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
    /// A post-quantum algorithm, identified by its entry in [`PQ`].
    Pq(usize),
}

/// Static description of one post-quantum algorithm: its full X.509
/// `signatureAlgorithm` OID (under `2.16.840.1.101.3.4.3`), its OpenSSL/FIPS
/// name (used both as the display label and the `EVP_PKEY_CTX_new_from_name`
/// string), and a filename token.
struct PqDesc {
    oid: &'static [u64],
    name: &'static str,
    short: &'static str,
}

/// The post-quantum algorithms, indexed by `KeyAlgorithm::Pq(i)`: ML-DSA
/// (FIPS 204) then SLH-DSA (FIPS 205), matching the NIST OID order.
const PQ: &[PqDesc] = &[
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 17], name: "ML-DSA-44", short: "mldsa44" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 18], name: "ML-DSA-65", short: "mldsa65" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 19], name: "ML-DSA-87", short: "mldsa87" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 20], name: "SLH-DSA-SHA2-128s", short: "slhdsa-sha2-128s" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 21], name: "SLH-DSA-SHA2-128f", short: "slhdsa-sha2-128f" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 22], name: "SLH-DSA-SHA2-192s", short: "slhdsa-sha2-192s" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 23], name: "SLH-DSA-SHA2-192f", short: "slhdsa-sha2-192f" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 24], name: "SLH-DSA-SHA2-256s", short: "slhdsa-sha2-256s" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 25], name: "SLH-DSA-SHA2-256f", short: "slhdsa-sha2-256f" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 26], name: "SLH-DSA-SHAKE-128s", short: "slhdsa-shake-128s" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 27], name: "SLH-DSA-SHAKE-128f", short: "slhdsa-shake-128f" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 28], name: "SLH-DSA-SHAKE-192s", short: "slhdsa-shake-192s" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 29], name: "SLH-DSA-SHAKE-192f", short: "slhdsa-shake-192f" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 30], name: "SLH-DSA-SHAKE-256s", short: "slhdsa-shake-256s" },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 31], name: "SLH-DSA-SHAKE-256f", short: "slhdsa-shake-256f" },
];

/// The algorithms offered in the public-key modification dialog, in display
/// order: classical first, then the post-quantum families.
pub const ALL: &[KeyAlgorithm] = &[
    KeyAlgorithm::EcdsaP256,
    KeyAlgorithm::EcdsaP384,
    KeyAlgorithm::Ed25519,
    KeyAlgorithm::RsaSha256_2048,
    KeyAlgorithm::RsaSha256_4096,
    KeyAlgorithm::Pq(0),
    KeyAlgorithm::Pq(1),
    KeyAlgorithm::Pq(2),
    KeyAlgorithm::Pq(3),
    KeyAlgorithm::Pq(4),
    KeyAlgorithm::Pq(5),
    KeyAlgorithm::Pq(6),
    KeyAlgorithm::Pq(7),
    KeyAlgorithm::Pq(8),
    KeyAlgorithm::Pq(9),
    KeyAlgorithm::Pq(10),
    KeyAlgorithm::Pq(11),
    KeyAlgorithm::Pq(12),
    KeyAlgorithm::Pq(13),
    KeyAlgorithm::Pq(14),
];

// Signature-algorithm OIDs (the `signatureAlgorithm` of a certificate).
const SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const ECDSA_WITH_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
const ED25519_OID: &[u64] = &[1, 3, 101, 112];

impl KeyAlgorithm {
    fn pq(self) -> Option<&'static PqDesc> {
        match self {
            KeyAlgorithm::Pq(i) => PQ.get(i),
            _ => None,
        }
    }

    /// Human-readable label for the dialog list.
    pub fn label(self) -> &'static str {
        match self {
            KeyAlgorithm::EcdsaP256 => "ECDSA P-256 (SHA-256)",
            KeyAlgorithm::EcdsaP384 => "ECDSA P-384 (SHA-384)",
            KeyAlgorithm::Ed25519 => "Ed25519",
            KeyAlgorithm::RsaSha256_2048 => "RSA-2048 (SHA-256)",
            KeyAlgorithm::RsaSha256_4096 => "RSA-4096 (SHA-256)",
            KeyAlgorithm::Pq(_) => self.pq().map(|d| d.name).unwrap_or("post-quantum"),
        }
    }

    /// Short token used to derive the default key file name.
    pub fn short_name(self) -> &'static str {
        match self {
            KeyAlgorithm::EcdsaP256 => "p256",
            KeyAlgorithm::EcdsaP384 => "p384",
            KeyAlgorithm::Ed25519 => "ed25519",
            KeyAlgorithm::RsaSha256_2048 => "rsa2048",
            KeyAlgorithm::RsaSha256_4096 => "rsa4096",
            KeyAlgorithm::Pq(_) => self.pq().map(|d| d.short).unwrap_or("pq"),
        }
    }

    /// The X.509 `signatureAlgorithm` OID arcs for signatures made with a key
    /// of this algorithm.
    pub fn sig_alg_oid(self) -> &'static [u64] {
        match self {
            KeyAlgorithm::EcdsaP256 => ECDSA_WITH_SHA256,
            KeyAlgorithm::EcdsaP384 => ECDSA_WITH_SHA384,
            KeyAlgorithm::Ed25519 => ED25519_OID,
            KeyAlgorithm::RsaSha256_2048 | KeyAlgorithm::RsaSha256_4096 => SHA256_WITH_RSA,
            KeyAlgorithm::Pq(_) => self.pq().map(|d| d.oid).unwrap_or(&[]),
        }
    }

    /// The DER of the `signatureAlgorithm` / `signature` `AlgorithmIdentifier`
    /// to install in a certificate signed with this key: `SEQUENCE { OID }`
    /// for ECDSA, Ed25519 and the post-quantum algorithms (no parameters),
    /// `SEQUENCE { OID, NULL }` for RSA PKCS#1.
    pub fn sig_alg_identifier_der(self) -> Vec<u8> {
        let dotted =
            self.sig_alg_oid().iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".");
        let oid = universal(TAG_OID, false, ber::encode_oid(&dotted).expect("static OID"));
        let mut children = vec![oid];
        let rsa = matches!(self, KeyAlgorithm::RsaSha256_2048 | KeyAlgorithm::RsaSha256_4096);
        if rsa {
            children.push(universal(TAG_NULL, false, Vec::new()));
        }
        ber::encode_node(&universal_seq(children))
    }

    fn generate_pkey(self) -> Result<PKey<Private>, String> {
        let crypto = |e: openssl::error::ErrorStack| format!("key generation failed: {}", e);
        match self {
            KeyAlgorithm::Ed25519 => PKey::generate_ed25519().map_err(crypto),
            KeyAlgorithm::EcdsaP256 => ec_key(Nid::X9_62_PRIME256V1).map_err(crypto),
            KeyAlgorithm::EcdsaP384 => ec_key(Nid::SECP384R1).map_err(crypto),
            KeyAlgorithm::RsaSha256_2048 => rsa_key(2048).map_err(crypto),
            KeyAlgorithm::RsaSha256_4096 => rsa_key(4096).map_err(crypto),
            KeyAlgorithm::Pq(_) => {
                let name = self.pq().ok_or("unknown post-quantum algorithm")?.name;
                generate_by_name(name)
            }
        }
    }
}

fn ec_key(curve: Nid) -> Result<PKey<Private>, openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(curve)?;
    PKey::from_ec_key(EcKey::generate(&group)?)
}

fn rsa_key(bits: u32) -> Result<PKey<Private>, openssl::error::ErrorStack> {
    PKey::from_rsa(Rsa::generate(bits)?)
}

/// Generate a key for the OpenSSL algorithm `name` (e.g. `"ML-DSA-65"`,
/// `"SLH-DSA-SHA2-128s"`). The safe `openssl` crate has no by-name key
/// generation covering SLH-DSA, so this drops to `openssl-sys`:
/// `EVP_PKEY_CTX_new_from_name` → `EVP_PKEY_keygen_init` → `EVP_PKEY_keygen`,
/// wrapping the resulting `EVP_PKEY` back into the safe `PKey` type.
fn generate_by_name(name: &str) -> Result<PKey<Private>, String> {
    let cname = CString::new(name).map_err(|_| "invalid algorithm name".to_string())?;
    // SAFETY: pointers are checked before use; the EVP_PKEY_CTX is freed by the
    // guard on every path, and a non-null EVP_PKEY is handed to PKey (which owns
    // and frees it). Uses the same openssl-sys the `openssl` crate is built on.
    unsafe {
        let ctx =
            openssl_sys::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), cname.as_ptr(), ptr::null());
        if ctx.is_null() {
            return Err(format!("no OpenSSL provider for {}", name));
        }
        struct CtxGuard(*mut openssl_sys::EVP_PKEY_CTX);
        impl Drop for CtxGuard {
            fn drop(&mut self) {
                unsafe { openssl_sys::EVP_PKEY_CTX_free(self.0) }
            }
        }
        let _guard = CtxGuard(ctx);
        if openssl_sys::EVP_PKEY_keygen_init(ctx) <= 0 {
            return Err(format!("{}: key generation could not be initialized", name));
        }
        let mut pkey: *mut openssl_sys::EVP_PKEY = ptr::null_mut();
        if openssl_sys::EVP_PKEY_keygen(ctx, &mut pkey) <= 0 || pkey.is_null() {
            return Err(format!("{}: key generation failed", name));
        }
        Ok(PKey::from_ptr(pkey))
    }
}

/// A freshly generated key pair, ready to install and to sign with.
pub struct GeneratedKey {
    /// Plaintext PKCS#8 `PrivateKeyInfo` DER — the signing input for
    /// `verify::sign` and the source for the encrypted form.
    pub pkcs8: Vec<u8>,
    /// `SubjectPublicKeyInfo` DER to splice into the rekeyed certificate.
    pub spki: Vec<u8>,
}

impl GeneratedKey {
    /// The DER to write to the key file for `password`: the plaintext PKCS#8
    /// when `password` is empty, otherwise an encrypted `EncryptedPrivateKeyInfo`
    /// (PBES2/PBKDF2/AES-256-CBC — the scheme `pkcs8.rs` decrypts).
    pub fn key_file_der(&self, password: &[u8]) -> Result<Vec<u8>, String> {
        if password.is_empty() {
            return Ok(self.pkcs8.clone());
        }
        let crypto = |e: openssl::error::ErrorStack| format!("key encryption failed: {}", e);
        let pkey = PKey::private_key_from_pkcs8(&self.pkcs8).map_err(crypto)?;
        pkey.private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), password).map_err(crypto)
    }
}

/// Generate a new private key for `alg`.
pub fn generate(alg: KeyAlgorithm) -> Result<GeneratedKey, String> {
    let crypto = |e: openssl::error::ErrorStack| format!("key generation failed: {}", e);
    let pkey = alg.generate_pkey()?;
    let pkcs8 = pkey.private_key_to_pkcs8().map_err(crypto)?;
    let spki = pkey.public_key_to_der().map_err(crypto)?;
    Ok(GeneratedKey { pkcs8, spki })
}

fn universal(tag: u32, constructed: bool, value: Vec<u8>) -> Node {
    Node {
        class: Class::Universal,
        tag,
        constructed,
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
    let mut node = universal(TAG_SEQUENCE, true, Vec::new());
    node.children = children;
    node
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify;

    fn spki_pubkey(spki: &[u8]) -> Vec<u8> {
        let roots = ber::parse_forest(spki, 0).unwrap();
        let bit = roots[0].children.last().unwrap();
        bit.value[1..].to_vec() // strip the unused-bits octet
    }

    fn spki_alg_oid(spki: &[u8]) -> Vec<u64> {
        let roots = ber::parse_forest(spki, 0).unwrap();
        ber::oid_arcs(&roots[0].children[0].children[0].value).unwrap()
    }

    /// SLH-DSA "small" (`s`) parameter sets have deliberately slow signing;
    /// the signing round-trip below skips them to keep the suite fast (their
    /// key generation is still exercised by the keygen test).
    fn slow_to_sign(alg: KeyAlgorithm) -> bool {
        alg.pq().is_some_and(|d| d.name.starts_with("SLH-DSA") && d.name.ends_with('s'))
    }

    #[test]
    fn every_algorithm_generates_a_key_and_pq_spki_carries_its_oid() {
        for &alg in ALL {
            let key = generate(alg).unwrap_or_else(|e| panic!("{}: {}", alg.label(), e));
            assert!(!key.pkcs8.is_empty() && !key.spki.is_empty(), "{}", alg.label());
            // A post-quantum SPKI's AlgorithmIdentifier is the signature OID.
            if alg.pq().is_some() {
                assert_eq!(spki_alg_oid(&key.spki), alg.sig_alg_oid(), "{}", alg.label());
            }
        }
    }

    #[test]
    fn signing_round_trips_for_classical_ml_dsa_and_fast_slh_dsa() {
        let tbs = b"a message standing in for a tbsCertificate";
        for &alg in ALL.iter().filter(|&&a| !slow_to_sign(a)) {
            let key = generate(alg).unwrap_or_else(|e| panic!("{}: {}", alg.label(), e));
            let sig = verify::sign(alg.sig_alg_oid(), &key.pkcs8, tbs)
                .unwrap_or_else(|e| panic!("{}: sign: {}", alg.label(), e));
            assert!(
                verify::verify_signature(alg.sig_alg_oid(), &spki_pubkey(&key.spki), tbs, &sig),
                "{}: signature must verify under the generated SPKI",
                alg.label()
            );
            assert!(
                !verify::verify_signature(alg.sig_alg_oid(), &spki_pubkey(&key.spki), b"x", &sig),
                "{}: a tampered message must not verify",
                alg.label()
            );
        }
    }

    #[test]
    fn empty_password_yields_plaintext_pkcs8() {
        let key = generate(KeyAlgorithm::EcdsaP256).unwrap();
        assert_eq!(key.key_file_der(b"").unwrap(), key.pkcs8);
    }

    #[test]
    fn a_password_yields_an_encrypted_pkcs8_our_module_decrypts() {
        let key = generate(KeyAlgorithm::EcdsaP256).unwrap();
        let enc = key.key_file_der(b"secret").unwrap();
        assert_ne!(enc, key.pkcs8);
        let roots = ber::parse_forest(&enc, 0).unwrap();
        let parsed = crate::pkcs8::parse(&roots).unwrap().expect("EncryptedPrivateKeyInfo");
        assert_eq!(parsed.decrypt(b"secret").unwrap(), key.pkcs8);
        assert!(parsed.decrypt(b"wrong").is_err());
    }

    #[test]
    fn a_post_quantum_key_encrypts_and_our_module_decrypts_it() {
        // ML-DSA-44 generates and signs quickly; the encrypted PKCS#8 is a
        // standard PBES2 blob our pkcs8 module reads back.
        let key = generate(KeyAlgorithm::Pq(0)).unwrap();
        let enc = key.key_file_der(b"pqpw").unwrap();
        assert_ne!(enc, key.pkcs8);
        let roots = ber::parse_forest(&enc, 0).unwrap();
        let parsed = crate::pkcs8::parse(&roots).unwrap().expect("EncryptedPrivateKeyInfo");
        assert_eq!(parsed.decrypt(b"pqpw").unwrap(), key.pkcs8);
    }

    #[test]
    fn signature_algorithm_identifier_shapes_are_correct() {
        // ECDSA / Ed25519 / PQ: SEQUENCE { OID } (no params). RSA: SEQUENCE { OID, NULL }.
        for (alg, children) in [
            (KeyAlgorithm::EcdsaP256, 1),
            (KeyAlgorithm::Ed25519, 1),
            (KeyAlgorithm::Pq(1), 1),  // ML-DSA-65
            (KeyAlgorithm::Pq(9), 1),  // SLH-DSA-SHAKE-128s
            (KeyAlgorithm::RsaSha256_2048, 2),
        ] {
            let der = alg.sig_alg_identifier_der();
            let roots = ber::parse_forest(&der, 0).unwrap();
            assert!(roots[0].is_universal(TAG_SEQUENCE));
            assert_eq!(roots[0].children.len(), children, "{}", alg.label());
            assert!(roots[0].children[0].is_universal(TAG_OID));
        }
    }
}
