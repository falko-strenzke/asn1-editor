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
//! The supported algorithms are exactly those `verify` can both *sign* with
//! and *verify*: RSA with SHA-256 (2048/4096-bit keys), ECDSA on P-256
//! (SHA-256) and P-384 (SHA-384), and Ed25519.

use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
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
}

/// The algorithms offered in the public-key modification dialog, in display
/// order.
pub const ALL: &[KeyAlgorithm] = &[
    KeyAlgorithm::EcdsaP256,
    KeyAlgorithm::EcdsaP384,
    KeyAlgorithm::Ed25519,
    KeyAlgorithm::RsaSha256_2048,
    KeyAlgorithm::RsaSha256_4096,
];

// Signature-algorithm OIDs (the `signatureAlgorithm` of a certificate).
const SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const ECDSA_WITH_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
const ED25519_OID: &[u64] = &[1, 3, 101, 112];

impl KeyAlgorithm {
    /// Human-readable label for the dialog list.
    pub fn label(self) -> &'static str {
        match self {
            KeyAlgorithm::EcdsaP256 => "ECDSA P-256 (SHA-256)",
            KeyAlgorithm::EcdsaP384 => "ECDSA P-384 (SHA-384)",
            KeyAlgorithm::Ed25519 => "Ed25519",
            KeyAlgorithm::RsaSha256_2048 => "RSA-2048 (SHA-256)",
            KeyAlgorithm::RsaSha256_4096 => "RSA-4096 (SHA-256)",
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
        }
    }

    /// The DER of the `signatureAlgorithm` / `signature` `AlgorithmIdentifier`
    /// to install in a certificate signed with this key: `SEQUENCE { OID }`
    /// for ECDSA and Ed25519 (no parameters), `SEQUENCE { OID, NULL }` for
    /// RSA PKCS#1.
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

    fn generate_pkey(self) -> Result<PKey<openssl::pkey::Private>, String> {
        let crypto = |e: openssl::error::ErrorStack| format!("key generation failed: {}", e);
        match self {
            KeyAlgorithm::Ed25519 => PKey::generate_ed25519().map_err(crypto),
            KeyAlgorithm::EcdsaP256 => ec_key(Nid::X9_62_PRIME256V1).map_err(crypto),
            KeyAlgorithm::EcdsaP384 => ec_key(Nid::SECP384R1).map_err(crypto),
            KeyAlgorithm::RsaSha256_2048 => rsa_key(2048).map_err(crypto),
            KeyAlgorithm::RsaSha256_4096 => rsa_key(4096).map_err(crypto),
        }
    }
}

fn ec_key(curve: Nid) -> Result<PKey<openssl::pkey::Private>, openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(curve)?;
    PKey::from_ec_key(EcKey::generate(&group)?)
}

fn rsa_key(bits: u32) -> Result<PKey<openssl::pkey::Private>, openssl::error::ErrorStack> {
    PKey::from_rsa(Rsa::generate(bits)?)
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

    #[test]
    fn every_algorithm_generates_a_key_that_signs_and_verifies() {
        let tbs = b"a message standing in for a tbsCertificate";
        for &alg in ALL {
            let key = generate(alg).unwrap_or_else(|e| panic!("{}: {}", alg.label(), e));
            let sig = verify::sign(alg.sig_alg_oid(), &key.pkcs8, tbs)
                .unwrap_or_else(|e| panic!("{}: sign: {}", alg.label(), e));
            assert!(
                verify::verify_signature(alg.sig_alg_oid(), &spki_pubkey(&key.spki), tbs, &sig),
                "{}: signature must verify under the generated SPKI",
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
    fn signature_algorithm_identifier_shapes_are_correct() {
        // ECDSA / Ed25519: SEQUENCE { OID } (no params). RSA: SEQUENCE { OID, NULL }.
        for (alg, children) in [
            (KeyAlgorithm::EcdsaP256, 1),
            (KeyAlgorithm::Ed25519, 1),
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
