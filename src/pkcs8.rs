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

//! Structural decoding and password decryption of `EncryptedPrivateKeyInfo`
//! (RFC 5958 §3 / RFC 5208). The structural part walks `ber::Node`
//! positionally, like `x509.rs`; `decrypt` is (with `verify.rs`) one of the
//! two modules that use `aws-lc-rs`.
//!
//! Supported scheme: PBES2 (`1.2.840.113549.1.5.13`) with a PBKDF2
//! (`…1.5.12`, PRF HMAC-SHA1/256/384/512) key-derivation and an
//! AES-128/256-CBC encryption scheme. Anything else is reported as
//! unsupported rather than mishandled.

use std::num::NonZeroU32;

use aws_lc_rs::cipher::{
    DecryptingKey, DecryptionContext, EncryptionContext, PaddedBlockEncryptingKey,
    UnboundCipherKey, AES_128, AES_256,
};
use aws_lc_rs::iv::{FixedLength, IV_LEN_128_BIT};
use aws_lc_rs::pbkdf2;

use crate::ber::{self, Node, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE};

const OID_PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
const OID_PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
const OID_HMAC_SHA1: &[u64] = &[1, 2, 840, 113549, 2, 7];
const OID_HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
const OID_HMAC_SHA384: &[u64] = &[1, 2, 840, 113549, 2, 10];
const OID_HMAC_SHA512: &[u64] = &[1, 2, 840, 113549, 2, 11];
const OID_AES128_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 2];
const OID_AES256_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];

const AES_BLOCK: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prf {
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl Prf {
    fn algorithm(self) -> pbkdf2::Algorithm {
        match self {
            Prf::HmacSha1 => pbkdf2::PBKDF2_HMAC_SHA1,
            Prf::HmacSha256 => pbkdf2::PBKDF2_HMAC_SHA256,
            Prf::HmacSha384 => pbkdf2::PBKDF2_HMAC_SHA384,
            Prf::HmacSha512 => pbkdf2::PBKDF2_HMAC_SHA512,
        }
    }
}

/// A decoded `EncryptedPrivateKeyInfo` using a supported PBES2 scheme,
/// ready to decrypt with a password.
pub struct EncryptedPrivateKey {
    /// Tree path of the `encryptedData` OCTET STRING node (always `[0, 1]`):
    /// the node whose decrypted content the UI reveals.
    pub encrypted_path: Vec<usize>,
    /// Tree path of the AES-CBC IV OCTET STRING.
    pub iv_path: Vec<usize>,
    salt: Vec<u8>,
    iterations: u32,
    prf: Prf,
    key_len: usize,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Try to decode `roots` as `EncryptedPrivateKeyInfo`.
///
/// * `Ok(None)` — not an encrypted private key at all (the common case).
/// * `Err(msg)` — it *is* an `EncryptedPrivateKeyInfo`, but uses a scheme
///   this tool doesn't implement; `msg` explains what.
/// * `Ok(Some(_))` — a supported PBES2 encrypted key ready to `decrypt`.
pub fn parse(roots: &[Node]) -> Result<Option<EncryptedPrivateKey>, String> {
    // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm
    //   AlgorithmIdentifier, encryptedData OCTET STRING }
    let Some(root) = roots.first() else { return Ok(None) };
    if roots.len() != 1 || !root.constructed || !root.is_universal(TAG_SEQUENCE) || root.children.len() != 2 {
        return Ok(None);
    }
    let alg = &root.children[0];
    let enc_data = &root.children[1];
    if !alg.constructed || !alg.is_universal(TAG_SEQUENCE) || alg.children.is_empty() {
        return Ok(None);
    }
    if enc_data.constructed || !enc_data.is_universal(TAG_OCTET_STRING) {
        return Ok(None);
    }
    // encryptionAlgorithm.algorithm must be PBES2 for this to be an
    // encrypted key we recognize at all.
    let Some(alg_oid) = oid_of(&alg.children[0]) else { return Ok(None) };
    if alg_oid != OID_PBES2 {
        // Some other encryption; report it as an (unsupported) encrypted key.
        return Err(format!("unsupported key encryption scheme (OID {})", oid_str(&alg_oid)));
    }

    // From here on we know it's an encrypted key; unsupported specifics are
    // errors, not `None`.
    let params = alg.children.get(1).ok_or("PBES2: missing parameters")?;
    if !params.constructed || !params.is_universal(TAG_SEQUENCE) || params.children.len() != 2 {
        return Err("PBES2: malformed parameters".to_string());
    }
    let (salt, iterations, prf, kdf_key_len) = parse_pbkdf2(&params.children[0])?;
    let (key_len, iv) = parse_scheme(&params.children[1])?;
    let key_len = kdf_key_len.unwrap_or(key_len);

    Ok(Some(EncryptedPrivateKey {
        encrypted_path: vec![0, 1],
        iv_path: vec![0, 0, 1, 1, 1],
        salt,
        iterations,
        prf,
        key_len,
        iv,
        ciphertext: enc_data.value.clone(),
    }))
}

/// PBKDF2-params: SEQUENCE { salt OCTET STRING, iterationCount INTEGER,
/// keyLength INTEGER OPTIONAL, prf AlgorithmIdentifier OPTIONAL }.
fn parse_pbkdf2(kdf: &Node) -> Result<(Vec<u8>, u32, Prf, Option<usize>), String> {
    if !kdf.constructed || !kdf.is_universal(TAG_SEQUENCE) || kdf.children.len() < 2 {
        return Err("PBES2: malformed keyDerivationFunc".to_string());
    }
    let Some(kdf_oid) = oid_of(&kdf.children[0]) else {
        return Err("PBES2: malformed keyDerivationFunc".to_string());
    };
    if kdf_oid != OID_PBKDF2 {
        return Err(format!("unsupported key-derivation function (OID {})", oid_str(&kdf_oid)));
    }
    let p = &kdf.children[1];
    if !p.constructed || !p.is_universal(TAG_SEQUENCE) || p.children.len() < 2 {
        return Err("PBES2: malformed PBKDF2 parameters".to_string());
    }
    let salt_node = &p.children[0];
    if salt_node.constructed || !salt_node.is_universal(TAG_OCTET_STRING) {
        return Err("PBES2: PBKDF2 salt must be an OCTET STRING".to_string());
    }
    let salt = salt_node.value.clone();
    let iter_node = &p.children[1];
    if iter_node.constructed || !iter_node.is_universal(TAG_INTEGER) {
        return Err("PBES2: PBKDF2 iterationCount must be an INTEGER".to_string());
    }
    let iterations = ber::decode_integer(&iter_node.value)
        .filter(|&i| i >= 1)
        .and_then(|i| u32::try_from(i).ok())
        .ok_or("PBES2: invalid PBKDF2 iterationCount")?;

    // Optional keyLength INTEGER and prf AlgorithmIdentifier, in order.
    let mut key_len = None;
    let mut prf = Prf::HmacSha1; // RFC 8018 default
    for extra in &p.children[2..] {
        if !extra.constructed && extra.is_universal(TAG_INTEGER) {
            key_len = ber::decode_integer(&extra.value)
                .and_then(|i| usize::try_from(i).ok());
        } else if extra.constructed && extra.is_universal(TAG_SEQUENCE) {
            prf = parse_prf(extra)?;
        }
    }
    Ok((salt, iterations, prf, key_len))
}

fn parse_prf(alg: &Node) -> Result<Prf, String> {
    let Some(oid) = alg.children.first().and_then(oid_of) else {
        return Err("PBES2: malformed PBKDF2 PRF".to_string());
    };
    match oid.as_slice() {
        OID_HMAC_SHA1 => Ok(Prf::HmacSha1),
        OID_HMAC_SHA256 => Ok(Prf::HmacSha256),
        OID_HMAC_SHA384 => Ok(Prf::HmacSha384),
        OID_HMAC_SHA512 => Ok(Prf::HmacSha512),
        _ => Err(format!("unsupported PBKDF2 PRF (OID {})", oid_str(&oid))),
    }
}

/// encryptionScheme: SEQUENCE { algorithm OID (aes-CBC), IV OCTET STRING }.
/// Returns the default key length for the cipher and the IV.
fn parse_scheme(scheme: &Node) -> Result<(usize, Vec<u8>), String> {
    if !scheme.constructed || !scheme.is_universal(TAG_SEQUENCE) || scheme.children.len() != 2 {
        return Err("PBES2: malformed encryptionScheme".to_string());
    }
    let Some(oid) = oid_of(&scheme.children[0]) else {
        return Err("PBES2: malformed encryptionScheme".to_string());
    };
    let key_len = match oid.as_slice() {
        OID_AES128_CBC => 16,
        OID_AES256_CBC => 32,
        _ => return Err(format!("unsupported encryption scheme (OID {})", oid_str(&oid))),
    };
    let iv_node = &scheme.children[1];
    if iv_node.constructed || !iv_node.is_universal(TAG_OCTET_STRING) {
        return Err("PBES2: cipher IV must be an OCTET STRING".to_string());
    }
    if iv_node.value.len() != AES_BLOCK {
        return Err("PBES2: cipher IV must be 16 bytes".to_string());
    }
    Ok((key_len, iv_node.value.clone()))
}

impl EncryptedPrivateKey {
    fn derived_key(&self, password: &[u8]) -> Result<Vec<u8>, String> {
        let iterations = NonZeroU32::new(self.iterations)
            .ok_or("PBKDF2 iteration count must be positive")?;
        let mut key = vec![0u8; self.key_len];
        pbkdf2::derive(self.prf.algorithm(), iterations, &self.salt, password, &mut key);
        Ok(key)
    }

    /// Derive the key with PBKDF2, AES-CBC decrypt, strip PKCS#7 padding,
    /// and confirm the result is a single ASN.1 SEQUENCE (a
    /// `PrivateKeyInfo`). A wrong password almost always shows up as bad
    /// padding; the ASN.1 check catches the rare case where random
    /// plaintext happens to end in valid padding.
    pub fn decrypt(&self, password: &[u8]) -> Result<Vec<u8>, String> {
        if self.ciphertext.is_empty() || !self.ciphertext.len().is_multiple_of(AES_BLOCK) {
            return Err("ciphertext length is not a whole number of AES blocks".to_string());
        }
        let key = self.derived_key(password)?;

        let cipher_alg = if self.key_len == 16 { &AES_128 } else { &AES_256 };
        let unbound = UnboundCipherKey::new(cipher_alg, &key)
            .map_err(|_| "invalid derived key".to_string())?;
        let decrypting = DecryptingKey::cbc(unbound).map_err(|_| "cipher init failed".to_string())?;
        let iv: [u8; IV_LEN_128_BIT] =
            self.iv.clone().try_into().map_err(|_| "bad IV length".to_string())?;
        let context = DecryptionContext::Iv128(FixedLength::from(iv));

        let mut buf = self.ciphertext.clone();
        let plain = decrypting
            .decrypt(&mut buf, context)
            .map_err(|_| "decryption failed".to_string())?;
        let plain = strip_pkcs7(plain)?;

        // Wrong-password sanity check: a real PrivateKeyInfo is one SEQUENCE.
        match ber::parse_forest(plain, 0) {
            Ok(roots) if roots.len() == 1 && roots[0].is_universal(TAG_SEQUENCE) => {
                Ok(plain.to_vec())
            }
            _ => Err("decryption failed (wrong password?)".to_string()),
        }
    }

    /// Encrypt a modified `PrivateKeyInfo` with the original PBKDF2
    /// parameters and a fresh AES-CBC IV. The caller stores both returned
    /// values in the outer `EncryptedPrivateKeyInfo` tree.
    pub fn encrypt(&self, password: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.encrypt_with_context(password, plaintext, None)
    }

    /// Encrypt using the IV already stored in the container. This primarily
    /// supports synchronized editing/tests where only `encryptedData` is
    /// replaced and the PBES2 parameters remain unchanged.
    pub fn encrypt_with_current_iv(
        &self,
        password: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.encrypt_with_context(password, plaintext, Some(&self.iv))
            .map(|(ciphertext, _)| ciphertext)
    }

    fn encrypt_with_context(
        &self,
        password: &[u8],
        plaintext: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        // Refuse to turn arbitrary bytes into an object that claims to be a
        // PKCS#8 private key. Tree edits normally guarantee this already;
        // this also protects whole-content edits.
        match ber::parse_forest(plaintext, 0) {
            Ok(roots) if roots.len() == 1 && roots[0].is_universal(TAG_SEQUENCE) => {}
            _ => return Err("decrypted content must be one ASN.1 SEQUENCE".to_string()),
        }

        let key = self.derived_key(password)?;
        let cipher_alg = if self.key_len == 16 { &AES_128 } else { &AES_256 };
        let unbound = UnboundCipherKey::new(cipher_alg, &key)
            .map_err(|_| "invalid derived key".to_string())?;
        let encrypting = PaddedBlockEncryptingKey::cbc_pkcs7(unbound)
            .map_err(|_| "cipher init failed".to_string())?;
        let mut ciphertext = plaintext.to_vec();
        let context = if let Some(iv) = iv {
            let iv: [u8; IV_LEN_128_BIT] = iv
                .try_into()
                .map_err(|_| "bad IV length".to_string())?;
            encrypting
                .less_safe_encrypt(
                    &mut ciphertext,
                    EncryptionContext::Iv128(FixedLength::from(iv)),
                )
                .map_err(|_| "encryption failed".to_string())?
        } else {
            encrypting
                .encrypt(&mut ciphertext)
                .map_err(|_| "encryption failed".to_string())?
        };
        let iv: &[u8] = (&context)
            .try_into()
            .map_err(|_| "cipher did not return an IV".to_string())?;
        Ok((ciphertext, iv.to_vec()))
    }
}

/// Remove and validate PKCS#7 (a.k.a. PKCS#5) block padding.
fn strip_pkcs7(data: &[u8]) -> Result<&[u8], String> {
    let bad = || "decryption failed (wrong password?)".to_string();
    let &pad = data.last().ok_or_else(bad)?;
    let pad = pad as usize;
    if pad == 0 || pad > AES_BLOCK || pad > data.len() {
        return Err(bad());
    }
    if data[data.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err(bad());
    }
    Ok(&data[..data.len() - pad])
}

fn oid_of(node: &Node) -> Option<Vec<u64>> {
    if node.constructed || !node.is_universal(TAG_OID) {
        return None;
    }
    ber::oid_arcs(&node.value)
}

fn oid_str(oid: &[u64]) -> String {
    oid.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".")
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

    #[test]
    fn parses_pbes2_parameters() {
        let roots = parse_file("testdata/enc_pkcs8.der");
        let enc = parse(&roots).unwrap().expect("supported encrypted key");
        assert_eq!(enc.encrypted_path, [0, 1]);
        assert_eq!(enc.salt.len(), 16);
        assert_eq!(enc.iterations, 2048);
        assert_eq!(enc.prf, Prf::HmacSha256);
        assert_eq!(enc.key_len, 32); // AES-256
        assert_eq!(enc.iv.len(), 16);
        assert!(!enc.ciphertext.is_empty() && enc.ciphertext.len().is_multiple_of(16));
    }

    #[test]
    fn decrypts_with_correct_password_to_a_private_key() {
        let roots = parse_file("testdata/enc_pkcs8.der");
        let enc = parse(&roots).unwrap().unwrap();
        let plain = enc.decrypt(b"asn1editor").expect("correct password decrypts");
        // The plaintext is a well-formed PKCS#8 PrivateKeyInfo.
        let inner = ber::parse_forest(&plain, 0).unwrap();
        assert_eq!(inner.len(), 1);
        assert!(inner[0].is_universal(TAG_SEQUENCE));
        // version INTEGER, privateKeyAlgorithm SEQUENCE, privateKey OCTET STRING
        assert!(inner[0].children.len() >= 3);
        assert!(inner[0].children[0].is_universal(TAG_INTEGER));
    }

    #[test]
    fn reencrypts_modified_plaintext_with_fresh_and_existing_ivs() {
        let roots = parse_file("testdata/enc_pkcs8.der");
        let enc = parse(&roots).unwrap().unwrap();
        let mut plain = enc.decrypt(b"asn1editor").unwrap();
        // Keep a valid PrivateKeyInfo while making its encoding observably
        // different for the round trips below.
        let mut inner = ber::parse_forest(&plain, 0).unwrap();
        inner[0].children[0].value = vec![1];
        plain = ber::encode_forest(&inner);

        let same_iv_ciphertext = enc
            .encrypt_with_current_iv(b"asn1editor", &plain)
            .unwrap();
        let mut same_iv_roots = roots.clone();
        node_at_mut_for_test(&mut same_iv_roots, &enc.encrypted_path).value = same_iv_ciphertext;
        assert_eq!(
            parse(&same_iv_roots).unwrap().unwrap().decrypt(b"asn1editor").unwrap(),
            plain
        );

        let (ciphertext, iv) = enc.encrypt(b"asn1editor", &plain).unwrap();
        assert_ne!(iv, enc.iv, "normal re-encryption must generate a fresh IV");
        let mut fresh_iv_roots = roots;
        node_at_mut_for_test(&mut fresh_iv_roots, &enc.encrypted_path).value = ciphertext;
        node_at_mut_for_test(&mut fresh_iv_roots, &enc.iv_path).value = iv;
        assert_eq!(
            parse(&fresh_iv_roots).unwrap().unwrap().decrypt(b"asn1editor").unwrap(),
            plain
        );
    }

    fn node_at_mut_for_test<'a>(roots: &'a mut [Node], path: &[usize]) -> &'a mut Node {
        let (&first, rest) = path.split_first().unwrap();
        let mut node = &mut roots[first];
        for &index in rest {
            node = &mut node.children[index];
        }
        node
    }

    #[test]
    fn wrong_password_is_rejected() {
        let roots = parse_file("testdata/enc_pkcs8.der");
        let enc = parse(&roots).unwrap().unwrap();
        assert!(enc.decrypt(b"not the password").is_err());
        assert!(enc.decrypt(b"").is_err());
    }

    #[test]
    fn plaintext_key_is_not_an_encrypted_key() {
        // A plaintext PKCS#8 key and a certificate are both Ok(None).
        assert!(parse(&parse_file("testdata/private_key_pkcs8.der")).unwrap().is_none());
        assert!(parse(&parse_file("testdata/cert_ec.der")).unwrap().is_none());
        assert!(parse(&parse_file("testdata/ec_key.der")).unwrap().is_none());
    }
}
