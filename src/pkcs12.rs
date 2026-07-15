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

//! Structural decoding and password decryption/re-encryption of PKCS#12
//! `PFX` containers (RFC 7292). Unlike the single encrypted region of an
//! `EncryptedPrivateKeyInfo` (`pkcs8.rs`), a PKCS#12 file can hold several
//! independently password-encrypted regions — one or more `EncryptedData`
//! content blobs (typically the certificates) and one or more
//! `PKCS8ShroudedKeyBag`s (the private keys). This module locates each such
//! region in the outer parse tree and, given the password, decrypts or
//! re-encrypts it.
//!
//! Scope: the password-based encryption must be **PBES2** (PBKDF2 +
//! AES-128/256-CBC), which is what current OpenSSL and comparable tools
//! emit by default. The legacy `pbeWithSHAAnd*` schemes use the RFC 7292
//! Appendix B key-derivation for the *cipher* key, which is not
//! implemented; those are reported as unsupported.
//!
//! Editing a decrypted region additionally requires recomputing the
//! container's integrity `MacData`: an HMAC over the `AuthenticatedSafe`
//! encoding whose key comes from the RFC 7292 Appendix B KDF (ID 3). That
//! KDF and HMAC are computed here with the `openssl` crate's digest
//! primitives ([`MacData::compute`]); a container whose `MacData` uses an
//! unsupported digest stays read-only ([`Mac::Unsupported`]).

use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::PKey;
use openssl::sign::Signer;

use crate::ber::{self, Class, Node, TAG_INTEGER, TAG_OCTET_STRING, TAG_SEQUENCE};
use crate::pkcs8::{oid_of, oid_str, Pbes2};

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
    /// Path of this region's AES-CBC IV OCTET STRING in the outer forest,
    /// updated alongside the ciphertext when the region is re-encrypted.
    pub iv_path: Vec<usize>,
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

    /// Encrypt an edited plaintext with this region's PBES2 parameters and a
    /// fresh AES-CBC IV, returning `(ciphertext, iv)` for the caller to store
    /// at `cipher_path` / `iv_path`. The caller must afterwards recompute the
    /// container MAC ([`MacData::compute`]).
    pub fn encrypt(&self, password: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        match ber::parse_forest(plaintext, 0) {
            Ok(roots) if roots.len() == 1 && roots[0].is_universal(TAG_SEQUENCE) => {}
            _ => return Err("decrypted content must be one ASN.1 SEQUENCE".to_string()),
        }
        self.pbes2.encrypt(password, plaintext)
    }
}

/// A decoded PKCS#12 `PFX` with the encrypted regions this tool can decrypt.
pub struct Pkcs12 {
    pub regions: Vec<Region>,
    /// The container's integrity MAC, which must be recomputed whenever
    /// anything inside the `AuthenticatedSafe` changes.
    pub mac: Mac,
    /// Path of the OCTET STRING whose content octets (the encoded
    /// `AuthenticatedSafe`) are the MAC input.
    pub auth_safe_content_path: Vec<usize>,
}

/// The state of the container's `MacData`, deciding whether edited regions
/// can be re-encrypted into a consistent file.
pub enum Mac {
    /// No `MacData` present — nothing needs recomputing after an edit.
    Absent,
    /// A supported HMAC scheme whose digest can be recomputed.
    Supported(MacData),
    /// `MacData` is present but malformed or uses an unsupported digest;
    /// edits must be refused, since the result could not be re-MAC'd.
    Unsupported(String),
}

/// A supported `MacData`: `SEQUENCE { mac DigestInfo, macSalt OCTET STRING,
/// iterations INTEGER DEFAULT 1 }` (RFC 7292 §4). The MAC key is derived
/// with the Appendix B KDF (ID 3) and the digest is
/// `HMAC-hash(key, AuthenticatedSafe)`.
pub struct MacData {
    /// Path of the `DigestInfo.digest` OCTET STRING to overwrite with a
    /// recomputed MAC.
    pub digest_path: Vec<usize>,
    algorithm: MacDigest,
    salt: Vec<u8>,
    iterations: u32,
}

const OID_SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_SHA384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
const OID_SHA512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MacDigest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl MacDigest {
    fn from_oid(oid: &[u64]) -> Option<MacDigest> {
        match oid {
            OID_SHA1 => Some(MacDigest::Sha1),
            OID_SHA256 => Some(MacDigest::Sha256),
            OID_SHA384 => Some(MacDigest::Sha384),
            OID_SHA512 => Some(MacDigest::Sha512),
            _ => None,
        }
    }

    fn message_digest(self) -> MessageDigest {
        match self {
            MacDigest::Sha1 => MessageDigest::sha1(),
            MacDigest::Sha256 => MessageDigest::sha256(),
            MacDigest::Sha384 => MessageDigest::sha384(),
            MacDigest::Sha512 => MessageDigest::sha512(),
        }
    }

    /// The hash's input block size `v` (RFC 7292 Appendix B).
    fn block_len(self) -> usize {
        match self {
            MacDigest::Sha1 | MacDigest::Sha256 => 64,
            MacDigest::Sha384 | MacDigest::Sha512 => 128,
        }
    }
}

impl MacData {
    /// Compute the MAC digest over `auth_safe_content` (the content octets of
    /// the `authSafe` data OCTET STRING, i.e. the encoded
    /// `AuthenticatedSafe`) for `password` (UTF-8, as typed by the user).
    pub fn compute(&self, password: &[u8], auth_safe_content: &[u8]) -> Result<Vec<u8>, String> {
        let crypto = |e: openssl::error::ErrorStack| format!("MAC computation failed: {}", e);
        let mut bmp = bmp_password(password)?;
        let mut key =
            derive_mac_key(self.algorithm, &bmp, &self.salt, self.iterations).map_err(crypto)?;
        bmp.fill(0);
        let result = (|| {
            let hmac_key = PKey::hmac(&key)?;
            let mut signer = Signer::new(self.algorithm.message_digest(), &hmac_key)?;
            signer.update(auth_safe_content)?;
            signer.sign_to_vec()
        })()
        .map_err(crypto);
        key.fill(0);
        result
    }
}

/// RFC 7292 Appendix B.1: passwords enter the KDF as a BMPString — the
/// UTF-16BE code units of the password followed by two zero terminator bytes.
fn bmp_password(utf8: &[u8]) -> Result<Vec<u8>, String> {
    let s = std::str::from_utf8(utf8).map_err(|_| "password is not valid UTF-8".to_string())?;
    let mut out = Vec::with_capacity(2 * s.len() + 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    Ok(out)
}

/// RFC 7292 Appendix B.2 key derivation for the integrity MAC (ID = 3). The
/// MAC key is exactly one hash output long (`n = u`), so only the first
/// output block `A_1` is produced and the general algorithm's `I`-update
/// step never runs.
fn derive_mac_key(
    digest: MacDigest,
    password_bmp: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let md = digest.message_digest();
    let v = digest.block_len();
    let d = vec![3u8; v]; // ID = 3: MAC key material
    let s = repeat_to_multiple(salt, v);
    let p = repeat_to_multiple(password_bmp, v);
    let mut hasher = Hasher::new(md)?;
    hasher.update(&d)?;
    hasher.update(&s)?;
    hasher.update(&p)?;
    let mut a = hasher.finish()?.to_vec();
    for _ in 1..iterations {
        let mut hasher = Hasher::new(md)?;
        hasher.update(&a)?;
        a = hasher.finish()?.to_vec();
    }
    Ok(a)
}

/// Repeat `data` cyclically to the next multiple of `v` bytes (empty input
/// stays empty), building the `S` and `P` strings of the Appendix B KDF.
fn repeat_to_multiple(data: &[u8], v: usize) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let len = data.len().div_ceil(v) * v;
    data.iter().cycle().take(len).copied().collect()
}

/// Decode the optional `macData` element (root child 2).
fn parse_mac_data(node: &Node) -> Mac {
    let unsupported = |why: String| Mac::Unsupported(format!("PKCS#12 MacData: {}", why));
    let Some(seq) = as_sequence(node) else {
        return unsupported("not a SEQUENCE".to_string());
    };
    if seq.children.len() < 2 || seq.children.len() > 3 {
        return unsupported("malformed".to_string());
    }
    // mac DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier,
    //   digest OCTET STRING }
    let Some(digest_info) = seq.children.first().and_then(as_sequence) else {
        return unsupported("malformed DigestInfo".to_string());
    };
    let Some(oid) = digest_info.children.first().and_then(as_sequence).and_then(|alg| {
        alg.children.first().and_then(oid_of)
    }) else {
        return unsupported("malformed digestAlgorithm".to_string());
    };
    let Some(algorithm) = MacDigest::from_oid(&oid) else {
        return unsupported(format!("unsupported digest (OID {})", oid_str(&oid)));
    };
    let digest_ok = digest_info
        .children
        .get(1)
        .map(|d| !d.constructed && d.is_universal(TAG_OCTET_STRING))
        .unwrap_or(false);
    if !digest_ok {
        return unsupported("digest must be an OCTET STRING".to_string());
    }
    let Some(salt) = seq
        .children
        .get(1)
        .filter(|s| !s.constructed && s.is_universal(TAG_OCTET_STRING))
        .map(|s| s.value.clone())
    else {
        return unsupported("macSalt must be an OCTET STRING".to_string());
    };
    let iterations = match seq.children.get(2) {
        None => 1,
        Some(n) if !n.constructed && n.is_universal(TAG_INTEGER) => {
            match ber::decode_integer(&n.value)
                .filter(|&i| i >= 1)
                .and_then(|i| u32::try_from(i).ok())
            {
                Some(i) => i,
                None => return unsupported("invalid iteration count".to_string()),
            }
        }
        Some(_) => return unsupported("malformed iteration count".to_string()),
    };
    // macData is root child 2; digest is DigestInfo (child 0) child 1.
    Mac::Supported(MacData { digest_path: vec![0, 2, 0, 1], algorithm, salt, iterations })
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
    let mac = match root.children.get(2) {
        None => Mac::Absent,
        Some(node) => parse_mac_data(node),
    };
    Ok(Some(Pkcs12 { regions, mac, auth_safe_content_path: vec![0, 1, 1, 0] }))
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
        //   → encryptedContentInfo (child 1) → encryptedContent (child 2);
        // the contentEncryptionAlgorithm is that SEQUENCE's child 1.
        let cipher_path = extend(ci_path, &[1, 0, 1, 2]);
        let alg_path = extend(ci_path, &[1, 0, 1, 1]);
        push_region(
            alg,
            &alg_path,
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
    //   (child 0) → encryptedData (child 1); the encryptionAlgorithm is
    //   that SEQUENCE's child 0.
    let cipher_path = extend(bag_path, &[1, 0, 1]);
    let alg_path = extend(bag_path, &[1, 0, 0]);
    push_region(
        alg,
        &alg_path,
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
    alg_path: &[usize],
    ciphertext: Vec<u8>,
    cipher_path: Vec<usize>,
    kind: RegionKind,
    regions: &mut Vec<Region>,
    unsupported: &mut Option<String>,
) {
    // Within a PBES2 AlgorithmIdentifier the IV sits at parameters (child 1)
    // → encryptionScheme (child 1) → iv (child 1).
    let iv_path = extend(alg_path, &[1, 1, 1]);
    match Pbes2::from_algorithm_identifier(alg) {
        Ok(Some(pbes2)) => regions.push(Region { cipher_path, iv_path, kind, pbes2, ciphertext }),
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
    fn computed_mac_matches_the_stored_digest() {
        // Recomputing the MAC of the unmodified container must reproduce the
        // digest openssl wrote — this pins the Appendix B KDF and the HMAC.
        let roots = parse_file("testdata/pkcs12.der");
        let p12 = parse(&roots).unwrap().unwrap();
        let Mac::Supported(mac) = &p12.mac else { panic!("expected a supported MacData") };
        let auth_safe = node_at(&roots, &p12.auth_safe_content_path);
        let digest = mac.compute(b"asn1editor", &auth_safe.content_octets()).unwrap();
        assert_eq!(digest, node_at(&roots, &mac.digest_path).value);
        // A different password yields a different (same-length) digest.
        let other = mac.compute(b"other", &auth_safe.content_octets()).unwrap();
        assert_eq!(other.len(), digest.len());
        assert_ne!(other, digest);
    }

    #[test]
    fn regions_reencrypt_and_round_trip() {
        let roots = parse_file("testdata/pkcs12.der");
        let p12 = parse(&roots).unwrap().unwrap();
        for (idx, region) in p12.regions.iter().enumerate() {
            // The recorded IV path points at this region's 16-byte cipher IV.
            let iv_node = node_at(&roots, &region.iv_path);
            assert!(iv_node.is_universal(TAG_OCTET_STRING));
            assert_eq!(iv_node.value.len(), 16);

            let plain = region.decrypt(b"asn1editor").unwrap();
            let (ciphertext, iv) = region.encrypt(b"asn1editor", &plain).unwrap();
            assert_ne!(iv, iv_node.value, "re-encryption must use a fresh IV");

            // Splicing ciphertext and IV back yields a container whose same
            // region decrypts to the same plaintext.
            let mut spliced = roots.clone();
            node_at_mut(&mut spliced, &region.cipher_path).value = ciphertext;
            node_at_mut(&mut spliced, &region.iv_path).value = iv;
            let reparsed = parse(&spliced).unwrap().unwrap();
            assert_eq!(reparsed.regions[idx].decrypt(b"asn1editor").unwrap(), plain);
        }
    }

    #[test]
    fn arbitrary_bytes_are_not_a_valid_region_plaintext() {
        let roots = parse_file("testdata/pkcs12.der");
        let p12 = parse(&roots).unwrap().unwrap();
        assert!(p12.regions[0].encrypt(b"asn1editor", b"not asn.1").is_err());
    }

    fn node_at_mut<'a>(roots: &'a mut [Node], path: &[usize]) -> &'a mut Node {
        let (&first, rest) = path.split_first().unwrap();
        let mut node = &mut roots[first];
        for &index in rest {
            node = &mut node.children[index];
        }
        node
    }

    #[test]
    fn non_pkcs12_files_are_not_pfx() {
        assert!(parse(&parse_file("testdata/enc_pkcs8.der")).unwrap().is_none());
        assert!(parse(&parse_file("testdata/private_key_pkcs8.der")).unwrap().is_none());
        assert!(parse(&parse_file("testdata/cert_ec.der")).unwrap().is_none());
        assert!(parse(&parse_file("testdata/pkcs7.der")).unwrap().is_none());
    }
}
