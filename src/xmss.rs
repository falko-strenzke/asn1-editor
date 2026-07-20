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

//! XMSS (RFC 8391) signatures via the Botan library — the third crypto
//! backend besides `aws-lc-rs` (classical) and OpenSSL (ML-DSA/SLH-DSA and
//! the small-RSA fallback). Neither of the other backends implements the
//! stateful hash-based schemes.
//!
//! Botan serializes XMSS keys in standard containers: the private key as a
//! PKCS#8 `PrivateKeyInfo` and the public key as a `SubjectPublicKeyInfo`,
//! both carrying the raw RFC 8391 key bytes. That lets XMSS keys flow through
//! the same `(pkcs8, spki)` plumbing as every other algorithm; only the code
//! paths that hand keys to OpenSSL or `aws-lc-rs` need to branch here instead.
//!
//! **OID translation.** Botan uses the ETSI/ISARA `id-alg-xmss-hashsig` OID
//! ([`XMSS_OID_BOTAN`]) in the keys it produces, but RFC 9802 assigns XMSS a
//! *different* OID for X.509 use ([`XMSS_OID`], `1.3.6.1.5.5.7.6.34`). So the
//! public keys this module hands back for splicing into certificates — from
//! [`generate`] and [`spki_from_pkcs8`] — are re-encoded under the RFC 9802
//! OID, and the certificate/CRL `signatureAlgorithm` uses it too (via
//! `keygen`). Private-key *files* keep Botan's native OID so Botan can load
//! them, and [`verify`] rebuilds the SPKI it feeds Botan under that native OID.
//! Only the algorithm OID changes across the boundary; the public-key bytes,
//! and hence the key↔certificate identity, are unaffected.
//!
//! **State.** XMSS is stateful: each signature consumes a one-time-signature
//! index, and reusing an index is catastrophic (two different messages under
//! the same index let an attacker forge signatures). Within one process
//! Botan's global XMSS index registry prevents reuse even when the same
//! serialized key is loaded repeatedly; across process restarts only the
//! index stored in the serialized key protects. [`sign`] therefore returns
//! the *updated* PKCS#8 alongside the signature, and callers persist it —
//! the re-key flow in `app.rs` threads the updated key through every
//! signature it makes and writes the final state to the key file.

use crate::ber;

/// The XMSS algorithm OID this tool puts into X.509 objects — the
/// `id-alg-xmss-hashsig` of **RFC 9802** (June 2025), `1.3.6.1.5.5.7.6.34`
/// under the PKIX `algorithms` arc. It is used, with the parameters field
/// absent, both in a certificate's `SubjectPublicKeyInfo` AlgorithmIdentifier
/// and in the certificate/CRL `signatureAlgorithm` (as with Ed25519 and the
/// NIST PQ algorithms, the same OID serves both).
///
/// Botan, however, encodes XMSS keys under a *different* OID (see
/// [`XMSS_OID_BOTAN`]); the two are translated at the boundary — see the
/// module docs.
pub const XMSS_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 6, 34];

/// The XMSS OID Botan emits and understands: `0.4.0.127.0.15.1.1.13.0`,
/// `id-alg-xmss-hashsig` from the ETSI/ISARA arc (draft-vangeest-x509-hash-sigs).
/// Botan can only load keys carrying this OID, so private-key files stay in
/// this native encoding while the X.509 objects use the RFC 9802 [`XMSS_OID`].
/// The two SPKIs differ only in the algorithm OID; the public-key BIT STRING
/// is identical.
pub const XMSS_OID_BOTAN: &[u64] = &[0, 4, 0, 127, 0, 15, 1, 1, 13, 0];

/// Whether `arcs` is an XMSS algorithm OID — the RFC 9802 OID this tool writes
/// or the Botan-native OID a private-key file (or a Botan-produced object)
/// carries. Accepting both keeps signing, verification and key loading working
/// across the translation boundary.
pub fn is_xmss_oid(arcs: &[u64]) -> bool {
    arcs == XMSS_OID || arcs == XMSS_OID_BOTAN
}

fn rng() -> Result<botan::RandomNumberGenerator, String> {
    botan::RandomNumberGenerator::new().map_err(|e| format!("Botan RNG unavailable: {:?}", e))
}

fn load_privkey(pkcs8: &[u8]) -> Result<botan::Privkey, String> {
    let key = botan::Privkey::load_der(pkcs8)
        .map_err(|_| "the key is not a Botan-loadable XMSS key".to_string())?;
    match key.algo_name() {
        Ok(name) if name == "XMSS" => Ok(key),
        _ => Err("the key is not an XMSS key".to_string()),
    }
}

/// Generate an XMSS key pair for a Botan parameter-set name (e.g.
/// `"XMSS-SHA2_10_256"`). Returns `(pkcs8, spki)` DER like the OpenSSL
/// generation paths in `keygen.rs`: the private key keeps Botan's native OID
/// (so Botan can load it), while the public key is re-encoded under the RFC
/// 9802 [`XMSS_OID`] for use in X.509 certificates.
pub fn generate(params: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut rng = rng()?;
    let key = botan::Privkey::create("XMSS", params, &mut rng)
        .map_err(|e| format!("XMSS key generation failed ({}): {:?}", params, e))?;
    let pkcs8 = key
        .der_encode()
        .map_err(|e| format!("XMSS private-key encoding failed: {:?}", e))?;
    let botan_spki = key
        .pubkey()
        .and_then(|p| p.der_encode())
        .map_err(|e| format!("XMSS public-key encoding failed: {:?}", e))?;
    let spki = spki_rfc9802(&botan_spki).ok_or("XMSS public key has an unexpected shape")?;
    Ok((pkcs8, spki))
}

/// Sign `msg` with an XMSS private key (PKCS#8 DER). Returns the signature
/// **and the updated private key**: the signature consumed a one-time-
/// signature index, and the caller must persist the returned key — signing
/// again from the old bytes would reuse the index (see the module docs).
pub fn sign(pkcs8: &[u8], msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key = load_privkey(pkcs8)?;
    let mut rng = rng()?;
    let sig = key.sign(msg, "", &mut rng).map_err(|e| format!("XMSS signing failed: {:?}", e))?;
    let updated = key
        .der_encode()
        .map_err(|e| format!("XMSS private-key state re-encoding failed: {:?}", e))?;
    Ok((sig, updated))
}

/// Verify an XMSS signature over `msg` under the raw `subjectPublicKey`
/// bytes (unused-bits octet already stripped). The `SubjectPublicKeyInfo`
/// is rebuilt around them — under Botan's native OID, since Botan parses the
/// whole SPKI and only recognizes its own OID.
pub fn verify(pubkey_bits: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Some(spki) = spki_der(XMSS_OID_BOTAN, pubkey_bits) else { return false };
    let Ok(key) = botan::Pubkey::load_der(&spki) else { return false };
    let Ok(mut verifier) = botan::Verifier::new(&key, "") else { return false };
    verifier.update(msg).is_ok() && verifier.finish(sig).unwrap_or(false)
}

/// Build a `SubjectPublicKeyInfo` DER — `SEQUENCE { SEQUENCE { OID },
/// subjectPublicKey BIT STRING }` — around raw XMSS public-key bytes, under
/// `oid` (the parameters field absent, as RFC 9802 requires).
fn spki_der(oid: &[u64], pubkey_bits: &[u8]) -> Option<Vec<u8>> {
    let dotted = oid.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".");
    let oid_node = ber::univ(ber::TAG_OID, false, ber::encode_oid(&dotted).ok()?);
    let alg_id = ber::univ_seq(vec![oid_node]);
    let mut bit_value = Vec::with_capacity(pubkey_bits.len() + 1);
    bit_value.push(0); // unused-bits octet
    bit_value.extend_from_slice(pubkey_bits);
    let bit_string = ber::univ(ber::TAG_BIT_STRING, false, bit_value);
    Some(ber::encode_node(&ber::univ_seq(vec![alg_id, bit_string])))
}

/// The raw `subjectPublicKey` bytes (unused-bits octet stripped) of a
/// `SubjectPublicKeyInfo` DER, regardless of its algorithm OID.
fn pubkey_bits_of_spki(spki: &[u8]) -> Option<Vec<u8>> {
    let roots = ber::parse_forest(spki, 0).ok()?;
    let bit = roots.first()?.children.last()?;
    if !bit.is_universal(ber::TAG_BIT_STRING) || bit.value.is_empty() {
        return None;
    }
    Some(bit.value[1..].to_vec()) // strip the unused-bits octet
}

/// Re-encode a Botan `SubjectPublicKeyInfo` under the RFC 9802 [`XMSS_OID`],
/// for splicing into an X.509 certificate. Only the algorithm OID changes.
fn spki_rfc9802(botan_spki: &[u8]) -> Option<Vec<u8>> {
    spki_der(XMSS_OID, &pubkey_bits_of_spki(botan_spki)?)
}

/// Whether `pkcs8` is a Botan-loadable XMSS private key.
pub fn key_usable(pkcs8: &[u8]) -> bool {
    load_privkey(pkcs8).is_ok()
}

/// The `SubjectPublicKeyInfo` DER of an XMSS private key (PKCS#8), under the
/// RFC 9802 [`XMSS_OID`], for the code paths that derive public keys to splice
/// into certificates (and which use OpenSSL for other algorithms — OpenSSL
/// cannot load XMSS).
pub fn spki_from_pkcs8(pkcs8: &[u8]) -> Option<Vec<u8>> {
    let botan_spki = load_privkey(pkcs8).ok()?.pubkey().and_then(|p| p.der_encode()).ok()?;
    spki_rfc9802(&botan_spki)
}

/// Encrypt an XMSS PKCS#8 key under `password` as a standard PBES2
/// `EncryptedPrivateKeyInfo` (AES-256/CBC, PBKDF2/HMAC-SHA-512 — a scheme
/// our own `pkcs8.rs` decrypts), replacing the OpenSSL encryption path
/// which cannot load XMSS keys.
pub fn encrypt_pkcs8(pkcs8: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let key = load_privkey(pkcs8)?;
    let mut rng = rng()?;
    key.der_encode_encrypted(password, &mut rng)
        .map_err(|e| format!("XMSS key encryption failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest/fastest parameter set (tree height 10).
    const FAST: &str = "XMSS-SHA2_10_256";

    fn pkcs8_alg_oid(pkcs8: &[u8]) -> Vec<u64> {
        let roots = ber::parse_forest(pkcs8, 0).unwrap();
        ber::oid_arcs(&roots[0].children[1].children[0].value).unwrap()
    }

    fn spki_pubkey_bits(spki: &[u8]) -> Vec<u8> {
        let roots = ber::parse_forest(spki, 0).unwrap();
        let bit = roots[0].children.last().unwrap();
        bit.value[1..].to_vec()
    }

    #[test]
    fn generate_sign_verify_roundtrip_with_standard_encodings() {
        let (pkcs8, spki) = generate(FAST).unwrap();
        // The private key keeps Botan's native OID (so Botan can load it)…
        assert_eq!(pkcs8_alg_oid(&pkcs8), XMSS_OID_BOTAN);
        // …while the public key for X.509 use carries the RFC 9802 OID, with
        // the parameters field absent (AlgorithmIdentifier is a lone OID).
        let spki_roots = ber::parse_forest(&spki, 0).unwrap();
        let alg_id = &spki_roots[0].children[0];
        assert_eq!(alg_id.children.len(), 1, "parameters must be absent");
        assert_eq!(ber::oid_arcs(&alg_id.children[0].value).unwrap(), XMSS_OID);

        let msg = b"a tbsCertificate stand-in";
        let (sig, _updated) = sign(&pkcs8, msg).unwrap();
        let bits = spki_pubkey_bits(&spki);
        assert!(verify(&bits, msg, &sig));
        assert!(!verify(&bits, b"tampered", &sig), "a tampered message must not verify");
        assert!(key_usable(&pkcs8));
        // The SPKI derived from the private key matches the generated one
        // (same RFC 9802 OID, same public-key bytes).
        assert_eq!(spki_from_pkcs8(&pkcs8).unwrap(), spki);
    }

    #[test]
    fn rfc9802_and_botan_oids_are_both_recognized_but_distinct() {
        assert_eq!(XMSS_OID, &[1, 3, 6, 1, 5, 5, 7, 6, 34]);
        assert_ne!(XMSS_OID, XMSS_OID_BOTAN);
        assert!(is_xmss_oid(XMSS_OID) && is_xmss_oid(XMSS_OID_BOTAN));
        assert!(!is_xmss_oid(&[1, 3, 6, 1, 5, 5, 7, 6, 35])); // XMSS^MT, not XMSS
    }

    #[test]
    fn signing_advances_the_key_state() {
        let (pkcs8, spki) = generate(FAST).unwrap();
        let bits = spki_pubkey_bits(&spki);
        let msg = b"stateful";
        let (sig1, updated) = sign(&pkcs8, msg).unwrap();
        assert_ne!(updated, pkcs8, "the returned key must carry the advanced index");
        // Signing from the updated state uses the next index.
        let (sig2, _) = sign(&updated, msg).unwrap();
        assert_ne!(sig1, sig2, "consecutive signatures must consume distinct indices");
        assert!(verify(&bits, msg, &sig1) && verify(&bits, msg, &sig2));
        // Signing from the STALE original bytes still gets a fresh index:
        // Botan's process-global XMSS index registry tracks the highest used
        // index per key material, so in-process reuse is prevented even
        // without persisting the updated key. (Across process restarts only
        // the serialized index protects — hence sign() returning it.)
        let (sig3, _) = sign(&pkcs8, msg).unwrap();
        assert_ne!(sig3, sig1);
        assert_ne!(sig3, sig2);
        assert!(verify(&bits, msg, &sig3));
    }

    #[test]
    fn encrypted_export_decrypts_with_our_pkcs8_module() {
        let (pkcs8, _) = generate(FAST).unwrap();
        let enc = encrypt_pkcs8(&pkcs8, "topsecret").unwrap();
        assert_ne!(enc, pkcs8);
        let roots = ber::parse_forest(&enc, 0).unwrap();
        let parsed = crate::pkcs8::parse(&roots).unwrap().expect("EncryptedPrivateKeyInfo");
        assert_eq!(parsed.decrypt(b"topsecret").unwrap(), pkcs8);
        assert!(parsed.decrypt(b"wrong").is_err());
    }

    #[test]
    fn non_xmss_keys_are_rejected() {
        let (ec, _) = {
            let key = crate::keygen::generate(crate::keygen::KeyAlgorithm::EcdsaP256).unwrap();
            (key.pkcs8, key.spki)
        };
        assert!(!key_usable(&ec), "an EC key is not an XMSS key");
        assert!(sign(&ec, b"x").is_err());
    }
}
