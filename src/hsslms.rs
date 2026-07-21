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

//! HSS/LMS (RFC 8554) stateful hash-based signatures via the Botan library.
//!
//! Botan generates and signs; **verification is split** (see `verify.rs`) by
//! reading the level count from the public key ([`hss_levels`]): a single-level
//! key (an HSS tree of one level ≡ plain LMS) is verified by **OpenSSL** (3.6+,
//! which implements LMS but not multi-level HSS), as the user requested, while
//! a multi-level HSS key is verified by **Botan** here, since OpenSSL has no
//! HSS support.
//!
//! **OIDs.** Botan already emits the RFC 9802 / RFC 8708 OID
//! [`HSS_LMS_OID`] (`1.2.840.113549.1.9.16.3.17`, `id-alg-hss-lms-hashsig`)
//! in the `SubjectPublicKeyInfo` — the correct X.509 OID — so, unlike XMSS,
//! no OID translation is needed for certificates. Botan's *private* key uses
//! its own OID ([`HSS_LMS_OID_BOTAN_PRIV`]); key files keep it so Botan can
//! load them.
//!
//! **State.** Like XMSS, HSS/LMS is stateful: each signature consumes a
//! one-time-signature index, so [`sign`] returns the updated key for the
//! caller to persist (Botan's in-process registry also prevents reuse within
//! a run).

use crate::ber;

/// The HSS/LMS X.509 algorithm OID — `id-alg-hss-lms-hashsig`,
/// `1.2.840.113549.1.9.16.3.17` (RFC 8708, used for X.509 by RFC 9802). Botan
/// emits it in the `SubjectPublicKeyInfo` and it is used, parameters absent,
/// as the certificate/CRL `signatureAlgorithm`.
pub const HSS_LMS_OID: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 3, 17];

/// The OID Botan puts in an HSS/LMS *private* key's PKCS#8 (its own arc,
/// `1.3.6.1.4.1.25258.1.13`). Key files keep this so Botan can load them; only
/// the public SPKI uses the standard [`HSS_LMS_OID`].
pub const HSS_LMS_OID_BOTAN_PRIV: &[u64] = &[1, 3, 6, 1, 4, 1, 25258, 1, 13];

/// Whether `arcs` is the HSS/LMS public (X.509) OID or Botan's private-key OID.
pub fn is_hss_lms_oid(arcs: &[u64]) -> bool {
    arcs == HSS_LMS_OID || arcs == HSS_LMS_OID_BOTAN_PRIV
}

/// The number of HSS levels encoded in a public key: the first four bytes of
/// the HSS public key are the big-endian level count `L` (1 = plain LMS).
/// `pubkey_bits` is the raw `subjectPublicKey` (unused-bits octet stripped).
pub fn hss_levels(pubkey_bits: &[u8]) -> Option<u32> {
    pubkey_bits.get(0..4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn rng() -> Result<botan::RandomNumberGenerator, String> {
    botan::RandomNumberGenerator::new().map_err(|e| format!("Botan RNG unavailable: {:?}", e))
}

fn load_privkey(pkcs8: &[u8]) -> Result<botan::Privkey, String> {
    let key = botan::Privkey::load_der(pkcs8)
        .map_err(|_| "the key is not a Botan-loadable HSS/LMS key".to_string())?;
    match key.algo_name() {
        Ok(name) if name == "HSS-LMS" => Ok(key),
        _ => Err("the key is not an HSS/LMS key".to_string()),
    }
}

/// Generate an HSS/LMS key pair for a Botan parameter string, e.g.
/// `"SHA-256,HW(5,8)"` (single-level LMS) or `"SHA-256,HW(10,8),HW(5,8)"`
/// (two-level HSS). Returns `(pkcs8, spki)` DER — the SPKI already carries the
/// standard [`HSS_LMS_OID`].
pub fn generate(params: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut rng = rng()?;
    let key = botan::Privkey::create("HSS-LMS", params, &mut rng)
        .map_err(|e| format!("HSS/LMS key generation failed ({}): {:?}", params, e))?;
    let pkcs8 = key
        .der_encode()
        .map_err(|e| format!("HSS/LMS private-key encoding failed: {:?}", e))?;
    let spki = key
        .pubkey()
        .and_then(|p| p.der_encode())
        .map_err(|e| format!("HSS/LMS public-key encoding failed: {:?}", e))?;
    Ok((pkcs8, spki))
}

/// Sign `msg` with an HSS/LMS private key (PKCS#8 DER). Returns the signature
/// and the **updated** private key (the signature consumed a one-time index;
/// the caller must persist the returned bytes — see the module docs).
pub fn sign(pkcs8: &[u8], msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key = load_privkey(pkcs8)?;
    let mut rng = rng()?;
    // Empty padding: HSS/LMS signs the message directly (no external hash).
    let sig = key.sign(msg, "", &mut rng).map_err(|e| format!("HSS/LMS signing failed: {:?}", e))?;
    let updated = key
        .der_encode()
        .map_err(|e| format!("HSS/LMS private-key state re-encoding failed: {:?}", e))?;
    Ok((sig, updated))
}

/// Verify an HSS/LMS signature with **Botan** (the multi-level HSS path). The
/// `SubjectPublicKeyInfo` is rebuilt around the raw public-key bytes under the
/// standard OID, which Botan loads.
pub fn verify(pubkey_bits: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Some(spki) = spki_der(pubkey_bits) else { return false };
    let Ok(key) = botan::Pubkey::load_der(&spki) else { return false };
    let Ok(mut verifier) = botan::Verifier::new(&key, "") else { return false };
    verifier.update(msg).is_ok() && verifier.finish(sig).unwrap_or(false)
}

/// Build a `SubjectPublicKeyInfo` DER — `SEQUENCE { SEQUENCE { OID },
/// subjectPublicKey BIT STRING }` — around raw HSS/LMS public-key bytes, under
/// the standard [`HSS_LMS_OID`] (parameters absent).
fn spki_der(pubkey_bits: &[u8]) -> Option<Vec<u8>> {
    let dotted = HSS_LMS_OID.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".");
    let oid = ber::univ(ber::TAG_OID, false, ber::encode_oid(&dotted).ok()?);
    let alg_id = ber::univ_seq(vec![oid]);
    let mut bit_value = Vec::with_capacity(pubkey_bits.len() + 1);
    bit_value.push(0); // unused-bits octet
    bit_value.extend_from_slice(pubkey_bits);
    let bit_string = ber::univ(ber::TAG_BIT_STRING, false, bit_value);
    Some(ber::encode_node(&ber::univ_seq(vec![alg_id, bit_string])))
}

/// Whether `pkcs8` is a Botan-loadable HSS/LMS private key.
pub fn key_usable(pkcs8: &[u8]) -> bool {
    load_privkey(pkcs8).is_ok()
}

/// The `SubjectPublicKeyInfo` DER of an HSS/LMS private key (PKCS#8) — Botan's
/// encoding, which already carries the standard [`HSS_LMS_OID`].
pub fn spki_from_pkcs8(pkcs8: &[u8]) -> Option<Vec<u8>> {
    load_privkey(pkcs8).ok()?.pubkey().and_then(|p| p.der_encode()).ok()
}

/// Encrypt an HSS/LMS PKCS#8 key under `password` as a standard PBES2
/// `EncryptedPrivateKeyInfo` (the scheme `pkcs8.rs` decrypts), via Botan.
pub fn encrypt_pkcs8(pkcs8: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let key = load_privkey(pkcs8)?;
    let mut rng = rng()?;
    key.der_encode_encrypted(password, &mut rng)
        .map_err(|e| format!("HSS/LMS key encryption failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LMS: &str = "SHA-256,HW(5,8)"; // single level
    const HSS2: &str = "SHA-256,HW(5,8),HW(5,8)"; // two levels

    fn spki_pubkey_bits(spki: &[u8]) -> Vec<u8> {
        let roots = ber::parse_forest(spki, 0).unwrap();
        let bit = roots[0].children.last().unwrap();
        bit.value[1..].to_vec()
    }

    fn spki_oid(spki: &[u8]) -> Vec<u64> {
        let roots = ber::parse_forest(spki, 0).unwrap();
        ber::oid_arcs(&roots[0].children[0].children[0].value).unwrap()
    }

    #[test]
    fn lms_and_hss_generate_with_standard_public_oid_and_level_count() {
        let (pkcs8, spki) = generate(LMS).unwrap();
        assert_eq!(spki_oid(&spki), HSS_LMS_OID, "public SPKI uses the RFC 8708/9802 OID");
        assert_eq!(hss_levels(&spki_pubkey_bits(&spki)), Some(1), "LMS = single level");
        // The private key carries Botan's own OID.
        let roots = ber::parse_forest(&pkcs8, 0).unwrap();
        let priv_oid = ber::oid_arcs(&roots[0].children[1].children[0].value).unwrap();
        assert_eq!(priv_oid, HSS_LMS_OID_BOTAN_PRIV);

        let (_, spki2) = generate(HSS2).unwrap();
        assert_eq!(hss_levels(&spki_pubkey_bits(&spki2)), Some(2), "two-level HSS");
    }

    #[test]
    fn botan_sign_verify_roundtrips_and_advances_state() {
        let (pkcs8, spki) = generate(HSS2).unwrap();
        let bits = spki_pubkey_bits(&spki);
        let msg = b"a tbsCertificate stand-in";
        let (sig, updated) = sign(&pkcs8, msg).unwrap();
        assert_ne!(updated, pkcs8, "signing advances the key state");
        // Multi-level HSS verifies via Botan.
        assert!(verify(&bits, msg, &sig));
        assert!(!verify(&bits, b"tampered", &sig));
        assert!(key_usable(&pkcs8));
        assert_eq!(spki_from_pkcs8(&pkcs8).unwrap(), spki);
    }

    #[test]
    fn encrypted_export_decrypts_with_our_pkcs8_module() {
        let (pkcs8, _) = generate(LMS).unwrap();
        let enc = encrypt_pkcs8(&pkcs8, "secret").unwrap();
        assert_ne!(enc, pkcs8);
        let roots = ber::parse_forest(&enc, 0).unwrap();
        let parsed = crate::pkcs8::parse(&roots).unwrap().expect("EncryptedPrivateKeyInfo");
        assert_eq!(parsed.decrypt(b"secret").unwrap(), pkcs8);
        assert!(parsed.decrypt(b"wrong").is_err());
    }
}
