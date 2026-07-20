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
//! *verify*: classically, RSA with SHA-256 (512- to 8192-bit keys), ECDSA on
//! P-256 (SHA-256) and P-384 (SHA-384), and Ed25519; and, post-quantum, the
//! FIPS 204 ML-DSA (44/65/87) and FIPS 205 SLH-DSA (all twelve parameter sets)
//! families. The post-quantum keys are generated with OpenSSL by algorithm
//! name (`EVP_PKEY_CTX_new_from_name`, via raw `openssl-sys` FFI, since the
//! safe crate lacks SLH-DSA), then handled by the same PKCS#8/SPKI code paths.
//!
//! The dialog presents the algorithms as a *family* (ECDSA, RSA, Ed25519,
//! ML-DSA, SLH-DSA — [`FAMILIES`]) plus a per-family *parameter* (the curve
//! for ECDSA, the key size for RSA, the parameter set for ML-DSA/SLH-DSA);
//! each `(family, parameter)` pair resolves to one [`KeyAlgorithm`].

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
    /// RSA with SHA-256, identified by its key-size entry in [`RSA`].
    Rsa(usize),
    /// RSA with SHA-256 and a user-entered modulus size in bits (the
    /// parameter column's "custom" row); valid sizes are
    /// [`RSA_CUSTOM_BITS_MIN`]..=[`RSA_CUSTOM_BITS_MAX`].
    RsaCustom(u32),
    EcdsaP256,
    EcdsaP384,
    Ed25519,
    /// A post-quantum algorithm, identified by its entry in [`PQ`].
    Pq(usize),
    /// XMSS (RFC 8391, stateful hash-based), identified by its entry in
    /// [`XMSS`]; generated and signed by the Botan backend (`xmss.rs`).
    Xmss(usize),
}

/// Bounds for a custom RSA modulus size: OpenSSL refuses to generate keys
/// below 512 bits (and SHA-256 PKCS#1 v1.5 needs at least 496); the upper
/// bound keeps generation time within reason.
pub const RSA_CUSTOM_BITS_MIN: u32 = 512;
pub const RSA_CUSTOM_BITS_MAX: u32 = 16384;

/// Static description of one RSA key size: the modulus bits, the labels for
/// the dialog (full and parameter-column form) and a filename token.
struct RsaDesc {
    bits: u32,
    name: &'static str,
    param: &'static str,
    short: &'static str,
}

/// The RSA key sizes, indexed by `KeyAlgorithm::Rsa(i)`, in ascending order.
const RSA: &[RsaDesc] = &[
    RsaDesc { bits: 512, name: "RSA-512 (SHA-256)", param: "512", short: "rsa512" },
    RsaDesc { bits: 768, name: "RSA-768 (SHA-256)", param: "768", short: "rsa768" },
    RsaDesc { bits: 1024, name: "RSA-1024 (SHA-256)", param: "1024", short: "rsa1024" },
    RsaDesc { bits: 2048, name: "RSA-2048 (SHA-256)", param: "2048", short: "rsa2048" },
    RsaDesc { bits: 3072, name: "RSA-3072 (SHA-256)", param: "3072", short: "rsa3072" },
    RsaDesc { bits: 4096, name: "RSA-4096 (SHA-256)", param: "4096", short: "rsa4096" },
    RsaDesc { bits: 8192, name: "RSA-8192 (SHA-256)", param: "8192", short: "rsa8192" },
];

/// Static description of one post-quantum algorithm: its full X.509
/// `signatureAlgorithm` OID (under `2.16.840.1.101.3.4.3`), its OpenSSL/FIPS
/// name (used both as the display label and the `EVP_PKEY_CTX_new_from_name`
/// string), its parameter-column label (the name without the family prefix),
/// and a filename token.
struct PqDesc {
    oid: &'static [u64],
    name: &'static str,
    param: &'static str,
    short: &'static str,
    /// Measured keygen wall-clock (seconds) on the calibration machine, for
    /// the SLH-DSA cost estimate ([`crate::cost`]). ML-DSA is effectively
    /// instant and gets no time estimate, so its value here is nominal.
    keygen_secs: f64,
    /// Measured single-signature wall-clock (seconds); dominant for SLH-DSA's
    /// slow-signing (`s`) parameter sets and multiplied by the re-signed
    /// object count.
    sign_secs: f64,
}

/// The post-quantum algorithms, indexed by `KeyAlgorithm::Pq(i)`: ML-DSA
/// (FIPS 204) then SLH-DSA (FIPS 205), matching the NIST OID order.
const PQ: &[PqDesc] = &[
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 17], name: "ML-DSA-44", param: "44", short: "mldsa44", keygen_secs: 0.0, sign_secs: 0.0 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 18], name: "ML-DSA-65", param: "65", short: "mldsa65", keygen_secs: 0.0, sign_secs: 0.0 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 19], name: "ML-DSA-87", param: "87", short: "mldsa87", keygen_secs: 0.0, sign_secs: 0.0 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 20], name: "SLH-DSA-SHA2-128s", param: "SHA2-128s", short: "slhdsa-sha2-128s", keygen_secs: 0.12, sign_secs: 1.02 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 21], name: "SLH-DSA-SHA2-128f", param: "SHA2-128f", short: "slhdsa-sha2-128f", keygen_secs: 0.003, sign_secs: 0.044 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 22], name: "SLH-DSA-SHA2-192s", param: "SHA2-192s", short: "slhdsa-sha2-192s", keygen_secs: 0.18, sign_secs: 1.75 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 23], name: "SLH-DSA-SHA2-192f", param: "SHA2-192f", short: "slhdsa-sha2-192f", keygen_secs: 0.003, sign_secs: 0.080 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 24], name: "SLH-DSA-SHA2-256s", param: "SHA2-256s", short: "slhdsa-sha2-256s", keygen_secs: 0.10, sign_secs: 1.39 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 25], name: "SLH-DSA-SHA2-256f", param: "SHA2-256f", short: "slhdsa-sha2-256f", keygen_secs: 0.007, sign_secs: 0.139 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 26], name: "SLH-DSA-SHAKE-128s", param: "SHAKE-128s", short: "slhdsa-shake-128s", keygen_secs: 0.22, sign_secs: 2.10 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 27], name: "SLH-DSA-SHAKE-128f", param: "SHAKE-128f", short: "slhdsa-shake-128f", keygen_secs: 0.004, sign_secs: 0.077 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 28], name: "SLH-DSA-SHAKE-192s", param: "SHAKE-192s", short: "slhdsa-shake-192s", keygen_secs: 0.29, sign_secs: 3.64 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 29], name: "SLH-DSA-SHAKE-192f", param: "SHAKE-192f", short: "slhdsa-shake-192f", keygen_secs: 0.006, sign_secs: 0.162 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 30], name: "SLH-DSA-SHAKE-256s", param: "SHAKE-256s", short: "slhdsa-shake-256s", keygen_secs: 0.22, sign_secs: 2.44 },
    PqDesc { oid: &[2, 16, 840, 1, 101, 3, 4, 3, 31], name: "SLH-DSA-SHAKE-256f", param: "SHAKE-256f", short: "slhdsa-shake-256f", keygen_secs: 0.011, sign_secs: 0.201 },
];

/// Static description of one XMSS parameter set: the Botan parameter-set
/// name (also the display label), the parameter-column label, and a
/// filename token. Only tree heights 10 and 16 are offered — height-20 key
/// generation takes on the order of an hour, unusable in a modal dialog.
struct XmssDesc {
    name: &'static str,
    param: &'static str,
    short: &'static str,
    /// Tree height (10 or 16), the exponent driving keygen cost (~2^h).
    height: u8,
    /// Measured keygen wall-clock at height 10 for this hash/output class on
    /// the calibration machine (seconds); the cost model scales it by
    /// `2^(height-10)`. XMSS signing reloads the key (Botan reconstructs the
    /// full state on load), so per-signature cost ≈ keygen cost — see
    /// [`crate::cost`].
    keygen_h10_secs: f64,
}

/// The XMSS parameter sets, indexed by `KeyAlgorithm::Xmss(i)`, in the dialog
/// display order: 192-bit, then 256-bit, then 512-bit. All share the single
/// RFC 9802 `id-alg-xmss-hashsig` X.509 OID (the concrete parameter set is carried in
/// the key bytes), so adding one needs no OID plumbing. The 192-bit sets are
/// NIST SP 800-208's truncated-hash additions (SHA-256/192 and SHAKE256/192);
/// the 256-bit and 512-bit (n=64, ~256-bit-security) sets are RFC 8391.
const XMSS: &[XmssDesc] = &[
    // NIST SP 800-208 192-bit sets (SHA-256/192 and SHAKE256/192).
    XmssDesc { name: "XMSS-SHA2_10_192", param: "SHA2_10_192", short: "xmss-sha2-10-192", height: 10, keygen_h10_secs: 0.37 },
    XmssDesc { name: "XMSS-SHA2_16_192", param: "SHA2_16_192", short: "xmss-sha2-16-192", height: 16, keygen_h10_secs: 0.37 },
    XmssDesc { name: "XMSS-SHAKE256_10_192", param: "SHAKE256_10_192", short: "xmss-shake256-10-192", height: 10, keygen_h10_secs: 0.57 },
    XmssDesc { name: "XMSS-SHAKE256_16_192", param: "SHAKE256_16_192", short: "xmss-shake256-16-192", height: 16, keygen_h10_secs: 0.57 },
    // RFC 8391 256-bit sets.
    XmssDesc { name: "XMSS-SHA2_10_256", param: "SHA2_10_256", short: "xmss-sha2-10-256", height: 10, keygen_h10_secs: 0.65 },
    XmssDesc { name: "XMSS-SHA2_16_256", param: "SHA2_16_256", short: "xmss-sha2-16-256", height: 16, keygen_h10_secs: 0.65 },
    XmssDesc { name: "XMSS-SHAKE_10_256", param: "SHAKE_10_256", short: "xmss-shake-10-256", height: 10, keygen_h10_secs: 0.81 },
    XmssDesc { name: "XMSS-SHAKE_16_256", param: "SHAKE_16_256", short: "xmss-shake-16-256", height: 16, keygen_h10_secs: 0.81 },
    // RFC 8391 512-bit (n=64) sets, ~256-bit security.
    XmssDesc { name: "XMSS-SHA2_10_512", param: "SHA2_10_512", short: "xmss-sha2-10-512", height: 10, keygen_h10_secs: 2.72 },
    XmssDesc { name: "XMSS-SHA2_16_512", param: "SHA2_16_512", short: "xmss-sha2-16-512", height: 16, keygen_h10_secs: 2.72 },
    XmssDesc { name: "XMSS-SHAKE_10_512", param: "SHAKE_10_512", short: "xmss-shake-10-512", height: 10, keygen_h10_secs: 2.66 },
    XmssDesc { name: "XMSS-SHAKE_16_512", param: "SHAKE_16_512", short: "xmss-shake-16-512", height: 16, keygen_h10_secs: 2.66 },
];

/// One algorithm family of the dialog's first column; the members are the
/// choices of its parameter column, in display order.
pub struct Family {
    /// First-column label (the family name alone).
    pub label: &'static str,
    /// The concrete algorithms behind the parameter column, in display order.
    pub members: &'static [KeyAlgorithm],
    /// Index into [`Self::members`] preselected when the family is chosen
    /// (e.g. RSA lands on 2048, not on the weak 512).
    pub default_member: usize,
    /// Whether the parameter column offers an extra "custom" row with a
    /// user-entered modulus size ([`KeyAlgorithm::RsaCustom`]; RSA only).
    pub custom_modulus: bool,
}

/// The algorithm families offered in the public-key modification dialog, in
/// display order.
pub const FAMILIES: &[Family] = &[
    Family {
        label: "ECDSA",
        members: &[KeyAlgorithm::EcdsaP256, KeyAlgorithm::EcdsaP384],
        default_member: 0,
        custom_modulus: false,
    },
    Family {
        label: "RSA",
        members: &[
            KeyAlgorithm::Rsa(0),
            KeyAlgorithm::Rsa(1),
            KeyAlgorithm::Rsa(2),
            KeyAlgorithm::Rsa(3),
            KeyAlgorithm::Rsa(4),
            KeyAlgorithm::Rsa(5),
            KeyAlgorithm::Rsa(6),
        ],
        default_member: 3, // 2048
        custom_modulus: true,
    },
    Family {
        label: "Ed25519",
        members: &[KeyAlgorithm::Ed25519],
        default_member: 0,
        custom_modulus: false,
    },
    Family {
        label: "ML-DSA",
        members: &[KeyAlgorithm::Pq(0), KeyAlgorithm::Pq(1), KeyAlgorithm::Pq(2)],
        default_member: 0,
        custom_modulus: false,
    },
    Family {
        label: "SLH-DSA",
        members: &[
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
        ],
        default_member: 0,
        custom_modulus: false,
    },
    Family {
        label: "XMSS",
        members: &[
            KeyAlgorithm::Xmss(0),
            KeyAlgorithm::Xmss(1),
            KeyAlgorithm::Xmss(2),
            KeyAlgorithm::Xmss(3),
            KeyAlgorithm::Xmss(4),
            KeyAlgorithm::Xmss(5),
            KeyAlgorithm::Xmss(6),
            KeyAlgorithm::Xmss(7),
            KeyAlgorithm::Xmss(8),
            KeyAlgorithm::Xmss(9),
            KeyAlgorithm::Xmss(10),
            KeyAlgorithm::Xmss(11),
        ],
        default_member: 0,
        custom_modulus: false,
    },
];

/// Every supported algorithm — [`FAMILIES`] flattened in display order. Used
/// where the family structure does not matter (tests, exhaustive checks).
pub const ALL: &[KeyAlgorithm] = &[
    KeyAlgorithm::EcdsaP256,
    KeyAlgorithm::EcdsaP384,
    KeyAlgorithm::Rsa(0),
    KeyAlgorithm::Rsa(1),
    KeyAlgorithm::Rsa(2),
    KeyAlgorithm::Rsa(3),
    KeyAlgorithm::Rsa(4),
    KeyAlgorithm::Rsa(5),
    KeyAlgorithm::Rsa(6),
    KeyAlgorithm::Ed25519,
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
    KeyAlgorithm::Xmss(0),
    KeyAlgorithm::Xmss(1),
    KeyAlgorithm::Xmss(2),
    KeyAlgorithm::Xmss(3),
    KeyAlgorithm::Xmss(4),
    KeyAlgorithm::Xmss(5),
    KeyAlgorithm::Xmss(6),
    KeyAlgorithm::Xmss(7),
    KeyAlgorithm::Xmss(8),
    KeyAlgorithm::Xmss(9),
    KeyAlgorithm::Xmss(10),
    KeyAlgorithm::Xmss(11),
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

    fn rsa(self) -> Option<&'static RsaDesc> {
        match self {
            KeyAlgorithm::Rsa(i) => RSA.get(i),
            _ => None,
        }
    }

    fn xmss(self) -> Option<&'static XmssDesc> {
        match self {
            KeyAlgorithm::Xmss(i) => XMSS.get(i),
            _ => None,
        }
    }

    /// Human-readable label naming the full algorithm (family and parameters),
    /// used in status messages.
    pub fn label(self) -> String {
        match self {
            KeyAlgorithm::EcdsaP256 => "ECDSA P-256 (SHA-256)".to_string(),
            KeyAlgorithm::EcdsaP384 => "ECDSA P-384 (SHA-384)".to_string(),
            KeyAlgorithm::Ed25519 => "Ed25519".to_string(),
            KeyAlgorithm::Rsa(_) => self.rsa().map(|d| d.name).unwrap_or("RSA").to_string(),
            KeyAlgorithm::RsaCustom(bits) => format!("RSA-{} (SHA-256)", bits),
            KeyAlgorithm::Pq(_) => {
                self.pq().map(|d| d.name).unwrap_or("post-quantum").to_string()
            }
            KeyAlgorithm::Xmss(_) => {
                self.xmss().map(|d| d.name).unwrap_or("XMSS").to_string()
            }
        }
    }

    /// Label for the dialog's parameter column: the part of the algorithm the
    /// family name leaves open — the curve for ECDSA, the key size for RSA,
    /// the parameter set for ML-DSA/SLH-DSA (Ed25519 has no parameters). The
    /// custom-size RSA row is rendered from its entered digits instead.
    pub fn param_label(self) -> &'static str {
        match self {
            KeyAlgorithm::EcdsaP256 => "P-256",
            KeyAlgorithm::EcdsaP384 => "P-384",
            KeyAlgorithm::Ed25519 => "(none)",
            KeyAlgorithm::Rsa(_) => self.rsa().map(|d| d.param).unwrap_or("?"),
            KeyAlgorithm::RsaCustom(_) => "custom",
            KeyAlgorithm::Pq(_) => self.pq().map(|d| d.param).unwrap_or("?"),
            KeyAlgorithm::Xmss(_) => self.xmss().map(|d| d.param).unwrap_or("?"),
        }
    }

    /// Whether the re-key flow shows a time estimate / progress window for
    /// this algorithm: only the slow stateful/hash-based families, XMSS and
    /// SLH-DSA. Everything else (classical, ML-DSA) completes near-instantly.
    pub fn shows_time_estimate(self) -> bool {
        matches!(self, KeyAlgorithm::Xmss(_))
            || self.pq().is_some_and(|d| d.name.starts_with("SLH-DSA"))
    }

    /// Estimated key-generation time (seconds) on the calibration machine, or
    /// `None` for an algorithm without a time estimate. XMSS scales its
    /// height-10 anchor by `2^(height-10)`; SLH-DSA reads a measured constant.
    pub fn est_keygen_secs(self) -> Option<f64> {
        if !self.shows_time_estimate() {
            return None;
        }
        match self {
            KeyAlgorithm::Xmss(_) => {
                let d = self.xmss()?;
                Some(d.keygen_h10_secs * 2f64.powi(i32::from(d.height) - 10))
            }
            KeyAlgorithm::Pq(_) => self.pq().map(|d| d.keygen_secs),
            _ => None,
        }
    }

    /// Estimated single-signature time (seconds) on the calibration machine,
    /// or `None` for an algorithm without a time estimate. For XMSS this ≈ the
    /// keygen time: signing reloads the key and Botan reconstructs the full
    /// tree state on load.
    pub fn est_sign_secs(self) -> Option<f64> {
        if !self.shows_time_estimate() {
            return None;
        }
        match self {
            KeyAlgorithm::Xmss(_) => self.est_keygen_secs(),
            KeyAlgorithm::Pq(_) => self.pq().map(|d| d.sign_secs),
            _ => None,
        }
    }

    /// Short token used to derive the default key file name.
    pub fn short_name(self) -> String {
        match self {
            KeyAlgorithm::EcdsaP256 => "p256".to_string(),
            KeyAlgorithm::EcdsaP384 => "p384".to_string(),
            KeyAlgorithm::Ed25519 => "ed25519".to_string(),
            KeyAlgorithm::Rsa(_) => self.rsa().map(|d| d.short).unwrap_or("rsa").to_string(),
            // 0 bits means "nothing entered yet" on the custom row; keep the
            // derived default file name generic until digits arrive.
            KeyAlgorithm::RsaCustom(0) => "rsa".to_string(),
            KeyAlgorithm::RsaCustom(bits) => format!("rsa{}", bits),
            KeyAlgorithm::Pq(_) => self.pq().map(|d| d.short).unwrap_or("pq").to_string(),
            KeyAlgorithm::Xmss(_) => {
                self.xmss().map(|d| d.short).unwrap_or("xmss").to_string()
            }
        }
    }

    /// The X.509 `signatureAlgorithm` OID arcs for signatures made with a key
    /// of this algorithm.
    pub fn sig_alg_oid(self) -> &'static [u64] {
        match self {
            KeyAlgorithm::EcdsaP256 => ECDSA_WITH_SHA256,
            KeyAlgorithm::EcdsaP384 => ECDSA_WITH_SHA384,
            KeyAlgorithm::Ed25519 => ED25519_OID,
            KeyAlgorithm::Rsa(_) | KeyAlgorithm::RsaCustom(_) => SHA256_WITH_RSA,
            KeyAlgorithm::Pq(_) => self.pq().map(|d| d.oid).unwrap_or(&[]),
            KeyAlgorithm::Xmss(_) => crate::xmss::XMSS_OID,
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
        if matches!(self, KeyAlgorithm::Rsa(_) | KeyAlgorithm::RsaCustom(_)) {
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
            KeyAlgorithm::Rsa(_) => {
                let bits = self.rsa().ok_or("unknown RSA key size")?.bits;
                rsa_key(bits).map_err(crypto)
            }
            KeyAlgorithm::RsaCustom(bits) => {
                if !(RSA_CUSTOM_BITS_MIN..=RSA_CUSTOM_BITS_MAX).contains(&bits) {
                    return Err(format!(
                        "the RSA modulus size must be between {} and {} bits",
                        RSA_CUSTOM_BITS_MIN, RSA_CUSTOM_BITS_MAX
                    ));
                }
                rsa_key(bits).map_err(crypto)
            }
            KeyAlgorithm::Pq(_) => {
                let name = self.pq().ok_or("unknown post-quantum algorithm")?.name;
                generate_by_name(name)
            }
            // XMSS is generated by the Botan backend; `generate` intercepts
            // it before this OpenSSL path.
            KeyAlgorithm::Xmss(_) => Err("XMSS keys are generated via Botan".to_string()),
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
    /// (PBES2/PBKDF2/AES-256-CBC — the scheme `pkcs8.rs` decrypts). An XMSS
    /// key is encrypted by Botan instead (OpenSSL cannot load it) into the
    /// same PBES2 shape.
    pub fn key_file_der(&self, password: &[u8]) -> Result<Vec<u8>, String> {
        encrypt_key_file_der(&self.pkcs8, password)
    }
}

/// Serialize a private key for a key file: the plaintext PKCS#8 when
/// `password` is empty, otherwise an encrypted `EncryptedPrivateKeyInfo`
/// (PBES2/PBKDF2/AES-256-CBC — the scheme `pkcs8.rs` decrypts). An XMSS key
/// is encrypted by Botan (OpenSSL cannot load it); everything else by
/// OpenSSL. Used both for freshly generated keys and to write a stateful
/// key's advanced state back to disk after signing.
pub fn encrypt_key_file_der(pkcs8: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    if password.is_empty() {
        return Ok(pkcs8.to_vec());
    }
    // An XMSS key file carries Botan's native OID; recognize either XMSS OID.
    if crate::verify::pkcs8_alg_arcs(pkcs8).as_deref().is_some_and(crate::xmss::is_xmss_oid) {
        let password = std::str::from_utf8(password)
            .map_err(|_| "the password is not valid UTF-8".to_string())?;
        return crate::xmss::encrypt_pkcs8(pkcs8, password);
    }
    let crypto = |e: openssl::error::ErrorStack| format!("key encryption failed: {}", e);
    let pkey = PKey::private_key_from_pkcs8(pkcs8).map_err(crypto)?;
    pkey.private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), password).map_err(crypto)
}

/// Generate a new private key for `alg`.
pub fn generate(alg: KeyAlgorithm) -> Result<GeneratedKey, String> {
    // XMSS comes from the Botan backend; everything else from OpenSSL.
    if let KeyAlgorithm::Xmss(_) = alg {
        let params = alg.xmss().ok_or("unknown XMSS parameter set")?.name;
        let (pkcs8, spki) = crate::xmss::generate(params)?;
        return Ok(GeneratedKey { pkcs8, spki });
    }
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

    /// Very large RSA moduli and tall XMSS trees take from tens of seconds
    /// to a minute to generate; the tests skip them (the generation code
    /// path is identical to the smaller parameters).
    fn slow_to_generate(alg: KeyAlgorithm) -> bool {
        alg.rsa().is_some_and(|d| d.bits > 4096)
            || alg.xmss().is_some_and(|d| !d.name.contains("_10_"))
    }

    #[test]
    fn every_algorithm_generates_a_key_and_pq_spki_carries_its_oid() {
        for &alg in ALL.iter().filter(|&&a| !slow_to_generate(a)) {
            let key = generate(alg).unwrap_or_else(|e| panic!("{}: {}", alg.label(), e));
            assert!(!key.pkcs8.is_empty() && !key.spki.is_empty(), "{}", alg.label());
            // A post-quantum or XMSS SPKI's AlgorithmIdentifier is the
            // signature OID.
            if alg.pq().is_some() || alg.xmss().is_some() {
                assert_eq!(spki_alg_oid(&key.spki), alg.sig_alg_oid(), "{}", alg.label());
            }
        }
    }

    #[test]
    fn families_flatten_to_all_and_default_members_are_valid() {
        let flattened: Vec<KeyAlgorithm> =
            FAMILIES.iter().flat_map(|f| f.members.iter().copied()).collect();
        assert_eq!(flattened, ALL);
        for family in FAMILIES {
            assert!(family.default_member < family.members.len(), "{}", family.label);
            for &member in family.members {
                assert!(!member.param_label().is_empty(), "{}", member.label());
            }
        }
    }

    #[test]
    fn xmss_family_offers_the_rfc8391_and_sp800_208_parameter_sets() {
        // Every offered XMSS parameter set, by its Botan name — the RFC 8391
        // 256-bit and 512-bit (n=64) sets plus the NIST SP 800-208 192-bit
        // (truncated-hash) additions, each at tree heights 10 and 16.
        let xmss = FAMILIES.iter().find(|f| f.label == "XMSS").expect("XMSS family");
        let names: Vec<String> = xmss.members.iter().map(|m| m.label()).collect();
        for expected in [
            "XMSS-SHA2_10_256",
            "XMSS-SHA2_16_256",
            "XMSS-SHAKE_10_256",
            "XMSS-SHAKE_16_256",
            "XMSS-SHA2_10_192",
            "XMSS-SHA2_16_192",
            "XMSS-SHAKE256_10_192",
            "XMSS-SHAKE256_16_192",
            "XMSS-SHA2_10_512",
            "XMSS-SHA2_16_512",
            "XMSS-SHAKE_10_512",
            "XMSS-SHAKE_16_512",
        ] {
            assert!(names.iter().any(|n| n == expected), "missing XMSS set {}", expected);
        }
        // All XMSS sets share the one id-alg-xmss-hashsig OID, and each has a
        // distinct filename token.
        for &m in xmss.members {
            assert_eq!(m.sig_alg_oid(), crate::xmss::XMSS_OID, "{}", m.label());
        }
        let mut shorts: Vec<String> = xmss.members.iter().map(|m| m.short_name()).collect();
        let unique = shorts.len();
        shorts.sort();
        shorts.dedup();
        assert_eq!(shorts.len(), unique, "XMSS filename tokens must be unique");
    }

    #[test]
    fn signing_round_trips_for_classical_ml_dsa_and_fast_slh_dsa() {
        let tbs = b"a message standing in for a tbsCertificate";
        for &alg in ALL.iter().filter(|&&a| !slow_to_sign(a) && !slow_to_generate(a)) {
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
            (KeyAlgorithm::Rsa(3), 2), // RSA-2048
        ] {
            let der = alg.sig_alg_identifier_der();
            let roots = ber::parse_forest(&der, 0).unwrap();
            assert!(roots[0].is_universal(TAG_SEQUENCE));
            assert_eq!(roots[0].children.len(), children, "{}", alg.label());
            assert!(roots[0].children[0].is_universal(TAG_OID));
        }
    }
}
