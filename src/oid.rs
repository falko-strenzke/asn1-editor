// Copyright 2026 Falko Strenzke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Built-in names for OIDs commonly encountered in PKI and cryptography.
//!
//! This deliberately is a small, curated repository rather than an online
//! resolver.  Keeping both the arcs and the textual path here makes lookup
//! deterministic and lets the TUI show useful names without network access.

/// A resolved object identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OidEntry {
    /// Numeric dot notation, retained for display without reformatting.
    pub dotted: &'static str,
    /// The final token in `chain`, used as the compact tree label.
    pub short_name: &'static str,
    /// Textual tokens from the root arc through the assigned object.
    pub chain: &'static [&'static str],
    arcs: &'static [u64],
}

macro_rules! oid {
    ($dotted:expr, [$($arc:expr),+], $short:literal, [$($token:literal),+]) => {
        OidEntry {
            dotted: $dotted,
            short_name: $short,
            chain: &[$($token),+],
            arcs: &[$($arc),+],
        }
    };
}

macro_rules! nist_sig {
    ($number:expr, $name:literal) => {
        oid!(
            concat!("2.16.840.1.101.3.4.3.", stringify!($number)),
            [2, 16, 840, 1, 101, 3, 4, 3, $number],
            $name,
            [
                "joint-iso-itu-t",
                "country",
                "us",
                "organization",
                "gov",
                "csor",
                "nistAlgorithm",
                "sigAlgs",
                $name
            ]
        )
    };
}

/// Curated built-in repository.
///
/// Names follow the ASN.1 identifiers used by the defining standards.  The
/// post-quantum assignments are from NIST's Computer Security Objects
/// Register; the remaining entries come from the applicable PKCS, CMS,
/// X.500/X.509, SEC/ANSI, NIST, and IETF specifications.
pub static OIDS: &[OidEntry] = &[
    // XMSS (RFC 9802, June 2025) — id-alg-xmss-hashsig on the PKIX algorithms
    // arc. This is the OID this tool writes into a certificate's
    // SubjectPublicKeyInfo and the certificate/CRL signatureAlgorithm.
    oid!(
        "1.3.6.1.5.5.7.6.34",
        [1, 3, 6, 1, 5, 5, 7, 6, 34],
        "id-alg-xmss-hashsig",
        [
            "iso",
            "identified-organization",
            "dod",
            "internet",
            "security",
            "mechanisms",
            "pkix",
            "algorithms",
            "id-alg-xmss-hashsig"
        ]
    ),
    // XMSS (RFC 8391) — the ETSI/ISARA id-alg-xmss-hashsig assignment Botan
    // uses natively in the private-key files it produces (distinct from the
    // RFC 9802 OID above, which this tool uses in X.509 objects).
    oid!(
        "0.4.0.127.0.15.1.1.13.0",
        [0, 4, 0, 127, 0, 15, 1, 1, 13, 0],
        "id-alg-xmss-hashsig",
        [
            "itu-t",
            "identified-organization",
            "etsi",
            "reserved",
            "etsi-identified-organization",
            "bsi-de",
            "algorithms",
            "sigAlgs",
            "xmss",
            "id-alg-xmss-hashsig"
        ]
    ),
    // ANSI X9.62 / SEC elliptic-curve algorithms and named curves.
    oid!(
        "1.2.840.10045.2.1",
        [1, 2, 840, 10045, 2, 1],
        "ecPublicKey",
        [
            "iso",
            "member-body",
            "us",
            "ansi-X9-62",
            "keyType",
            "ecPublicKey"
        ]
    ),
    oid!(
        "1.2.840.10045.3.1.7",
        [1, 2, 840, 10045, 3, 1, 7],
        "prime256v1",
        [
            "iso",
            "member-body",
            "us",
            "ansi-X9-62",
            "curves",
            "prime",
            "prime256v1"
        ]
    ),
    oid!(
        "1.2.840.10045.4.1",
        [1, 2, 840, 10045, 4, 1],
        "ecdsaWithSHA1",
        [
            "iso",
            "member-body",
            "us",
            "ansi-X9-62",
            "signatures",
            "ecdsaWithSHA1"
        ]
    ),
    oid!(
        "1.2.840.10045.4.3.1",
        [1, 2, 840, 10045, 4, 3, 1],
        "ecdsaWithSHA224",
        [
            "iso",
            "member-body",
            "us",
            "ansi-X9-62",
            "signatures",
            "ecdsa-with-SHA2",
            "ecdsaWithSHA224"
        ]
    ),
    oid!(
        "1.2.840.10045.4.3.2",
        [1, 2, 840, 10045, 4, 3, 2],
        "ecdsaWithSHA256",
        [
            "iso",
            "member-body",
            "us",
            "ansi-X9-62",
            "signatures",
            "ecdsa-with-SHA2",
            "ecdsaWithSHA256"
        ]
    ),
    oid!(
        "1.2.840.10045.4.3.3",
        [1, 2, 840, 10045, 4, 3, 3],
        "ecdsaWithSHA384",
        [
            "iso",
            "member-body",
            "us",
            "ansi-X9-62",
            "signatures",
            "ecdsa-with-SHA2",
            "ecdsaWithSHA384"
        ]
    ),
    oid!(
        "1.2.840.10045.4.3.4",
        [1, 2, 840, 10045, 4, 3, 4],
        "ecdsaWithSHA512",
        [
            "iso",
            "member-body",
            "us",
            "ansi-X9-62",
            "signatures",
            "ecdsa-with-SHA2",
            "ecdsaWithSHA512"
        ]
    ),
    // PKCS #1, #5, #7/CMS, #9, and RSADSI digest algorithms.
    oid!(
        "1.2.840.113549.1.1.1",
        [1, 2, 840, 113549, 1, 1, 1],
        "rsaEncryption",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-1",
            "rsaEncryption"
        ]
    ),
    oid!(
        "1.2.840.113549.1.1.5",
        [1, 2, 840, 113549, 1, 1, 5],
        "sha1WithRSAEncryption",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-1",
            "sha1WithRSAEncryption"
        ]
    ),
    oid!(
        "1.2.840.113549.1.1.7",
        [1, 2, 840, 113549, 1, 1, 7],
        "rsaesOaep",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-1",
            "rsaesOaep"
        ]
    ),
    oid!(
        "1.2.840.113549.1.1.8",
        [1, 2, 840, 113549, 1, 1, 8],
        "mgf1",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-1",
            "mgf1"
        ]
    ),
    oid!(
        "1.2.840.113549.1.1.10",
        [1, 2, 840, 113549, 1, 1, 10],
        "rsassaPss",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-1",
            "rsassaPss"
        ]
    ),
    oid!(
        "1.2.840.113549.1.1.11",
        [1, 2, 840, 113549, 1, 1, 11],
        "sha256WithRSAEncryption",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-1",
            "sha256WithRSAEncryption"
        ]
    ),
    oid!(
        "1.2.840.113549.1.1.12",
        [1, 2, 840, 113549, 1, 1, 12],
        "sha384WithRSAEncryption",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-1",
            "sha384WithRSAEncryption"
        ]
    ),
    oid!(
        "1.2.840.113549.1.1.13",
        [1, 2, 840, 113549, 1, 1, 13],
        "sha512WithRSAEncryption",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-1",
            "sha512WithRSAEncryption"
        ]
    ),
    oid!(
        "1.2.840.113549.1.1.14",
        [1, 2, 840, 113549, 1, 1, 14],
        "sha224WithRSAEncryption",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-1",
            "sha224WithRSAEncryption"
        ]
    ),
    oid!(
        "1.2.840.113549.1.5.12",
        [1, 2, 840, 113549, 1, 5, 12],
        "PBKDF2",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-5",
            "PBKDF2"
        ]
    ),
    oid!(
        "1.2.840.113549.1.5.13",
        [1, 2, 840, 113549, 1, 5, 13],
        "PBES2",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-5",
            "PBES2"
        ]
    ),
    oid!(
        "1.2.840.113549.1.7.1",
        [1, 2, 840, 113549, 1, 7, 1],
        "data",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-7",
            "data"
        ]
    ),
    oid!(
        "1.2.840.113549.1.7.2",
        [1, 2, 840, 113549, 1, 7, 2],
        "signedData",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-7",
            "signedData"
        ]
    ),
    oid!(
        "1.2.840.113549.1.7.3",
        [1, 2, 840, 113549, 1, 7, 3],
        "envelopedData",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-7",
            "envelopedData"
        ]
    ),
    oid!(
        "1.2.840.113549.1.7.5",
        [1, 2, 840, 113549, 1, 7, 5],
        "digestedData",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-7",
            "digestedData"
        ]
    ),
    oid!(
        "1.2.840.113549.1.7.6",
        [1, 2, 840, 113549, 1, 7, 6],
        "encryptedData",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-7",
            "encryptedData"
        ]
    ),
    oid!(
        "1.2.840.113549.1.9.1",
        [1, 2, 840, 113549, 1, 9, 1],
        "emailAddress",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-9",
            "emailAddress"
        ]
    ),
    // PKCS#9 attributes carried by CMS signedAttrs (RFC 5652 §11).
    oid!(
        "1.2.840.113549.1.9.3",
        [1, 2, 840, 113549, 1, 9, 3],
        "contentType",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-9",
            "contentType"
        ]
    ),
    oid!(
        "1.2.840.113549.1.9.4",
        [1, 2, 840, 113549, 1, 9, 4],
        "messageDigest",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-9",
            "messageDigest"
        ]
    ),
    oid!(
        "1.2.840.113549.1.9.5",
        [1, 2, 840, 113549, 1, 9, 5],
        "signingTime",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-9",
            "signingTime"
        ]
    ),
    // PKCS#9 attributes carried by PKCS#12 SafeBags (RFC 7292 / RFC 2985).
    oid!(
        "1.2.840.113549.1.9.20",
        [1, 2, 840, 113549, 1, 9, 20],
        "friendlyName",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-9",
            "friendlyName"
        ]
    ),
    oid!(
        "1.2.840.113549.1.9.21",
        [1, 2, 840, 113549, 1, 9, 21],
        "localKeyId",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "pkcs",
            "pkcs-9",
            "localKeyId"
        ]
    ),
    // PKCS#12 bag types (RFC 7292 §4.2), bagtypes ::= {pkcs-12 10 1}.
    oid!(
        "1.2.840.113549.1.12.10.1.1",
        [1, 2, 840, 113549, 1, 12, 10, 1, 1],
        "keyBag",
        ["iso", "member-body", "us", "rsadsi", "pkcs", "pkcs-12", "bagtypes", "keyBag"]
    ),
    oid!(
        "1.2.840.113549.1.12.10.1.2",
        [1, 2, 840, 113549, 1, 12, 10, 1, 2],
        "pkcs8ShroudedKeyBag",
        ["iso", "member-body", "us", "rsadsi", "pkcs", "pkcs-12", "bagtypes", "pkcs8ShroudedKeyBag"]
    ),
    oid!(
        "1.2.840.113549.1.12.10.1.3",
        [1, 2, 840, 113549, 1, 12, 10, 1, 3],
        "certBag",
        ["iso", "member-body", "us", "rsadsi", "pkcs", "pkcs-12", "bagtypes", "certBag"]
    ),
    oid!(
        "1.2.840.113549.1.12.10.1.4",
        [1, 2, 840, 113549, 1, 12, 10, 1, 4],
        "crlBag",
        ["iso", "member-body", "us", "rsadsi", "pkcs", "pkcs-12", "bagtypes", "crlBag"]
    ),
    oid!(
        "1.2.840.113549.1.12.10.1.5",
        [1, 2, 840, 113549, 1, 12, 10, 1, 5],
        "secretBag",
        ["iso", "member-body", "us", "rsadsi", "pkcs", "pkcs-12", "bagtypes", "secretBag"]
    ),
    oid!(
        "1.2.840.113549.1.12.10.1.6",
        [1, 2, 840, 113549, 1, 12, 10, 1, 6],
        "safeContentsBag",
        ["iso", "member-body", "us", "rsadsi", "pkcs", "pkcs-12", "bagtypes", "safeContentsBag"]
    ),
    oid!(
        "1.2.840.113549.2.7",
        [1, 2, 840, 113549, 2, 7],
        "hmacWithSHA1",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "digestAlgorithm",
            "hmacWithSHA1"
        ]
    ),
    oid!(
        "1.2.840.113549.2.9",
        [1, 2, 840, 113549, 2, 9],
        "hmacWithSHA256",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "digestAlgorithm",
            "hmacWithSHA256"
        ]
    ),
    oid!(
        "1.2.840.113549.2.10",
        [1, 2, 840, 113549, 2, 10],
        "hmacWithSHA384",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "digestAlgorithm",
            "hmacWithSHA384"
        ]
    ),
    oid!(
        "1.2.840.113549.2.11",
        [1, 2, 840, 113549, 2, 11],
        "hmacWithSHA512",
        [
            "iso",
            "member-body",
            "us",
            "rsadsi",
            "digestAlgorithm",
            "hmacWithSHA512"
        ]
    ),
    // PKIX key-purpose identifiers.
    oid!(
        "1.3.6.1.5.5.7.3.1",
        [1, 3, 6, 1, 5, 5, 7, 3, 1],
        "serverAuth",
        [
            "iso",
            "identified-organization",
            "dod",
            "internet",
            "security",
            "mechanisms",
            "pkix",
            "kp",
            "serverAuth"
        ]
    ),
    oid!(
        "1.3.6.1.5.5.7.3.2",
        [1, 3, 6, 1, 5, 5, 7, 3, 2],
        "clientAuth",
        [
            "iso",
            "identified-organization",
            "dod",
            "internet",
            "security",
            "mechanisms",
            "pkix",
            "kp",
            "clientAuth"
        ]
    ),
    oid!(
        "1.3.6.1.5.5.7.3.3",
        [1, 3, 6, 1, 5, 5, 7, 3, 3],
        "codeSigning",
        [
            "iso",
            "identified-organization",
            "dod",
            "internet",
            "security",
            "mechanisms",
            "pkix",
            "kp",
            "codeSigning"
        ]
    ),
    oid!(
        "1.3.6.1.5.5.7.3.4",
        [1, 3, 6, 1, 5, 5, 7, 3, 4],
        "emailProtection",
        [
            "iso",
            "identified-organization",
            "dod",
            "internet",
            "security",
            "mechanisms",
            "pkix",
            "kp",
            "emailProtection"
        ]
    ),
    oid!(
        "1.3.6.1.5.5.7.3.8",
        [1, 3, 6, 1, 5, 5, 7, 3, 8],
        "timeStamping",
        [
            "iso",
            "identified-organization",
            "dod",
            "internet",
            "security",
            "mechanisms",
            "pkix",
            "kp",
            "timeStamping"
        ]
    ),
    oid!(
        "1.3.6.1.5.5.7.3.9",
        [1, 3, 6, 1, 5, 5, 7, 3, 9],
        "OCSPSigning",
        [
            "iso",
            "identified-organization",
            "dod",
            "internet",
            "security",
            "mechanisms",
            "pkix",
            "kp",
            "OCSPSigning"
        ]
    ),
    // Curve25519/448 and EdDSA identifiers.
    oid!(
        "1.3.101.110",
        [1, 3, 101, 110],
        "X25519",
        ["iso", "identified-organization", "thawte", "X25519"]
    ),
    oid!(
        "1.3.101.111",
        [1, 3, 101, 111],
        "X448",
        ["iso", "identified-organization", "thawte", "X448"]
    ),
    oid!(
        "1.3.101.112",
        [1, 3, 101, 112],
        "Ed25519",
        ["iso", "identified-organization", "thawte", "Ed25519"]
    ),
    oid!(
        "1.3.101.113",
        [1, 3, 101, 113],
        "Ed448",
        ["iso", "identified-organization", "thawte", "Ed448"]
    ),
    // SEC named curves.
    oid!(
        "1.3.132.0.10",
        [1, 3, 132, 0, 10],
        "secp256k1",
        [
            "iso",
            "identified-organization",
            "certicom",
            "curve",
            "secp256k1"
        ]
    ),
    oid!(
        "1.3.132.0.34",
        [1, 3, 132, 0, 34],
        "secp384r1",
        [
            "iso",
            "identified-organization",
            "certicom",
            "curve",
            "secp384r1"
        ]
    ),
    oid!(
        "1.3.132.0.35",
        [1, 3, 132, 0, 35],
        "secp521r1",
        [
            "iso",
            "identified-organization",
            "certicom",
            "curve",
            "secp521r1"
        ]
    ),
    // NIST AES modes and hash algorithms.
    oid!(
        "2.16.840.1.101.3.4.1.2",
        [2, 16, 840, 1, 101, 3, 4, 1, 2],
        "aes128-CBC",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "aes",
            "aes128-CBC"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.1.6",
        [2, 16, 840, 1, 101, 3, 4, 1, 6],
        "aes128-GCM",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "aes",
            "aes128-GCM"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.1.22",
        [2, 16, 840, 1, 101, 3, 4, 1, 22],
        "aes192-CBC",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "aes",
            "aes192-CBC"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.1.26",
        [2, 16, 840, 1, 101, 3, 4, 1, 26],
        "aes192-GCM",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "aes",
            "aes192-GCM"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.1.42",
        [2, 16, 840, 1, 101, 3, 4, 1, 42],
        "aes256-CBC",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "aes",
            "aes256-CBC"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.1.46",
        [2, 16, 840, 1, 101, 3, 4, 1, 46],
        "aes256-GCM",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "aes",
            "aes256-GCM"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.2.1",
        [2, 16, 840, 1, 101, 3, 4, 2, 1],
        "id-sha256",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "hashAlgs",
            "id-sha256"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.2.2",
        [2, 16, 840, 1, 101, 3, 4, 2, 2],
        "id-sha384",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "hashAlgs",
            "id-sha384"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.2.3",
        [2, 16, 840, 1, 101, 3, 4, 2, 3],
        "id-sha512",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "hashAlgs",
            "id-sha512"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.2.4",
        [2, 16, 840, 1, 101, 3, 4, 2, 4],
        "id-sha224",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "hashAlgs",
            "id-sha224"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.2.8",
        [2, 16, 840, 1, 101, 3, 4, 2, 8],
        "id-sha3-256",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "hashAlgs",
            "id-sha3-256"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.2.9",
        [2, 16, 840, 1, 101, 3, 4, 2, 9],
        "id-sha3-384",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "hashAlgs",
            "id-sha3-384"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.2.10",
        [2, 16, 840, 1, 101, 3, 4, 2, 10],
        "id-sha3-512",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "hashAlgs",
            "id-sha3-512"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.2.11",
        [2, 16, 840, 1, 101, 3, 4, 2, 11],
        "id-shake128",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "hashAlgs",
            "id-shake128"
        ]
    ),
    oid!(
        "2.16.840.1.101.3.4.2.12",
        [2, 16, 840, 1, 101, 3, 4, 2, 12],
        "id-shake256",
        [
            "joint-iso-itu-t",
            "country",
            "us",
            "organization",
            "gov",
            "csor",
            "nistAlgorithm",
            "hashAlgs",
            "id-shake256"
        ]
    ),
    // FIPS 204 ML-DSA and HashML-DSA assignments (NIST CSOR).
    nist_sig!(17, "id-ml-dsa-44"),
    nist_sig!(18, "id-ml-dsa-65"),
    nist_sig!(19, "id-ml-dsa-87"),
    nist_sig!(32, "id-hash-ml-dsa-44-with-sha512"),
    nist_sig!(33, "id-hash-ml-dsa-65-with-sha512"),
    nist_sig!(34, "id-hash-ml-dsa-87-with-sha512"),
    // FIPS 205 SLH-DSA and HashSLH-DSA assignments (NIST CSOR).
    nist_sig!(20, "id-slh-dsa-sha2-128s"),
    nist_sig!(21, "id-slh-dsa-sha2-128f"),
    nist_sig!(22, "id-slh-dsa-sha2-192s"),
    nist_sig!(23, "id-slh-dsa-sha2-192f"),
    nist_sig!(24, "id-slh-dsa-sha2-256s"),
    nist_sig!(25, "id-slh-dsa-sha2-256f"),
    nist_sig!(26, "id-slh-dsa-shake-128s"),
    nist_sig!(27, "id-slh-dsa-shake-128f"),
    nist_sig!(28, "id-slh-dsa-shake-192s"),
    nist_sig!(29, "id-slh-dsa-shake-192f"),
    nist_sig!(30, "id-slh-dsa-shake-256s"),
    nist_sig!(31, "id-slh-dsa-shake-256f"),
    nist_sig!(35, "id-hash-slh-dsa-sha2-128s-with-sha256"),
    nist_sig!(36, "id-hash-slh-dsa-sha2-128f-with-sha256"),
    nist_sig!(37, "id-hash-slh-dsa-sha2-192s-with-sha512"),
    nist_sig!(38, "id-hash-slh-dsa-sha2-192f-with-sha512"),
    nist_sig!(39, "id-hash-slh-dsa-sha2-256s-with-sha512"),
    nist_sig!(40, "id-hash-slh-dsa-sha2-256f-with-sha512"),
    nist_sig!(41, "id-hash-slh-dsa-shake-128s-with-shake128"),
    nist_sig!(42, "id-hash-slh-dsa-shake-128f-with-shake128"),
    nist_sig!(43, "id-hash-slh-dsa-shake-192s-with-shake256"),
    nist_sig!(44, "id-hash-slh-dsa-shake-192f-with-shake256"),
    nist_sig!(45, "id-hash-slh-dsa-shake-256s-with-shake256"),
    nist_sig!(46, "id-hash-slh-dsa-shake-256f-with-shake256"),
    // X.500 distinguished-name attributes.
    oid!(
        "2.5.4.3",
        [2, 5, 4, 3],
        "commonName",
        ["joint-iso-itu-t", "ds", "attributeType", "commonName"]
    ),
    oid!(
        "2.5.4.4",
        [2, 5, 4, 4],
        "surname",
        ["joint-iso-itu-t", "ds", "attributeType", "surname"]
    ),
    oid!(
        "2.5.4.5",
        [2, 5, 4, 5],
        "serialNumber",
        ["joint-iso-itu-t", "ds", "attributeType", "serialNumber"]
    ),
    oid!(
        "2.5.4.6",
        [2, 5, 4, 6],
        "countryName",
        ["joint-iso-itu-t", "ds", "attributeType", "countryName"]
    ),
    oid!(
        "2.5.4.7",
        [2, 5, 4, 7],
        "localityName",
        ["joint-iso-itu-t", "ds", "attributeType", "localityName"]
    ),
    oid!(
        "2.5.4.8",
        [2, 5, 4, 8],
        "stateOrProvinceName",
        [
            "joint-iso-itu-t",
            "ds",
            "attributeType",
            "stateOrProvinceName"
        ]
    ),
    oid!(
        "2.5.4.9",
        [2, 5, 4, 9],
        "streetAddress",
        ["joint-iso-itu-t", "ds", "attributeType", "streetAddress"]
    ),
    oid!(
        "2.5.4.10",
        [2, 5, 4, 10],
        "organizationName",
        ["joint-iso-itu-t", "ds", "attributeType", "organizationName"]
    ),
    oid!(
        "2.5.4.11",
        [2, 5, 4, 11],
        "organizationalUnitName",
        [
            "joint-iso-itu-t",
            "ds",
            "attributeType",
            "organizationalUnitName"
        ]
    ),
    oid!(
        "2.5.4.12",
        [2, 5, 4, 12],
        "title",
        ["joint-iso-itu-t", "ds", "attributeType", "title"]
    ),
    oid!(
        "2.5.4.42",
        [2, 5, 4, 42],
        "givenName",
        ["joint-iso-itu-t", "ds", "attributeType", "givenName"]
    ),
    oid!(
        "2.5.4.46",
        [2, 5, 4, 46],
        "dnQualifier",
        ["joint-iso-itu-t", "ds", "attributeType", "dnQualifier"]
    ),
    oid!(
        "2.5.4.65",
        [2, 5, 4, 65],
        "pseudonym",
        ["joint-iso-itu-t", "ds", "attributeType", "pseudonym"]
    ),
    // X.509 certificate and CRL extensions.
    oid!(
        "2.5.29.14",
        [2, 5, 29, 14],
        "subjectKeyIdentifier",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "subjectKeyIdentifier"
        ]
    ),
    oid!(
        "2.5.29.15",
        [2, 5, 29, 15],
        "keyUsage",
        ["joint-iso-itu-t", "ds", "certificateExtension", "keyUsage"]
    ),
    oid!(
        "2.5.29.16",
        [2, 5, 29, 16],
        "privateKeyUsagePeriod",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "privateKeyUsagePeriod"
        ]
    ),
    oid!(
        "2.5.29.17",
        [2, 5, 29, 17],
        "subjectAltName",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "subjectAltName"
        ]
    ),
    oid!(
        "2.5.29.18",
        [2, 5, 29, 18],
        "issuerAltName",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "issuerAltName"
        ]
    ),
    oid!(
        "2.5.29.19",
        [2, 5, 29, 19],
        "basicConstraints",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "basicConstraints"
        ]
    ),
    oid!(
        "2.5.29.20",
        [2, 5, 29, 20],
        "cRLNumber",
        ["joint-iso-itu-t", "ds", "certificateExtension", "cRLNumber"]
    ),
    oid!(
        "2.5.29.21",
        [2, 5, 29, 21],
        "reasonCode",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "reasonCode"
        ]
    ),
    oid!(
        "2.5.29.24",
        [2, 5, 29, 24],
        "invalidityDate",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "invalidityDate"
        ]
    ),
    oid!(
        "2.5.29.27",
        [2, 5, 29, 27],
        "deltaCRLIndicator",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "deltaCRLIndicator"
        ]
    ),
    oid!(
        "2.5.29.28",
        [2, 5, 29, 28],
        "issuingDistributionPoint",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "issuingDistributionPoint"
        ]
    ),
    oid!(
        "2.5.29.29",
        [2, 5, 29, 29],
        "certificateIssuer",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "certificateIssuer"
        ]
    ),
    oid!(
        "2.5.29.30",
        [2, 5, 29, 30],
        "nameConstraints",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "nameConstraints"
        ]
    ),
    oid!(
        "2.5.29.31",
        [2, 5, 29, 31],
        "cRLDistributionPoints",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "cRLDistributionPoints"
        ]
    ),
    oid!(
        "2.5.29.32",
        [2, 5, 29, 32],
        "certificatePolicies",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "certificatePolicies"
        ]
    ),
    oid!(
        "2.5.29.33",
        [2, 5, 29, 33],
        "policyMappings",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "policyMappings"
        ]
    ),
    oid!(
        "2.5.29.35",
        [2, 5, 29, 35],
        "authorityKeyIdentifier",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "authorityKeyIdentifier"
        ]
    ),
    oid!(
        "2.5.29.36",
        [2, 5, 29, 36],
        "policyConstraints",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "policyConstraints"
        ]
    ),
    oid!(
        "2.5.29.37",
        [2, 5, 29, 37],
        "extKeyUsage",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "extKeyUsage"
        ]
    ),
    oid!(
        "2.5.29.46",
        [2, 5, 29, 46],
        "freshestCRL",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "freshestCRL"
        ]
    ),
    oid!(
        "2.5.29.54",
        [2, 5, 29, 54],
        "inhibitAnyPolicy",
        [
            "joint-iso-itu-t",
            "ds",
            "certificateExtension",
            "inhibitAnyPolicy"
        ]
    ),
];

/// Find a built-in OID by numeric arcs.
pub fn lookup(arcs: &[u64]) -> Option<&'static OidEntry> {
    OIDS.iter().find(|entry| entry.arcs == arcs)
}

/// Format arbitrary arcs in dot notation.
pub fn dotted(arcs: &[u64]) -> String {
    arcs.iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

impl OidEntry {
    /// The complete textual resolution, from root to leaf.
    pub fn long_name(&self) -> String {
        self.chain.join(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_entries_are_self_consistent_and_unique() {
        for (i, entry) in OIDS.iter().enumerate() {
            assert_eq!(dotted(entry.arcs), entry.dotted);
            assert_eq!(entry.chain.last().copied(), Some(entry.short_name));
            assert!(!entry.chain.is_empty());
            assert!(OIDS[..i].iter().all(|earlier| earlier.arcs != entry.arcs));
        }
    }

    #[test]
    fn lookup_returns_short_and_long_names() {
        let entry = lookup(&[1, 2, 840, 10045, 4, 3, 2]).unwrap();
        assert_eq!(entry.short_name, "ecdsaWithSHA256");
        assert_eq!(
            entry.long_name(),
            "iso.member-body.us.ansi-X9-62.signatures.ecdsa-with-SHA2.ecdsaWithSHA256"
        );
    }
}
