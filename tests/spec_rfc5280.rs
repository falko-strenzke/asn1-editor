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

//! End-to-end tests of the ASN.1 specification support against the real
//! bundled modules in `specs/asn1` (RFC 5280 certificates/CRLs, RFC 5208
//! PKCS#8 private keys, RFC 5958 asymmetric key packages) and the DER test
//! files.

use std::path::Path;

use asn1_editor::{ber, spec};

fn manifest(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// The database of every bundled spec module (all files in `specs/asn1`).
/// Named for RFC 5280 for historical reasons; it is the whole directory.
fn rfc5280_db() -> spec::SpecDb {
    let (db, errors) = spec::load_dir(&manifest("specs/asn1"));
    assert!(errors.is_empty(), "spec parse errors: {:?}", errors);
    assert!(!db.is_empty());
    db
}

/// A database built from just the named spec files (in `specs/asn1`), for
/// testing behavior with a subset of the bundled modules present.
fn db_from(files: &[&str]) -> spec::SpecDb {
    let mut db = spec::SpecDb::default();
    for f in files {
        let text = std::fs::read_to_string(manifest(&format!("specs/asn1/{}", f))).unwrap();
        db.add(spec::parse_spec(f, &text).unwrap_or_else(|e| panic!("{}: {}", f, e)));
    }
    db
}

#[test]
fn rfc5280_modules_parse_completely() {
    let db = rfc5280_db();
    // Both modules were digested (Explicit88 + Implicit88).
    for name in [
        "Certificate",
        "TBSCertificate",
        "AlgorithmIdentifier",
        "Name",
        "Validity",
        "SubjectPublicKeyInfo",
        "Extensions",
        "Extension",
        "CertificateList",
        "TBSCertList",
        "GeneralName",   // from PKIX1Implicit88
        "AuthorityKeyIdentifier",
    ] {
        assert!(db.resolve(name).is_some(), "type {} missing", name);
    }
    // Module tag defaults were tracked.
    assert!(!db.resolve("Certificate").unwrap().implicit_tags);
    assert!(db.resolve("GeneralName").unwrap().implicit_tags);
}

#[test]
fn certificates_are_identified() {
    let db = rfc5280_db();
    for file in ["testdata/cert_ec.der", "testdata/cert_rsa.der"] {
        let data = std::fs::read(manifest(file)).unwrap();
        let roots = ber::parse_forest(&data, 0).unwrap();
        let ident = spec::identify(&db, &roots)
            .unwrap_or_else(|| panic!("{} not identified", file));
        assert_eq!(ident.type_name, "Certificate", "{}", file);
        assert_eq!(ident.source, "rfc5280");

        let label = |path: &[usize]| ident.labels.get(path).unwrap();
        assert_eq!(label(&[0]).type_name, "Certificate");
        assert_eq!(label(&[0, 0]).field.as_deref(), Some("tbsCertificate"));
        assert_eq!(label(&[0, 0]).type_name, "TBSCertificate");
        // version [0] EXPLICIT wrapper and its INTEGER payload.
        assert_eq!(label(&[0, 0, 0]).field.as_deref(), Some("version"));
        assert_eq!(label(&[0, 0, 0, 0]).type_name, "Version");
        assert_eq!(label(&[0, 0, 1]).field.as_deref(), Some("serialNumber"));
        assert_eq!(label(&[0, 0, 1]).type_name, "CertificateSerialNumber");
        // issuer resolves through the Name CHOICE.
        assert_eq!(label(&[0, 0, 3]).field.as_deref(), Some("issuer"));
        assert_eq!(label(&[0, 0, 3]).type_name, "Name.rdnSequence.RDNSequence");
        // validity times resolve through the Time CHOICE.
        assert_eq!(label(&[0, 0, 4, 0]).field.as_deref(), Some("notBefore"));
        assert_eq!(label(&[0, 0, 4, 0]).type_name, "Time.utcTime");
        assert_eq!(label(&[0, 1]).field.as_deref(), Some("signatureAlgorithm"));
        assert_eq!(label(&[0, 2]).field.as_deref(), Some("signature"));
    }
}

#[test]
fn crl_is_identified_as_certificate_list() {
    let db = rfc5280_db();
    let data = std::fs::read(manifest("testdata/crl.der")).unwrap();
    let roots = ber::parse_forest(&data, 0).unwrap();
    let ident = spec::identify(&db, &roots).expect("CRL identified");
    assert_eq!(ident.type_name, "CertificateList");
    let label = |path: &[usize]| ident.labels.get(path).unwrap();
    assert_eq!(label(&[0, 0]).field.as_deref(), Some("tbsCertList"));
    assert_eq!(label(&[0, 0, 2]).field.as_deref(), Some("issuer"));
    assert_eq!(label(&[0, 0, 3]).field.as_deref(), Some("thisUpdate"));
}

#[test]
fn pkcs8_private_key_is_identified() {
    let db = rfc5280_db();
    // Both the legacy (RFC 5208) and the updated (RFC 5958) private-key
    // types were parsed.
    assert!(db.resolve("PrivateKeyInfo").is_some());
    assert!(db.resolve("OneAsymmetricKey").is_some());

    let data = std::fs::read(manifest("testdata/private_key_pkcs8.der")).unwrap();
    let roots = ber::parse_forest(&data, 0).unwrap();
    let ident = spec::identify(&db, &roots).expect("PKCS#8 key identified");

    // A v1 PKCS#8 key matches both formats identically; the updated RFC
    // 5958 OneAsymmetricKey is preferred (see rfc5958_is_preferred_over_rfc5208).
    assert_eq!(ident.type_name, "OneAsymmetricKey");
    assert_eq!(ident.source, "rfc5958");

    let label = |path: &[usize]| ident.labels.get(path).unwrap();
    // OneAsymmetricKey ::= SEQUENCE { version, privateKeyAlgorithm,
    //                                 privateKey, [0] attributes OPTIONAL,
    //                                 [1] publicKey OPTIONAL }
    assert_eq!(label(&[0]).type_name, "OneAsymmetricKey");
    assert_eq!(label(&[0, 0]).field.as_deref(), Some("version"));
    assert_eq!(label(&[0, 0]).type_name, "Version");
    assert_eq!(label(&[0, 1]).field.as_deref(), Some("privateKeyAlgorithm"));
    // privateKeyAlgorithm resolves through PrivateKeyAlgorithmIdentifier
    // to the AlgorithmIdentifier imported from the RFC 5280 module (proving
    // cross-module reference resolution): its inner OID is labeled.
    assert!(label(&[0, 1]).type_name.contains("AlgorithmIdentifier"));
    assert_eq!(label(&[0, 1, 0]).field.as_deref(), Some("algorithm"));
    assert_eq!(label(&[0, 1, 0]).type_name, "OBJECT IDENTIFIER");
    // privateKey is an OCTET STRING (even though the BER encapsulation
    // heuristic parses its contents, the node's universal tag is still 4).
    assert_eq!(label(&[0, 2]).field.as_deref(), Some("privateKey"));
    assert_eq!(label(&[0, 2]).type_name, "PrivateKey");
}

#[test]
fn rfc5958_is_preferred_over_rfc5208() {
    let data = std::fs::read(manifest("testdata/private_key_pkcs8.der")).unwrap();
    let roots = ber::parse_forest(&data, 0).unwrap();

    // With only RFC 5208 present (plus RFC 5280 for AlgorithmIdentifier),
    // a v1 PKCS#8 key is the legacy PrivateKeyInfo.
    let legacy = db_from(&["rfc5280", "rfc5208"]);
    let id = spec::identify(&legacy, &roots).expect("identified");
    assert_eq!(id.type_name, "PrivateKeyInfo");
    assert_eq!(id.source, "rfc5208");

    // Adding RFC 5958 (which obsoletes 5208): the identical match is now
    // interpreted as the updated OneAsymmetricKey.
    let full = db_from(&["rfc5280", "rfc5208", "rfc5958"]);
    let id = spec::identify(&full, &roots).expect("identified");
    assert_eq!(id.type_name, "OneAsymmetricKey");
    assert_eq!(id.source, "rfc5958");

    // The preference is by source (RFC number), not the order files were
    // added to the database.
    let reordered = db_from(&["rfc5958", "rfc5208", "rfc5280"]);
    let id = spec::identify(&reordered, &roots).expect("identified");
    assert_eq!(id.type_name, "OneAsymmetricKey");
}

#[test]
fn rfc5958_v2_public_key_field_is_matched() {
    // A synthetic OneAsymmetricKey v2 with the RFC 5958 publicKey [1]
    // field present:
    //   SEQUENCE { INTEGER 1, SEQUENCE { OID 1.3.101.112 },
    //              OCTET STRING, [1] BIT STRING }
    let der: &[u8] = &[
        0x30, 0x15, //                                 SEQUENCE (21 bytes)
        0x02, 0x01, 0x01, //                             version v2
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, //    AlgorithmIdentifier { id-Ed25519 }
        0x04, 0x03, 0x01, 0x02, 0x03, //                privateKey OCTET STRING
        0x81, 0x04, 0x00, 0xAA, 0xBB, 0xCC, //          [1] publicKey (IMPLICIT BIT STRING)
    ];
    let roots = ber::parse_forest(der, 0).unwrap();

    let db = rfc5280_db();
    let id = spec::identify(&db, &roots).expect("v2 key identified");
    assert_eq!(id.type_name, "OneAsymmetricKey");
    assert_eq!(id.source, "rfc5958");
    // The publicKey field (new in RFC 5958) is matched and labeled.
    assert_eq!(id.labels.get([0, 3].as_slice()).unwrap().field.as_deref(), Some("publicKey"));

    // The legacy RFC 5208 PrivateKeyInfo (no publicKey field) does not
    // match this structure at all — proving the field is genuinely new.
    let legacy = db_from(&["rfc5280", "rfc5208"]);
    if let Some(id) = spec::identify(&legacy, &roots) {
        assert_ne!(id.type_name, "PrivateKeyInfo");
    }
}

#[test]
fn ec_private_key_is_identified() {
    // testdata/ec_key.der is a SEC1 / RFC 5915 EC private key (distinct
    // from the PKCS#8 wrapping): SEQUENCE { version, privateKey OCTET
    // STRING, [0] parameters, [1] publicKey }.
    let db = rfc5280_db();
    assert!(db.resolve("ECPrivateKey").is_some());

    let data = std::fs::read(manifest("testdata/ec_key.der")).unwrap();
    let roots = ber::parse_forest(&data, 0).unwrap();
    let ident = spec::identify(&db, &roots).expect("EC private key identified");

    assert_eq!(ident.type_name, "ECPrivateKey");
    assert_eq!(ident.source, "rfc5915");
    // It must not be confused with the PKCS#8 key formats or a certificate.
    assert_ne!(ident.type_name, "OneAsymmetricKey");
    assert_ne!(ident.type_name, "Certificate");

    let label = |path: &[usize]| ident.labels.get(path).unwrap();
    assert_eq!(label(&[0]).type_name, "ECPrivateKey");
    assert_eq!(label(&[0, 0]).field.as_deref(), Some("version"));
    assert_eq!(label(&[0, 1]).field.as_deref(), Some("privateKey"));
    assert_eq!(label(&[0, 1]).type_name, "OCTET STRING");
    // parameters [0] EXPLICIT wraps the ECParameters CHOICE (namedCurve OID).
    assert_eq!(label(&[0, 2]).field.as_deref(), Some("parameters"));
    assert_eq!(label(&[0, 2, 0]).type_name, "ECParameters.namedCurve");
    // publicKey [1] EXPLICIT wraps the BIT STRING.
    assert_eq!(label(&[0, 3]).field.as_deref(), Some("publicKey"));
    assert_eq!(label(&[0, 3, 0]).type_name, "BIT STRING");
}

#[test]
fn unrelated_structure_is_not_misidentified_as_certificate() {
    // A PKCS#7 SignedData bundle is not a certificate or CRL.
    let db = rfc5280_db();
    let data = std::fs::read(manifest("testdata/pkcs7.der")).unwrap();
    let roots = ber::parse_forest(&data, 0).unwrap();
    if let Some(ident) = spec::identify(&db, &roots) {
        assert_ne!(ident.type_name, "Certificate");
        assert_ne!(ident.type_name, "CertificateList");
    }
}
