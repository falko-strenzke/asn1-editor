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
//! RFC 5280 modules in `specs/asn1/rfc5280` and the DER test files.

use std::path::Path;

use asn1_editor::{ber, spec};

fn manifest(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn rfc5280_db() -> spec::SpecDb {
    let (db, errors) = spec::load_dir(&manifest("specs/asn1"));
    assert!(errors.is_empty(), "spec parse errors: {:?}", errors);
    assert!(!db.is_empty());
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
fn unrelated_structure_is_not_misidentified_as_certificate() {
    let db = rfc5280_db();
    let data = std::fs::read(manifest("testdata/ec_key.der")).unwrap();
    let roots = ber::parse_forest(&data, 0).unwrap();
    if let Some(ident) = spec::identify(&db, &roots) {
        assert_ne!(ident.type_name, "Certificate");
        assert_ne!(ident.type_name, "CertificateList");
    }
}
