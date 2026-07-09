//! Compatibility check against Peter Gutmann's `dumpasn1`.
//!
//! For every file in `testdata/` the structural fields of our dump
//! (absolute offset, content length, type name, one line per ASN.1 item,
//! including items nested via the encapsulation heuristic) must be
//! identical to dumpasn1's output. Value rendering and warning lines are
//! not compared.
//!
//! The test is skipped (with a message) when no `dumpasn1` binary is on
//! PATH, so that the suite still passes on machines without it.

use std::path::{Path, PathBuf};
use std::process::Command;

use asn1_editor::{ber, dump};

/// Type names as printed by both tools; used to cut value text off a line.
const TYPE_NAMES: &[&str] = &[
    "End-of-contents octets",
    "OBJECT IDENTIFIER",
    "Unknown (Reserved)",
    "GeneralizedTime",
    "ObjectDescriptor",
    "PrintableString",
    "UniversalString",
    "VideotexString",
    "GraphicString",
    "GeneralString",
    "NumericString",
    "TeletexString",
    "VisibleString",
    "OCTET STRING",
    "EMBEDDED PDV",
    "BIT STRING",
    "ENUMERATED",
    "UTF8String",
    "IA5String",
    "BMPString",
    "SEQUENCE",
    "EXTERNAL",
    "BOOLEAN",
    "INTEGER",
    "UTCTime",
    "NULL",
    "REAL",
    "SET",
];

/// Extract (offset, length, type name) triples from a dump. Lines that do
/// not start with "<offset> <length>:" (hex continuations, closing braces,
/// warnings, summary lines) are ignored.
fn structure(text: &str) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((head, rest)) = line.split_once(':') else { continue };
        let mut fields = head.split_whitespace();
        let (Some(off), Some(len), None) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        let (Ok(off), Ok(len)) = (off.parse::<usize>(), len.parse::<usize>()) else {
            continue;
        };
        let body = rest.trim();
        let name = if body.starts_with('[') {
            match body.find(']') {
                Some(i) => body[..=i].to_string(),
                None => continue,
            }
        } else {
            match TYPE_NAMES.iter().find(|n| body.starts_with(**n)) {
                Some(n) => n.to_string(),
                None => continue,
            }
        };
        out.push((off, len, name));
    }
    out
}

fn dumpasn1_available() -> bool {
    match Command::new("dumpasn1").arg("-h").output() {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

fn testdata_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("testdata directory exists")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "der"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .der files in {}", dir.display());
    files
}

#[test]
fn structure_matches_dumpasn1() {
    if !dumpasn1_available() {
        eprintln!("SKIPPED: dumpasn1 not found on PATH");
        return;
    }
    for file in testdata_files() {
        let data = std::fs::read(&file).unwrap();
        let roots = ber::parse_forest(&data, 0)
            .unwrap_or_else(|e| panic!("{}: parse error at {}", file.display(), e));
        let ours = structure(&dump::dump(&roots, data.len()));

        // dumpasn1 may exit non-zero on warnings; only stdout matters.
        let output = Command::new("dumpasn1").arg(&file).output().unwrap();
        let theirs = structure(&String::from_utf8_lossy(&output.stdout));

        assert!(!ours.is_empty(), "{}: empty dump", file.display());
        for (i, (a, b)) in ours.iter().zip(theirs.iter()).enumerate() {
            assert_eq!(
                a, b,
                "{}: mismatch at item {} (ours vs dumpasn1)",
                file.display(),
                i
            );
        }
        assert_eq!(
            ours.len(),
            theirs.len(),
            "{}: item count differs (ours {} vs dumpasn1 {})",
            file.display(),
            ours.len(),
            theirs.len()
        );
    }
}

#[test]
fn parse_encode_roundtrip_on_testdata() {
    for file in testdata_files() {
        let data = std::fs::read(&file).unwrap();
        let roots = ber::parse_forest(&data, 0)
            .unwrap_or_else(|e| panic!("{}: parse error at {}", file.display(), e));
        assert_eq!(
            ber::encode_forest(&roots),
            data,
            "{}: re-encoding is not byte-identical",
            file.display()
        );
    }
}
