// Copyright 2026 Falko Strenzke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

use asn1_editor::{ber, input, oid};
use std::path::{Path, PathBuf};

fn files_below(dir: &Path, out: &mut Vec<PathBuf>) {
    for item in std::fs::read_dir(dir).unwrap() {
        let path = item.unwrap().path();
        if path.is_dir() {
            files_below(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn assert_node_oids_known(path: &Path, node: &ber::Node) {
    if !node.constructed && node.is_universal(ber::TAG_OID) {
        let arcs = ber::oid_arcs(&node.value)
            .unwrap_or_else(|| panic!("{} contains a malformed OID", path.display()));
        assert!(
            oid::lookup(&arcs).is_some(),
            "{} contains unresolved OID {}",
            path.display(),
            oid::dotted(&arcs)
        );
    }
    for child in &node.children {
        assert_node_oids_known(path, child);
    }
}

#[test]
fn every_oid_in_testdata_is_in_the_repository() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
    let mut files = Vec::new();
    files_below(&root, &mut files);

    for path in files {
        let raw = std::fs::read(&path).unwrap();
        let (der, _) =
            input::load(&raw).unwrap_or_else(|e| panic!("cannot load {}: {}", path.display(), e));
        let roots = ber::parse_forest(&der, 0)
            .unwrap_or_else(|e| panic!("cannot parse {}: {}", path.display(), e));
        for node in &roots {
            assert_node_oids_known(&path, node);
        }
    }
}

#[test]
fn all_nist_ml_dsa_and_slh_dsa_assignments_are_present() {
    // NIST CSOR assigned the contiguous sigAlgs range 17..=46 to the pure
    // and pre-hash variants of ML-DSA and SLH-DSA.
    for leaf in 17..=46 {
        let entry = oid::lookup(&[2, 16, 840, 1, 101, 3, 4, 3, leaf])
            .unwrap_or_else(|| panic!("NIST sigAlgs {} is missing", leaf));
        assert!(entry.short_name.contains("ml-dsa") || entry.short_name.contains("slh-dsa"));
    }
}
