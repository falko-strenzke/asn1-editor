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

//! X.509 certification-path validation via the **Botan** library — a second,
//! independent opinion alongside the OpenSSL-based [`crate::pathval`]. The two
//! can legitimately disagree (each applies its own policy): Botan, for one,
//! enforces a minimum key strength (~110 bits) and its own path/name rules, so
//! showing both is informative.
//!
//! The inputs mirror `pathval::validate` — a target certificate, the trusted
//! anchors, the pool of untrusted intermediates, and CRLs — all as raw DER.
//! Botan's `verify_with_crl` builds the path and checks revocation in one call
//! and returns only a status code (no chain), so [`BotanPathStatus::Valid`]
//! carries no depth, unlike the OpenSSL result.

use botan::{Certificate, CRL};

/// Outcome of Botan's path validation for one certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BotanPathStatus {
    /// Botan built and accepted a path to a trusted anchor.
    Valid,
    /// Botan reports a certificate on the path as revoked.
    Revoked,
    /// Botan rejected the path; `reason` is its status string.
    Invalid { reason: String },
    /// The validation could not be set up (e.g. the target does not load).
    Error { detail: String },
}

/// Validate `target_der` against the `trusted` anchors, using `untrusted` as
/// candidate intermediates and `crls` for revocation, all as raw DER. Mirrors
/// [`crate::pathval::validate`] but via Botan. Certificates/CRLs that fail to
/// load are skipped; a target that fails to load is an `Error`.
pub fn validate(
    target_der: &[u8],
    trusted: &[Vec<u8>],
    untrusted: &[Vec<u8>],
    crls: &[Vec<u8>],
) -> BotanPathStatus {
    let target = match Certificate::load(target_der) {
        Ok(c) => c,
        Err(e) => return BotanPathStatus::Error { detail: format!("not a valid certificate: {:?}", e) },
    };
    // With no anchor, Botan cannot establish trust; report it plainly rather
    // than relaying a cryptic status code.
    if trusted.is_empty() {
        return BotanPathStatus::Invalid { reason: "no trust anchor is marked".to_string() };
    }

    let trusted_certs: Vec<Certificate> =
        trusted.iter().filter_map(|d| Certificate::load(d).ok()).collect();
    let inter_certs: Vec<Certificate> =
        untrusted.iter().filter_map(|d| Certificate::load(d).ok()).collect();
    let crl_objs: Vec<CRL> = crls.iter().filter_map(|d| CRL::load(d).ok()).collect();

    let trusted_refs: Vec<&Certificate> = trusted_certs.iter().collect();
    let inter_refs: Vec<&Certificate> = inter_certs.iter().collect();
    let crl_refs: Vec<&CRL> = crl_objs.iter().collect();

    // No hostname check (not TLS), current time as the reference.
    match target.verify_with_crl(&inter_refs, &trusted_refs, None, None, None, &crl_refs) {
        Ok(status) if status.success() => BotanPathStatus::Valid,
        Ok(status) => {
            let reason = status.to_string();
            if reason.to_lowercase().contains("revoked") {
                BotanPathStatus::Revoked
            } else {
                BotanPathStatus::Invalid { reason }
            }
        }
        Err(e) => BotanPathStatus::Error { detail: format!("{:?}", e) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn der(rel: &str) -> Vec<u8> {
        std::fs::read(Path::new("testdata/chain").join(rel)).unwrap()
    }

    #[test]
    fn valid_chain_to_a_trusted_root() {
        // server → intermediate → root; trust the root.
        let status = validate(
            &der("server.der"),
            &[der("root_ca.der")],
            &[der("intermediate_ca.der")],
            &[],
        );
        assert_eq!(status, BotanPathStatus::Valid, "Botan should accept the chain");
    }

    #[test]
    fn no_anchor_is_invalid() {
        let status = validate(&der("server.der"), &[], &[der("intermediate_ca.der")], &[]);
        assert!(matches!(status, BotanPathStatus::Invalid { .. }));
    }

    #[test]
    fn a_non_certificate_target_is_an_error() {
        let status = validate(b"not a certificate", &[der("root_ca.der")], &[], &[]);
        assert!(matches!(status, BotanPathStatus::Error { .. }));
    }
}
