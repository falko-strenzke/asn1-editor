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

//! X.509 certification-path validation via OpenSSL (the `openssl` crate).
//!
//! This is intentionally separate from `verify.rs` (single-signature checks
//! against a claimed issuer, using `aws-lc-rs`): here OpenSSL builds and
//! validates a full path from a target certificate up to a trust anchor,
//! applying the usual chain rules (issuer/subject chaining, signatures,
//! validity periods, basic constraints). The caller supplies the trust
//! anchors (certificates the user marked trusted) and the pool of untrusted
//! intermediates (every other certificate in the browsed tree).

use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::{X509StoreContext, X509};

/// Outcome of validating one certificate's path to a trust anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathStatus {
    /// A path to a trusted anchor was found and fully validated. `depth` is
    /// the number of certificates in the built chain (leaf through anchor).
    Valid { depth: usize },
    /// No valid path exists; `reason` is OpenSSL's verification error string.
    Invalid { reason: String },
    /// The chain could not even be set up (e.g. the target is not a parseable
    /// certificate); `detail` explains what went wrong.
    Error { detail: String },
}

/// Validate `target_der` against the `trusted` anchors, using `untrusted` as
/// the pool of candidate intermediates. All slices are raw DER certificate
/// encodings. Certificates that fail to parse are skipped (for trusted /
/// untrusted) or reported as an `Error` (for the target).
pub fn validate(target_der: &[u8], trusted: &[Vec<u8>], untrusted: &[Vec<u8>]) -> PathStatus {
    let target = match X509::from_der(target_der) {
        Ok(cert) => cert,
        Err(e) => return PathStatus::Error { detail: format!("not a valid certificate: {}", e) },
    };

    let store = {
        let mut builder = match X509StoreBuilder::new() {
            Ok(b) => b,
            Err(e) => return PathStatus::Error { detail: e.to_string() },
        };
        // Accept any trusted certificate as a valid path terminus, not only a
        // self-signed root — the user may mark an intermediate (or a leaf)
        // trusted, and such a chain should validate up to it.
        let _ = builder.set_flags(X509VerifyFlags::PARTIAL_CHAIN);
        for der in trusted {
            if let Ok(cert) = X509::from_der(der) {
                let _ = builder.add_cert(cert);
            }
        }
        builder.build()
    };

    let mut chain = match Stack::new() {
        Ok(s) => s,
        Err(e) => return PathStatus::Error { detail: e.to_string() },
    };
    for der in untrusted {
        if let Ok(cert) = X509::from_der(der) {
            let _ = chain.push(cert);
        }
    }

    let mut ctx = match X509StoreContext::new() {
        Ok(c) => c,
        Err(e) => return PathStatus::Error { detail: e.to_string() },
    };
    let outcome = ctx.init(&store, &target, &chain, |c| {
        if c.verify_cert()? {
            let depth = c.chain().map(|ch| ch.len()).unwrap_or(0);
            Ok(PathStatus::Valid { depth })
        } else {
            Ok(PathStatus::Invalid { reason: c.error().error_string().to_string() })
        }
    });
    match outcome {
        Ok(status) => status,
        Err(e) => PathStatus::Error { detail: e.to_string() },
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
    fn valid_path_when_the_root_is_trusted() {
        // server → intermediate → root; trust the root, supply the
        // intermediate as an untrusted candidate.
        let status = validate(&der("server.der"), &[der("root_ca.der")], &[der("intermediate_ca.der")]);
        assert!(matches!(status, PathStatus::Valid { .. }), "{:?}", status);
    }

    #[test]
    fn valid_path_when_the_intermediate_itself_is_trusted() {
        // Trusting the intermediate directly needs no untrusted certs.
        let status = validate(&der("server.der"), &[der("intermediate_ca.der")], &[]);
        assert!(matches!(status, PathStatus::Valid { .. }), "{:?}", status);
    }

    #[test]
    fn no_trust_anchor_is_invalid() {
        // Every cert present but none trusted → no anchor → invalid.
        let untrusted = [der("intermediate_ca.der"), der("root_ca.der")];
        let status = validate(&der("server.der"), &[], &untrusted);
        assert!(matches!(status, PathStatus::Invalid { .. }), "{:?}", status);
    }

    #[test]
    fn missing_intermediate_is_invalid() {
        // Root trusted but the intermediate is not available → cannot chain.
        let status = validate(&der("server.der"), &[der("root_ca.der")], &[]);
        assert!(matches!(status, PathStatus::Invalid { .. }), "{:?}", status);
    }

    #[test]
    fn a_broken_signature_does_not_validate() {
        let status = validate(
            &der("server_bad_signature.der"),
            &[der("root_ca.der")],
            &[der("intermediate_ca.der")],
        );
        assert!(matches!(status, PathStatus::Invalid { .. }), "{:?}", status);
    }
}
