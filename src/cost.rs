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

//! Time estimates for the slow re-key operations (XMSS and SLH-DSA), used by
//! the dialog's estimate line and the progress window.
//!
//! The re-key does one key generation (when a new key is generated) plus one
//! signature per object it re-signs: the certificate itself when self-signed,
//! and every selected issued object. Per-operation costs come from
//! [`keygen::KeyAlgorithm`]'s measured anchors — calibrated on the
//! development machine, extrapolated for the higher parameter sets (XMSS
//! keygen ~2^height; XMSS signing ≈ keygen because Botan rebuilds tree state
//! on load; SLH-DSA from per-set constants).
//!
//! Those anchors are absolute times on one machine, so on faster or slower
//! hardware they would be systematically off. To correct for that, the module
//! measures this machine once on first use ([`speed_factor`]) — a ~20 ms
//! SHA-256 throughput benchmark — and rescales every estimate by this
//! machine's speed relative to the calibration machine. Estimates remain
//! order-of-magnitude guidance, not promises.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::keygen::KeyAlgorithm;

/// Mebibytes of SHA-256 hashed by the one-shot calibration benchmark; sized
/// so it runs in a few tens of milliseconds.
const CALIBRATION_MIB: usize = 24;

/// Wall-clock (nanoseconds) the [`CALIBRATION_MIB`]-MiB benchmark took on the
/// machine the timing anchors in `keygen.rs` were measured on. A machine that
/// runs the same benchmark faster gets a proportionally smaller estimate.
const DEV_HASH_BASELINE_NANOS: f64 = 18_700_000.0;

/// Time this machine to hash [`CALIBRATION_MIB`] MiB of SHA-256, after a brief
/// warm-up so the timed pass runs at a steady clock (matching how the dev
/// baseline was measured).
fn measure_hash_nanos() -> f64 {
    use aws_lc_rs::digest;
    let buf = vec![0x5au8; 1 << 20]; // 1 MiB
    for _ in 0..8 {
        let _ = digest::digest(&digest::SHA256, &buf);
    }
    let start = Instant::now();
    for _ in 0..CALIBRATION_MIB {
        let _ = digest::digest(&digest::SHA256, &buf);
    }
    start.elapsed().as_nanos() as f64
}

/// This machine's speed relative to the calibration machine: `1.0` means the
/// same speed, `0.5` twice as fast (estimates halved), `2.0` half as fast.
/// Measured once, lazily, and cached for the life of the process; clamped to a
/// sane range so a noisy or interrupted measurement cannot produce an absurd
/// estimate.
pub fn speed_factor() -> f64 {
    static FACTOR: OnceLock<f64> = OnceLock::new();
    *FACTOR.get_or_init(|| (measure_hash_nanos() / DEV_HASH_BASELINE_NANOS).clamp(0.1, 20.0))
}

/// The re-key estimate in seconds *before* the machine-speed correction — the
/// raw sum of the `keygen.rs` anchors. `None` for algorithms without an
/// estimate. Separated from [`rekey_estimate`] so the machine-independent
/// arithmetic can be tested directly.
fn raw_estimate_secs(
    alg: KeyAlgorithm,
    signature_count: usize,
    generate_key: bool,
) -> Option<f64> {
    let sign = alg.est_sign_secs()?;
    let keygen = if generate_key { alg.est_keygen_secs()? } else { 0.0 };
    Some((keygen + sign * signature_count as f64).max(0.0))
}

/// Estimated wall-clock for a re-key with `alg` that makes `signature_count`
/// signatures, generating a fresh key when `generate_key` is true (an
/// existing key skips the keygen term). `None` for algorithms without a time
/// estimate (classical, ML-DSA), which finish near-instantly.
///
/// `signature_count` is the certificate's own re-signature (when self-signed)
/// plus every selected issued object.
pub fn rekey_estimate(
    alg: KeyAlgorithm,
    signature_count: usize,
    generate_key: bool,
) -> Option<Duration> {
    let raw = raw_estimate_secs(alg, signature_count, generate_key)?;
    Some(Duration::from_secs_f64(raw * speed_factor()))
}

/// Like [`rekey_estimate`] but for HSS/LMS, whose cost depends on its
/// structured parameters (per-level height and Winternitz, hash) rather than a
/// `KeyAlgorithm` discriminant. Machine-speed-corrected like the others.
pub fn rekey_estimate_hsslms(
    params: &crate::keygen::HssLmsParams,
    signature_count: usize,
    generate_key: bool,
) -> Duration {
    let sign = params.est_sign_secs();
    let keygen = if generate_key { params.est_keygen_secs() } else { 0.0 };
    Duration::from_secs_f64((keygen + sign * signature_count as f64).max(0.0) * speed_factor())
}

/// Format a duration as `"x h, y mins, z secs"`, omitting any unit whose value
/// is zero (e.g. `"3 mins, 12 secs"`, `"2 h, 5 secs"`, `"41 secs"`). Rounds to
/// whole seconds; a sub-second or zero duration renders as `"0 secs"`.
pub fn format_hms(d: Duration) -> String {
    let total = d.as_secs_f64().round() as u64;
    let (h, m, s) = (total / 3600, (total % 3600) / 60, total % 60);
    let mut parts = Vec::new();
    if h > 0 {
        parts.push(format!("{} h", h));
    }
    if m > 0 {
        parts.push(format!("{} mins", m));
    }
    if s > 0 {
        parts.push(format!("{} secs", s));
    }
    if parts.is_empty() {
        return "0 secs".to_string();
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_omits_zero_units() {
        assert_eq!(format_hms(Duration::from_secs(0)), "0 secs");
        assert_eq!(format_hms(Duration::from_secs(41)), "41 secs");
        assert_eq!(format_hms(Duration::from_secs(192)), "3 mins, 12 secs");
        assert_eq!(format_hms(Duration::from_secs(3600)), "1 h");
        assert_eq!(format_hms(Duration::from_secs(3605)), "1 h, 5 secs");
        assert_eq!(format_hms(Duration::from_secs(7325)), "2 h, 2 mins, 5 secs");
        // Sub-second rounds to whole seconds.
        assert_eq!(format_hms(Duration::from_secs_f64(0.4)), "0 secs");
        assert_eq!(format_hms(Duration::from_secs_f64(1.6)), "2 secs");
    }

    #[test]
    fn estimate_is_none_for_fast_algorithms() {
        assert!(rekey_estimate(KeyAlgorithm::EcdsaP256, 3, true).is_none());
        assert!(rekey_estimate(KeyAlgorithm::Ed25519, 3, true).is_none());
        assert!(rekey_estimate(KeyAlgorithm::Pq(0), 3, true).is_none()); // ML-DSA-44
    }

    #[test]
    fn estimate_grows_with_object_count_and_includes_keygen() {
        // XMSS-SHA2_10_192 (index 0): keygen ≈ sign ≈ small. Uses the raw
        // (unscaled) estimate so the arithmetic is machine-independent.
        let alg = KeyAlgorithm::Xmss(0);
        let none = raw_estimate_secs(alg, 0, true).unwrap();
        let three = raw_estimate_secs(alg, 3, true).unwrap();
        assert!(three > none, "more signatures cost more");
        // With no key generation, the keygen term drops out, so signing the
        // same count is cheaper.
        let three_no_keygen = raw_estimate_secs(alg, 3, false).unwrap();
        assert!(three_no_keygen < three);
        // XMSS keygen ≈ sign, so total ≈ keygen * (1 + count).
        let one_sign = alg.est_sign_secs().unwrap();
        let expected = alg.est_keygen_secs().unwrap() + 3.0 * one_sign;
        assert!((three - expected).abs() < 1e-9);
    }

    #[test]
    fn slh_dsa_estimate_is_signing_dominated() {
        // SLH-DSA-SHAKE-192s (Pq index 11): slow signing dwarfs keygen.
        let alg = KeyAlgorithm::Pq(11);
        assert!(alg.shows_time_estimate());
        let five = raw_estimate_secs(alg, 5, true).unwrap();
        // Five signatures should dominate; comfortably over 10 s.
        assert!(five > 10.0, "five slow SLH-DSA signatures: {five}s");
    }

    #[test]
    fn speed_factor_is_sane_and_scales_the_estimate() {
        // The one-shot calibration yields a finite, positive factor in range.
        let f = speed_factor();
        assert!(f.is_finite() && (0.1..=20.0).contains(&f), "speed factor {f}");
        // Cached: a second call returns the identical value with no re-measure.
        assert_eq!(f, speed_factor());
        // The public estimate is the raw estimate scaled by the factor.
        let alg = KeyAlgorithm::Xmss(0);
        let raw = raw_estimate_secs(alg, 3, true).unwrap();
        let scaled = rekey_estimate(alg, 3, true).unwrap().as_secs_f64();
        assert!((scaled - raw * f).abs() < 1e-6, "scaled {scaled} vs raw {raw} × {f}");
    }
}
