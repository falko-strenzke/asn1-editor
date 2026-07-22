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

//! Field-by-field documentation of the *stateful hash-based* values that
//! `xmss.rs` and `hsslms.rs` put into X.509 objects: XMSS (RFC 8391) and
//! HSS/LMS (RFC 8554) public keys and signatures.
//!
//! Unlike an RSA or ECDSA signature, these blobs are long, highly structured
//! concatenations of fixed-size hash outputs — a one-time signature, an
//! authentication path, a tree root — with no ASN.1 inside to show the seams.
//! [`describe_node`] recovers those seams: it recognises the value a BIT
//! STRING or OCTET STRING carries and returns a [`Description`] with prose for
//! the content pane plus a [`Field`] per component, which `tui.rs` uses to
//! colour the hex dump and to name each component in the dump's right-hand
//! gutter (where a plain dump shows the ASCII reading).
//!
//! **Self-description.** HSS/LMS is fully self-describing: every LMS tree and
//! every one-time signature carries its typecode, so the parameters — hash,
//! node size, tree height, Winternitz width — are read straight out of the
//! bytes, and a parse that consumes the value exactly is strong evidence that
//! the value really is HSS/LMS. An XMSS *public key* likewise begins with its
//! parameter-set OID. An XMSS *signature* does not: RFC 8391 §4.1.8 defines it
//! as `idx_sig || r || sig_ots || auth` with no identifier, so it is
//! recognised by its length together with an in-range leaf index, and the
//! parameter set is reported as the set of candidates that share that layout
//! (the public key decides among them).

use crate::ber::{self, Node};

/// One labelled component of a recognised value. `start`/`len` are byte
/// offsets into the node's *content octets*, so they index the hex dump
/// directly; `short` is the token shown in the dump's right-hand gutter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub start: usize,
    pub len: usize,
    pub short: String,
}

/// A recognised XMSS or HSS/LMS value: a heading and explanatory lines for the
/// content pane, plus the byte ranges of its components.
#[derive(Clone, Debug)]
pub struct Description {
    /// Section heading, e.g. `"HSS/LMS signature (RFC 8554 §3.3)"`.
    pub heading: String,
    /// Plain-language lines shown under the heading; `tui.rs` wraps them.
    pub notes: Vec<String>,
    /// The components, in ascending offset order and non-overlapping.
    pub fields: Vec<Field>,
}

// ---------------------------------------------------------------------------
// Parameter sets
// ---------------------------------------------------------------------------

/// An LMS parameter set (RFC 8554 §5.1 and draft-fluhrer-lms-more-parm-sets):
/// the tree's hash, node size `m` and height `h`.
struct LmsSet {
    code: u32,
    name: String,
    hash: &'static str,
    m: usize,
    h: u32,
}

/// The LMS parameter set for a typecode, or `None` for a reserved/unknown one.
/// The five heights 5/10/15/20/25 run consecutively within each hash+size
/// family, which is how the typecodes are assigned.
fn lms_set(code: u32) -> Option<LmsSet> {
    let (family, hash, m) = match code {
        0x05..=0x09 => ("LMS_SHA256_M32", "SHA-256", 32),
        0x0a..=0x0e => ("LMS_SHA256_M24", "SHA-256 truncated to 192 bits", 24),
        0x0f..=0x13 => ("LMS_SHAKE_M32", "SHAKE-256 with 256-bit output", 32),
        0x14..=0x18 => ("LMS_SHAKE_M24", "SHAKE-256 with 192-bit output", 24),
        _ => return None,
    };
    let h = 5 * (1 + (code - 5) % 5);
    Some(LmsSet { code, name: format!("{}_H{}", family, h), hash, m, h })
}

/// An LM-OTS parameter set (RFC 8554 §4.1): hash output size `n`, Winternitz
/// width `w`, and the derived chain count `p` and checksum shift `ls`.
struct OtsSet {
    code: u32,
    name: String,
    hash: &'static str,
    n: usize,
    w: u32,
    p: usize,
    ls: u32,
}

/// The LM-OTS parameter set for a typecode. The four widths 1/2/4/8 run
/// consecutively within each hash+size family.
fn ots_set(code: u32) -> Option<OtsSet> {
    let (family, hash, n) = match code {
        0x01..=0x04 => ("LMOTS_SHA256_N32", "SHA-256", 32),
        0x05..=0x08 => ("LMOTS_SHA256_N24", "SHA-256 truncated to 192 bits", 24),
        0x09..=0x0c => ("LMOTS_SHAKE_N32", "SHAKE-256 with 256-bit output", 32),
        0x0d..=0x10 => ("LMOTS_SHAKE_N24", "SHAKE-256 with 192-bit output", 24),
        _ => return None,
    };
    let w = 1 << ((code - 1) % 4);
    let (p, ls) = winternitz_chains(n, w);
    Some(OtsSet { code, name: format!("{}_W{}", family, w), hash, n, w, p, ls })
}

/// The number of Winternitz hash chains `p` and the checksum's left shift `ls`
/// of an LM-OTS parameter set, derived from `n` and `w` as RFC 8554 §4.1 does:
/// `u = ceil(8n/w)` chains for the message digest, `v = ceil((floor(lg((2^w −
/// 1)·u)) + 1)/w)` for the checksum, `p = u + v` and `ls = 16 − v·w`.
fn winternitz_chains(n: usize, w: u32) -> (usize, u32) {
    let u = (8 * n as u32).div_ceil(w);
    // floor(lg x) + 1 — the position of x's highest set bit.
    let digits = 32 - (((1u32 << w) - 1) * u).leading_zeros();
    let v = digits.div_ceil(w);
    ((u + v) as usize, 16 - v * w)
}

/// The XMSS parameter sets, as `(oid, name, hash, n, h, len)` — RFC 8391 §5.3
/// plus the 192-bit and SHAKE-256 additions. `len` is the number of WOTS+
/// chains; the Winternitz width is 16 for every XMSS set.
const XMSS_SETS: &[(u32, &str, &str, usize, u32, usize)] = &[
    (0x01, "XMSS-SHA2_10_256", "SHA-256", 32, 10, 67),
    (0x02, "XMSS-SHA2_16_256", "SHA-256", 32, 16, 67),
    (0x03, "XMSS-SHA2_20_256", "SHA-256", 32, 20, 67),
    (0x04, "XMSS-SHA2_10_512", "SHA-512", 64, 10, 131),
    (0x05, "XMSS-SHA2_16_512", "SHA-512", 64, 16, 131),
    (0x06, "XMSS-SHA2_20_512", "SHA-512", 64, 20, 131),
    (0x07, "XMSS-SHAKE_10_256", "SHAKE-128 with 256-bit output", 32, 10, 67),
    (0x08, "XMSS-SHAKE_16_256", "SHAKE-128 with 256-bit output", 32, 16, 67),
    (0x09, "XMSS-SHAKE_20_256", "SHAKE-128 with 256-bit output", 32, 20, 67),
    (0x0a, "XMSS-SHAKE_10_512", "SHAKE-256 with 512-bit output", 64, 10, 131),
    (0x0b, "XMSS-SHAKE_16_512", "SHAKE-256 with 512-bit output", 64, 16, 131),
    (0x0c, "XMSS-SHAKE_20_512", "SHAKE-256 with 512-bit output", 64, 20, 131),
    (0x0d, "XMSS-SHA2_10_192", "SHA-256 truncated to 192 bits", 24, 10, 51),
    (0x0e, "XMSS-SHA2_16_192", "SHA-256 truncated to 192 bits", 24, 16, 51),
    (0x0f, "XMSS-SHA2_20_192", "SHA-256 truncated to 192 bits", 24, 20, 51),
    (0x10, "XMSS-SHAKE256_10_256", "SHAKE-256 with 256-bit output", 32, 10, 67),
    (0x11, "XMSS-SHAKE256_16_256", "SHAKE-256 with 256-bit output", 32, 16, 67),
    (0x12, "XMSS-SHAKE256_20_256", "SHAKE-256 with 256-bit output", 32, 20, 67),
    (0x13, "XMSS-SHAKE256_10_192", "SHAKE-256 with 192-bit output", 24, 10, 51),
    (0x14, "XMSS-SHAKE256_16_192", "SHAKE-256 with 192-bit output", 24, 16, 51),
    (0x15, "XMSS-SHAKE256_20_192", "SHAKE-256 with 192-bit output", 24, 20, 51),
];

/// The size in bytes of an XMSS signature under a parameter set:
/// `idx_sig` (4) plus the randomizer, the `len` WOTS+ chain values and the
/// `h` authentication-path nodes, each `n` bytes (RFC 8391 §4.1.8).
fn xmss_signature_size(n: usize, h: u32, len: usize) -> usize {
    4 + n * (len + h as usize + 1)
}

// ---------------------------------------------------------------------------
// Byte-level parsing
// ---------------------------------------------------------------------------

/// A forward-only reader that records a [`Field`] for every slice it takes,
/// so parsing a value produces its field map as a side effect.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    fields: Vec<Field>,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0, fields: Vec::new() }
    }

    /// Consume `len` bytes as a field named `short`, or `None` past the end.
    fn take(&mut self, len: usize, short: String) -> Option<()> {
        let end = self.pos.checked_add(len)?;
        if end > self.bytes.len() {
            return None;
        }
        self.fields.push(Field { start: self.pos, len, short });
        self.pos = end;
        Some(())
    }

    /// Consume a big-endian `u32` field — every length, index and typecode in
    /// these formats is one.
    fn take_u32(&mut self, short: String) -> Option<u32> {
        let at = self.pos;
        self.take(4, short)?;
        let b = &self.bytes[at..at + 4];
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Whether the value has been consumed exactly — the check that turns a
    /// speculative parse into a recognition.
    fn at_end(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

/// One LMS public key (RFC 8554 §5.3): `u32 lmsType || u32 otsType || I[16] ||
/// T[1][m]`. `prefix` distinguishes the levels of a multi-level HSS value.
fn read_lms_public_key(r: &mut Reader, prefix: &str) -> Option<(LmsSet, OtsSet)> {
    let lms = lms_set(r.take_u32(format!("{}lmsType", prefix))?)?;
    let ots = ots_set(r.take_u32(format!("{}otsType", prefix))?)?;
    r.take(16, format!("{}I", prefix))?;
    r.take(lms.m, format!("{}T[1]", prefix))?;
    Some((lms, ots))
}

/// One LMS signature (RFC 8554 §5.4): `u32 q || u32 otsType || C[n] ||
/// y[0..p-1][n] || u32 lmsType || path[0..h-1][m]`. Returns the parameter sets
/// and the leaf index `q`.
fn read_lms_signature(r: &mut Reader, prefix: &str) -> Option<(LmsSet, OtsSet, u32)> {
    let q = r.take_u32(format!("{}q", prefix))?;
    let ots = ots_set(r.take_u32(format!("{}otsType", prefix))?)?;
    r.take(ots.n, format!("{}C", prefix))?;
    for i in 0..ots.p {
        r.take(ots.n, format!("{}y[{}]", prefix, i))?;
    }
    let lms = lms_set(r.take_u32(format!("{}lmsType", prefix))?)?;
    // A leaf index past the end of the tree cannot be a real signature; the
    // check also keeps random data from parsing as one.
    if q >= 1 << lms.h {
        return None;
    }
    for i in 0..lms.h {
        r.take(lms.m, format!("{}path[{}]", prefix, i))?;
    }
    Some((lms, ots, q))
}

/// The `L` levels of an HSS value are bounded by RFC 8554 §6 (and Botan's
/// implementation limit), which makes an out-of-range first word a cheap
/// rejection for unrelated data.
const HSS_MAX_LEVELS: u32 = 8;

/// `u32 L || lms_public_key` — RFC 8554 §3.3. `L = 1` is plain LMS.
fn describe_hss_public_key(bytes: &[u8]) -> Option<Description> {
    let mut r = Reader::new(bytes);
    let levels = r.take_u32("L".into())?;
    if levels == 0 || levels > HSS_MAX_LEVELS {
        return None;
    }
    let (lms, ots) = read_lms_public_key(&mut r, "")?;
    if !r.at_end() {
        return None;
    }
    let notes = vec![
        format!(
            "L = {} — the number of HSS levels, i.e. the depth of the tree of LMS trees. \
             The key below is the top-level (root) LMS public key; the lower levels are \
             generated on demand and travel inside each signature. L = 1 means a single \
             LMS tree, i.e. plain LMS.",
            levels
        ),
        lms_note(&lms),
        ots_note(&ots),
        "I is the 16-byte identifier of this LMS tree; T[1] is the root node of its Merkle \
         tree, the value a verifier recomputes from the signature."
            .to_string(),
        "Layout: u32 L || u32 lmsType || u32 otsType || I[16] || T[1][m]".to_string(),
    ];
    Some(Description {
        heading: "HSS/LMS public key (RFC 8554 §3.3)".to_string(),
        notes,
        fields: r.fields,
    })
}

/// `u32 Nspk || (lms_signature || lms_public_key) × Nspk || lms_signature` —
/// RFC 8554 §3.3. The `Nspk` inner pairs are the signed public keys of the
/// lower HSS levels; the trailing signature is the one over the message.
fn describe_hss_signature(bytes: &[u8]) -> Option<Description> {
    let mut r = Reader::new(bytes);
    let nspk = r.take_u32("Nspk".into())?;
    if nspk >= HSS_MAX_LEVELS {
        return None;
    }
    // With a single level the prefixes would only add noise, so plain LMS
    // keeps the bare RFC field names.
    let multi = nspk > 0;
    let mut levels = Vec::new();
    for i in 0..nspk {
        let sig_prefix = format!("sig[{}].", i);
        levels.push(read_lms_signature(&mut r, &sig_prefix)?);
        read_lms_public_key(&mut r, &format!("pub[{}].", i + 1))?;
    }
    let last_prefix = if multi { format!("sig[{}].", nspk) } else { String::new() };
    levels.push(read_lms_signature(&mut r, &last_prefix)?);
    if !r.at_end() {
        return None;
    }

    let mut notes = vec![format!(
        "Nspk = {} — the number of signed public keys carried by this signature, one \
         short of the number of HSS levels (L = {}). {}",
        nspk,
        nspk + 1,
        if multi {
            "Each sig[i] signs the LMS public key pub[i+1] of the level below it, and the \
             last signature is the one over the message."
        } else {
            "A single LMS tree signs the message directly — this is plain LMS."
        }
    )];
    for (i, (lms, ots, q)) in levels.iter().enumerate() {
        if multi {
            notes.push(format!("Level {}:", i));
        }
        notes.push(lms_note(lms));
        notes.push(ots_note(ots));
        notes.push(format!(
            "q = {} — the index of the one-time key (Merkle-tree leaf) this level used, out \
             of the tree's {}. It must never be reused, which is what makes the scheme \
             stateful.",
            q,
            1u64 << lms.h
        ));
    }
    notes.push(
        "C is the LM-OTS message randomizer; y[i] is the i-th Winternitz hash-chain value \
         (the one-time signature proper); path[i] is the i-th node of the authentication \
         path from the used leaf up to the tree root."
            .to_string(),
    );
    notes.push(
        "Layout of one LMS signature: u32 q || u32 otsType || C[n] || y[0..p-1][n] || \
         u32 lmsType || path[0..h-1][m]"
            .to_string(),
    );
    Some(Description {
        heading: "HSS/LMS signature (RFC 8554 §3.3)".to_string(),
        notes,
        fields: r.fields,
    })
}

/// `u32 oid || root[n] || SEED[n]` — the XMSS public key of RFC 8391 §4.1.7,
/// which names its own parameter set.
fn describe_xmss_public_key(bytes: &[u8]) -> Option<Description> {
    let mut r = Reader::new(bytes);
    let oid = r.take_u32("oid".into())?;
    let &(_, name, hash, n, h, len) = XMSS_SETS.iter().find(|s| s.0 == oid)?;
    r.take(n, "root".into())?;
    r.take(n, "SEED".into())?;
    if !r.at_end() {
        return None;
    }
    let notes = vec![
        format!(
            "Parameter set {} (OID 0x{:08X}) — {}, node size n = {} bytes, tree height \
             h = {} (2^{} = {} one-time keys), len = {} WOTS+ hash chains, Winternitz \
             w = 16 (XMSS fixes w).",
            name,
            oid,
            hash,
            n,
            h,
            h,
            1u64 << h,
            len
        ),
        "root is the root node of the XMSS Merkle tree — the value a verifier recomputes \
         from a signature. SEED is the public seed that randomizes the tree's hash calls; \
         it is public, not secret."
            .to_string(),
        "Layout: u32 oid || root[n] || SEED[n]".to_string(),
    ];
    Some(Description {
        heading: "XMSS public key (RFC 8391 §4.1.7)".to_string(),
        notes,
        fields: r.fields,
    })
}

/// `u32 idx_sig || r[n] || sig_ots[0..len-1][n] || auth[0..h-1][n]` — the XMSS
/// signature of RFC 8391 §4.1.8. It carries no parameter-set identifier, so
/// the set is inferred from the total length and the leaf index's range; sets
/// that differ only in their hash share one layout and are all reported.
fn describe_xmss_signature(bytes: &[u8]) -> Option<Description> {
    let idx = u32::from_be_bytes(bytes.get(0..4)?.try_into().ok()?);
    let candidates: Vec<_> = XMSS_SETS
        .iter()
        .filter(|&&(_, _, _, n, h, len)| {
            xmss_signature_size(n, h, len) == bytes.len() && u64::from(idx) < 1u64 << h
        })
        .collect();
    let &&(_, _, _, n, h, len) = candidates.first()?;

    let mut r = Reader::new(bytes);
    r.take_u32("idx_sig".into())?;
    r.take(n, "r".into())?;
    for i in 0..len {
        r.take(n, format!("ots[{}]", i))?;
    }
    for i in 0..h {
        r.take(n, format!("auth[{}]", i))?;
    }
    if !r.at_end() {
        return None;
    }

    let names: Vec<String> =
        candidates.iter().map(|&&(oid, name, _, _, _, _)| format!("{} (0x{:08X})", name, oid)).collect();
    let hashes: Vec<&str> = candidates.iter().map(|&&(_, _, hash, _, _, _)| hash).collect();
    let notes = vec![
        format!(
            "idx_sig = {} — the index of the one-time key (Merkle-tree leaf) used, out of \
             the tree's 2^{} = {}. It must never be reused, which is what makes the scheme \
             stateful.",
            idx,
            h,
            1u64 << h
        ),
        format!(
            "Node size n = {} bytes, tree height h = {}, len = {} WOTS+ hash chains, \
             Winternitz w = 16 (XMSS fixes w).",
            n, h, len
        ),
        format!(
            "An XMSS signature carries no parameter-set identifier; this layout is the one \
             of {}. The hash function ({}) is fixed by the public key, not by the \
             signature.",
            names.join(" and "),
            hashes.join(" / ")
        ),
        "r is the randomizer hashed together with the message; ots[i] is the i-th WOTS+ \
         chain value (the one-time signature proper); auth[i] is the i-th node of the \
         authentication path from the used leaf up to the tree root."
            .to_string(),
        "Layout: u32 idx_sig || r[n] || ots[0..len-1][n] || auth[0..h-1][n]".to_string(),
    ];
    Some(Description {
        heading: "XMSS signature (RFC 8391 §4.1.8)".to_string(),
        notes,
        fields: r.fields,
    })
}

fn lms_note(set: &LmsSet) -> String {
    format!(
        "LMS parameter set {} (typecode 0x{:08X}) — {}, node size m = {} bytes, tree \
         height h = {}: the tree has 2^{} = {} leaves, each usable for one signature.",
        set.name,
        set.code,
        set.hash,
        set.m,
        set.h,
        set.h,
        1u64 << set.h
    )
}

fn ots_note(set: &OtsSet) -> String {
    format!(
        "LM-OTS parameter set {} (typecode 0x{:08X}) — {}, hash size n = {} bytes, \
         Winternitz w = {} bit{} per coefficient: p = {} hash chains (of which {} for the \
         checksum) and checksum shift ls = {}. A larger w trades signature size for \
         signing and verification time.",
        set.name,
        set.code,
        set.hash,
        set.n,
        set.w,
        if set.w == 1 { "" } else { "s" },
        set.p,
        set.p - (8 * set.n).div_ceil(set.w as usize),
        set.ls
    )
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Recognise `bytes` as an XMSS or HSS/LMS public key or signature. The four
/// forms are tried in order of how strongly they are self-describing, and each
/// must consume the value exactly, so at most one can match.
pub fn describe(bytes: &[u8]) -> Option<Description> {
    describe_hss_public_key(bytes)
        .or_else(|| describe_hss_signature(bytes))
        .or_else(|| describe_xmss_public_key(bytes))
        .or_else(|| describe_xmss_signature(bytes))
}

/// If `payload` is exactly one DER OCTET STRING, the length of its header —
/// Botan wraps an XMSS public key in one inside the `subjectPublicKey` BIT
/// STRING, so the raw key starts that many bytes in.
fn octet_string_header(payload: &[u8]) -> Option<usize> {
    if *payload.first()? != 0x04 {
        return None;
    }
    let first = *payload.get(1)?;
    let (len, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | usize::from(*payload.get(2 + i)?);
        }
        (len, 2 + count)
    };
    (header + len == payload.len()).then_some(header)
}

/// Recognise the XMSS / HSS-LMS value a BIT STRING or OCTET STRING carries.
/// The returned [`Field`] offsets are relative to the node's *content octets*
/// — that is, they already account for a BIT STRING's unused-bits octet and
/// for Botan's DER OCTET STRING wrapper around an XMSS public key.
pub fn describe_node(node: &Node) -> Option<Description> {
    let content = node.content_octets();
    // The BIT STRING's leading octet counts the unused bits and is not part of
    // the value; an OCTET STRING's content is the value itself.
    let base = if node.is_universal(ber::TAG_BIT_STRING) {
        1
    } else if node.is_universal(ber::TAG_OCTET_STRING) {
        0
    } else {
        return None;
    };
    let payload = content.get(base..)?;

    if let Some(mut described) = describe(payload) {
        shift_fields(&mut described, base);
        return Some(described);
    }
    // Botan's XMSS SPKI nests a DER OCTET STRING inside the BIT STRING; the
    // tree shows it as an encapsulated child, but the enclosing BIT STRING
    // should document the key too.
    let header = octet_string_header(payload)?;
    let mut described = describe(&payload[header..])?;
    shift_fields(&mut described, base + header);
    described.notes.push(
        "These bytes sit inside a DER OCTET STRING within the BIT STRING — the encoding \
         Botan produces for an XMSS public key."
            .to_string(),
    );
    Some(described)
}

fn shift_fields(described: &mut Description, by: usize) {
    for field in &mut described.fields {
        field.start += by;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field is contiguous with the last and the map covers the value.
    fn assert_tiles(fields: &[Field], from: usize, to: usize) {
        let mut at = from;
        for field in fields {
            assert_eq!(field.start, at, "field {} does not follow the previous one", field.short);
            at += field.len;
        }
        assert_eq!(at, to, "the fields must cover the whole value");
    }

    fn note_containing<'a>(described: &'a Description, needle: &str) -> &'a str {
        described
            .notes
            .iter()
            .find(|n| n.contains(needle))
            .unwrap_or_else(|| panic!("no note mentions {:?}: {:#?}", needle, described.notes))
    }

    #[test]
    fn lms_public_key_and_signature_resolve_their_typecodes_to_parameters() {
        // Single-level (plain LMS), tree height 5, Winternitz width 8.
        let (pkcs8, spki) = crate::hsslms::generate("SHA-256,HW(5,8)").unwrap();
        let roots = ber::parse_forest(&spki, 0).unwrap();
        let bit_string = roots[0].children.last().unwrap();

        let key = describe_node(bit_string).expect("the SPKI BIT STRING holds an LMS public key");
        assert_eq!(key.heading, "HSS/LMS public key (RFC 8554 §3.3)");
        // Offsets skip the BIT STRING's unused-bits octet.
        assert_tiles(&key.fields, 1, bit_string.content_octets().len());
        assert_eq!(
            key.fields.iter().map(|f| f.short.as_str()).collect::<Vec<_>>(),
            ["L", "lmsType", "otsType", "I", "T[1]"]
        );
        assert!(note_containing(&key, "L = 1").contains("plain LMS"));
        let lms = note_containing(&key, "LMS_SHA256_M32_H5");
        assert!(lms.contains("tree height h = 5") && lms.contains("32 leaves"), "{}", lms);
        let ots = note_containing(&key, "LMOTS_SHA256_N32_W8");
        assert!(ots.contains("Winternitz w = 8 bits") && ots.contains("p = 34"), "{}", ots);

        let (sig, _) = crate::hsslms::sign(&pkcs8, b"a tbsCertificate stand-in").unwrap();
        let sig_node = ber::univ(ber::TAG_BIT_STRING, false, [&[0u8][..], &sig].concat());
        let described = describe_node(&sig_node).expect("an LMS signature");
        assert_eq!(described.heading, "HSS/LMS signature (RFC 8554 §3.3)");
        assert_tiles(&described.fields, 1, sig.len() + 1);
        let shorts: Vec<&str> = described.fields.iter().map(|f| f.short.as_str()).collect();
        // Nspk, q, otsType, C, 34 chain values, lmsType, 5 path nodes.
        assert_eq!(&shorts[..5], ["Nspk", "q", "otsType", "C", "y[0]"]);
        assert_eq!(shorts[38], "lmsType");
        assert_eq!(&shorts[39..], ["path[0]", "path[1]", "path[2]", "path[3]", "path[4]"]);
        assert!(note_containing(&described, "Nspk = 0").contains("plain LMS"));
        assert!(note_containing(&described, "q = 0").contains("32"));
    }

    #[test]
    fn a_two_level_hss_signature_labels_each_level_and_its_signed_public_key() {
        let (pkcs8, _) = crate::hsslms::generate("SHA-256,HW(5,8),HW(5,8)").unwrap();
        let (sig, _) = crate::hsslms::sign(&pkcs8, b"two levels").unwrap();
        let described = describe(&sig).expect("a two-level HSS signature");
        assert_tiles(&described.fields, 0, sig.len());
        let shorts: Vec<&str> = described.fields.iter().map(|f| f.short.as_str()).collect();
        assert!(shorts.contains(&"sig[0].q"), "{:?}", &shorts[..6]);
        assert!(shorts.contains(&"pub[1].T[1]"));
        assert!(shorts.contains(&"sig[1].path[4]"));
        assert!(note_containing(&described, "Nspk = 1").contains("L = 2"));
        assert_eq!(described.notes.iter().filter(|n| n.starts_with("Level ")).count(), 2);
    }

    /// An XMSS signature is recognised by its length, so build one of the
    /// right size rather than paying for a real (slow) XMSS key generation.
    #[test]
    fn an_xmss_signature_is_recognised_by_its_length_and_leaf_index() {
        // XMSS-SHA2_10_256: n = 32, h = 10, len = 67.
        let size = xmss_signature_size(32, 10, 67);
        assert_eq!(size, 2500);
        let mut sig = vec![0xAB; size];
        sig[..4].copy_from_slice(&7u32.to_be_bytes());
        let described = describe(&sig).expect("an XMSS signature");
        assert_eq!(described.heading, "XMSS signature (RFC 8391 §4.1.8)");
        assert_tiles(&described.fields, 0, size);
        let shorts: Vec<&str> = described.fields.iter().map(|f| f.short.as_str()).collect();
        assert_eq!(&shorts[..3], ["idx_sig", "r", "ots[0]"]);
        assert_eq!(shorts.last(), Some(&"auth[9]"));
        assert!(note_containing(&described, "idx_sig = 7").contains("1024"));
        // The three 10/256 sets share this layout and are all named.
        let sets = note_containing(&described, "carries no parameter-set identifier");
        assert!(sets.contains("XMSS-SHA2_10_256") && sets.contains("XMSS-SHAKE256_10_256"), "{}", sets);

        // A leaf index past the end of the tree is not a signature.
        let mut bad = sig.clone();
        bad[..4].copy_from_slice(&1024u32.to_be_bytes());
        assert!(describe(&bad).is_none());
    }

    #[test]
    fn an_xmss_public_key_is_read_through_botans_octet_string_wrapper() {
        // u32 oid || root[64] || SEED[64] for XMSS-SHA2_10_512.
        let mut key = 4u32.to_be_bytes().to_vec();
        key.extend(std::iter::repeat_n(0xCD, 128));
        let inner = ber::univ(ber::TAG_OCTET_STRING, false, key.clone());
        let described = describe_node(&inner).expect("a bare XMSS public key");
        assert_eq!(described.heading, "XMSS public key (RFC 8391 §4.1.7)");
        assert_tiles(&described.fields, 0, key.len());
        let set = note_containing(&described, "XMSS-SHA2_10_512");
        assert!(set.contains("n = 64 bytes") && set.contains("len = 131"), "{}", set);

        // The same key as Botan encodes it: a DER OCTET STRING inside the
        // subjectPublicKey BIT STRING.
        let wrapped = ber::encode_node(&inner);
        let bit_string = ber::univ(ber::TAG_BIT_STRING, false, [&[0u8][..], &wrapped].concat());
        let through = describe_node(&bit_string).expect("the wrapped key is still recognised");
        // 1 unused-bits octet + 3 OCTET STRING header octets (04 81 84).
        assert_tiles(&through.fields, 4, 4 + key.len());
        assert!(through.notes.last().unwrap().contains("DER OCTET STRING"));
    }

    #[test]
    fn unrelated_values_are_not_mistaken_for_hash_based_ones() {
        assert!(describe(&[]).is_none());
        assert!(describe(&[0; 4]).is_none());
        // An ECDSA public key point and an RSA-2048 signature.
        assert!(describe(&[0x04; 65]).is_none());
        assert!(describe(&vec![0x5A; 256]).is_none());
        // The right length for XMSS-SHA2_10_256 but a wild leaf index.
        assert!(describe(&vec![0xFF; xmss_signature_size(32, 10, 67)]).is_none());
    }

    #[test]
    fn winternitz_chain_counts_match_rfc_8554_table_1() {
        // n = 32 (SHA-256) and n = 24 (SHA-256/192), widths 1/2/4/8.
        assert_eq!(winternitz_chains(32, 1), (265, 7));
        assert_eq!(winternitz_chains(32, 2), (133, 6));
        assert_eq!(winternitz_chains(32, 4), (67, 4));
        assert_eq!(winternitz_chains(32, 8), (34, 0));
        assert_eq!(winternitz_chains(24, 1), (200, 8));
        assert_eq!(winternitz_chains(24, 2), (101, 6));
        assert_eq!(winternitz_chains(24, 4), (51, 4));
        assert_eq!(winternitz_chains(24, 8), (26, 0));
    }

    #[test]
    fn typecodes_map_to_the_parameter_sets_of_rfc_8554_and_its_extensions() {
        assert!(lms_set(0x00).is_none() && lms_set(0x19).is_none());
        assert_eq!(lms_set(0x05).unwrap().name, "LMS_SHA256_M32_H5");
        assert_eq!(lms_set(0x09).unwrap().name, "LMS_SHA256_M32_H25");
        assert_eq!(lms_set(0x0a).unwrap().name, "LMS_SHA256_M24_H5");
        assert_eq!(lms_set(0x0f).unwrap().name, "LMS_SHAKE_M32_H5");
        let shake24 = lms_set(0x14).unwrap();
        assert_eq!((shake24.name.as_str(), shake24.m, shake24.h), ("LMS_SHAKE_M24_H5", 24, 5));

        assert!(ots_set(0x00).is_none() && ots_set(0x11).is_none());
        assert_eq!(ots_set(0x01).unwrap().name, "LMOTS_SHA256_N32_W1");
        assert_eq!(ots_set(0x04).unwrap().name, "LMOTS_SHA256_N32_W8");
        assert_eq!(ots_set(0x09).unwrap().name, "LMOTS_SHAKE_N32_W1");
        let shake24 = ots_set(0x10).unwrap();
        assert_eq!((shake24.name.as_str(), shake24.n, shake24.w), ("LMOTS_SHAKE_N24_W8", 24, 8));
    }
}
