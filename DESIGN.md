# asn1-editor — Design Document

## 1. Overview and goals

`asn1-editor` is a terminal (TUI) viewer **and editor** for ASN.1 BER/DER
encoded files, written in Rust using the [ratatui](https://ratatui.rs)
framework. It is inspired by
[SergZen/asn1_viewer](https://github.com/SergZen/asn1_viewer) but differs in
two fundamental ways:

1. **It can edit.** Values are edited as hex in the content pane and the
   whole file is re-encoded with corrected lengths on save.
2. **Its parse tree is verified against `dumpasn1`.** The parser is a
   hand-rolled TLV (tag/length/value) decoder whose structural output —
   including the heuristic detection of ASN.1 encapsulated in OCTET STRING /
   BIT STRING values — replicates Peter Gutmann's `dumpasn1` and is checked
   against the real binary by an integration test.

Goals:

* View the nested ASN.1 structure of a file as an interactive tree
  (left pane), with the selected element's decoded value and hex content
  shown on the right pane.
* Edit the content octets of any element in hex (invoked with `e`),
  re-encode with recomputed definite lengths, and save.
* Accept raw DER/BER, PEM, bare base64 and hex text input, and write the
  file back in the same outer format.
* Structural output parity with `dumpasn1` (`--dump` mode).
* Identify well-known structures by matching against ASN.1 specification
  modules in `specs/asn1/` (bundled: RFC 5280 → X.509 certificates and
  CRLs, RFC 5208 → PKCS#8 private keys, RFC 5958 → asymmetric key
  packages, RFC 5915 → SEC1 EC private keys, RFC 7292 → PKCS#12) and
  annotate the tree with the spec's field and type names (§8).
* Resolve common PKI and cryptographic OBJECT IDENTIFIER values from a
  deterministic built-in repository, showing a short name in the tree and
  the numeric and full textual forms in the content pane (§8a).
* Decrypt supported password-encrypted PKCS#8 containers into an editable
  virtual tree and keep the plaintext and ciphertext representations
  synchronized in both directions (§9a).
* Decrypt the encrypted regions of a supported PKCS#12 (`PFX`) container
  into editable virtual subtrees, revealing the certificates and private
  keys inside; an edit re-encrypts the region and recomputes the
  container's integrity `MacData` so the saved file stays consistent (§9b).
* Show, in the file browser, an undirected connection between a private-key
  file and the certificate carrying its public key — including keys that
  become known only after a password is entered (§9 → Key ↔ certificate
  links).
* Re-sign a modified certificate or CRL with its issuer's private key, when
  that key is available in the folder (as a plaintext key, or an encrypted
  key/PKCS#12 whose password was entered this session and retained) (§9c).
* Validate a certificate's certification path with OpenSSL against a set of
  trust anchors the user marks in the browser (`t`), using every other
  certificate in the tree as an untrusted intermediate, and show the result
  in the content pane (§9d).
* Modify a certificate's public key (`e` on its `subjectPublicKeyInfo`):
  generate a new key pair for a chosen signature algorithm, optionally save
  the private key (encrypted or not), and resign the certificates this one
  issued so they remain valid under the new key (§9e).
* Verify and generate signatures with the post-quantum FIPS 204 (ML-DSA) and
  FIPS 205 (SLH-DSA) algorithms, alongside the classical RSA/ECDSA/Ed25519
  set — so PQ-signed certificates and CRLs verify, and objects can be
  re-signed or re-keyed with any of them (§9c/§9e).
* Interpret the X.509 `BasicConstraints`, `KeyUsage` and `ExtendedKeyUsage`
  extensions in plain language in the content pane, and edit their fields
  through a structured form (`e` on the extension, or the `E` edit menu) —
  `cA` / `pathLenConstraint` for Basic Constraints (§9f), the nine named usage
  bits for Key Usage (§9g), and a set of well-known key purposes plus arbitrary
  dot-notation OIDs for Extended Key Usage (§9h).

Non-goals (see §14):

* Schema-aware *editing* (specs annotate and identify, but edits are not
  constrained by them).
* Preserving non-canonical BER encodings (indefinite lengths,
  non-minimal length octets) across a save.

## 2. Why not the `der` crate?

The reference project (`asn1_viewer`) decodes with RustCrypto's `der`
crate. That crate is designed for schema-driven decoding of *valid DER*:
it normalizes values, hides header offsets/lengths, rejects BER, and its
typed `ASN1Value` enum must special-case every tag. For an editor we need
the opposite: an uninterpreted TLV tree that

* keeps the absolute file offset, header length and content length of every
  element (required both for dumpasn1-identical output and for showing the
  user where a value lives),
* keeps unknown/arbitrary tags without loss,
* can be re-encoded byte-identically (proved by a round-trip test), and
* tolerates BER constructs such as indefinite lengths.

Therefore `src/ber.rs` implements a ~350-line TLV parser/encoder with no
dependencies. Interpretation (integers, OIDs, strings, times) is layered on
top as pure display helpers and never influences the tree structure.

## 3. Architecture

```
src/
  main.rs    CLI argument handling; dispatches to --dump or the TUI
  lib.rs     module exports (so integration tests can use the internals)
  ber.rs     TLV parser + encoder + Node model + value-decoding helpers
  dump.rs    dumpasn1-style text output (used by --dump and the tests)
  input.rs   container detection (raw / PEM / base64 / hex) + re-wrapping
  oid.rs     curated offline PKI/cryptography OID repository
  spec.rs    ASN.1 specification parser + structural matcher/labeler
  browser.rs far-left file browser: folding directory tree, independent
             of whatever document (if any) is open; refreshed against the
             filesystem, tagging new/modified/deleted files vs a startup snapshot
  x509.rs    structural decoding of Certificate/CertificateList + a
             recursive directory scan for candidate CA certs; also extracts
             the public-key identity of a private key or certificate for the
             key↔certificate links, and normalizes a key to PKCS#8 for signing
  verify.rs  signature verification and generation: classical via aws-lc-rs,
             post-quantum ML-DSA/SLH-DSA via openssl + the key↔cert link matcher
  pathval.rs certification-path validation against user-chosen trust anchors
             (uses the openssl crate)
  keygen.rs  private-key generation for the public-key modification flow
             (uses openssl, incl. openssl-sys FFI for ML-DSA/SLH-DSA by name):
             plaintext/encrypted PKCS#8 + the SPKI
  pkcs8.rs   structural decoding + password decryption/re-encryption of
             EncryptedPrivateKeyInfo (PBES2; uses aws-lc-rs). Exposes a
             reusable Pbes2 (PBKDF2 + AES-CBC) decryptor shared with pkcs12.rs
  pkcs12.rs  structural decoding + password decryption/re-encryption of
             PKCS#12 (PFX) containers; reuses pkcs8::Pbes2 for the regions
             and the openssl crate for the MacData HMAC (RFC 7292 App. B KDF)
  x509/basic_constraints.rs  structural decoding, interpretation and
             re-encoding of the X.509 BasicConstraints extension (a submodule
             of x509; structural only, no crypto)
  x509/key_usage.rs  the same for the X.509 KeyUsage extension (a BIT STRING
             of nine named bits)
  x509/extended_key_usage.rs  the same for the X.509 ExtendedKeyUsage extension
             (a SEQUENCE OF key-purpose OID; also uses oid.rs for names)
  app.rs     application state: tree, flattened rows, selection, edit logic
  tui.rs     ratatui event loop and rendering (no business logic)
tests/
  dumpasn1_compat.rs  structural comparison against the dumpasn1 binary,
                      plus a parse→encode round-trip test over testdata/
  spec_rfc5280.rs     spec parsing + identification of the DER test files
  oid_repository.rs  test-corpus OID coverage plus ML-DSA/SLH-DSA coverage
specs/asn1/  ASN.1 specification modules (rfc5280: certificates + CRLs;
             rfc5208: PKCS#8 private keys; rfc5958: asymmetric key packages;
             rfc5915: SEC1 EC private keys; rfc7292: PKCS#12)
testdata/  DER samples (EC cert, RSA cert, SEC1 EC key, PKCS#8 key,
           encrypted PKCS#8 key [password "asn1editor"], PKCS#12
           [password "asn1editor"], PKCS#7, CRL)
  chain/   a 3-level ECDSA P-256 hierarchy (root CA -> intermediate CA ->
           TLS server leaf) plus CRLs from the root and intermediate, for
           exercising signature verification (§9) end to end; also
           server_bad_signature.der, a structurally valid leaf cert with
           one signature byte flipped, for the "does NOT verify" path
  keylink/ one EC key pair (cert + plaintext PKCS#8 + SEC1 + encrypted
           PKCS#8 + PKCS#12) and one RSA pair (cert + PKCS#8), for exercising
           the key↔certificate links; the encrypted/PKCS#12 files use the
           password "asn1editor"
```

Dependency rule: `ber.rs` and `oid.rs` depend on nothing; `input.rs` and
`spec.rs` depend only on `ber.rs`, while `dump.rs` uses `ber.rs` plus the
shared OID repository; `browser.rs` depends only on the standard library
(it knows nothing about ASN.1); `x509.rs` depends on `ber.rs` + `input.rs`
(structural decoding only, no crypto); `verify.rs` depends on `x509.rs` +
`ber.rs` + `aws-lc-rs` + `openssl` (classical algorithms use `aws-lc-rs`; the
post-quantum ML-DSA/SLH-DSA pair uses OpenSSL, which covers both — `aws-lc-rs`
has ML-DSA but not SLH-DSA); `pkcs8.rs` depends on `ber.rs` + `aws-lc-rs` and
`pkcs12.rs` depends on `ber.rs` + `pkcs8.rs` + the `openssl` crate (region
encryption reuses `pkcs8::Pbes2`; only the `MacData` KDF/HMAC uses OpenSSL's
digest primitives); `pathval.rs` depends
on the `openssl` crate + `ber.rs` (it takes raw DER, not the `Node` tree);
`keygen.rs` depends on `openssl` + `openssl-sys`/`foreign-types` (raw FFI for
by-name PQ key generation) + `ber.rs` (`verify::sign` does the actual signing);
`x509::basic_constraints` and `x509::key_usage` depend only on `ber.rs`, and
`x509::extended_key_usage` on `ber.rs` + `oid.rs` (all structural, no crypto);
`app.rs` depends on all of the above; `tui.rs` renders `app.rs` and resolves
OID display names through `oid.rs` and formats file change-times through
`libc` (POSIX `localtime_r` / Windows `localtime_s`). External dependencies: `ratatui`, `aws-lc-rs`,
`openssl` (requires a system OpenSSL — 3.5+ for the post-quantum algorithms —
to link against), `openssl-sys` + `foreign-types` (raw OpenSSL key generation),
and `libc` (local-time conversion for the browser's change timestamps).

## 4. Data model

```rust
pub struct Node {
    pub class: Class,        // Universal / Application / ContextSpecific / Private
    pub tag: u32,            // tag number (high tag numbers supported)
    pub constructed: bool,
    pub indefinite: bool,    // was encoded with BER indefinite length
    pub offset: usize,       // absolute offset of the first identifier octet
    pub header_len: usize,   // identifier + length octets
    pub content_len: usize,  // content octets (excl. end-of-contents)
    pub value: Vec<u8>,      // content octets (primitive nodes only)
    pub children: Vec<Node>, // constructed children or encapsulated items
    pub encapsulates: bool,  // primitive OCTET/BIT STRING holding ASN.1
    pub expanded: bool,      // UI fold state
}
```

Invariants:

* Constructed node ⇒ `value` is empty, content is derived from `children`.
* Primitive node ⇒ `value` holds the content octets verbatim. For a
  BIT STRING this **includes** the leading unused-bits octet.
* `encapsulates` ⇒ primitive OCTET STRING or BIT STRING whose `value` also
  parsed as exactly one nested ASN.1 item (stored in `children`).
* A document is a *forest* (`Vec<Node>`): files with several concatenated
  top-level TLVs are supported.

Offsets/lengths are those of the *current* encoding. After an edit the tree
is re-encoded and re-parsed (§7), so they are always consistent.

## 5. Parser

`ber::parse_forest(data, abs_offset)` parses TLVs until `data` is exhausted;
trailing garbage is a hard error carrying the offset. Details:

* Identifier octets: low tags direct, high tags (`0x1F`) as base-128 with
  continuation bit; capped at 4 continuation octets like dumpasn1.
* Lengths: short form, long form up to 8 octets, and indefinite (`0x80`,
  constructed only), where children are read until an end-of-contents
  (`00 00`) marker.
* Recursion depth is capped (100) to protect against hostile inputs.

### Encapsulation heuristic (dumpasn1 parity)

`dumpasn1` displays primitive OCTET STRING / BIT STRING values that *look
like* they contain a nested ASN.1 object as a constructed item
(`OCTET STRING, encapsulates { … }`). Since the tree must match, the same
heuristic — a port of `checkEncapsulate()` from `dumpasn1.c` — is applied:

1. Content shorter than 2 bytes never encapsulates.
2. For BIT STRING the unused-bits octet is skipped first, and contents of
   ≤ 4 remaining bytes are treated as bit flags, never as nested data.
3. Read one nested TLV header from the content. Its class must be
   *universal* or *context-specific*; its tag number must be in 1..=0x31.
4. The nested item must fill the content **exactly** (single item, no
   trailing bytes).
5. A primitive nested item is accepted as-is; a constructed one only if it
   is a SEQUENCE or SET (avoids false positives on string types that
   masquerade as constructed tags).
6. Additionally (stricter than dumpasn1) the nested content must parse
   fully and recursively; otherwise the node falls back to a plain
   primitive. This can only diverge from dumpasn1 on inputs that dumpasn1
   itself would report as broken.

Like dumpasn1, this produces well-known "false positives" (e.g. a
SubjectKeyIdentifier whose 20-byte hash happens to start with `0x04 0x12`
would not, but other values may decode as nested items). That is accepted:
the goal is to display exactly what dumpasn1 displays.

## 6. Encoder

`ber::encode_node` always emits **definite, minimal-length DER framing**:

* constructed / encapsulating nodes: content = concatenated encodings of
  the children (for an encapsulating BIT STRING prefixed by the preserved
  unused-bits octet);
* primitive nodes: content = `value` verbatim.

Consequences, verified by tests:

* Parsing a DER file and re-encoding it is **byte-identical**
  (`parse_encode_roundtrip_on_testdata`).
* BER files using indefinite lengths or non-minimal length octets are
  *normalized* on save. The TUI marks such nodes ("indefinite length").

## 7. Editing model

All value edits ultimately replace the **content octets** of the selected
element. What that means per node kind:

| Node kind        | Edit buffer contains                | On apply |
|------------------|-------------------------------------|----------|
| primitive        | the value bytes (BIT STRING: incl. unused-bits octet) | bytes stored verbatim; encapsulation re-detected |
| constructed      | the encoding of all children        | bytes must parse as a valid TLV series, else the edit is rejected with an error in the status bar |
| encapsulating    | the (current) nested encoding       | same as primitive; if it no longer parses it becomes a plain value |

Apply pipeline (`App::commit_edit` → `App::rebuild`):

1. The editor buffer is converted to bytes (`Editor::to_bytes`); a
   validation error (odd hex digit count, bad base64, malformed number/OID,
   out-of-range date field, …) blocks apply and is shown in the status bar
   as well as live in the editor pane.
2. The new bytes are placed into the node (children re-parsed for
   constructed nodes).
3. The **whole forest is re-encoded and re-parsed.** This single mechanism
   recomputes every offset and every parent length (length changes
   propagate up automatically), and re-runs encapsulation detection —
   there is no incremental fix-up code to get wrong.
4. Fold state and selection are carried over by structural walk / node path.

The re-parse in step 3 cannot fail for tree shapes produced in step 2 (our
own encoder output is always parseable); if it ever did, the previous tree
is kept and an internal error is shown.

For ordinary rows this pipeline operates on the document forest. Rows in
the decrypted PKCS#8 virtual forest use the same editors and structural
operations, but `rebuild()` first serializes and re-encrypts that forest,
then applies the pipeline to the resulting outer document (§9a). Conversely,
an edit to the outer representation refreshes an already-unlocked virtual
forest by decrypting it again.

### The edit menu and value editors

`e` opens the type-specific editor directly (mode 5 below); `E` opens a
popup menu (`Mode::EditMenu`) with five editing modes, also selectable
with `1`-`5`:

1. **Tag type** — the type-picker dialog with a `Retag` target (below).
2. **Hex** — `Editor::Hex`, a 16-bytes-per-line hex grid.
3. **Base64** — `Editor::Text` with `TextFormat::Base64`; pre-filled with
   the current value, whitespace ignored on apply.
4. **Raw binary** — `TextFormat::Raw`: typed or pasted characters become
   the value bytes verbatim (UTF-8). Bracketed paste is enabled, so
   clipboard content arrives as a single paste event in every editor (the
   hex editor filters it to hex digits). Pre-filled only when the current
   value is valid UTF-8. A terminal cannot transport arbitrary byte values
   as key input, hence "raw" means "the UTF-8 bytes of the characters".
5. **Type specific** — the most natural editor for the element's universal
   type:

   | Type | Editor |
   |------|--------|
   | INTEGER, ENUMERATED | decimal integer (pre-filled) |
   | REAL | decimal number, `inf`/`-inf`; encoded as ISO 6093 NR3 (decimal), zero as empty content |
   | OBJECT IDENTIFIER | dot notation (pre-filled) |
   | BOOLEAN | TRUE / FALSE (also 1 / 0) |
   | UTF8String and other ASCII/UTF-8 string types | plain text |
   | BMPString / UniversalString | plain text, encoded UCS-2 / UCS-4 big-endian |
   | UTCTime / GeneralizedTime | a form with **separate fields for year, month, day, hour, minute, second** (`Editor::DateTime`), pre-filled from the current value; `←→`/Tab switch fields, `↑↓` adjust, ranges validated on apply |
   | OCTET STRING, BIT STRING, everything else | hex grid |

   NULL and constructed elements have no single natural value; the menu
   says so and stays open.

Every editor shows a live feedback line: the byte count the buffer would
encode to, or the validation error, recomputed each frame.

### The type-picker dialog

Both inserting a new element and changing an existing element's type open a
centered popup (`Mode::TypePicker`) that chooses an identifier octet, with
**one column per bit field**:

- *Class (bits 8-7)*: universal / application / context-specific / private;
- *Form (bit 6)*: primitive / constructed — automatically forced where only
  one form is legal (SEQUENCE/SET are always constructed, the scalar
  universal types always primitive; string types remain free, as BER allows
  constructed strings);
- *Tag number (bits 5-1)*: a list of the named universal types, or a typed
  decimal number for the other classes (high tag numbers > 30 are encoded in
  the multi-octet form automatically).

The resulting identifier octets are previewed live at the bottom of the
dialog. The `PickerState` carries a `PickerTarget` (`Insert{parent,index}`
or `Retag{path}`) that decides what `Enter` does.

### Structural edits: insert, retag, delete, reorder

Beyond value edits, the tree structure itself can be changed. These
operations mutate the node forest in place and then run the same
`rebuild()` pipeline as value edits, so enclosing lengths and all offsets
are recomputed by the one existing mechanism:

* **Insert** (`i` = new sibling after the selection, `I` = new first child
  of a constructed/encapsulating element): opens the type-picker with an
  `Insert` target. `Enter` proceeds to the hex editor where **only the
  value (content octets) is entered, defaulting to empty**; identifier and
  length octets are generated by the encoder, so the element's length — and
  that of every enclosing element — is set automatically. For a constructed
  element the value must parse as a valid TLV series (empty is fine),
  otherwise the insert is rejected non-destructively. Inserting into an
  empty document (or an empty constructed element) is supported; a
  collapsed parent is auto-expanded so the insertion is visible, and the
  selection lands on the inserted element.
* **Retag** (`E` → "Tag type"): opens the type-picker with a `Retag` target,
  pre-populated with the selected element's current class, form and tag.
  Confirming a different type rewrites the identifier octets **in place
  while keeping the content octets**; the length is unchanged unless the
  encoding of the new tag differs in size, which `rebuild()` handles. The
  value is edited separately with `e`. Switching from primitive to
  constructed re-parses the existing content as children (rejected
  non-destructively if it is not valid ASN.1); the reverse flattens the
  children back into raw content octets. Confirming the unchanged type is a
  no-op.
* **Delete** (`d` twice): removes the selected element and its subtree.
  The first `d` arms a confirmation shown in the status bar (any other key
  disarms it); the second `d` deletes. Deleting the last top-level element
  leaves a valid empty document.
* **Reorder** (`J`/`K`): swaps the selected element with its next/previous
  sibling; the selection follows the moved element. Moving past the first
  or last sibling is a no-op with a status message.

A structural edit inside an *encapsulating* OCTET/BIT STRING can change
what the encapsulation heuristic sees (e.g. two items no longer "fill the
value exactly" as one); after the rebuild such a node is then displayed as
a plain primitive value again — consistent with what dumpasn1 would show
for the resulting bytes.

## 8. ASN.1 specifications (`src/spec.rs`, `specs/asn1/`)

The editor can identify well-known structures and annotate the tree with
the names from their ASN.1 definition.

### Specification files

`specs/asn1/` holds ASN.1 modules in 1988 syntax. `specs/asn1/rfc5280`
contains the two modules of RFC 5280 Appendix A (PKIX1Explicit88 and
PKIX1Implicit88), extracted verbatim from the RFC text (de-paginated,
otherwise unmodified). `specs/asn1/rfc5208` contains the PKCS#8 module
(RFC 5208 Appendix A → `PrivateKeyInfo` and `EncryptedPrivateKeyInfo`) and
`specs/asn1/rfc5958` the asymmetric-key-package module that obsoletes it
(RFC 5958 Appendix A → `OneAsymmetricKey`, which is `PrivateKeyInfo` plus
an optional `[1] publicKey` field present in version v2, plus its own
`EncryptedPrivateKeyInfo`). Both carry documented
adaptations for this subset parser: the `{{…}}` / `{ … }` information-
object-set parameters on `AlgorithmIdentifier` (and, for RFC 5958, the
`[[2: … ]]` version-bracket around `publicKey`) are dropped — none affect
the DER structure being matched. Their `AlgorithmIdentifier` is left as an
(import) reference, resolved across modules against the RFC 5280
definition loaded from the same directory — exercising the cross-module
reference resolution described below.

`specs/asn1/rfc5915` contains the SEC1 EC private-key structure (RFC 5915
Section 3 → `ECPrivateKey` — the "EC PRIVATE KEY" PEM, distinct from the
PKCS#8 wrapping). RFC 5915 gives the type inline rather than as a wrapped
module, so it is wrapped here in a `DEFINITIONS EXPLICIT TAGS` module (the
DER uses constructed `[0]`/`[1]` tags); its `{{NamedCurve}}` parameter is
dropped and the referenced `ECParameters` (from RFC 5480) is reproduced
with just its `namedCurve` alternative.

`specs/asn1/rfc7292` contains the PKCS#12 `PFX` structure (RFC 7292
Appendix C) together with the PKCS#7 `ContentInfo`/`EncryptedData` types it
builds on, so a `.p12`/`.pfx` identifies as `PFX` and its bags, safe
contents, and encryption parameters are labeled. Two adaptations avoid the
subset parser's and matcher's sharp edges: the open-type bag/attribute
fields (`BAG-TYPE.&Type`, etc.) become `[0] EXPLICIT ANY` / `SET OF ANY`
(the concrete bag contents are still named by the encapsulation pass), and
the `DigestInfo` used by `MacData.mac` is inlined into `MacData` rather than
given its own top-level name — a standalone `SEQUENCE { AlgorithmIdentifier,
OCTET STRING }` is structurally identical to an `EncryptedPrivateKeyInfo`,
and as a named candidate root it would win the source-ordered tie (rfc7292 >
rfc5958) and mislabel encrypted PKCS#8 keys.

Additional files dropped into the directory are parsed automatically;
parse failures are reported as warnings and the file is skipped. Files are
loaded in sorted filename order and the *first* definition of a type name
wins (so `rfc5208`, which sorts before `rfc5280`, must not redefine any
shared type — it doesn't; it only references `AlgorithmIdentifier`, and
`rfc5958` likewise only adds `OneAsymmetricKey`/`PublicKey`). Which of two
equally-good *matches* wins is a separate, source-ordered rule (§ below):
that is how the newer RFC 5958 interpretation is preferred over RFC 5208
for a document both describe. The directory is located via
`$ASN1_EDITOR_SPECS`, then `./specs/asn1`, then `specs/asn1` next to an
ancestor of the executable.

### The specification parser

A tokenizer (ASN.1 comments `--…--`/`--…EOL`, identifiers with hyphens,
`::=`, braces/brackets/parens) feeds a recursive-descent parser for the
'88 subset used by such modules:

* module headers with `DEFINITIONS [EXPLICIT|IMPLICIT] TAGS ::= BEGIN … END`
  (the tagging default is recorded per type definition);
* `IMPORTS`/`EXPORTS` sections (skipped);
* type assignments `Name ::= Type` with SEQUENCE/SET (fields), SEQUENCE
  OF/SET OF (incl. `SIZE` constraints before `OF`), CHOICE, tagged types
  `[n]`, `[APPLICATION n]` … with optional IMPLICIT/EXPLICIT, OPTIONAL and
  DEFAULT components, ANY (DEFINED BY), and all universal primitive types;
* value assignments (OID constants, integer bounds like `ub-name`) are
  parsed and discarded;
* constraints (`(SIZE (1..MAX))`, value ranges), named INTEGER values and
  named BIT STRING bits are skipped — they do not affect structure.

The result is a flat database of `TypeDef`s from all files; references
resolve across modules (so PKIX1Implicit88's imports from PKIX1Explicit88
work), and unknown references match like ANY, keeping partial spec sets
usable.

### Structural matching and identification

At load time (and after every edit `rebuild()`), a document consisting of
exactly one top-level element is matched against **every** type
definition:

* primitives check the universal tag; SEQUENCE/SET require the
  corresponding constructed universal tag; SEQUENCE OF/SET OF require all
  children to match the element type;
* SEQUENCE/SET components are matched in order with backtracking over
  OPTIONAL/DEFAULT components;
* CHOICE tries each alternative;
* tagged types check class and tag number. EXPLICIT tags must wrap
  exactly one element which is matched against the inner type; IMPLICIT
  tags re-check the inner type's body against the same element. The
  module's tagging default applies where no keyword is given, and an
  IMPLICIT tag on a type that resolves to an untagged CHOICE or ANY is
  treated as EXPLICIT (X.680 rule);
* ANY matches any single element.

Every successful (sub-)match records a label `(field name, type name)`
for the node's path; choices append the alternative name (e.g.
`Time.utcTime`). The candidate whose match labels the **most nodes**
wins; matches labeling fewer than two nodes (e.g. a bare `ANY`) are
discarded as noise. **Ties in node count are broken in favor of the
lexicographically greater `source`** (spec filename). Since bundled
modules are named by RFC number, this makes a newer RFC supersede an
older one it obsoletes when a document matches both: an RFC 5208
`PrivateKeyInfo` and the RFC 5958 `OneAsymmetricKey` that replaces it
match a v1 PKCS#8 key identically, and `rfc5958` (> `rfc5208`) is
preferred, so the key is reported as `OneAsymmetricKey`. (A v2 key, whose
`[1] publicKey` field only `OneAsymmetricKey` defines, matches only RFC
5958 outright — no tie to break.) Within one source, ties keep the first-
defined type. With the bundled modules loaded, X.509 certificates
identify as `Certificate`, CRLs as `CertificateList`, PKCS#8 /
asymmetric-key private keys as `OneAsymmetricKey`, and SEC1 EC private
keys as `ECPrivateKey`.

After the top-level match, ASN.1 nested inside **encapsulating** OCTET /
BIT STRING values (§5) is labeled too. The top-level match treats such a
value as an opaque primitive (`PrivateKey ::= OCTET STRING`,
`subjectPublicKey BIT STRING`, …) and never descends into it, so a
separate post-pass (`label_encapsulated`) walks the tree and, for each
encapsulating node, independently `identify`s its single nested item and
merges the resulting labels under that node's path. This is what names the
fields of the RFC 5915 `ECPrivateKey` carried inside a PKCS#8
`OneAsymmetricKey`'s `privateKey` OCTET STRING. Only extra per-node labels
are added — the document's overall type stays that of the top-level match
— and the same `score ≥ 2` noise filter applies, so content that matches
no bundled type (e.g. an RSA `SEQUENCE { INTEGER, INTEGER }` public key,
with no PKCS#1 module loaded) is left unlabeled rather than
mis-identified.

The identification is recomputed after every edit, so a document can gain
or lose its labels as edits make it conform or not conform to a spec.

### Display

* Tree pane: `field: ` prefixes (cyan italic) and ` ·TypeName` suffixes
  (green, shown when the spec name adds information beyond the raw ASN.1
  type); the identified document type in the pane title.
* Content pane: a `Spec` line with the selected element's field and type
  name plus the overall document type and source file.

Not yet done (future work): OID-to-*type* dispatch for `ANY DEFINED BY`
and OCTET STRING bodies whose type is selected by a sibling OID (e.g.
labeling an X.509 extension's `extnValue` according to its `extnID`, or an
RSA private key by its algorithm OID). This is separate from the OID name
repository in §8a: the latter resolves values for display but does not map
an algorithm/extension OID to an ASN.1 schema. The encapsulation post-pass
above labels nested content only when it structurally matches a bundled
type on its own. Value-level checks are also future work (constraints are
ignored).

## 8a. Built-in OID repository (`src/oid.rs`)

OID name resolution is offline and deterministic. `oid.rs` owns one
curated repository shared by the TUI and `dump.rs`; it does not read
`dumpasn1.cfg`, contact a resolver, or allow display behavior to depend on
the host machine. Each `OidEntry` stores:

* numeric arcs and their preformatted dot notation;
* a short descriptor, equal to the final textual token; and
* the complete textual token chain from the root to the leaf (rendered by
  joining the tokens with dots).

The repository covers all OIDs parsed from the bundled test corpus and a
broader practical set of PKI/cryptographic identifiers: X.500 attributes,
X.509 certificate/CRL extensions, PKIX extended-key purposes, PKCS #1/#5/
#7/#9, CMS content types, RSA and EC algorithms and curves, Ed25519/Ed448
and X25519/X448, HMAC and SHA families, and AES CBC/GCM modes. It also
contains the complete NIST CSOR signature-algorithm allocation for pure
and pre-hash ML-DSA and SLH-DSA (`2.16.840.1.101.3.4.3.17` through
`.46`).

Display rules deliberately preserve information for unknown values:

* the tree summary uses `short_name` for a known OID and dot notation for
  an unknown OID;
* the content header always adds an `OID` line in dot notation for a valid
  OID node and, when it is known, a `Name` line containing the complete
  textual chain. These lines are the final header fields immediately
  before the blank line and raw content-octet display;
* `--dump` uses the same `short_name` lookup, replacing its former private
  minimal table. Unknown OIDs retain the existing numeric dump form.

`tests/oid_repository.rs` recursively loads every file under `testdata/`
and fails if any parsed OID is absent. A second test checks every ML-DSA /
SLH-DSA assignment in the NIST range; module tests additionally enforce
unique arcs, matching dotted/arcs forms, and `short_name == chain.last()`.

## 9. Signature verification (`src/x509.rs`, `src/verify.rs`)

On startup, the directory the opened file lives in (or the directory
itself, when the program is started with one — see §11) is scanned
recursively for X.509 certificates, which are kept as candidate issuers.
For the currently open document, if it structurally decodes as a
`Certificate` or `CertificateList` (CRL), the tool reports who signed it
and whether the signature actually verifies.

This is independent of §8's spec-based identification — it works whether
or not the RFC 5280 spec files are installed, and needs a structurally
unambiguous decoder rather than best-effort annotation (the generic spec
matcher gives `TBSCertificate.signature` and `Certificate.signatureAlgorithm`
the same field name at different depths, which would be ambiguous here).
`src/x509.rs` therefore decodes `Certificate`/`CertificateList` directly
over `ber::Node` by fixed ASN.1 grammar position — the same style
`dump.rs` uses to interpret universal tags — with no cryptographic
knowledge of its own:

* Both shapes are `SEQUENCE { tbs, signatureAlgorithm, signature }`; the
  outer `tbs` element is then matched positionally against
  `TBSCertificate` (looking for `issuer`, `validity`, `subject`,
  `subjectPublicKeyInfo` after the optional `[0]` version) or, on
  failure, against `TBSCertList` (`issuer` followed by a *primitive*
  `thisUpdate` Time — the field that is constructed, `validity`, in a
  Certificate at the same position — is what disambiguates the two
  shapes). Only OPTIONAL/context-tagged fields vary in presence; DER
  otherwise encodes SEQUENCE fields in fixed declaration order, so this
  positional walk is simpler and more precise here than generic
  structural matching.
* `authorityKeyIdentifier`/`subjectKeyIdentifier` extension values are
  read from the tree's own encapsulation heuristic (§5) — both extensions
  decode to nested ASN.1 that already satisfies it, so no separate nested
  parse is needed; if the heuristic didn't fire (a malformed extension),
  the key identifier is just reported absent and matching falls back to
  DN comparison.
* Issuer/subject `Name` comparison is byte equality on the raw DER
  encoding (sliced directly out of the document's bytes using the node's
  `offset`/`header_len`/`content_len`, same as offsets are used
  everywhere else in the tool) rather than a semantic RDN comparison —
  correct because DER encoding is canonical, and much simpler than
  writing an AttributeTypeAndValue comparator.
* The public key bytes handed to the verifier are exactly the SPKI's
  `subjectPublicKey` BIT STRING content (RSA: DER `RSAPublicKey`; EC: SEC1
  uncompressed point; Ed25519: raw 32 bytes) — no re-encoding. Note this
  is read from `Node::value` (the raw content octets, always populated),
  not `Node::content_octets()`: RSA and ECDSA signature/key BIT STRINGs
  routinely satisfy the encapsulation heuristic themselves (an RSA
  `RSAPublicKey` or an ECDSA `(r, s)` signature *is* valid nested ASN.1),
  and `content_octets()` would re-encode from the parsed children —
  correct for DER input, but a real (if rare) risk of silently altering
  the exact bytes a signature is defined over.

`src/verify.rs` uses two crypto backends. **Classical** algorithms go through
`aws-lc-rs` (chosen for its `ring`-compatible API): the signature-algorithm
OID maps to a `VerificationAlgorithm` (RSA PKCS#1 v1.5 with SHA-1/256/384/512,
ECDSA P-256/P-384 with SHA-256/384, Ed25519). **Post-quantum** ML-DSA
(FIPS 204: 44/65/87) and SLH-DSA (FIPS 205: all twelve parameter sets) go
through the `openssl` crate (OpenSSL 3.5+), which covers *both* families —
`aws-lc-rs` has ML-DSA but not SLH-DSA, so OpenSSL is used uniformly for the
pair. `is_pq` routes the pure PQ OIDs (`2.16.840.1.101.3.4.3.{17..=31}`) to
that path; these signatures are "pure" (the message is signed directly, no
external digest, matching the LAMPS X.509 profiles), so OpenSSL's one-shot
`Signer`/`Verifier` *without* a digest are used. `verify_signature` is the
single choke point both `verify_against` and `is_self_signed` call: given the
raw `subjectPublicKey` bytes it either hands them to `aws-lc-rs` (classical) or
rebuilds a `SubjectPublicKeyInfo` around them (`spki_der`) and loads it with
`PKey::public_key_from_der` (PQ). `verify_against` picks a candidate issuer
from the scanned index (an `authorityKeyIdentifier` / `subjectKeyIdentifier`
match is preferred over issuer/subject DN byte-equality when available) and
verifies. It takes a generic `(tbs bytes, sig alg OID, signature bytes,
candidate issuers)` shape, so a future CMS `SignerInfo` decoder can reuse it
unchanged. (RSA-PSS and the pre-hash `HashML-DSA`/`HashSLH-DSA` variants are
still not implemented.)

Display: a `Signature` line in the content pane header, directly below
`Spec` — shown once per document regardless of which node is selected,
since (unlike `Spec`) it is a whole-document fact, not a per-node one.
Recomputed after every edit (the same `rebuild()` that re-runs spec
identification), so an in-TUI edit that breaks a certificate's signature
is reflected immediately, without saving.

The directory itself is only walked once, at startup — `signables`/
`ca_index` are not refreshed to pick up other files changing on disk
during the session. The *currently open file's own entry* in both is the
one exception: every time `sig_status` is recomputed (`App::
recompute_sig_status`, i.e. on load and after every edit), that entry is
first replaced with one derived from the live, possibly-unsaved document,
not the on-disk bytes the startup scan read. Without this, an edit could
correctly update the edited file's own `sig_status` while leaving every
*other* file's relation to it stale — e.g. editing an intermediate CA's
certificate wouldn't retroactively show the leaves it issued as
unverified, since `relations_for` (below) resolves issuers purely by
searching `signables`/`ca_index`. This is why the sync lives inside
`recompute_sig_status` rather than being folded into `rebuild()`
ad hoc: the two are computed from the same index and must stay
consistent with each other. Directory scanning skips symlinks (rules out
symlink cycles) and files over 1 MiB (real certs/CRLs are always tiny;
this keeps scanning e.g. a `target/` or `.git/` directory cheap) —
non-signable and unparseable files are silently skipped, not errors.

### Cross-file relation graph (file browser)

The same scan also drives a graphical view, in the file browser, of how
the selected file relates cryptographically to the others. `scan_dir_signables`
returns every signed object found (certs *and* CRLs, unlike the
cert-only candidate index, which is derived from it via `cert_candidates`);
`verify::relations_for(signables, selected)` then resolves, for each
scanned file, the single issuer `verify_against` would pick, and reads off
the two kinds of edge touching `selected`:

* `signed_by` (incoming) — the one file whose signature covers `selected`;
* `signs` (outgoing) — every file `selected` is the issuer of.

Each `RelationEdge` carries a `verified` flag: true when the signature
cryptographically checks out, false when the issuance is only *claimed*
(the issuer is present but its signature does not verify). Self-signed
certificates — issuer equal to their own subject *and* the signature
verifying under their own key — contribute no issuance edge at all: their
"issuer" is themselves, so any arrow could only point at the file itself
or at another *copy* of the same certificate (the same root stored as
both `.der` and `.pem`, like `testdata/cert_ec.*`), which is issuance
noise, not a relation. Note this only suppresses the self-signed
certificate's own incoming edge; the objects it signed still point at it.
The check is cryptographic rather than by file path or DN alone, so a
key-rollover certificate (self-*issued*: same DN, but signed by the
previous key) still shows its true issuance edge. The logic is pure and
unit-tested against the bundled `testdata/chain/` hierarchy and the
duplicated `cert_ec` pair; rendering is separate and untested.

In the browser pane, the arrows are drawn as routed elbow connectors that
really travel from source row to destination row — a horizontal stub out
of the source, a vertical trunk, and a horizontal stub with an arrowhead
into the destination (two 90° turns, rounded corners):

```
╭─►   • intermediate_ca ───╮     incoming (cyan): root_ca signed the
│       intermediate_crl◄──┤       selection, arrowhead entering it on
╰──     root_ca.der        │       the left
        root_crl.der       │     outgoing (magenta): objects the selection
        server.der      ◄──┤       signed, drawn to the right of the
        server_bad_si…  ◄──╯       names, sharing one trunk with ┤/╯
                                   branches (the last one red: claimed
                                   but cryptographically broken)
```

**The incoming "signed by" edge is drawn to the left of the file names**
(cyan), **outgoing "signs" edges to the right** (magenta), with names
padded — and truncated with `…` if need be — so the shared right-hand
trunk stays aligned inside the pane. A claimed-but-unverified edge is
**red** (currently only reachable via a cryptographic signature failure —
e.g. `testdata/chain/server_bad_signature.der`); when *every* drawn
outgoing edge is broken the whole trunk turns red, otherwise only the
broken targets' stubs do. The gutters take up columns only while there is
an arrow to draw. Routing (corner/junction/color selection per row) lives
in `tui::arrow_gutters`, a pure function unit-tested separately from any
rendering; edges to rows hidden inside collapsed directories are skipped.
A short colored legend sits on the pane's bottom border.

`App::browser_relations` is recomputed whenever the browser selection
moves, and also whenever `sig_status` is (`App::recompute_sig_status`,
which syncs the open file's index entry as described above before calling
`recompute_browser_relations`) — so editing the open document updates the
arrows for *any* browser row currently on screen, not only the one
matching the edited file, and not only after the browser selection next
moves. This matters because the browser selection and the open document
are independent (live preview aside): a user can edit file A while the
browser happens to be showing file B's relation to A, and B's arrow must
still reflect the edit without any navigation happening in between.

### Key ↔ certificate links (file browser)

Alongside the directional signature edges, the browser draws an
**undirected** link between a private-key file and the certificate that
carries its public key — "this folder holds the key for that cert". The
match is structural, not cryptographic: `x509::public_key_id_of_private_key`
recovers the public key a private key corresponds to (the EC public point a
SEC1 `ECPrivateKey` / PKCS#8-wrapped EC key embeds in its optional
`publicKey [1]`; the modulus and exponent of an RSA key), reducing it to a
canonical `PublicKeyId` that compares equal to the same key extracted from a
certificate's `subjectPublicKeyInfo` (`public_key_id_of_signable`). No point
multiplication happens — a key without an embedded public part simply isn't
matched. `verify::key_links_for(key_bearers, certs, selected)` is the pure
matcher; it links a key-bearing file and a certificate file sharing a
`PublicKeyId`, never a file to itself.

The set of key-bearers has two halves, assembled in
`App::compute_key_links`:

* **static** — plaintext key files found by `x509::scan_dir_key_files` at
  startup (a snapshot like `signables`; encrypted keys and PKCS#12
  containers are excluded, their key being unreadable without a password).
  Each is kept only if it is a **cryptographically usable** key
  (`verify::private_key_usable` loads it, which for an EC key confirms the
  private scalar matches the embedded public key) — a structurally-valid but
  corrupted key never shows a link. The open document's own entry is
  refreshed from its live, possibly-edited content on every
  `recompute_sig_status` (`App::refresh_own_key_file`, the key-file analog of
  the `signables` refresh), so editing a key to break it removes its link
  immediately, and changing its key updates the target;
* **unlocked** — public keys recovered when the user decrypts an encrypted
  PKCS#8 key or a PKCS#12 (§9a/§9b) with `z`. These are cached in
  `App::unlocked_keys` keyed by file path at decryption time and **persist
  across navigation**, so the link stays visible after the user browses away
  from the file they decrypted (browsing previews/opens files, which clears
  the live decrypted state — the cache is what carries the recovered key
  forward). This is what "shown once the password becomes available"
  requires: before the password there is no link; after it, the link appears
  and remains for the session.

The certificates are taken from the same `signables` scan. Because a
PKCS#12 is not itself a certificate file, its internal certificate never
creates an intra-file self-link; the container links to *external*
certificate files matching its shrouded key.

In the browser these links are rendered in their **own leftmost gutter**,
separate from the signature gutters so the two never collide when a
certificate has both a signer and a matching key present. The connector uses
the same rounded elbow as the signature arrows but with **no arrowheads**
(the relation has no direction) and a distinct color (`REL_KEY`, green): one
trunk from the selected row branching (`╭`/`├`/`╰`) into every linked file.
Routing lives in `tui::arrow_gutters` alongside the signature routing and is
unit-tested the same way. The bottom-border legend gains a `── key` entry.

## 9a. Encrypted private-key decryption and synchronized editing (`src/pkcs8.rs`)

An `EncryptedPrivateKeyInfo` (RFC 5958 §3 / RFC 5208) wraps a private key
in password-based encryption; its serialized `encryptedData` OCTET STRING
is opaque ASN.1 content. The editor exposes the corresponding plaintext as
a **virtual, editable ASN.1 subtree** directly below that OCTET STRING. The
virtual nodes are not inserted into the outer `EncryptedPrivateKeyInfo`
forest; saving always writes only the real outer tree, whose ciphertext and
PBES2 IV are updated when the virtual tree changes.

`pkcs8::parse` structurally decodes `EncryptedPrivateKeyInfo ::= SEQUENCE {
encryptionAlgorithm AlgorithmIdentifier, encryptedData OCTET STRING }`
(positional `ber::Node` walking, like `x509.rs`) and extracts the PBES2
(`1.2.840.113549.1.5.13`) parameters: a **PBKDF2** key-derivation
(`…1.5.12` — salt, iteration count, PRF HMAC-SHA1/256/384/512, optional
key length) and an **AES-128/256-CBC** encryption scheme (IV). Its return
type distinguishes the three cases the UI needs: `Ok(None)` (not an
encrypted key), `Err(msg)` (an encrypted key but an unsupported scheme —
PBES1, scrypt, AES-192 which `aws-lc-rs` doesn't expose, …), `Ok(Some)`
(supported). `decrypt(password)` PBKDF2-derives the key (`aws-lc-rs`
`pbkdf2::derive`), AES-CBC decrypts (`cipher::DecryptingKey::cbc`, raw, so
PKCS#7 padding is stripped and validated manually), and confirms the
plaintext is a single ASN.1 SEQUENCE — the wrong-password signal (bad
padding, or the rare valid-padding-but-garbage case).

The inverse `encrypt(password, plaintext)` validates the plaintext shape,
reuses the container's PBKDF2 parameters, applies PKCS#7 padding, and
AES-CBC encrypts with a fresh IV. It returns both the ciphertext and IV so
`app.rs` can replace the `encryptedData` value and the IV in the PBES2
parameter tree together. `encrypt_with_current_iv` exists for synchronized
editing tests and callers that explicitly need to preserve the IV.

### Virtual-tree state and presentation

`App::rows` distinguishes `Document`, `Decrypted`, and
`DecryptedPlaceholder` sources. Whenever the open document parses as a
supported `EncryptedPrivateKeyInfo`, `rebuild_rows` inserts one of the
following immediately after, and one indentation level below, its
`encryptedData` row:

* before successful decryption, a non-editable yellow
  **`🔒 decrypted content not available`** placeholder;
* after decryption, the parsed plaintext forest as ordinary foldable rows.
  The virtual root begins with a green **`🔓 decrypted: `** prefix; its
  descendants use the normal type, summary, and specification labels.

The placeholder's content pane explains that `z` supplies the password.
Pressing **`z`** in either focused pane (`start_decrypt`, acting on the open
document — browser live-preview keeps it current) opens a masked
`Mode::Password` popup. On success, `submit_password` stores a `Decrypted`
state containing the encrypted-node path, plaintext bytes, parsed roots,
retained password, and an independent specification match for the virtual
forest. The password is zeroed when this state is dropped. A wrong password
leaves decryption unavailable and reports the error in the status bar.

Virtual rows otherwise participate in normal navigation and editing. Value
edits, insertion, retagging, deletion, and reordering are routed to either
the real or virtual forest by `RowSource`. The plaintext must remain exactly
one top-level SEQUENCE: its root cannot be deleted, retagged away from
SEQUENCE, or given a top-level sibling. This preserves the invariant checked
by the PKCS#8 encrypt/decrypt layer.

### Bidirectional synchronization

`App::rebuild` uses the selected row's source to decide which representation
was edited:

1. After an edit in the virtual `Decrypted` tree,
   `encrypt_decrypted_tree` serializes that forest, re-encrypts it using the
   retained password and a fresh IV, replaces both the real ciphertext and
   IV nodes, then runs the ordinary outer-document encode/re-parse pipeline.
2. After an edit in the serialized `Document` tree,
   `refresh_decrypted_tree` parses the updated PBES2 parameters/ciphertext
   and decrypts again with the retained password. On success it replaces the
   virtual plaintext while carrying over fold state. If the changed outer
   representation no longer parses or decrypts, the decrypted state is
   discarded, the closed-lock placeholder returns, and the status bar
   explains why decryption became unavailable.

Thus the two views remain synchronized while the password is available,
but only the standards-compliant encrypted representation is part of the
saved document.

## 9b. PKCS#12 decryption and editing (`src/pkcs12.rs`)

A PKCS#12 (`PFX`, RFC 7292) container nests its content in a
`ContentInfo`-wrapped `AuthenticatedSafe`, and can hold **several**
independently password-encrypted regions rather than the single one of an
`EncryptedPrivateKeyInfo`: any number of `EncryptedData` content blobs
(typically the certificate bags) and `PKCS8ShroudedKeyBag`s (the private
keys). Pressing **`z`** on such a file therefore reveals a *set* of
decrypted subtrees, one below each ciphertext node — the same key that
decrypts a lone PKCS#8 key (§9a), routed to whichever container shape the
open document matches (the two are structurally disjoint, so
`start_decrypt`/`submit_password` simply try `pkcs8::parse` then
`pkcs12::parse`).

The reveal is **editable**, like the PKCS#8 reveal of §9a, with one extra
obligation: a PKCS#12 carries an integrity `MacData` — an HMAC over the
encoded `AuthenticatedSafe` whose key comes from the RFC 7292 Appendix B
key-derivation (ID 3), a construction distinct from PBES2/PBKDF2. That KDF
(iterated hashing over the `ID‖salt‖password` blocks, password as a
UTF-16BE `BMPString`) and the HMAC are computed with the `openssl` crate's
digest primitives (`MacData::compute`; SHA-1/256/384/512 digests). The
correctness of the implementation is pinned by a unit test that recomputes
the MAC of the unmodified test container and compares it byte-for-byte
with the digest OpenSSL originally wrote. A container whose `MacData` uses
an unsupported digest (or none of the regions' schemes are editable)
degrades gracefully: the reveal is shown but mutating actions are refused
with the reason (`Pkcs12Reveal::editable`); a container without `MacData`
is simply edited without one. Decryption by itself never modifies the
outer document.

`pkcs12::parse` walks the `PFX` positionally (`PFX → ContentInfo →
AuthenticatedSafe → ContentInfo* / SafeBag*`, descending through the
encapsulated OCTET STRINGs the BER parser already exposes as children) and
records every decryptable region: its ciphertext-node path and cipher-IV
path in the outer forest, its kind, and the PBES2 scheme decoded from the
region's `AlgorithmIdentifier` — plus the container's `MacData` state
(absent / supported / unsupported-with-reason). The password-based
encryption must be **PBES2** (PBKDF2 + AES-128/256-CBC) — the scheme
current tools emit by default and the one already implemented for §9a;
`pkcs12.rs` reuses `pkcs8::Pbes2` (the shared PBKDF2/AES-CBC core)
verbatim for the regions. Legacy `pbeWithSHAAnd*` *encryption* schemes
(RFC 7292 Appendix B KDF for the cipher key) are reported as unsupported. `parse`'s three-way return mirrors `pkcs8::parse`: `Ok(None)`
(not a PKCS#12), `Err(msg)` (a PKCS#12 with nothing decryptable — no
encrypted content, or an unsupported scheme), `Ok(Some)` (at least one
supported region). `Region::decrypt` decrypts and confirms the plaintext
is a single ASN.1 SEQUENCE (a `SafeContents` or a `PrivateKeyInfo`) — the
wrong-password signal; because one password protects every region, a wrong
password fails them all and reads as a single "wrong password" error.

`App::pkcs12` holds the reveal: the retained password (zeroed on drop) and
one `RevealedRegion` per decrypted region, each carrying the ciphertext
path, kind, parsed plaintext forest, and an independent specification
match. Before decryption (`App::pkcs12` is `None`), `rebuild_rows` shows the
same closed-lock **`🔒 decrypted content not available`** placeholder below
*each* encrypted region that a locked PKCS#8 `encryptedData` node shows —
reusing the shared `RowSource::DecryptedPlaceholder`. After decryption it
splices each region's rows (source `RowSource::Pkcs12Revealed(index)`) below
its ciphertext node, and the tree labels each region root with a green
**`🔓 <kind>: `** prefix. These rows navigate, fold and **edit** like any
other (each region root, like the PKCS#8 one, must remain a single
SEQUENCE and cannot be deleted). An edit inside a region follows the §9a
synchronization pattern, extended by the MAC: `rebuild()` routes a
`Pkcs12Revealed` selection through `encrypt_pkcs12_region`, which
serializes the region's virtual forest, re-encrypts it with the retained
password and a **fresh IV** (both spliced into the outer tree at the
region's recorded paths), and then recomputes the `MacData` digest over
the updated `AuthenticatedSafe` content octets, overwriting the digest
node. The result is a container OpenSSL itself accepts — the app-level
test round-trips an edit through `openssl::pkcs12::Pkcs12::parse2`, which
verifies the MAC. When the MAC is unsupported, every mutating action
refuses the row with a "read-only" status instead. An edit to the *outer*
document re-derives the reveal with the retained password
(`refresh_pkcs12_reveal`, carrying over fold state), or discards it if the
document no longer decrypts; an outer edit does *not* auto-update the MAC,
since direct byte-level edits (including to `MacData` itself) are the
user's to control in a raw ASN.1 editor.

## 9c. Re-signing a modified object (`src/verify.rs`, `src/app.rs`)

After editing a certificate or CRL its signature no longer matches the
`tbsCertificate`/`tbsCertList`. Pressing **`z`** on such an object (once the
`z` handler has ruled out the encrypted-container cases of §9a/§9b) opens a
re-sign dialog. It reports whether the **issuer's** signing key — the private
key matching the issuer certificate's public key — is available, and if so
offers to generate a fresh signature.

Availability (`App::resign_state`) requires three things: the signature
algorithm is one `verify::sign` supports (RSA PKCS#1 v1.5 SHA-256/384/512,
ECDSA P-256/P-384, Ed25519, and the post-quantum ML-DSA/SLH-DSA sets — a
subset of what can be *verified*, since `aws-lc-rs` will not sign with legacy
SHA-1); the claimed issuer certificate
is present in the scanned tree (`verify::claimed_issuers` matches by
`authorityKeyIdentifier`/`subjectKeyIdentifier` or issuer/subject DN —
*without* checking the current, now-broken signature); and a **usable**
issuer key must actually produce a valid signature.

Rather than commit to the first key that merely parses, `resign_state`
gathers *every* candidate private key — `App::signing_materials_for` collects
all matching plaintext key files (`x509::to_pkcs8_der`, which returns PKCS#8
as-is and wraps a bare SEC1 key) and all session-unlocked encrypted keys /
PKCS#12s (re-decrypted on demand with their **retained password**, below),
drawn from the same two pools as the key↔certificate links (§9). It then
tries each in turn: `verify::sign` generates a signature and
`verify::verify_signature` checks it against the issuer certificate's public
key; the first signature that verifies is kept. This makes the search robust
to a key that matches by public key but cannot sign — an invalidated,
corrupted, or replaced plaintext key is skipped in favor of a valid
alternate (another key file, or an unlocked encrypted key), instead of the
whole operation failing on the first candidate. A self-signed certificate is
its own issuer, so its own key signs it.

The verified signature is computed when the dialog opens and stored in
`ResignState` (public data — no private key material is held in the dialog).
On confirmation (`App::submit_resign`) it is installed into the object's
outer `signature` BIT STRING (the third element of the
`Certificate`/`CertificateList` SEQUENCE, at path `[0, 2]`) as a leading
unused-bits octet followed by the signature — the `tbs` cannot have changed
while the dialog was open, so the pre-computed signature still matches. The
document is re-encoded and then **auto-saved** in place (`write_current`, the
same helper the re-key flow uses), so the freshly signed object lands on disk
without a separate `s` (the status line reports the save, or a `SAVE FAILED`
note leaving the document dirty for a manual retry); the intervening
`recompute_sig_status` shows the signature verifying again. `verify.rs` gains
signature generation (it already owned `aws-lc-rs` verification), keeping all
signature crypto in one module.

### Retained passwords

To re-sign with an *encrypted* issuer key without re-prompting, the private-
key passwords the user enters (for §9a/§9b decryption) are retained for the
lifetime of the process in `App::retained_passwords` — a small path→password
map, zeroed on drop. On any successful decryption the password is stored
under the open file's path; when re-signing later needs that file's key, it
is re-read and re-decrypted with the retained password (the decrypted key
material itself is not cached, only the password). This is a deliberate
convenience/secret-exposure trade-off scoped to a single session.

## 9d. Certification-path validation (`src/pathval.rs`)

Beyond the single-signature check of §9 (does this object verify under its
claimed issuer's key?), the editor validates a certificate's full
**certification path** to a trust anchor, using OpenSSL — the `openssl`
crate, which is the only place OpenSSL is used (all other crypto is
`aws-lc-rs`). This is a deliberately different engine from `verify.rs`:
OpenSSL applies the complete chain-building and validation rules (issuer
chaining, signatures at every link, validity periods, basic constraints),
which is exactly what path validation calls for.

The user builds the trust store interactively: pressing **`t`** on a
certificate selected in the browser toggles it in `App::trusted_certs`
(`App::toggle_trust`; non-certificates are refused). `pathval::validate`
then takes the target certificate's DER, the DER of every trusted anchor,
and the DER of every *other* certificate in the scanned tree as untrusted
intermediates, and runs an `X509StoreContext::verify_cert` over an
`X509Store` of the anchors with the intermediates supplied as the candidate
chain. The store is built with `X509VerifyFlags::PARTIAL_CHAIN`, so a
trusted **intermediate** (or even a leaf) terminates a path just as a trusted
root would — "trusted" means any certificate the user marked, not only
self-signed roots. The result is `Valid { depth }`, `Invalid { reason }`
(OpenSSL's verification error string, e.g. "unable to get issuer
certificate"), or `Error { detail }` (the target isn't a parseable
certificate).

`App::path_status` holds the result for the open document when it is a
certificate. It is recomputed by `App::recompute_path_status` — called from
`recompute_sig_status` (so it refreshes on every selection/preview and after
edits, using the open document's *live* content as both the target and its
entry in the pool) and from `toggle_trust` (so changing the trust set
re-validates the open certificate immediately). The content pane renders it
on a `Path` line directly below the `Signature` line (§11). Trusted
certificates are tagged `[trusted]` in the browser. Re-reading the other
certificate files on each recompute is cheap for the small, few-file trees
this targets.

## 9e. Modifying a certificate's public key (`src/keygen.rs`, `src/app.rs`)

The public-key modification dialog is reachable three ways: pressing **`e`**
on the `subjectPublicKeyInfo` element of an open certificate (recognized by
`App::selection_is_cert_spki`, which compares the selection to the
structurally computed SPKI path — `[0, 0, v+5]`, where `v` accounts for the
optional `[0] version`; `e` elsewhere or on a CRL keeps the ordinary value
editor), the **Re-key this cert** entry appended to the `E` edit menu when the
selection is that SPKI, and the **Re-key** entry of the `z`
cryptographic-adjustment menu (below). All three call `App::start_rekey`,
which builds the dialog from the open certificate regardless of the current
selection. The dialog (`Mode::EditPubKey`) has three columns:

1. **Algorithm** — the signature algorithms `keygen`/`verify` support: the
   classical ECDSA P-256 (SHA-256), ECDSA P-384 (SHA-384), Ed25519, RSA-2048
   and RSA-4096 (both SHA-256), followed by the post-quantum ML-DSA-44/65/87
   and the twelve SLH-DSA parameter sets. The list is longer than the popup,
   so this column scrolls to keep the selection visible.
2. **New private key** — a radio choosing the key *source*:
   * **generate new private key** (default): an editable file-name field
     (defaulting to `<cert-stem>_<alg>_key.der` and tracking the algorithm
     until the user edits it) and an optional password (blank ⇒ an unencrypted
     PKCS#8 key; non-blank ⇒ PBES2/AES-256-CBC, the form §9a can later decrypt).
   * **use existing key**: a list of the private keys available this session —
     plaintext key files plus any encrypted key or PKCS#12 unlocked with a
     password — filtered to those *fitting the chosen algorithm*. A key fits
     when the signature algorithm it produces (derived from its OpenSSL
     `SubjectPublicKeyInfo`: EC by curve, RSA, Ed25519, or the PQ OID) equals
     the chosen algorithm's `sig_alg_oid`. A **PKCS#12**-sourced key is offered
     only when the certificate inside the container shares the *issuer and
     subject* of the certificate being rekeyed — its key belongs to that
     certificate (`App::gather_existing_keys`, `certificate_from_safecontents`).
3. **Resign issued certs** — every signed object the open certificate issued
   (resolved with the same `verify::relations_for` used for the browser
   arrows): certificates first, each shown with its serial number, then the
   issued CRLs (`CRL` suffix), each with a default-on checkbox.

Key generation lives in `keygen.rs` and uses the `openssl` crate: OpenSSL
produces the key pair and encodes its plaintext PKCS#8 (the signing input for
`verify::sign`), its `SubjectPublicKeyInfo` (spliced into the certificate),
and — for a password — the encrypted PKCS#8. Classical keys use OpenSSL's typed
generators; the post-quantum keys are generated **by algorithm name** through
raw `openssl-sys` FFI (`EVP_PKEY_CTX_new_from_name` → `keygen`, wrapped back
into a safe `PKey`), since the safe crate's by-name generation does not cover
SLH-DSA. Everything downstream — PKCS#8 encoding/encryption, SPKI extraction,
signing — is algorithm-agnostic, so the PQ keys flow through the same code.
`keygen` and `pkcs8`/`verify` interoperate cleanly: a unit test signs with each
generated key and verifies under its own generated SPKI, and confirms an
encrypted generated key round-trips back through `pkcs8::parse`.

On confirm (`App::submit_pubkey`): the key material — PKCS#8 + SPKI — is
obtained either by **generating** a new key (validating the file name, which
never overwrites an existing file, then writing it) or by loading the chosen
**existing** key (`signing_materials_for` gives its PKCS#8, OpenSSL derives the
SPKI); the certificate's `subjectPublicKeyInfo` is replaced in the tree
(`install_new_public_key`); and — when the certificate
is **self-signed** under its current key (`sig_status` reports
`Verified { self_signed: true }`) — both of its `signatureAlgorithm`
identifiers are switched to the new algorithm and its own signature is
regenerated with the new key, so it stays valid. Each selected issued object
— certificate or CRL — is then resigned *on disk* (`resign_issued_file`, whose
`resignable_paths` locates the inner `signature` AlgorithmIdentifier at its
kind-dependent position): its two `signatureAlgorithm` identifiers are
rewritten, its re-encoded `tbsCertificate`/`tbsCertList` is signed with the new
key, the new signature is installed, and the file is written back in its
original container. A *newly generated* key is registered for the session
(plaintext keys join `key_files`, an encrypted key joins `unlocked_keys` with
its password retained), so its key↔certificate link shows and a later re-sign
can reuse it; its identity is read from the SPKI, not the private key, since an
Ed25519/EC/PQ private key may omit its public part. An existing key is already
known, so nothing is written or registered. Finally the rekeyed certificate
itself is **auto-saved** in place (`write_current`), so that — together with the
sibling key and issued-object files, written immediately during the operation —
the whole set is left consistent on disk without a separate `s` (the status
line reports the save, or a `SAVE FAILED` note if the write did not succeed, in
which case the document stays dirty for a manual retry). This whole flow is verified
end to end against the OpenSSL CLI: after rekeying a self-signed root, `openssl
verify` accepts the root's new self-signature, the resigned intermediate under
the new root, the full leaf→intermediate→root chain, and (`openssl crl
-verify`) the resigned CRL under the new root key.

### The `z` cryptographic-adjustment menu

Pressing **`z`** on a signed object no longer opens the re-sign dialog
directly. After `start_decrypt` rules out the encrypted-container cases
(§9a/§9b), it calls `start_crypto_menu`, which opens a small titled menu
(**Cryptographic adjustment**, reusing the generic `Mode::EditMenu`): a
**Re-sign** entry (→ §9c) for any certificate or CRL, plus a **Re-key** entry
(→ this section) for a certificate. Both the `E` edit menu and this menu are
now data-driven: `MenuState` carries a title and a `Vec<MenuItem>`, and each
`MenuItem` names a `MenuAction` that `menu_confirm` dispatches — so the same
menu machinery renders the five base edit modes, the optional trailing
**Re-key this cert**, and the two cryptographic adjustments.

## 9f. Basic Constraints interpretation and structured editing (`src/x509/basic_constraints.rs`)

The X.509 `BasicConstraints` extension (RFC 5280 §4.2.1.9,
`id-ce-basicConstraints` = 2.5.29.19) gets a dedicated read and edit path so
the user does not have to reason about the raw `cA` / `pathLenConstraint`
encoding.

`x509::basic_constraints` (`src/x509/basic_constraints.rs`, a submodule of
`x509`) walks a `ber::Node` positionally, like `x509.rs` itself. It
operates on the **outer `Extension` SEQUENCE** (`{ extnID, critical?,
extnValue }`) — the node the user selects in the tree — so one node drives
everything. `value_index` recognises the extension (first child is the
BasicConstraints OID, last child a primitive OCTET STRING) and returns the
`extnValue` child index; `parse` decodes `cA`, `pathLenConstraint` (from the
inner SEQUENCE the encapsulation heuristic already exposed, §5) and the
enclosing extension's `critical` flag.

* **Interpretation.** When a BasicConstraints extension is selected,
  `draw_content_browse` inserts a plain-language section (`describe`) between
  the header information and the raw content octets: whether the extension is
  critical, whether this is a CA certificate, and what the path-length
  constraint means (or that it is unlimited / meaningless when `cA` is FALSE).

* **Structured editor.** `Mode::EditBasicConstraints(BcEditState)` is a small
  form editing the two fields "in a natural way": `cA` as a boolean, and
  `pathLenConstraint` as a present/absent toggle plus a plain integer field
  (which defaults to `0` when the constraint is currently absent). It is
  reached by **`e`** anywhere inside the extension (`edit_selected` routes there
  before the generic type-specific editor) and by the **As Basic Constraints**
  entry appended to the `E` edit menu (a new `MenuAction`). "Inside the
  extension" is resolved by `selection_extension_path`, a shared helper that
  walks from the selected node up towards the root and returns the nearest
  enclosing `Extension` SEQUENCE the extension's `value_index` recognises — so
  the editor opens from the outer node or any descendant (the OID, the
  `critical` flag, the `extnValue`, or the parsed inner value). On
  submit, `commit_basic_constraints` re-encodes the value with `encode_der`
  (DER rules: `cA = FALSE` omitted; `pathLenConstraint` emitted only when `cA`
  is asserted, per RFC 5280) and replaces the `extnValue` OCTET STRING's
  content octets — `rebuild` then re-detects the nested encoding and
  recomputes lengths, exactly like a primitive value edit (§7). The `critical`
  flag belongs to the Extension, not to BasicConstraints, so it is shown for
  context but edited elsewhere.

## 9g. Key Usage interpretation and structured editing (`src/x509/key_usage.rs`)

The `KeyUsage` extension (RFC 5280 §4.2.1.3, `id-ce-keyUsage` = 2.5.29.15) is
a named `BIT STRING` of nine bits (`digitalSignature` (0) … `decipherOnly`
(8)). `x509::key_usage` handles it exactly like `x509::basic_constraints`
(§9f) — same outer-`Extension`-SEQUENCE anchoring, same `value_index` / `parse`
/ `describe` / `encode_der` shape, and the same write-back path (replace the
`extnValue` OCTET STRING content, let `rebuild` re-detect the nested encoding).
The only differences are in the value:

* **Interpretation.** `describe` lists, one line each, the usages the set bits
  permit (e.g. `keyCertSign: verify signatures on certificates …`), or a note
  that no bit is set (which RFC 5280 forbids).

* **Structured editor.** `Mode::EditKeyUsage(KuEditState)` is a checkbox list —
  one row per named bit — navigated with `↑↓` and toggled with `Space`, reached
  by `e` anywhere inside the extension (via the shared `selection_extension_path`,
  §9f) or the **As Key Usage** `E`-menu entry. `encode_der`
  follows the DER rule for named bit strings: trailing zero bits are trimmed,
  so the encoded length tracks the highest set bit (bit 0 alone → `03 02 07 80`;
  `keyCertSign`+`cRLSign` → `03 02 01 06`).

## 9h. Extended Key Usage interpretation and structured editing (`src/x509/extended_key_usage.rs`)

The `ExtKeyUsage` extension (RFC 5280 §4.2.1.12, `id-ce-extKeyUsage` =
2.5.29.37) is an open `SEQUENCE OF KeyPurposeId` (each an OBJECT IDENTIFIER).
`x509::extended_key_usage` handles it like the other two extension modules
(§9f/§9g) — same outer-`Extension` anchoring and write-back path — but the
value is a variable-length OID list rather than a fixed set of fields, so the
editor is richer:

* **Interpretation.** `describe` lists each `KeyPurposeId`, naming the
  well-known ones from a built-in table (`PURPOSES`: `serverAuth`,
  `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`,
  `OCSPSigning`, `anyExtendedKeyUsage`) with a short meaning, resolving other
  known OIDs through the `oid.rs` repository, and showing unrecognised ones by
  their dotted form.

* **Structured editor.** `Mode::EditExtKeyUsage(EkuEditState)` is a checkbox
  list of the well-known purposes, followed by a checkbox per arbitrary OID
  already present, followed by a **dot-notation input field**. `Space` toggles
  the focused checkbox; on the input row, typing an OID and pressing `Enter`
  validates it (via `ber::encode_oid`), folds it into the list (checking the
  matching well-known box, re-enabling a matching custom row, or appending a
  new one) and clears the field — `Enter` on any other row (or an empty input)
  applies the whole dialog. `encode_der` emits a `SEQUENCE OF` the enabled OIDs
  (well-known in table order, then customs). RFC 5280 requires at least one
  `KeyPurposeId`, so applying an empty list is refused and keeps the dialog
  open. Reached by `e` anywhere inside the extension (via the shared
  `selection_extension_path`, §9f) or the **As Extended Key Usage** `E`-menu
  entry.

## 10. Input containers

`input::load` detects, in order: PEM (`-----BEGIN <label>-----`, first
block), raw BER/DER (must parse), hex text, base64. The decoded-from
container is remembered and `s`ave re-wraps the new DER the same way
(PEM label preserved, 64-column base64). `-o FILE` redirects the save
target; by default the input file is overwritten.

## 11. TUI

Built with ratatui 0.29 (bundled crossterm backend, `ratatui::init()` /
`restore()` with automatic panic-hook cleanup).

```
┌ Files — dir ──┐┌ Structure — file.der ────────────┐┌ Content ───────────────────────────────┐
│    a.der      ││ ▾ SEQUENCE (3 elem)              ││ Type    INTEGER  class: universal, ...  │
│  • b.der      ││   ▾ SEQUENCE (8 elem)            ││ Offset  10  header: 2  content: 1 bytes │
│▸   sub/       ││     ▾ [0] (1 elem)               ││ Decoded 2                               │
│    c.pem      ││         INTEGER 2                ││                                         │
│               ││       INTEGER 70 60 96 41 99 …   ││ Content octets (1 bytes) — 'e' to edit: │
│               ││     ▸ SEQUENCE (1 elem)          ││ 00000000  02              |.|           │
│               ││       …                          ││                                         │
└───────────────┘└──────────────────────────────────┘└─────────────────────────────────────────┘
  status message      | q quit  Tab switch pane  ↑↓ move  ←→ fold  ⏎ toggle  e edit  s save
```

* **Far-left pane — file browser.** A folding directory tree (`src/browser.rs`)
  of the directory the current file lives in (or, if the program was
  started with a directory instead of a file, that directory, with the
  other two panes starting empty until the first navigation). Fold marker
  (`▸`/`▾`) on directories, their children read lazily on first expand.
  `Tab` switches keyboard focus between this pane and the document panes;
  the focused pane gets a highlighted border.

  The pane tracks the filesystem live. The event loop calls
  `App::refresh_filesystem` on a timer (`FS_POLL_INTERVAL`, 750 ms — the
  input poll already wakes at least every 250 ms); it re-reads the loaded
  parts of the tree and, when anything changed, also rebuilds the
  certificate/key indexes so relation arrows and path validation stay
  consistent with disk. Each entry is classified against a snapshot of
  modification times taken at startup (`FileBrowser::baseline`, a bounded
  recursive walk): a **new** file (absent from the baseline) shows a green
  change-time in a leftmost column, a **modified** file (newer mtime) a
  yellow one, a **deleted** file is kept visible in gray and struck through
  (no timestamp), and an unchanged file carries no timestamp. Statuses are
  sticky for the session — always relative to the startup baseline, not the
  previous refresh — and a deleted file's row stays (so a key file the
  program wrote appears the moment it is created, and the selection is
  preserved by path across a refresh). The change-time column and the legend
  entries appear only once some visible file carries a status; times are
  local (`libc::localtime_r`).

  Moving the browser selection with any navigation key (`↑↓`/`←→`/
  `PgUp`/`PgDn`/`Home`/`End`) **live-previews the highlighted file** into
  the tree/content panes (`App::preview_browser_selection`), without
  moving focus away from the browser — so repeatedly pressing `↓` browses
  through file contents the same way it browses file names. The file
  currently loaded (whether by live preview or explicitly opened) is
  marked with `•` even if the browser selection has since moved
  elsewhere. Live preview is a no-op while highlighting a directory, the
  already-loaded file, or — to avoid silently discarding work — while the
  open document has unsaved changes; a failed preview (the highlighted
  file isn't recognizable ASN.1) reports the error in the status bar but
  leaves the previously previewed content on screen. On a file,
  `Enter`/`Space` then just switches focus to the document panes (the
  common case: the file is already loaded from live preview); it only
  triggers a load itself — with the same two-step unsaved-changes
  confirmation as `delete` — when live preview was skipped because of
  unsaved changes. On a directory, `Enter`/`Space` folds/unfolds, as
  before. Started with a directory and no file picked yet, `save` and
  insert are refused with a status message — there is nothing to write
  to. Colored elbow arrows show the selected file's cryptographic
  relations to the other visible files (§9), routed from source row to
  destination row: the signer's arrow enters the selection from the left
  (cyan), arrows to the objects the selection signed leave it to the right
  (magenta), red = claimed issuance whose signature does not verify. A
  further leftmost gutter draws the undirected, arrowhead-less
  key↔certificate links (green) between a private-key file and the
  certificate carrying its public key — including keys unlocked by a
  password this session (§9 → Key ↔ certificate links).
* **Middle pane — tree.** One row per visible node: fold marker (`▸`/`▾`),
  indentation by depth, type name (colored by tag class; bold when
  constructed/encapsulating) and a short decoded value preview. Known OID
  values use the repository's leaf descriptor; unknown OIDs retain dot
  notation. An encrypted PKCS#8 `encryptedData` row additionally owns the
  closed-lock placeholder or open-lock virtual plaintext subtree described
  in §9a, at the same position and with normal folding/navigation behavior;
  a PKCS#12 container's ciphertext rows likewise own the closed-lock
  placeholder (before decryption) or the open-lock, editable reveal
  subtrees of §9b (green `🔓 <kind>: ` region roots).
* **Right pane — content.** At the top, the build-up of the tag and the
  length octets is shown graphically: bit-field diagrams with the bit
  positions (8..1), the actual bit values, each field's width in bits and
  its decoded meaning —

  ```
  Type    SEQUENCE
  Tag     identifier octet: 30
  ┌ 8 7 ───────────┬ 6 ──────────┬ 5 4 3 2 1 ──────────┐
  │ 0 0            │ 1           │ 1 0 0 0 0           │
  │ class (2 bits) │ P/C (1 bit) │ tag number (5 bits) │
  │ universal      │ constructed │ 16 = SEQUENCE       │
  └────────────────┴─────────────┴─────────────────────┘
  Length  length octets: 82 01 C3
  ┌ 8 ───────────┬ 7 6 5 4 3 2 1 ──────────────┐
  │ 1            │ 0 0 0 0 0 1 0               │
  │ form (1 bit) │ # of length octets (7 bits) │
  │ long form    │ 2 octets follow ↓           │
  └──────────────┴─────────────────────────────┘
  octet 2:  00000001   (= 0x01, big-endian value byte)
  octet 3:  11000011   (= 0xC3, big-endian value byte)
  content length = 451
  ```

  For high tag numbers (long form, tag ≥ 31) the identifier continuation
  octets are broken down the same way (bit 8 = more-octets flag, bits 7-1
  = tag bits), followed by the resulting tag number. Short-form lengths
  show bit 8 = 0 and the 7-bit content length directly; indefinite
  lengths (BER) show `0x80` with a note that the content ends with
  end-of-contents octets. The length diagram shows the canonical
  (minimal) encoding of the current content length — identical to the
  file bytes for DER input, normalized for BER inputs with redundant
  length octets. Below the diagrams: offset, header and content length,
  and decoded value (integers, known OID leaf names, strings, times, unused
  bits). For an OID, the final header fields are its numeric dot notation
  and, when known, its complete textual token chain (§8a). A blank line then
  separates the header from a `hexdump -C`-style dump of the raw content
  octets. Decrypted PKCS#8 content is no longer duplicated here as a text
  dump; it is selected and inspected through its virtual tree rows (§9a).
* **Edit mode** (`e` for the type-specific editor, `E` for the edit
  menu): the right pane becomes one of the value editors of §7 — hex grid,
  text line
  (base64 / raw / number / OID / boolean / text) or the date/time form —
  with insert-at-cursor semantics and a live feedback line (resulting byte
  count, or the validation error in red). `Enter` applies (§7), `Esc`
  cancels. The pane border turns yellow as a mode cue.
* **Dialog popups**: several actions open a centered popup over the panes —
  the type picker (`Mode::TypePicker`), the edit / cryptographic-adjustment
  menus (`Mode::EditMenu`, a generic titled list), the
  decrypt password prompt (`Mode::Password`), the re-sign dialog
  (`Mode::Resign`, §9c), and the public-key modification dialog
  (`Mode::EditPubKey`, §9e — a three-column form: algorithm list, key source
  (generate/use-existing radio with either the file-name/password fields or the
  list of compatible existing keys), and issued-object checkboxes, navigated
  with `←→` between columns, `↑↓` within one, `Space` to toggle the radio or a
  checkbox, and typing to edit the file name / password).
* **Status bar**: `[modified]` flag, last action / error message, key help.

### Key bindings

`Tab` switches keyboard focus between the file browser pane and the
document (tree/content) panes, both in and out of a loaded document; `q`
quits regardless of focus. The rest of the browse-mode bindings below
apply to whichever pane is focused — arrow keys and fold navigation work
the same way in both, but in the browser they also live-preview the
highlighted file (see above), `Enter`/`Space` switches focus to an
already-previewed file (or folds a directory) versus toggling fold in the
tree, and the editing/save/insert/delete/reorder keys only apply to the
document pane.

| Key | Action |
|-----|--------|
| `Tab` | switch focus between the file browser and the document panes |
| `↑`/`k`, `↓`/`j` | move selection (browser: also live-previews the file) |
| `PgUp`/`PgDn` | move selection by 15 (browser: also live-previews) |
| `g`/`Home`, `G`/`End` | first / last row (browser: also live-previews) |
| `←`/`h` | collapse node/directory, or jump to parent (browser: also live-previews) |
| `→`/`l` | expand node/directory, or enter first child (browser: also live-previews) |
| `Enter`/`Space` | toggle fold (tree); switch to the previewed file / toggle fold (browser) |
| `e` | edit selected element's value (type-specific editor); on a certificate's `subjectPublicKeyInfo`, open the public-key modification dialog (§9e) |
| `E` | edit menu: tag type / hex / base64 / raw binary / type specific; on a certificate's `subjectPublicKeyInfo`, also *Re-key this cert* (§9e) |
| `i` | insert new element after the selection (type-picker dialog, then value) |
| `I` | insert new element as first child of a constructed element |
| `←→`/`Tab`, `↑↓`, `0-9`, `Enter`, `Esc` | (type picker) column / selection / tag number / confirm / cancel |
| `d` `d` | delete selected element (first press arms a confirmation) |
| `J` / `K` | move selected element down / up among its siblings |
| `Enter` / `Esc` | (edit mode) apply / cancel |
| `s` | save (re-encode + re-wrap container) |
| `z` | context action: decrypt an `EncryptedPrivateKeyInfo` (§9a) or PKCS#12 (§9b, prompts for a password), or — on a certificate/CRL — open the *Cryptographic adjustment* menu (re-sign §9c / re-key §9e) |
| `t` | (browser) mark/unmark the selected certificate as a path-validation trust anchor (§9d) |
| `[` / `]` | scroll content pane |
| `q` | quit (`q q` to discard unsaved changes) |

## 12. Verification against dumpasn1

Two layers, both in `tests/dumpasn1_compat.rs` and run by `cargo test`:

1. **Structural equality** (`structure_matches_dumpasn1`): for every file
   in `testdata/`, our `--dump` output and the output of the real
   `dumpasn1` binary are reduced to `(offset, content-length, type-name)`
   triples — one per ASN.1 item, in traversal order, *including* items
   nested via the encapsulation heuristic — and must be identical. Value
   text, warnings and closing-brace lines are ignored, which keeps the
   test independent of the local `dumpasn1.cfg` OID database. The test
   self-skips with a notice when `dumpasn1` is not installed.
2. **Round-trip** (`parse_encode_roundtrip_on_testdata`): `encode(parse(x))
   == x` for every test file, proving the editor rewrites files without
   collateral changes.

OID coverage is verified independently in `tests/oid_repository.rs`: every
OID node recursively parsed from every bundled test file must resolve in the
built-in repository, and every NIST ML-DSA/SLH-DSA signature assignment in
the registered `.17` through `.46` range must be present. Unit tests cover
known/unknown tree summaries, numeric/full-name content details, repository
consistency, and the closed/open lock labels. PKCS#8 tests cover initial
decryption, wrong passwords, plaintext edits updating ciphertext, and
ciphertext edits refreshing or invalidating the virtual tree. PKCS#12 tests
cover locating both encrypted regions of a real container, decrypting them,
rejecting a wrong password, not misfiring on non-PKCS#12 files, recomputing
the `MacData` digest byte-for-byte against the one OpenSSL wrote,
re-encrypting a region through its recorded paths, and — at the app level —
that the reveal appears below each ciphertext node, that editing a revealed
value re-encrypts the region and re-MACs the container into a file
`openssl::pkcs12::Pkcs12::parse2` verifies, and that a container with an
unsupported MAC digest stays read-only. Key↔certificate-link tests cover public-key extraction from EC
(PKCS#8 and SEC1) and RSA keys and the equal/unequal comparison with a
certificate, the pure `key_links_for` matcher (both directions, dedup, no
self-links), the headless gutter routing, and — at the app level — that a
certificate links to its plaintext key files, that an encrypted key or
PKCS#12 links only after the password is entered, that the link persists
after navigating to the certificate, and that editing a key to corrupt its
private scalar removes the link. Re-signing tests cover the sign→verify
round trip (including a SEC1 key wrapped to PKCS#8, and rejection of a
wrong-type key), and — at the app level — that modifying a certificate breaks
its signature and re-signing restores it with a plaintext issuer key, that
the same works with an *encrypted* issuer key via a retained password, that
re-signing falls through an invalidated key to a valid alternate (another key
file, or an unlocked encrypted key) rather than failing on it, and that a
missing issuer key is reported and confirming it is a no-op.
Certification-path tests run OpenSSL over the bundled `testdata/chain`
hierarchy: `pathval` unit tests check that trusting the root (or the
intermediate directly) validates the leaf, that no trust anchor or a missing
intermediate is invalid, and that a broken signature does not validate; app
tests check that `t` toggles a certificate's trust, re-validates the open
certificate, refuses a CRL, and leaves a non-certificate with no path status.
Post-quantum tests confirm the OpenSSL backend end to end: `verify` generates a
self-signed ML-DSA and a fast SLH-DSA certificate with the `openssl` CLI and
checks our parser + `verify_against` accept the signature and reject a tampered
one, and `keygen` round-trips signing/verification for the classical, ML-DSA
and fast SLH-DSA algorithms (the slow SLH-DSA "small" sets are exercised for
key generation only), plus an encrypted ML-DSA key that `pkcs8` reads back.
Public-key-modification tests cover `keygen` (each algorithm generates a key,
and every post-quantum SPKI carries its signature OID; a password yields an
encrypted PKCS#8 our `pkcs8` module decrypts; the signature-algorithm identifier
shapes) and, at the app level over `testdata/chain`, that `e` opens the dialog
only on the SPKI (with the issued list showing the certificate first and the CRL
last), that rekeying a self-signed CA resigns it and its issued certificate
under the new key — classically and to **ML-DSA** — that a selected issued
*CRL* is likewise resigned and verifies under the new key, that a password
writes an encrypted key that still signs, that an existing key file is never
overwritten, that **using an existing key** rekeys the certificate to that
key's public key without writing a new file, and that a PKCS#12-sourced key is
offered only for the certificate whose issuer/subject match the container's own
certificate. Menu-routing tests check that `z` on a
certificate opens the cryptographic-adjustment menu (re-sign + re-key) and on a
CRL offers only re-sign, and that the `E` menu gains a trailing *Re-key this
cert* entry on the SPKI that opens the dialog. Browser-refresh tests check
that a newly created file appears tagged `New` with a timestamp, a modified
file (older baseline) `Modified`, a deleted file stays visible as `Deleted`
with the selection preserved, and an unchanged directory reports no change;
an app-level test confirms a key file the re-key flow just wrote surfaces as a
new browser row.

Beyond the automated triples check, the `--dump` output format itself
(column widths derived from file size, `offset length:` prefix,
2-space indent, `{`/`}` block layout, `, encapsulates {`, hex-block
wrapping at 80 columns with indent capping, 128-byte cap with
`[ Another N bytes skipped ]`, zero-length `SET {}`) replicates dumpasn1
closely enough that `diff` against `dumpasn1 <file>` on the bundled test
data shows **no differences** on a machine with the standard dumpasn1
configuration.

Test corpus: EC P-256 certificate, RSA-2048 certificate (BIT STRING
encapsulation, long INTEGER hex blocks), SEC1 EC private key (context
tags `[0]`/`[1]`, OCTET STRING that must *not* encapsulate), PKCS#7
certificate bundle (`[0]` constructed, empty SET, deep nesting), encrypted
PKCS#8 key and PKCS#12 container (both PBES2/PBKDF2/AES-256-CBC, password
"asn1editor").

## 13. Error handling

* Parse errors carry the absolute offset and are fatal at load time
  (reported on stderr).
* Edit errors (odd digit count, invalid content for a constructed node)
  are non-destructive: the editor stays open, the message goes to the
  status bar.
* Save errors (I/O) are reported in the status bar; the dirty flag stays
  set.
* Quitting with unsaved changes requires a second `q`.

## 14. Limitations and future work

* Re-encoding normalizes BER (indefinite lengths, redundant length octets)
  to DER framing; a byte-preserving mode would require storing original
  header bytes.
* No undo stack (single-level: quit without saving).
* OID names come from a curated built-in repository rather than a complete
  global registry. Unknown values remain usable and are displayed in dot
  notation; expanding coverage requires adding a reviewed static entry (or
  a future optional external resolver/configuration source).
* Value display for exotic universal types (REAL, EMBEDDED PDV, …) falls
  back to hex.
* Reading from stdin is not supported (the terminal owns stdin in a TUI).
* Signature verification (§9) covers RSA PKCS#1 v1.5, ECDSA and Ed25519;
  RSA-PSS and post-quantum algorithms (ML-DSA/SLH-DSA) are not
  implemented. CMS SignedData is not supported — only bare X.509
  `Certificate`/`CertificateList`; `verify.rs`'s `verify_against` is
  already shaped generically enough for a future CMS `SignerInfo` decoder
  to reuse. The candidate-issuer index is a startup-only snapshot of the
  directory: it is not refreshed if *other* files change on disk during
  the session (the currently open file's own entry is the one exception —
  see §9).
