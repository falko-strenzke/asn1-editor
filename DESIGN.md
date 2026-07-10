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
  CRLs) and annotate the tree with the spec's field and type names (§8).

Non-goals (see §13):

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
  spec.rs    ASN.1 specification parser + structural matcher/labeler
  app.rs     application state: tree, flattened rows, selection, edit logic
  tui.rs     ratatui event loop and rendering (no business logic)
tests/
  dumpasn1_compat.rs  structural comparison against the dumpasn1 binary,
                      plus a parse→encode round-trip test over testdata/
  spec_rfc5280.rs     spec parsing + identification of the DER test files
specs/asn1/  ASN.1 specification modules (rfc5280: certificates + CRLs)
testdata/  DER samples (EC cert, RSA cert, EC key, PKCS#7, CRL)
```

Dependency rule: `ber.rs` depends on nothing; `dump.rs`/`input.rs`/
`spec.rs` depend only on `ber.rs`; `app.rs` depends on `ber.rs` +
`input.rs` + `spec.rs`; `tui.rs` renders `app.rs`. The only external
dependency is `ratatui`.

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
otherwise unmodified). Additional files dropped into the directory are
parsed automatically; parse failures are reported as warnings and the
file is skipped. The directory is located via `$ASN1_EDITOR_SPECS`, then
`./specs/asn1`, then `specs/asn1` next to an ancestor of the executable.

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
discarded as noise. With the RFC 5280 modules loaded, X.509 certificates
identify as `Certificate` and CRLs as `CertificateList`.

The identification is recomputed after every edit, so a document can gain
or lose its labels as edits make it conform or not conform to a spec.

### Display

* Tree pane: `field: ` prefixes (cyan italic) and ` ·TypeName` suffixes
  (green, shown when the spec name adds information beyond the raw ASN.1
  type); the identified document type in the pane title.
* Content pane: a `Spec` line with the selected element's field and type
  name plus the overall document type and source file.

Not yet done (future work): resolving `ANY DEFINED BY` and OCTET STRING
extension bodies via OID tables (e.g. labeling the contents of X.509
extensions), and value-level checks (constraints are ignored).

## 9. Input containers

`input::load` detects, in order: PEM (`-----BEGIN <label>-----`, first
block), raw BER/DER (must parse), hex text, base64. The decoded-from
container is remembered and `s`ave re-wraps the new DER the same way
(PEM label preserved, 64-column base64). `-o FILE` redirects the save
target; by default the input file is overwritten.

## 10. TUI

Built with ratatui 0.29 (bundled crossterm backend, `ratatui::init()` /
`restore()` with automatic panic-hook cleanup).

```
┌ Structure — file.der ────────────┐┌ Content ───────────────────────────────┐
│ ▾ SEQUENCE (3 elem)              ││ Type    INTEGER  class: universal, ...  │
│   ▾ SEQUENCE (8 elem)            ││ Offset  10  header: 2  content: 1 bytes │
│     ▾ [0] (1 elem)               ││ Decoded 2                               │
│         INTEGER 2                ││                                         │
│       INTEGER 70 60 96 41 99 …   ││ Content octets (1 bytes) — 'e' to edit: │
│     ▸ SEQUENCE (1 elem)          ││ 00000000  02              |.|           │
│       …                          ││                                         │
└──────────────────────────────────┘└─────────────────────────────────────────┘
  status message                        | q quit ↑↓ move ←→ fold ⏎ toggle e edit s save
```

* **Left pane — tree.** One row per visible node: fold marker (`▸`/`▾`),
  indentation by depth, type name (colored by tag class; bold when
  constructed/encapsulating) and a short decoded value preview.
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
  decoded value (integers, OIDs dotted, strings, times, unused bits) and
  a `hexdump -C`-style dump of the content octets.
* **Edit mode** (`e` for the type-specific editor, `E` for the edit
  menu): the right pane becomes one of the value editors of §7 — hex grid,
  text line
  (base64 / raw / number / OID / boolean / text) or the date/time form —
  with insert-at-cursor semantics and a live feedback line (resulting byte
  count, or the validation error in red). `Enter` applies (§7), `Esc`
  cancels. The pane border turns yellow as a mode cue.
* **Status bar**: `[modified]` flag, last action / error message, key help.

### Key bindings

| Key | Action |
|-----|--------|
| `↑`/`k`, `↓`/`j` | move selection |
| `PgUp`/`PgDn` | move selection by 15 |
| `g`/`Home`, `G`/`End` | first / last row |
| `←`/`h` | collapse node, or jump to parent |
| `→`/`l` | expand node, or enter first child |
| `Enter`/`Space` | toggle fold |
| `e` | edit selected element's value (type-specific editor) |
| `E` | edit menu: tag type / hex / base64 / raw binary / type specific |
| `i` | insert new element after the selection (type-picker dialog, then value) |
| `I` | insert new element as first child of a constructed element |
| `←→`/`Tab`, `↑↓`, `0-9`, `Enter`, `Esc` | (type picker) column / selection / tag number / confirm / cancel |
| `d` `d` | delete selected element (first press arms a confirmation) |
| `J` / `K` | move selected element down / up among its siblings |
| `Enter` / `Esc` | (edit mode) apply / cancel |
| `s` | save (re-encode + re-wrap container) |
| `[` / `]` | scroll content pane |
| `q` | quit (`q q` to discard unsaved changes) |

## 11. Verification against dumpasn1

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
certificate bundle (`[0]` constructed, empty SET, deep nesting).

## 12. Error handling

* Parse errors carry the absolute offset and are fatal at load time
  (reported on stderr).
* Edit errors (odd digit count, invalid content for a constructed node)
  are non-destructive: the editor stays open, the message goes to the
  status bar.
* Save errors (I/O) are reported in the status bar; the dirty flag stays
  set.
* Quitting with unsaved changes requires a second `q`.

## 13. Limitations and future work

* Re-encoding normalizes BER (indefinite lengths, redundant length octets)
  to DER framing; a byte-preserving mode would require storing original
  header bytes.
* No undo stack (single-level: quit without saving).
* OID names come from a small built-in table; parsing `dumpasn1.cfg` for
  full name coverage would be a natural extension.
* Value display for exotic universal types (REAL, EMBEDDED PDV, …) falls
  back to hex.
* Reading from stdin is not supported (the terminal owns stdin in a TUI).
