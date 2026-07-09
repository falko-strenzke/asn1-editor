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

Non-goals (see §9):

* Schema-aware editing (no ASN.1 module compiler).
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
  app.rs     application state: tree, flattened rows, selection, edit logic
  tui.rs     ratatui event loop and rendering (no business logic)
tests/
  dumpasn1_compat.rs  structural comparison against the dumpasn1 binary,
                      plus a parse→encode round-trip test over testdata/
testdata/  DER samples (EC cert, RSA cert, EC private key, PKCS#7)
```

Dependency rule: `ber.rs` depends on nothing; `dump.rs`/`input.rs` depend
only on `ber.rs`; `app.rs` depends on `ber.rs` + `input.rs`; `tui.rs`
renders `app.rs`. The only external dependency is `ratatui`.

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

Editing is deliberately low-level and format-agnostic: the user edits the
**content octets** of the selected element as hex. What that means per node
kind:

| Node kind        | Edit buffer contains                | On apply |
|------------------|-------------------------------------|----------|
| primitive        | the value bytes (BIT STRING: incl. unused-bits octet) | bytes stored verbatim; encapsulation re-detected |
| constructed      | the encoding of all children        | bytes must parse as a valid TLV series, else the edit is rejected with an error in the status bar |
| encapsulating    | the (current) nested encoding       | same as primitive; if it no longer parses it becomes a plain value |

Apply pipeline (`App::commit_edit` → `App::rebuild`):

1. Hex digits are validated on input; an odd digit count blocks apply.
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

### Structural edits: insert, delete, reorder

Beyond value edits, the tree structure itself can be changed. All three
operations mutate the node forest in place and then run the same
`rebuild()` pipeline as value edits, so enclosing lengths and all offsets
are recomputed by the one existing mechanism:

* **Insert** (`i` = new sibling after the selection, `I` = new first child
  of a constructed/encapsulating element): opens the hex editor in
  `EditKind::Insert` mode. The input is not content octets but one or more
  **complete TLV encodings** (e.g. `0500` for NULL); it must parse as a
  valid TLV series, otherwise the insert is rejected non-destructively.
  Several elements can be inserted at once. This is also how the tag or
  class of an element is changed in practice: insert the replacement,
  delete the original (or edit the parent's full content with `e`).
  Inserting into an empty document (or an empty constructed element) is
  supported; a collapsed parent is auto-expanded so the insertion is
  visible, and the selection lands on the first inserted element.
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

## 8. Input containers

`input::load` detects, in order: PEM (`-----BEGIN <label>-----`, first
block), raw BER/DER (must parse), hex text, base64. The decoded-from
container is remembered and `s`ave re-wraps the new DER the same way
(PEM label preserved, 64-column base64). `-o FILE` redirects the save
target; by default the input file is overwritten.

## 9. TUI

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
* **Right pane — content.** Type/class/tag, offset, header and content
  length, decoded value (integers, OIDs dotted, strings, times, unused
  bits) and a `hexdump -C`-style dump of the content octets.
* **Edit mode** (`e`): the right pane becomes a hex editor over the content
  octets — 16 bytes per line, insert-at-cursor semantics, live byte count,
  red indicator while the digit count is odd. `Enter` applies (§7),
  `Esc` cancels. The pane border turns yellow as a mode cue.
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
| `e` | edit selected element's content octets (hex) |
| `i` | insert new element(s) after the selection, typed as full TLV hex |
| `I` | insert new element(s) as first child of a constructed element |
| `d` `d` | delete selected element (first press arms a confirmation) |
| `J` / `K` | move selected element down / up among its siblings |
| `Enter` / `Esc` | (edit mode) apply / cancel |
| `s` | save (re-encode + re-wrap container) |
| `[` / `]` | scroll content pane |
| `q` | quit (`q q` to discard unsaved changes) |

## 10. Verification against dumpasn1

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

## 11. Error handling

* Parse errors carry the absolute offset and are fatal at load time
  (reported on stderr).
* Edit errors (odd digit count, invalid content for a constructed node)
  are non-destructive: the editor stays open, the message goes to the
  status bar.
* Save errors (I/O) are reported in the status bar; the dirty flag stays
  set.
* Quitting with unsaved changes requires a second `q`.

## 12. Limitations and future work

* Re-encoding normalizes BER (indefinite lengths, redundant length octets)
  to DER framing; a byte-preserving mode would require storing original
  header bytes.
* No undo stack (single-level: quit without saving).
* No direct re-tagging of an element; change a tag by inserting a
  replacement TLV and deleting the original, or by editing the parent's
  full content in hex.
* OID names come from a small built-in table; parsing `dumpasn1.cfg` for
  full name coverage would be a natural extension.
* Value display for exotic universal types (REAL, EMBEDDED PDV, …) falls
  back to hex.
* Reading from stdin is not supported (the terminal owns stdin in a TUI).
