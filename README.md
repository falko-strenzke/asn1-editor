# asn1-editor

A terminal (TUI) viewer **and editor** for ASN.1 BER/DER files, written in
Rust with [ratatui](https://ratatui.rs). The nested ASN.1 structure is shown
as a foldable tree in the left pane; the right pane shows the selected
element's decoded value and a hex dump of its content octets, which can be
edited in place.

The parser's structural output (offsets, lengths, type names, including the
"encapsulated ASN.1 inside OCTET STRING / BIT STRING" heuristic) replicates
Peter Gutmann's `dumpasn1` and is verified against the real binary by the
test suite. See [DESIGN.md](DESIGN.md) for the full design.

## Build

```sh
cargo build --release        # binary in target/release/asn1-editor
cargo test                   # includes the dumpasn1 comparison if installed
```

The only dependency is `ratatui`.

## Usage

```sh
asn1-editor cert.der             # open the TUI (edits overwrite cert.der on 's')
asn1-editor -o out.der cert.der  # save edits to out.der instead
asn1-editor --dump cert.der      # dumpasn1-style dump to stdout, no TUI
```

Input may be raw BER/DER, PEM, bare base64, or hex text; saving re-wraps
the edited data in the same outer format.

## Keys

| Key | Action |
|-----|--------|
| `↑`/`k`, `↓`/`j`, `PgUp`/`PgDn`, `g`, `G` | navigate the tree |
| `←`/`h`, `→`/`l`, `Enter`/`Space` | collapse / expand / toggle |
| `e` | edit the selected element's content octets as hex |
| `E` | open the edit menu: tag type / hex / base64 / raw binary / type specific |
| `i` | insert a new element after the selected one (type-picker dialog, then value) |
| `I` | insert a new element as first child of the selected constructed element |
| `d` `d` | delete the selected element (press twice to confirm) |
| `J` / `K` | move the selected element down / up among its siblings |
| `Enter` / `Esc` | apply / cancel the edit |
| `s` | save |
| `[` / `]` | scroll the content pane |
| `q` | quit (`q q` discards unsaved changes) |

Editing notes: the hex editor works on the element's *content octets*
(for BIT STRING including the leading unused-bits octet). Lengths of all
enclosing elements are recomputed automatically. Content of constructed
elements must remain valid ASN.1, otherwise the edit is rejected.

Inserting (`i`/`I`) first opens a popup dialog to choose the ASN.1 type,
with one column per bit field of the identifier octet: **class**
(universal / application / context-specific / private, bits 8-7), **form**
(primitive / constructed, bit 6) and **tag number** (bits 5-1; a list of
the named universal types, or a typed number for the other classes).
Illegal form combinations (e.g. primitive SEQUENCE) are ruled out
automatically and the resulting identifier octets are previewed live.
After confirming, only the value is entered in the hex editor (empty by
default); identifier and length octets are generated, and the lengths of
all enclosing elements are recomputed automatically — as for every other
edit operation.

`E` opens an **edit menu** for the selected element with five modes:

1. **Tag type** — the type-picker dialog pre-populated with the element's
   current class/form/tag; confirming re-tags the element in place while
   keeping its content octets.
2. **Hex** — the same hex editor as `e`.
3. **Base64** — the value as base64 text (pre-filled, whitespace ignored).
4. **Raw binary** — typed or pasted characters become the value bytes
   verbatim (UTF-8); useful for pasting data from the clipboard.
5. **Type specific** — the value in its most natural form: decimal entry
   for INTEGER/ENUMERATED/REAL, dot notation for OBJECT IDENTIFIER,
   TRUE/FALSE for BOOLEAN, plain text for the string types (encoded as
   UCS-2/UCS-4 for BMPString/UniversalString), hex for OCTET/BIT STRING,
   and for UTCTime/GeneralizedTime a form with separate year, month, day,
   hour, minute and second fields — no date-format guessing needed.

Every editor shows live feedback (resulting byte count or the validation
error) and applies with `Enter`; lengths are recomputed automatically.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
