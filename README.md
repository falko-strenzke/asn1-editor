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
| `i` | insert a new element after the selected one (typed as full TLV hex) |
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

Inserting (`i`/`I`) opens the same hex editor, but the input is one or
more *complete TLV encodings* (tag, length, value — e.g. `0500` for NULL,
`020107` for INTEGER 7); it is validated before being spliced into the
tree. Delete, insert and reorder all re-encode the enclosing lengths
automatically, like value edits.
