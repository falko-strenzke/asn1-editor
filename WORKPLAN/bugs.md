# Bugs reported

## Unresolved

(none)

## Resolved

### Dirty file should be marked in file browser

When a file has been modified but no been saved, it should be marked with a yellow disk symbol on left hand side of the file name in the file browser.

**Fix:** the file browser's open-file marker (`src/tui.rs::draw_browser`)
now switches from the plain dot `•` to U+1F5AB WHITE HARD SHELL FLOPPY
DISK (🖫), colored yellow, whenever the currently open file has unsaved
changes (`app.dirty`); it reverts to the plain green dot as soon as the
file is saved or a clean file is opened. Only the marker glyph itself is
recolored — the filename text keeps its normal styling — via a
`styled_with_marker` helper that splits the row's text into up to three
spans around the marker's character offset, without touching the existing
width/truncation math that keeps the browser pane's arrow gutters aligned
(`arrow_gutters`, added for the cryptographic-relations feature). That
math assumes `str::chars().count()` reflects display width, which would
break for a genuinely wide (double-column) glyph — checked against
`unicode-width` (the crate ratatui's own renderer uses internally): U+1F5AB
reports as a single display column, matching its Unicode "Neutral" (not
"Wide") East Asian Width classification, so no further changes were
needed there. A short legend entry (`🖫 unsaved`) was added to the pane's
existing bottom-border legend. Regression tests:
`tui::tests::styled_with_marker_*` (marker splitting, the no-marker
passthrough case, and graceful degradation if the marker would fall
outside a truncated row).

### Display of ASN.1 integer

Display of ASN.1 integer in the tree is HEX on opening a file, but after editing it is in decimal. It should always be displayed in decimal in the ASN.1 tree.

**Cause:** the tree preview used `ber::decode_integer`, which converts via
`i128` and gives up on INTEGERs longer than 16 octets (e.g. the 20-octet
serial numbers openssl generates), falling back to hex. Values written by
the integer editor always fit `i128`, hence the inconsistency after editing.

**Fix:** arbitrary-precision decimal conversion in `ber.rs`
(`integer_decimal` / `encode_integer_decimal`, plain base-256 ↔ base-10 on
byte arrays, no new dependency), used by the tree preview, the content
pane's Decoded line, and the type-specific integer editor — which
previously also prefilled empty for such values and could not have applied
them back. `--dump` output intentionally keeps showing large integers as
hex: that is dumpasn1-compatible behavior, verified by the compat test.
Regression tests: `ber::tests::integer_decimal_*`,
`ber::tests::encode_integer_decimal_is_minimal_twos_complement`,
`tui::tests::tree_summary_shows_large_integers_in_decimal`,
`app::tests::type_specific_integer_handles_values_beyond_i128`.
