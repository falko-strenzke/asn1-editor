# Bugs reported

## Unresolved

(none)

## Resolved

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
