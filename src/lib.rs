//! ASN.1 (BER/DER) viewer and editor library.
//!
//! The binary target (`asn1-editor`) provides a ratatui-based TUI; the
//! library exposes the parser, encoder and dump formatter so that they can
//! be exercised from integration tests (in particular the dumpasn1
//! compatibility test).

pub mod app;
pub mod ber;
pub mod dump;
pub mod input;
pub mod tui;
