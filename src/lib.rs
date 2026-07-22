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

//! ASN.1 (BER/DER) viewer and editor library.
//!
//! The binary target (`asn1-editor`) provides a ratatui-based TUI; the
//! library exposes the parser, encoder and dump formatter so that they can
//! be exercised from integration tests (in particular the dumpasn1
//! compatibility test).

pub mod app;
pub mod ber;
pub mod browser;
pub mod cost;
pub mod dump;
pub mod hashsig;
pub mod hsslms;
pub mod input;
pub mod keygen;
pub mod oid;
pub mod pathval;
pub mod pathval_botan;
pub mod pkcs12;
pub mod pkcs8;
pub mod spec;
pub mod tui;
pub mod verify;
pub mod x509;
pub mod xmss;
