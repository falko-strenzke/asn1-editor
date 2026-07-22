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

//! Getting bytes into the hex editor from outside: reading the system
//! clipboard, and deciding what pasted data was meant to be.
//!
//! **Reading the clipboard.** A terminal program has no clipboard of its own.
//! Ctrl+V therefore asks whichever helper the desktop provides ([`read`]);
//! where none is installed the editor says so and the terminal's own paste —
//! usually Ctrl+Shift+V, which arrives as a bracketed paste — still works.
//! Both routes end in the same place, so the interpretation below applies
//! however the data arrived.
//!
//! **Interpreting it.** The editor edits hex, but what people have on the
//! clipboard is rarely hex: it may be a base64 blob copied out of a PEM file,
//! or arbitrary bytes. [`hex_digits`] decides between the three readings in
//! the order that keeps each one unambiguous — hex first, because a run of hex
//! digits is also valid base64 and reading `DEADBEEF` as base64 would silently
//! paste something else entirely — and reports which reading it used so the
//! status line can say so rather than leaving the user to spot the difference.

/// How pasted data was read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PasteKind {
    /// The text was already hex digits (whitespace ignored).
    Hex,
    /// The text decoded as base64.
    Base64,
    /// Neither: the bytes themselves were converted to hex.
    Binary,
}

impl PasteKind {
    /// Wording for the status line, saying how the data was read.
    pub fn describe(self) -> &'static str {
        match self {
            PasteKind::Hex => "read as hex digits",
            PasteKind::Base64 => "decoded from base64",
            PasteKind::Binary => "taken as raw bytes",
        }
    }
}

/// The hex digits `data` should be pasted as, and how it was read.
///
/// Empty input yields no digits; the caller treats that as nothing to paste.
pub fn hex_digits(data: &[u8]) -> (String, PasteKind) {
    if let Ok(text) = std::str::from_utf8(data) {
        let stripped: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if !stripped.is_empty() {
            // Already hex: keep the digits as they stand rather than
            // round-tripping through bytes, so an odd digit count survives to
            // be flagged by the editor instead of being silently altered.
            if stripped.chars().all(|c| c.is_ascii_hexdigit()) {
                return (stripped.to_ascii_uppercase(), PasteKind::Hex);
            }
            if let Ok(bytes) = crate::input::b64_decode(&stripped) {
                if !bytes.is_empty() {
                    return (crate::ber::hex_pairs(&bytes).replace(' ', ""), PasteKind::Base64);
                }
            }
        }
    }
    (crate::ber::hex_pairs(data).replace(' ', ""), PasteKind::Binary)
}

/// The helpers [`read`] tries, in order: the first that runs and succeeds
/// wins. Wayland, then X11, then macOS.
#[cfg(not(windows))]
const HELPERS: &[(&str, &[&str])] = &[
    ("wl-paste", &["--no-newline"]),
    ("xclip", &["-selection", "clipboard", "-out"]),
    ("xsel", &["--clipboard", "--output"]),
    ("pbpaste", &[]),
];

/// On Windows the clipboard is reached through PowerShell — `pwsh` if it is
/// installed, else the `powershell` that ships with the system. `-Raw` keeps
/// the text in one piece instead of splitting it into lines, and the output
/// encoding is forced to UTF-8 so that what arrives is not re-coded into the
/// console's codepage.
///
/// This route is **text only**: `Get-Clipboard` hands back a string, so
/// clipboard data that is not text cannot come through it (nor through a
/// bracketed paste, which is also a string). Hex and base64 — what is
/// actually copied out of certificates and key files — are unaffected.
#[cfg(windows)]
const HELPERS: &[(&str, &[&str])] = &[
    ("pwsh", &["-NoProfile", "-Command", WINDOWS_READ]),
    ("powershell", &["-NoProfile", "-Command", WINDOWS_READ]),
];

#[cfg(windows)]
const WINDOWS_READ: &str =
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Clipboard -Raw";

/// What to suggest when nothing worked, which differs by platform.
#[cfg(not(windows))]
const NO_HELPER: &str = "no clipboard tool found (install wl-clipboard, xclip or xsel) — \
                         the terminal's own paste, usually Ctrl+Shift+V, works regardless";
#[cfg(windows)]
const NO_HELPER: &str = "PowerShell could not be run to read the clipboard — \
                         the terminal's own paste (Ctrl+Shift+V, or right-click) \
                         works regardless";

/// The clipboard's contents, read through whichever helper this system has.
///
/// Raw bytes are returned, not a string: on the Unix-like systems the helpers
/// hand over whatever the clipboard holds, and [`hex_digits`] can take bytes
/// that are not text. (The Windows route is text only — see [`HELPERS`].)
pub fn read() -> Result<Vec<u8>, String> {
    let mut tried = Vec::new();
    for (command, args) in HELPERS {
        match std::process::Command::new(command).args(*args).output() {
            Ok(out) if out.status.success() => return Ok(trim_helper_newline(out.stdout)),
            // Present but unhappy (an empty clipboard, a missing display):
            // keep looking, and report this one if nothing else works.
            Ok(_) => tried.push(*command),
            Err(_) => {}
        }
    }
    if tried.is_empty() {
        Err(NO_HELPER.to_string())
    } else {
        Err(format!("{} could not read the clipboard", tried.join(", ")))
    }
}

/// The helpers [`write`] tries, in the same order and for the same reasons as
/// [`HELPERS`]. Each takes the text on standard input.
#[cfg(not(windows))]
const WRITERS: &[(&str, &[&str])] = &[
    ("wl-copy", &[]),
    ("xclip", &["-selection", "clipboard", "-in"]),
    ("xsel", &["--clipboard", "--input"]),
    ("pbcopy", &[]),
];

/// On Windows, `clip` (which ships with the system) reads standard input
/// straight onto the clipboard, so PowerShell is not needed for this half.
#[cfg(windows)]
const WRITERS: &[(&str, &[&str])] = &[("clip", &[])];

/// Put `text` on the system clipboard, for Ctrl+C and Ctrl+X.
///
/// The helper is fed on standard input and waited for: `xclip` in particular
/// forks a process that keeps serving the selection, so the write is only
/// certain once the parent has exited.
pub fn write(text: &str) -> Result<(), String> {
    use std::io::Write;
    let mut tried = Vec::new();
    for (command, args) in WRITERS {
        let child = std::process::Command::new(command)
            .args(*args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let Ok(mut child) = child else { continue };
        let written = child
            .stdin
            .take()
            .map(|mut pipe| pipe.write_all(text.as_bytes()))
            .unwrap_or(Ok(()));
        match (written, child.wait()) {
            (Ok(()), Ok(status)) if status.success() => return Ok(()),
            _ => tried.push(*command),
        }
    }
    if tried.is_empty() {
        Err(NO_HELPER.to_string())
    } else {
        Err(format!("{} could not write to the clipboard", tried.join(", ")))
    }
}

/// PowerShell terminates its output with a newline of its own, which is not
/// part of the clipboard. Dropping one trailing line ending keeps a binary
/// paste from picking up a stray `0D 0A`; the hex and base64 readings ignore
/// whitespace anyway. The Unix helpers do not add anything, so nothing is
/// trimmed there.
#[cfg(windows)]
fn trim_helper_newline(mut out: Vec<u8>) -> Vec<u8> {
    if out.last() == Some(&b'\n') {
        out.pop();
        if out.last() == Some(&b'\r') {
            out.pop();
        }
    }
    out
}

#[cfg(not(windows))]
fn trim_helper_newline(out: Vec<u8>) -> Vec<u8> {
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_text_is_taken_as_hex_however_it_is_spaced() {
        assert_eq!(hex_digits(b"30 82 01 0A"), ("3082010A".to_string(), PasteKind::Hex));
        assert_eq!(hex_digits(b"deadbeef"), ("DEADBEEF".to_string(), PasteKind::Hex));
        assert_eq!(hex_digits(b"04\n05\t06"), ("040506".to_string(), PasteKind::Hex));
        // An odd digit count is kept as typed; the editor flags it rather than
        // this silently changing what was pasted.
        assert_eq!(hex_digits(b"ABC"), ("ABC".to_string(), PasteKind::Hex));
    }

    /// A run of hex digits is also valid base64, so the order of the two tests
    /// decides what `DEADBEEF` means — and it must mean hex.
    #[test]
    fn hex_wins_over_base64_where_the_two_readings_overlap() {
        let (digits, kind) = hex_digits(b"DEADBEEF");
        assert_eq!(kind, PasteKind::Hex);
        assert_eq!(digits, "DEADBEEF");
        assert_ne!(digits, crate::ber::hex_pairs(&crate::input::b64_decode("DEADBEEF").unwrap()));
    }

    #[test]
    fn base64_is_decoded_before_the_text_is_taken_as_bytes() {
        // "Hello!" in base64 — has a non-hex letter, so it cannot be hex.
        let (digits, kind) = hex_digits(b"SGVsbG8h");
        assert_eq!(kind, PasteKind::Base64);
        assert_eq!(digits, "48656C6C6F21");
        // Line breaks inside a PEM-style blob are ignored.
        assert_eq!(hex_digits(b"SGVs\nbG8h").0, digits);
    }

    #[test]
    fn anything_else_is_taken_as_the_bytes_it_is() {
        let (digits, kind) = hex_digits("Grüße!".as_bytes());
        assert_eq!(kind, PasteKind::Binary);
        assert_eq!(digits, "4772C3BCC39F6521");
        // Not text at all.
        assert_eq!(hex_digits(&[0x00, 0xFF, 0x80]), ("00FF80".to_string(), PasteKind::Binary));
        // Nothing to paste.
        assert_eq!(hex_digits(b"").0, "");
        assert_eq!(hex_digits(b"   ").1, PasteKind::Binary);
    }

    #[test]
    fn every_reading_has_wording_for_the_status_line() {
        for kind in [PasteKind::Hex, PasteKind::Base64, PasteKind::Binary] {
            assert!(!kind.describe().is_empty());
        }
    }

    /// Reading may well fail on the machine running the tests — no display,
    /// no helper installed, an empty clipboard — but it must not panic or
    /// hang, and a failure must carry a reason for the status line. Every
    /// platform is compiled with a list of helpers to try, so this exercises
    /// whichever one this build has.
    #[test]
    fn reading_the_clipboard_either_works_or_says_why_not() {
        match read() {
            Ok(_) => {}
            Err(reason) => assert!(!reason.is_empty(), "a failure must be explained"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn powershells_own_trailing_newline_is_not_part_of_the_clipboard() {
        assert_eq!(trim_helper_newline(b"AB\r\n".to_vec()), b"AB");
        assert_eq!(trim_helper_newline(b"AB\n".to_vec()), b"AB");
        // Only one is dropped — the rest could be clipboard content.
        assert_eq!(trim_helper_newline(b"AB\n\n".to_vec()), b"AB\n");
        assert_eq!(trim_helper_newline(b"AB".to_vec()), b"AB");
        assert_eq!(trim_helper_newline(Vec::new()), Vec::<u8>::new());
    }
}
