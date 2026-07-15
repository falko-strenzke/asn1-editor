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

//! Application state: the parsed tree, the flattened visible rows, the
//! selection, and the hex edit workflow.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ratatui::widgets::ListState;

use crate::ber::{self, Class, Node};
use crate::browser::FileBrowser;
use crate::input::{self, Container};
use crate::keygen;
use crate::pathval::{self, PathStatus};
use crate::pkcs12;
use crate::pkcs8;
use crate::spec::{self, Identification, Label, SpecDb};
use crate::verify::{self, FileRelations, SignatureStatus};
use crate::x509::{self, CaCandidate, Kind, Signable, SignableFile};

/// Bytes per line in the hex editor; the cursor moves in units of hex digits.
pub const EDIT_BYTES_PER_LINE: usize = 16;
pub const EDIT_DIGITS_PER_LINE: usize = EDIT_BYTES_PER_LINE * 2;

/// One visible line of the tree pane: the path of child indices from the
/// corresponding real or virtual root forest down to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub path: Vec<usize>,
    pub depth: usize,
    pub source: RowSource,
}

/// A tree row either addresses the serialized document, the virtual
/// decrypted forest, or the placeholder shown before a password is entered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowSource {
    Document,
    Decrypted,
    DecryptedPlaceholder,
    /// A virtual row of the PKCS#12 reveal: the plaintext of the `usize`-th
    /// decrypted region (see [`Pkcs12Reveal`]).
    Pkcs12Revealed(usize),
}

/// What the hex editor is operating on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EditKind {
    /// Replace the selected node's content octets.
    Content,
    /// Insert a new element with the type chosen in the picker dialog at
    /// position `index` of `parent`'s children (`parent` empty = top
    /// level). Only the value (content octets) is typed; identifier and
    /// length octets are generated.
    Insert {
        parent: Vec<usize>,
        index: usize,
        class: Class,
        constructed: bool,
        tag: u32,
        source: RowSource,
    },
}

/// Choices of the type-picker dialog, one entry per class-bits value.
pub const PICKER_CLASSES: [(&str, Class); 4] = [
    ("Universal", Class::Universal),
    ("Application", Class::Application),
    ("Context-specific", Class::ContextSpecific),
    ("Private", Class::Private),
];

/// Universal tag numbers offered by the picker's tag column (all named
/// universal types, so an existing element's type can always be shown).
pub const PICKER_UNIVERSAL: [(u32, &str); 26] = [
    (1, "BOOLEAN"),
    (2, "INTEGER"),
    (3, "BIT STRING"),
    (4, "OCTET STRING"),
    (5, "NULL"),
    (6, "OBJECT IDENTIFIER"),
    (7, "ObjectDescriptor"),
    (8, "EXTERNAL"),
    (9, "REAL"),
    (10, "ENUMERATED"),
    (11, "EMBEDDED PDV"),
    (12, "UTF8String"),
    (16, "SEQUENCE"),
    (17, "SET"),
    (18, "NumericString"),
    (19, "PrintableString"),
    (20, "TeletexString"),
    (21, "VideotexString"),
    (22, "IA5String"),
    (23, "UTCTime"),
    (24, "GeneralizedTime"),
    (25, "GraphicString"),
    (26, "VisibleString"),
    (27, "GeneralString"),
    (28, "UniversalString"),
    (30, "BMPString"),
];

/// What the type-picker dialog acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PickerTarget {
    /// Insert a new element at `index` of `parent`'s children.
    Insert { parent: Vec<usize>, index: usize, source: RowSource },
    /// Change the type of the existing element at `path`, keeping its
    /// content octets.
    Retag { path: Vec<usize>, source: RowSource },
}

/// State of the "choose ASN.1 type" popup shown by the insert actions.
/// One column per bit field of the identifier octet: class (bits 8-7),
/// form (bit 6, primitive/constructed) and tag number (bits 5-1).
pub struct PickerState {
    pub target: PickerTarget,
    /// Active column: 0 = class, 1 = form, 2 = tag.
    pub column: usize,
    pub class_idx: usize,
    /// 0 = primitive, 1 = constructed (may be overridden, see `forced_form`).
    pub form_idx: usize,
    /// Selection in the universal-type list (class = Universal).
    pub univ_idx: usize,
    /// Typed tag number (classes other than Universal).
    pub tag_digits: String,
}

impl PickerState {
    fn new(target: PickerTarget) -> Self {
        PickerState {
            target,
            column: 2,
            class_idx: 0,
            form_idx: 0,
            univ_idx: 0,
            tag_digits: String::new(),
        }
    }

    pub fn class(&self) -> Class {
        PICKER_CLASSES[self.class_idx].1
    }

    pub fn tag(&self) -> u32 {
        if self.class() == Class::Universal {
            PICKER_UNIVERSAL[self.univ_idx].0
        } else {
            self.tag_digits.parse().unwrap_or(0)
        }
    }

    /// Some universal types only exist in one form: SEQUENCE/SET are
    /// always constructed, the scalar types always primitive. Returns the
    /// mandated form, or None when both are legal (string types in BER).
    pub fn forced_form(&self) -> Option<bool> {
        if self.class() != Class::Universal {
            return None;
        }
        match self.tag() {
            ber::TAG_SEQUENCE | ber::TAG_SET => Some(true),
            1 | 2 | 5 | 6 | 9 | 10 | 13 | 23 | 24 => Some(false),
            _ => None,
        }
    }

    /// Effective constructed bit after applying `forced_form`.
    pub fn constructed(&self) -> bool {
        self.forced_form().unwrap_or(self.form_idx == 1)
    }

    /// Identifier octets of the current choice, for the live preview.
    pub fn identifier_preview(&self) -> Vec<u8> {
        ber::identifier_octets(self.class(), self.tag(), self.constructed())
    }
}

pub struct EditState {
    pub kind: EditKind,
    pub editor: Editor,
}

impl EditState {
    /// Hex-grid editor over `content` (the classic 'e' edit).
    pub fn hex(kind: EditKind, content: &[u8]) -> Self {
        EditState { kind, editor: Editor::hex(content) }
    }

    /// Convert the editor buffer to content octets; Err carries the
    /// message for the status bar.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        self.editor.to_bytes()
    }
}

/// The value editors reachable from the edit menu.
pub enum Editor {
    /// Hex grid (16 bytes per line).
    Hex(HexEditor),
    /// Single text buffer whose interpretation depends on `format`.
    Text(TextEditor),
    /// Date/time form with one field per token.
    DateTime(DateTimeEditor),
}

pub struct HexEditor {
    /// Hex digits typed so far (no spaces).
    pub digits: Vec<char>,
    /// Cursor position in `digits` (0..=len).
    pub cursor: usize,
    /// First visible editor line, kept up to date by the renderer.
    pub scroll: usize,
}

/// Byte encoding of a text value, derived from the string type's tag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StrEncoding {
    Utf8,
    /// BMPString (UCS-2 big-endian).
    Utf16Be,
    /// UniversalString (UCS-4 big-endian).
    Utf32Be,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TextFormat {
    /// Standard base64; whitespace is ignored.
    Base64,
    /// Characters are taken literally as bytes (UTF-8), e.g. for pasting.
    Raw,
    /// Decimal integer, optionally negative.
    Integer,
    /// Decimal real; encoded as ISO 6093 NR3, "inf"/"-inf" supported.
    Real,
    /// OBJECT IDENTIFIER in dot notation.
    Oid,
    /// TRUE / FALSE (also 1 / 0).
    Boolean,
    /// Free text, encoded per the string type.
    Text(StrEncoding),
}

pub struct TextEditor {
    pub format: TextFormat,
    pub buf: Vec<char>,
    pub cursor: usize,
}

pub const DATE_FIELDS: [&str; 6] = ["Year", "Month", "Day", "Hour", "Minute", "Second"];

pub struct DateTimeEditor {
    /// Digit strings for year, month, day, hour, minute, second.
    pub fields: [String; 6],
    pub active: usize,
    pub generalized: bool,
    /// True while the active field has not been typed into since it was
    /// focused: the first typed digit then replaces the (pre-filled)
    /// content instead of appending to an already-full field.
    pub pristine: bool,
}

impl Editor {
    pub fn hex(content: &[u8]) -> Self {
        let digits = ber::hex_pairs(content)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        Editor::Hex(HexEditor { digits, cursor: 0, scroll: 0 })
    }

    pub fn text(format: TextFormat, initial: String) -> Self {
        let buf: Vec<char> = initial.chars().collect();
        let cursor = buf.len();
        Editor::Text(TextEditor { format, buf, cursor })
    }

    /// Printable character typed by the user.
    pub fn insert_char(&mut self, c: char) {
        match self {
            Editor::Hex(h) => {
                if c.is_ascii_hexdigit() {
                    h.digits.insert(h.cursor, c.to_ascii_uppercase());
                    h.cursor += 1;
                }
            }
            Editor::Text(t) => {
                if !c.is_control() {
                    t.buf.insert(t.cursor, c);
                    t.cursor += 1;
                }
            }
            Editor::DateTime(d) => {
                if c.is_ascii_digit() {
                    if d.pristine {
                        d.fields[d.active].clear();
                        d.pristine = false;
                    }
                    let max = if d.active == 0 { 4 } else { 2 };
                    if d.fields[d.active].len() < max {
                        d.fields[d.active].push(c);
                    }
                }
            }
        }
    }

    pub fn backspace(&mut self) {
        match self {
            Editor::Hex(h) => {
                if h.cursor > 0 {
                    h.cursor -= 1;
                    h.digits.remove(h.cursor);
                }
            }
            Editor::Text(t) => {
                if t.cursor > 0 {
                    t.cursor -= 1;
                    t.buf.remove(t.cursor);
                }
            }
            Editor::DateTime(d) => {
                d.fields[d.active].pop();
                d.pristine = false; // further digits append
            }
        }
    }

    pub fn delete(&mut self) {
        match self {
            Editor::Hex(h) => {
                if h.cursor < h.digits.len() {
                    h.digits.remove(h.cursor);
                }
            }
            Editor::Text(t) => {
                if t.cursor < t.buf.len() {
                    t.buf.remove(t.cursor);
                }
            }
            Editor::DateTime(d) => {
                d.fields[d.active].clear();
                d.pristine = false;
            }
        }
    }

    /// Left/right: cursor movement, or the active date/time field.
    pub fn move_horizontal(&mut self, delta: isize) {
        match self {
            Editor::Hex(h) => {
                h.cursor = (h.cursor as isize + delta).clamp(0, h.digits.len() as isize) as usize;
            }
            Editor::Text(t) => {
                t.cursor = (t.cursor as isize + delta).clamp(0, t.buf.len() as isize) as usize;
            }
            Editor::DateTime(d) => {
                d.active = (d.active as isize + delta).rem_euclid(6) as usize;
                d.pristine = true; // newly focused field: typing replaces
            }
        }
    }

    /// Up/down: hex row, or numeric adjust of the active date/time field.
    pub fn move_vertical(&mut self, delta: isize) {
        match self {
            Editor::Hex(h) => {
                let step = delta * EDIT_DIGITS_PER_LINE as isize;
                h.cursor = (h.cursor as isize + step).clamp(0, h.digits.len() as isize) as usize;
            }
            Editor::Text(_) => {}
            Editor::DateTime(d) => {
                let v = d.fields[d.active].parse::<i64>().unwrap_or(0) - delta as i64;
                d.fields[d.active] = v.max(0).to_string();
                d.pristine = true; // typing after adjusting starts fresh
            }
        }
    }

    pub fn home(&mut self) {
        match self {
            Editor::Hex(h) => h.cursor = 0,
            Editor::Text(t) => t.cursor = 0,
            Editor::DateTime(d) => {
                d.active = 0;
                d.pristine = true;
            }
        }
    }

    pub fn end(&mut self) {
        match self {
            Editor::Hex(h) => h.cursor = h.digits.len(),
            Editor::Text(t) => t.cursor = t.buf.len(),
            Editor::DateTime(d) => {
                d.active = 5;
                d.pristine = true;
            }
        }
    }

    /// Bracketed-paste input.
    pub fn paste(&mut self, s: &str) {
        for c in s.chars() {
            match self {
                // The raw editor keeps line breaks (they are data).
                Editor::Text(t)
                    if t.format == TextFormat::Raw && (c == '\n' || c == '\r') =>
                {
                    t.buf.insert(t.cursor, '\n');
                    t.cursor += 1;
                }
                _ => self.insert_char(c),
            }
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            Editor::Hex(h) => {
                if !h.digits.len().is_multiple_of(2) {
                    return Err("odd number of hex digits — add or remove one".to_string());
                }
                let hex: String = h.digits.iter().collect();
                input::hex_decode(&hex).map_err(|e| format!("invalid hex: {}", e))
            }
            Editor::Text(t) => text_to_bytes(t),
            Editor::DateTime(d) => datetime_to_bytes(d),
        }
    }
}

fn text_to_bytes(t: &TextEditor) -> Result<Vec<u8>, String> {
    let s: String = t.buf.iter().collect();
    match t.format {
        TextFormat::Base64 => {
            let stripped: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            input::b64_decode(&stripped).map_err(|e| format!("invalid base64: {}", e))
        }
        TextFormat::Raw => Ok(s.into_bytes()),
        // Arbitrary precision, so a prefilled 20-octet serial number can be
        // applied back unchanged.
        TextFormat::Integer => ber::encode_integer_decimal(&s),
        TextFormat::Real => {
            let trimmed = s.trim();
            match trimmed.to_ascii_lowercase().as_str() {
                "inf" | "+inf" => return Ok(vec![0x40]),
                "-inf" => return Ok(vec![0x41]),
                _ => {}
            }
            let v: f64 = trimmed
                .parse()
                .map_err(|_| "not a valid decimal number (or inf / -inf)".to_string())?;
            if v == 0.0 {
                Ok(Vec::new()) // REAL zero has empty content
            } else {
                // ISO 6093 NR3 decimal encoding.
                let mut out = vec![0x03];
                out.extend_from_slice(format!("{:E}", v).as_bytes());
                Ok(out)
            }
        }
        TextFormat::Oid => ber::encode_oid(s.trim()),
        TextFormat::Boolean => match s.trim().to_ascii_uppercase().as_str() {
            "TRUE" | "T" | "1" | "YES" => Ok(vec![0xFF]),
            "FALSE" | "F" | "0" | "NO" => Ok(vec![0x00]),
            _ => Err("enter TRUE or FALSE".to_string()),
        },
        TextFormat::Text(enc) => Ok(match enc {
            StrEncoding::Utf8 => s.into_bytes(),
            StrEncoding::Utf16Be => s
                .encode_utf16()
                .flat_map(|u| u.to_be_bytes())
                .collect(),
            StrEncoding::Utf32Be => s
                .chars()
                .flat_map(|c| (c as u32).to_be_bytes())
                .collect(),
        }),
    }
}

fn datetime_to_bytes(d: &DateTimeEditor) -> Result<Vec<u8>, String> {
    let mut nums = [0u32; 6];
    for (i, field) in d.fields.iter().enumerate() {
        nums[i] = field
            .parse()
            .map_err(|_| format!("{} is not filled in", DATE_FIELDS[i]))?;
    }
    let [year, month, day, hour, minute, second] = nums;
    let range_err = |what: &str, lo: u32, hi: u32| format!("{} must be {}..{}", what, lo, hi);
    if d.generalized {
        if year > 9999 {
            return Err(range_err("Year", 0, 9999));
        }
    } else if !(1950..=2049).contains(&year) {
        return Err("UTCTime years span 1950..2049 (two digits)".to_string());
    }
    if !(1..=12).contains(&month) {
        return Err(range_err("Month", 1, 12));
    }
    if !(1..=31).contains(&day) {
        return Err(range_err("Day", 1, 31));
    }
    if hour > 23 {
        return Err(range_err("Hour", 0, 23));
    }
    if minute > 59 {
        return Err(range_err("Minute", 0, 59));
    }
    if second > 59 {
        return Err(range_err("Second", 0, 59));
    }
    let s = if d.generalized {
        format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", year, month, day, hour, minute, second)
    } else {
        format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", year % 100, month, day, hour, minute, second)
    };
    Ok(s.into_bytes())
}

/// Pre-populate the date/time form from an existing UTCTime /
/// GeneralizedTime value; falls back to a neutral default.
fn datetime_from_value(value: &[u8], generalized: bool) -> DateTimeEditor {
    let default = DateTimeEditor {
        fields: [
            "2000".to_string(),
            "01".to_string(),
            "01".to_string(),
            "00".to_string(),
            "00".to_string(),
            "00".to_string(),
        ],
        active: 0,
        generalized,
        pristine: true,
    };
    let Ok(s) = std::str::from_utf8(value) else { return default };
    let Some(digits) = s.strip_suffix('Z') else { return default };
    let need = if generalized { 14 } else { 12 };
    if digits.len() != need || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return default;
    }
    let (year, rest) = if generalized {
        (digits[0..4].to_string(), &digits[4..])
    } else {
        let yy: u32 = digits[0..2].parse().unwrap();
        let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
        (year.to_string(), &digits[2..])
    };
    DateTimeEditor {
        fields: [
            year,
            rest[0..2].to_string(),
            rest[2..4].to_string(),
            rest[4..6].to_string(),
            rest[6..8].to_string(),
            rest[8..10].to_string(),
        ],
        active: 0,
        generalized,
        pristine: true,
    }
}

fn decode_utf16be(v: &[u8]) -> String {
    let units: Vec<u16> = v.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])).collect();
    String::from_utf16_lossy(&units)
}

fn decode_utf32be(v: &[u8]) -> String {
    v.chunks(4)
        .map(|c| {
            let mut b = [0u8; 4];
            b[..c.len()].copy_from_slice(c);
            char::from_u32(u32::from_be_bytes(b)).unwrap_or('\u{FFFD}')
        })
        .collect()
}

/// What confirming a popup-menu entry does. Shared by the 'E' edit menu and
/// the 'z' cryptographic-adjustment menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuAction {
    Retag,
    EditHex,
    EditBase64,
    EditRaw,
    EditTypeSpecific,
    /// Open the public-key modification dialog (§9e).
    Rekey,
    /// Open the re-sign dialog (§9c).
    Resign,
}

/// One entry of a popup menu.
pub struct MenuItem {
    pub action: MenuAction,
    pub label: &'static str,
    pub desc: &'static str,
}

/// The five base editing modes offered by the 'E' menu, in order.
const EDIT_MENU: [(MenuAction, &str, &str); 5] = [
    (MenuAction::Retag, "Tag type", "change class / form / tag number of the element"),
    (MenuAction::EditHex, "Hex", "edit the content octets as hex digits"),
    (MenuAction::EditBase64, "Base64", "edit the content octets as base64 text"),
    (MenuAction::EditRaw, "Raw binary", "characters become bytes verbatim (paste-friendly)"),
    (MenuAction::EditTypeSpecific, "Type specific", "number, OID, text, TRUE/FALSE, date/time fields …"),
];

/// A generic popup menu: a title and a list of actionable entries.
pub struct MenuState {
    pub title: &'static str,
    pub items: Vec<MenuItem>,
    pub selected: usize,
}

pub enum Mode {
    Browse,
    /// Type-picker popup of the insert and retag actions.
    TypePicker(PickerState),
    /// Edit-mode chooser popup ('E').
    EditMenu(MenuState),
    Edit(EditState),
    /// Password prompt for decrypting an `EncryptedPrivateKeyInfo` ('z').
    Password(PasswordState),
    /// Re-sign dialog for a modified certificate/CRL ('z' on a signed object).
    Resign(ResignState),
    /// Public-key modification dialog ('e' on a certificate's
    /// `subjectPublicKeyInfo`): choose an algorithm, optionally generate and
    /// save a new private key, and resign the certificates this one issued.
    EditPubKey(PubKeyState),
}

/// One signed object (certificate or CRL) issued by the certificate being
/// rekeyed, offered in the dialog's third column for re-signing with the new
/// key. Certificates are listed first, then CRLs.
pub struct IssuedObject {
    pub path: PathBuf,
    pub name: String,
    /// Short display suffix: `#<serial>` for a certificate, `CRL` for a CRL.
    pub detail: String,
    /// Whether this object will be resigned (checkbox; default true).
    pub selected: bool,
}

/// State of the public-key modification dialog. A new key pair is always
/// generated in memory (it is what rekeys the certificate and resigns the
/// issued certificates); `generate` controls only whether that private key is
/// also written to a file.
pub struct PubKeyState {
    /// Index into [`keygen::ALL`] of the chosen signature algorithm.
    pub alg_idx: usize,
    /// Whether to write the generated private key to `filename` (default true).
    pub generate: bool,
    /// Target key-file name (in the certificate's directory).
    pub filename: String,
    /// True while `filename` still tracks the algorithm-derived default; set
    /// false once the user edits it, so an algorithm change stops overwriting.
    pub filename_auto: bool,
    /// Optional password; empty means an unencrypted PKCS#8 key.
    pub password: String,
    /// Signed objects issued by this certificate (certs then CRLs), each with
    /// a re-sign checkbox.
    pub issued: Vec<IssuedObject>,
    /// Active column: 0 = algorithm, 1 = key options, 2 = issued certs.
    pub column: usize,
    /// Active field within the key-options column: 0 = generate checkbox,
    /// 1 = file name, 2 = password.
    pub option_field: usize,
    /// Selection within the issued-certs column.
    pub issued_idx: usize,
}

impl PubKeyState {
    fn alg(&self) -> keygen::KeyAlgorithm {
        keygen::ALL[self.alg_idx]
    }

    /// The default key file name for the current algorithm, derived from the
    /// certificate's file stem: `<stem>_<alg>_key.der`.
    fn default_filename(cert_stem: &str, alg: keygen::KeyAlgorithm) -> String {
        format!("{}_{}_key.der", cert_stem, alg.short_name())
    }

    fn move_column(&mut self, delta: isize) {
        self.column = (self.column as isize + delta).clamp(0, 2) as usize;
    }

    fn move_row(&mut self, delta: isize, cert_stem: &str) {
        match self.column {
            0 => {
                let n = keygen::ALL.len() as isize;
                self.alg_idx = (self.alg_idx as isize + delta).clamp(0, n - 1) as usize;
                if self.filename_auto {
                    self.filename = Self::default_filename(cert_stem, self.alg());
                }
            }
            1 => self.option_field = (self.option_field as isize + delta).clamp(0, 2) as usize,
            _ => {
                if !self.issued.is_empty() {
                    let n = self.issued.len() as isize;
                    self.issued_idx = (self.issued_idx as isize + delta).clamp(0, n - 1) as usize;
                }
            }
        }
    }

    /// Space toggles the generate checkbox (column 1, field 0) or an issued
    /// certificate's re-sign checkbox (column 2).
    fn toggle(&mut self) {
        if self.column == 1 && self.option_field == 0 {
            self.generate = !self.generate;
        } else if self.column == 2 {
            if let Some(cert) = self.issued.get_mut(self.issued_idx) {
                cert.selected = !cert.selected;
            }
        }
    }

    fn insert_char(&mut self, c: char) {
        if c.is_control() || self.column != 1 {
            return;
        }
        match self.option_field {
            1 => {
                self.filename.push(c);
                self.filename_auto = false;
            }
            2 => self.password.push(c),
            _ => {}
        }
    }

    fn backspace(&mut self) {
        if self.column != 1 {
            return;
        }
        match self.option_field {
            1 => {
                self.filename.pop();
                self.filename_auto = false;
            }
            2 => {
                self.password.pop();
            }
            _ => {}
        }
    }
}

/// State of the re-sign dialog: whether a new signature can be produced and,
/// if so, the already-generated (and verified) signature to apply on confirm.
/// The signature is computed when the dialog opens by trying every available
/// issuer key, so "available" means a *usable* key was actually found — not
/// merely that some key file is present.
pub struct ResignState {
    /// Short description of the signer (issuer) whose key is needed.
    pub issuer_summary: String,
    /// One-line explanation shown in the dialog.
    pub detail: String,
    /// Whether a new signature can be created.
    pub ready: bool,
    /// The new signature to install on confirm; `Some` only when `ready`.
    /// (Public data — no private key material is retained in the dialog.)
    signature: Option<Vec<u8>>,
}

/// Private-key passwords entered this session, retained (until the program
/// quits) so an issuer's encrypted key can be re-used to re-sign a modified
/// object without prompting again. Keyed by the file the password unlocked;
/// zeroed on drop.
#[derive(Default)]
pub struct RetainedPasswords(Vec<(PathBuf, Vec<u8>)>);

impl RetainedPasswords {
    fn set(&mut self, path: PathBuf, password: Vec<u8>) {
        self.0.retain(|(p, _)| *p != path);
        self.0.push((path, password));
    }

    fn get(&self, path: &Path) -> Option<&[u8]> {
        self.0.iter().find(|(p, _)| p == path).map(|(_, pw)| pw.as_slice())
    }
}

impl Drop for RetainedPasswords {
    fn drop(&mut self) {
        for (_, pw) in &mut self.0 {
            pw.fill(0);
        }
    }
}

/// State of the decrypt-password prompt: the (masked) characters typed so far.
pub struct PasswordState {
    pub buf: String,
}

impl PasswordState {
    pub fn insert_char(&mut self, c: char) {
        if !c.is_control() {
            self.buf.push(c);
        }
    }

    pub fn backspace(&mut self) {
        self.buf.pop();
    }

    pub fn paste(&mut self, s: &str) {
        self.buf.extend(s.chars().filter(|c| !c.is_control()));
    }
}

/// A successful decryption of the currently open `EncryptedPrivateKeyInfo`.
/// Its parsed roots are displayed as virtual rows below `encrypted_path` and
/// are never included directly in the outer document encoding.
pub struct Decrypted {
    /// Path of the `encryptedData` node whose plaintext this is.
    pub encrypted_path: Vec<usize>,
    /// The decrypted plaintext DER (a `PrivateKeyInfo`).
    pub plaintext: Vec<u8>,
    /// Parsed, editable representation of `plaintext`.
    pub roots: Vec<Node>,
    /// Password retained for synchronizing edits in either representation.
    password: Vec<u8>,
    /// Specification match for the virtual plaintext tree.
    pub ident: Option<Identification>,
}

impl Drop for Decrypted {
    fn drop(&mut self) {
        self.password.fill(0);
    }
}

/// A successful decryption of the currently open PKCS#12 (`PFX`) container.
/// Unlike the single-region `Decrypted`, a PKCS#12 may hold several
/// encrypted regions; each region's plaintext is shown (and edited) as
/// virtual rows below its ciphertext node. An edit re-encrypts the region
/// in place and recomputes the container's integrity `MacData` — unless
/// `editable` carries the reason that is impossible (an unsupported MAC
/// digest), in which case the reveal stays read-only.
pub struct Pkcs12Reveal {
    /// Password retained to re-encrypt edited regions and re-derive the
    /// reveal after outer-document edits (`refresh_pkcs12_reveal`). Zeroed
    /// on drop.
    password: Vec<u8>,
    pub regions: Vec<RevealedRegion>,
    /// `Ok` when edited regions can be re-encrypted into a consistent file
    /// (the `MacData` is absent or recomputable); `Err(reason)` otherwise.
    pub editable: Result<(), String>,
}

/// One decrypted region of a [`Pkcs12Reveal`].
pub struct RevealedRegion {
    /// Path of the ciphertext node (in `self.roots`) this hangs below.
    pub cipher_path: Vec<usize>,
    pub kind: pkcs12::RegionKind,
    /// Parsed, editable plaintext of this region.
    pub roots: Vec<Node>,
    /// Specification match for this region's plaintext tree.
    pub ident: Option<Identification>,
}

impl Drop for Pkcs12Reveal {
    fn drop(&mut self) {
        self.password.fill(0);
    }
}

/// Whether a PKCS#12 reveal may be edited, given the container's `MacData`
/// state: absent or supported MACs keep the file consistent after
/// re-encryption, an unsupported one cannot be recomputed.
fn mac_editable(mac: &pkcs12::Mac) -> Result<(), String> {
    match mac {
        pkcs12::Mac::Unsupported(reason) => Err(reason.clone()),
        pkcs12::Mac::Absent | pkcs12::Mac::Supported(_) => Ok(()),
    }
}

/// Which pane receives navigation keys while in `Mode::Browse`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    /// The file browser pane (far left).
    Browser,
    /// The ASN.1 structure/content panes.
    Document,
}

pub struct App {
    pub path: PathBuf,
    pub out_path: PathBuf,
    pub container: Container,
    pub roots: Vec<Node>,
    /// Length of the current encoding, for offset column width.
    pub total_len: usize,
    pub rows: Vec<Row>,
    pub selected: usize,
    pub tree_state: ListState,
    pub mode: Mode,
    pub status: String,
    pub dirty: bool,
    /// Set after the first 'q' while there are unsaved changes.
    pub quit_confirm: bool,
    /// Set after the first 'd'; the second 'd' actually deletes.
    pub delete_confirm: bool,
    /// Scroll offset of the content pane in browse mode.
    pub content_scroll: u16,
    /// Loaded ASN.1 specifications (may be empty).
    pub spec_db: SpecDb,
    /// Result of matching the document against the specifications.
    pub ident: Option<Identification>,
    /// Far-left directory tree pane.
    pub browser: FileBrowser,
    /// Which pane currently receives navigation keys.
    pub focus: Focus,
    /// False when the program was started with a directory and no file has
    /// been picked from the browser yet: `roots`/`rows` are empty, and
    /// document-mutating actions (`save`, insert) are refused.
    pub file_open: bool,
    /// Set after the first Enter on a file in the browser while the current
    /// document has unsaved changes; a second Enter discards them and opens.
    pub open_confirm: bool,
    /// Certificates found while scanning the browser's root directory on
    /// startup, kept as candidate issuers. Static for the process lifetime
    /// — not rescanned on edits or when switching files.
    pub ca_index: Vec<CaCandidate>,
    /// Signature verification result for the currently open document, if
    /// it structurally decodes as a Certificate or CRL.
    pub sig_status: Option<SignatureStatus>,
    /// Certificate files the user has marked trusted (`t`) — the trust
    /// anchors for OpenSSL certification-path validation.
    pub trusted_certs: BTreeSet<PathBuf>,
    /// OpenSSL certification-path validation result for the currently open
    /// document, if it is a certificate. Recomputed on selection and whenever
    /// the trust set changes.
    pub path_status: Option<PathStatus>,
    /// All signed objects (certs + CRLs) found in the browser tree on
    /// startup — the source for both `ca_index` and the browser relation
    /// graph. Static snapshot of the on-disk state.
    pub signables: Vec<SignableFile>,
    /// Cryptographic relations of the currently selected browser file to
    /// the others (who signed it / what it signs). Recomputed whenever the
    /// browser selection changes; empty when a directory or nothing is
    /// selected.
    pub browser_relations: FileRelations,
    /// Plaintext private-key files found in the browser tree at startup, each
    /// reduced to its public key — the static half of the key↔certificate
    /// links (a snapshot, like `signables`).
    pub key_files: Vec<x509::KeyFile>,
    /// Public keys recovered by decrypting an encrypted key or PKCS#12 with a
    /// password this session, tagged with the file they came from. The
    /// dynamic half of the key↔certificate links; persists across navigation
    /// so a link stays visible after the user browses away from the file
    /// they decrypted.
    pub unlocked_keys: Vec<(PathBuf, x509::PublicKeyId)>,
    /// Private-key passwords entered this session (path → password), retained
    /// so an encrypted issuer key can re-sign a modified object without
    /// re-prompting. Zeroed when the program quits.
    pub retained_passwords: RetainedPasswords,
    /// Editable virtual plaintext of the open document's `encryptedData`,
    /// once the user has decrypted it with 'z'.
    pub decrypted: Option<Decrypted>,
    /// Read-only virtual plaintext of the open PKCS#12 container's encrypted
    /// regions, once the user has decrypted it with 'z'.
    pub pkcs12: Option<Pkcs12Reveal>,
}

impl App {
    pub fn new(
        path: PathBuf,
        out_path: PathBuf,
        container: Container,
        roots: Vec<Node>,
        total_len: usize,
    ) -> Self {
        let dir = path.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        let mut browser = FileBrowser::new(dir.clone());
        browser.reveal(&path);
        let signables = x509::scan_dir_signables(&dir);
        let ca_index = x509::cert_candidates(&signables);
        let key_files = scan_usable_key_files(&dir);
        let mut app = App {
            path,
            out_path,
            container: container.clone(),
            roots,
            total_len,
            rows: Vec::new(),
            selected: 0,
            tree_state: ListState::default(),
            mode: Mode::Browse,
            status: format!("loaded {} bytes ({})", total_len, container.describe()),
            dirty: false,
            quit_confirm: false,
            delete_confirm: false,
            content_scroll: 0,
            spec_db: SpecDb::default(),
            ident: None,
            browser,
            focus: Focus::Document,
            file_open: true,
            open_confirm: false,
            ca_index,
            sig_status: None,
            trusted_certs: BTreeSet::new(),
            path_status: None,
            signables,
            browser_relations: FileRelations::default(),
            key_files,
            unlocked_keys: Vec::new(),
            retained_passwords: RetainedPasswords::default(),
            decrypted: None,
            pkcs12: None,
        };
        app.rebuild_rows();
        app.recompute_sig_status(); // also refreshes browser_relations
        app
    }

    /// Started with a directory instead of a file: the browser shows that
    /// directory and no document is loaded until one is picked (Enter).
    pub fn new_dir(dir: PathBuf) -> Self {
        let browser = FileBrowser::new(dir.clone());
        let signables = x509::scan_dir_signables(&dir);
        let ca_index = x509::cert_candidates(&signables);
        let key_files = scan_usable_key_files(&dir);
        let mut app = App {
            path: dir.clone(),
            out_path: dir,
            container: Container::Raw,
            roots: Vec::new(),
            total_len: 0,
            rows: Vec::new(),
            selected: 0,
            tree_state: ListState::default(),
            mode: Mode::Browse,
            status: "↑↓ to preview a file — Enter switches to it".to_string(),
            dirty: false,
            quit_confirm: false,
            delete_confirm: false,
            content_scroll: 0,
            spec_db: SpecDb::default(),
            ident: None,
            browser,
            focus: Focus::Browser,
            file_open: false,
            open_confirm: false,
            ca_index,
            sig_status: None,
            trusted_certs: BTreeSet::new(),
            path_status: None,
            signables,
            browser_relations: FileRelations::default(),
            key_files,
            unlocked_keys: Vec::new(),
            retained_passwords: RetainedPasswords::default(),
            decrypted: None,
            pkcs12: None,
        };
        app.rebuild_rows();
        app.recompute_browser_relations();
        app
    }

    /// Recompute the selected browser file's cryptographic relations to
    /// the rest of the scanned tree. Called whenever the browser selection
    /// changes. A directory (or an empty browser) has no relations.
    pub fn recompute_browser_relations(&mut self) {
        let selected = match self.browser.selected_entry() {
            Some(entry) if !entry.is_dir => entry.path.clone(),
            _ => {
                self.browser_relations = FileRelations::default();
                return;
            }
        };
        let mut relations = verify::relations_for(&self.signables, &selected);
        relations.key_links = self.compute_key_links(&selected);
        self.browser_relations = relations;
    }

    /// Undirected key↔certificate links touching `selected`: the private-key
    /// files (plaintext scans, plus any encrypted key or PKCS#12 whose
    /// password has been supplied this session) matched to the certificate
    /// files carrying their public key.
    fn compute_key_links(&self, selected: &Path) -> Vec<PathBuf> {
        let certs: Vec<(PathBuf, x509::PublicKeyId)> = self
            .signables
            .iter()
            .filter_map(|f| Some((f.path.clone(), x509::public_key_id_of_signable(&f.signable)?)))
            .collect();
        // Plaintext key files found on disk, plus keys unlocked by a password
        // this session (encrypted PKCS#8 / PKCS#12). The unlocked cache
        // persists across navigation, so a link stays visible after the user
        // browses away from the file they decrypted.
        let mut bearers: Vec<(PathBuf, x509::PublicKeyId)> = self
            .key_files
            .iter()
            .map(|k| (k.path.clone(), k.key.clone()))
            .collect();
        bearers.extend(self.unlocked_keys.iter().cloned());
        verify::key_links_for(&bearers, &certs, selected)
    }

    /// Record the public key(s) recovered by decrypting the open document, so
    /// the key↔certificate link survives navigating away from it. Replaces
    /// any prior entries for the same path.
    fn cache_unlocked_keys(&mut self, keys: Vec<x509::PublicKeyId>) {
        let path = self.path.clone();
        self.unlocked_keys.retain(|(p, _)| *p != path);
        for key in keys {
            self.unlocked_keys.push((path.clone(), key));
        }
    }

    /// Toggle keyboard focus between the file browser and the document
    /// panes ('Tab').
    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Browser => Focus::Document,
            Focus::Document => Focus::Browser,
        };
        self.open_confirm = false;
    }

    /// Load `path` as the current document, replacing whatever (if
    /// anything) was open before. Errors are non-fatal — the caller shows
    /// them in the status bar and the browser stays as it was.
    pub fn open_file(&mut self, path: PathBuf) -> Result<(), String> {
        let raw = std::fs::read(&path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
        let (der, container) = input::load(&raw)?;
        let roots = ber::parse_forest(&der, 0).map_err(|e| format!("ASN.1 parse error at {}", e))?;
        self.total_len = der.len();
        self.path = path.clone();
        self.out_path = path;
        self.container = container.clone();
        self.roots = roots;
        self.selected = 0;
        self.mode = Mode::Browse;
        self.dirty = false;
        self.quit_confirm = false;
        self.delete_confirm = false;
        self.content_scroll = 0;
        self.file_open = true;
        self.decrypted = None;
        self.pkcs12 = None;
        self.rebuild_rows();
        self.identify();
        self.recompute_sig_status();
        self.status = format!("loaded {} bytes ({})", self.total_len, container.describe());
        Ok(())
    }

    /// 'z': prompt for a password to decrypt the open document, if it is a
    /// supported `EncryptedPrivateKeyInfo`. Works from either pane (it acts
    /// on the open document, which browser live-preview keeps current).
    pub fn start_decrypt(&mut self) {
        if !self.file_open {
            self.status = "no file open — select an encrypted private key first".to_string();
            return;
        }
        // Two decryptable container shapes share the 'z' flow: an encrypted
        // PKCS#8 key and a PKCS#12 file. They are structurally disjoint, so
        // try each in turn.
        match pkcs8::parse(&self.roots) {
            Ok(Some(_)) => {
                self.mode = Mode::Password(PasswordState { buf: String::new() });
                self.status = "enter the password to decrypt this private key".to_string();
                return;
            }
            Ok(None) => {}
            Err(msg) => {
                self.status = format!("cannot decrypt: {}", msg);
                return;
            }
        }
        match pkcs12::parse(&self.roots) {
            Ok(Some(_)) => {
                self.mode = Mode::Password(PasswordState { buf: String::new() });
                self.status = "enter the password to decrypt this PKCS#12 file".to_string();
                return;
            }
            Ok(None) => {}
            Err(msg) => {
                self.status = format!("cannot decrypt PKCS#12: {}", msg);
                return;
            }
        }
        // Not an encrypted container — offer the cryptographic-adjustment
        // menu (re-sign / re-key), if this is a certificate or CRL.
        self.start_crypto_menu();
    }

    /// 'z' on a certificate or CRL: open the re-sign dialog, reporting
    /// whether the issuer's signing key is available. Not a signed object →
    /// just a status message.
    pub fn start_resign(&mut self) {
        let der = ber::encode_forest(&self.roots);
        let signable = ber::parse_forest(&der, 0)
            .ok()
            .and_then(|roots| x509::parse_signable(&roots, &der));
        let Some(signable) = signable else {
            self.status = "not an encrypted key, PKCS#12, certificate or CRL".to_string();
            return;
        };
        let state = self.resign_state(&signable);
        self.status = if state.ready {
            "the signing key is available — ⏎ creates a new signature".to_string()
        } else {
            "re-signing is not available (see the dialog)".to_string()
        };
        self.mode = Mode::Resign(state);
    }

    /// Determine whether the modified `signable` can be re-signed, and if so
    /// produce the new signature. The algorithm must be supported and the
    /// issuer certificate present; then *every* candidate private key (all
    /// plaintext key files and session-unlocked encrypted keys/PKCS#12s whose
    /// public key matches an issuer) is tried until one produces a signature
    /// that actually verifies against that issuer's certificate. Trying all of
    /// them — rather than committing to the first key that merely parses —
    /// means an invalidated or mismatched key is skipped in favor of a valid
    /// one (e.g. a corrupted plaintext key falls through to the SEC1 copy or
    /// to an unlocked encrypted key).
    fn resign_state(&self, signable: &Signable) -> ResignState {
        let not_ready = |issuer: &str, detail: &str| ResignState {
            issuer_summary: issuer.to_string(),
            detail: detail.to_string(),
            ready: false,
            signature: None,
        };
        if !verify::signing_supported(&signable.sig_alg) {
            return not_ready("", "this signature algorithm is not supported for re-signing");
        }
        let candidates = verify::claimed_issuers(&self.ca_index, signable);
        if candidates.is_empty() {
            return not_ready("(issuer not found)", "the issuer's certificate is not in this folder");
        }
        for candidate in &candidates {
            let Some(id) = x509::public_key_id(&candidate.pubkey_alg, &candidate.pubkey) else {
                continue;
            };
            for material in self.signing_materials_for(&id) {
                let Ok(signature) = verify::sign(&signable.sig_alg, &material, &signable.tbs) else {
                    continue; // this key cannot sign (wrong type, inconsistent, …)
                };
                if verify::verify_signature(
                    &signable.sig_alg,
                    &candidate.pubkey,
                    &signable.tbs,
                    &signature,
                ) {
                    return ResignState {
                        issuer_summary: candidate.subject_summary.clone(),
                        detail: "the issuer's signing key is available".to_string(),
                        ready: true,
                        signature: Some(signature),
                    };
                }
            }
        }
        not_ready(
            &candidates[0].subject_summary,
            "the issuer's private key is not available — open its key file and, \
             if it is encrypted, decrypt it with 'z' first",
        )
    }

    /// Every reachable private key whose public key is `id`, as PKCS#8
    /// `PrivateKeyInfo` DER: each plaintext key file (freshly re-read, so an
    /// on-disk change is reflected) plus each session-unlocked encrypted
    /// key/PKCS#12 (re-decrypted with its retained password). The caller
    /// tries them in turn — none is trusted to actually work until it signs.
    fn signing_materials_for(&self, id: &x509::PublicKeyId) -> Vec<Vec<u8>> {
        let mut materials = Vec::new();
        for key_file in &self.key_files {
            if key_file.key == *id {
                if let Some(pkcs8) = read_plaintext_key_pkcs8(&key_file.path) {
                    materials.push(pkcs8);
                }
            }
        }
        for (path, pubkey) in &self.unlocked_keys {
            if pubkey == id {
                if let Some(pkcs8) = self.decrypt_key_pkcs8(path, id) {
                    materials.push(pkcs8);
                }
            }
        }
        materials
    }

    /// Re-decrypt a session-unlocked key/PKCS#12 file with its retained
    /// password and return the PKCS#8 for the key whose public key is `id`.
    fn decrypt_key_pkcs8(&self, path: &Path, id: &x509::PublicKeyId) -> Option<Vec<u8>> {
        let password = self.retained_passwords.get(path)?;
        let raw = std::fs::read(path).ok()?;
        let (der, _) = input::load(&raw).ok()?;
        let roots = ber::parse_forest(&der, 0).ok()?;
        if let Ok(Some(enc)) = pkcs8::parse(&roots) {
            // The decrypted plaintext is itself a PKCS#8 PrivateKeyInfo.
            return enc.decrypt(password).ok();
        }
        if let Ok(Some(p12)) = pkcs12::parse(&roots) {
            for region in &p12.regions {
                let Ok(plaintext) = region.decrypt(password) else { continue };
                let Ok(key_roots) = ber::parse_forest(&plaintext, 0) else { continue };
                if x509::public_key_id_of_private_key(&key_roots).as_ref() == Some(id) {
                    return x509::to_pkcs8_der(&key_roots);
                }
            }
        }
        None
    }

    pub fn cancel_resign(&mut self) {
        self.mode = Mode::Browse;
        self.status = "re-signing cancelled".to_string();
    }

    /// Confirm re-signing: install the signature the dialog already generated
    /// and verified (over the current, unchanged `tbs`) into the object's
    /// outer signature.
    pub fn submit_resign(&mut self) {
        let Mode::Resign(ref state) = self.mode else { return };
        let signature = if state.ready { state.signature.clone() } else { None };
        self.mode = Mode::Browse;
        let Some(sig) = signature else {
            self.status = "re-signing is not available".to_string();
            return;
        };
        // The outer `signature` BIT STRING is the third element of a
        // Certificate / CertificateList; its content is one unused-bits octet
        // (0) followed by the signature.
        if let Some(node) = node_at_mut(&mut self.roots, &[0, 2]) {
            node.value = std::iter::once(0u8).chain(sig).collect();
            node.children.clear();
            node.encapsulates = false;
        }
        self.dirty = true;
        self.rebuild();
        self.status = "new signature created — 's' writes the file".to_string();
    }

    // ---- public-key modification ('e' on subjectPublicKeyInfo) -----------

    /// 'e': if the selected element is the `subjectPublicKeyInfo` of the open
    /// certificate, open the public-key modification dialog; otherwise fall
    /// through to the normal type-specific value edit.
    pub fn edit_selected(&mut self) {
        if self.open_public_key_editor() {
            return;
        }
        self.start_edit_type_specific();
    }

    /// Open the public-key modification dialog when the current selection is a
    /// certificate's `subjectPublicKeyInfo`. Returns whether it was opened.
    fn open_public_key_editor(&mut self) -> bool {
        if !self.file_open || !self.selection_is_cert_spki() {
            return false;
        }
        self.start_rekey();
        true
    }

    /// Whether the current tree selection is the `subjectPublicKeyInfo` of the
    /// open certificate.
    fn selection_is_cert_spki(&self) -> bool {
        let Some(paths) = cert_paths(&self.roots) else { return false };
        self.rows
            .get(self.selected)
            .is_some_and(|r| r.source == RowSource::Document && r.path == paths.spki)
    }

    /// Open the public-key modification dialog for the open certificate,
    /// regardless of the current selection (reached from the SPKI via 'e', from
    /// the 'E' edit menu, or from the 'z' cryptographic-adjustment menu).
    pub fn start_rekey(&mut self) {
        if cert_paths(&self.roots).is_none() {
            self.status = "re-keying is only available for a certificate".to_string();
            return;
        }
        let alg = keygen::ALL[0];
        let issued = self.issued_objects();
        let state = PubKeyState {
            alg_idx: 0,
            generate: true,
            filename: PubKeyState::default_filename(&self.cert_file_stem(), alg),
            filename_auto: true,
            password: String::new(),
            issued,
            column: 0,
            option_field: 0,
            issued_idx: 0,
        };
        self.mode = Mode::EditPubKey(state);
        self.status =
            "choose an algorithm, generate a key, and resign the issued objects".to_string();
    }

    /// The open certificate's file-name stem (without extension), used to
    /// derive the default key file name.
    fn cert_file_stem(&self) -> String {
        self.path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "key".to_string())
    }

    /// The signed objects in the scanned tree that the open certificate issued,
    /// for the dialog's third column: certificates first (each with its serial
    /// number), then CRLs. Uses the same issuer resolution as the relation
    /// graph.
    fn issued_objects(&self) -> Vec<IssuedObject> {
        let relations = verify::relations_for(&self.signables, &self.path);
        let mut certs = Vec::new();
        let mut crls = Vec::new();
        for edge in &relations.signs {
            let Some(kind) = self
                .signables
                .iter()
                .find(|f| f.path == edge.other)
                .map(|f| f.signable.kind)
            else {
                continue;
            };
            let (detail, bucket) = match kind {
                Kind::Certificate => {
                    let serial = read_cert_der(&edge.other)
                        .and_then(|der| ber::parse_forest(&der, 0).ok())
                        .and_then(|roots| cert_serial_hex(&roots))
                        .unwrap_or_else(|| "?".to_string());
                    (format!("#{}", serial), &mut certs)
                }
                Kind::Crl => ("CRL".to_string(), &mut crls),
            };
            bucket.push(IssuedObject {
                path: edge.other.clone(),
                name: file_name_string(&edge.other),
                detail,
                selected: true,
            });
        }
        certs.sort_by(|a, b| a.name.cmp(&b.name));
        crls.sort_by(|a, b| a.name.cmp(&b.name));
        certs.extend(crls); // certificates first, then CRLs
        certs
    }

    pub fn cancel_pubkey(&mut self) {
        self.mode = Mode::Browse;
        self.status = "public-key modification cancelled".to_string();
    }

    pub fn pubkey_move_column(&mut self, delta: isize) {
        if let Mode::EditPubKey(ref mut s) = self.mode {
            s.move_column(delta);
        }
    }

    pub fn pubkey_move_row(&mut self, delta: isize) {
        let stem = self.cert_file_stem();
        if let Mode::EditPubKey(ref mut s) = self.mode {
            s.move_row(delta, &stem);
        }
    }

    pub fn pubkey_toggle(&mut self) {
        if let Mode::EditPubKey(ref mut s) = self.mode {
            s.toggle();
        }
    }

    pub fn pubkey_insert_char(&mut self, c: char) {
        if let Mode::EditPubKey(ref mut s) = self.mode {
            s.insert_char(c);
        }
    }

    pub fn pubkey_backspace(&mut self) {
        if let Mode::EditPubKey(ref mut s) = self.mode {
            s.backspace();
        }
    }

    /// Confirm the public-key modification: generate a new key pair, optionally
    /// write the private key to a file, replace the certificate's
    /// `subjectPublicKeyInfo` with the new public key (re-signing the
    /// certificate itself when it is self-signed), and resign every selected
    /// issued certificate with the new key.
    pub fn submit_pubkey(&mut self) {
        let Mode::EditPubKey(ref state) = self.mode else { return };
        let alg = state.alg();
        let generate = state.generate;
        let filename = state.filename.clone();
        let password = state.password.clone();
        let selected_issued: Vec<PathBuf> =
            state.issued.iter().filter(|c| c.selected).map(|c| c.path.clone()).collect();

        // Validate the target key file before generating anything.
        let dir = self.path.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        let key_path = dir.join(&filename);
        if generate {
            if filename.trim().is_empty() {
                self.status = "enter a file name for the new private key".to_string();
                return; // stay in the dialog
            }
            if key_path.exists() {
                self.status = format!("{} already exists — choose another name", filename);
                return; // stay in the dialog
            }
        }

        let key = match keygen::generate(alg) {
            Ok(k) => k,
            Err(e) => {
                self.mode = Mode::Browse;
                self.status = e;
                return;
            }
        };

        // Whether the certificate is self-signed under its *current* key, so
        // its own signature must be regenerated with the new key too.
        let self_signed =
            matches!(self.sig_status, Some(SignatureStatus::Verified { self_signed: true, .. }));

        // Write the private-key file, if requested.
        if generate {
            let der = match key.key_file_der(password.as_bytes()) {
                Ok(der) => der,
                Err(e) => {
                    self.mode = Mode::Browse;
                    self.status = e;
                    return;
                }
            };
            if let Err(e) = std::fs::write(&key_path, &der) {
                self.mode = Mode::Browse;
                self.status = format!("could not write {}: {}", filename, e);
                return;
            }
        }

        // Replace the certificate's subjectPublicKeyInfo with the new key.
        if let Err(e) = self.install_new_public_key(&key, alg, self_signed) {
            self.mode = Mode::Browse;
            self.status = format!("could not modify the public key: {}", e);
            return;
        }

        // Resign each selected issued certificate with the new key.
        let mut resigned = 0usize;
        let mut failures = Vec::new();
        for path in &selected_issued {
            match resign_issued_file(path, alg, &key.pkcs8) {
                Ok(()) => resigned += 1,
                Err(e) => failures.push(format!("{}: {}", file_name_string(path), e)),
            }
        }

        // Register the new key so its key↔certificate link and any later
        // re-signing can find it this session.
        if generate {
            self.register_generated_key(&key_path, &key.spki, password.as_bytes());
        }
        self.recompute_browser_relations();

        self.mode = Mode::Browse;
        self.status = self.pubkey_summary(alg, generate, &filename, resigned, &failures, self_signed);
    }

    /// Splice the generated `SubjectPublicKeyInfo` into the open certificate,
    /// re-signing the certificate itself when it is self-signed (so it stays
    /// valid under the new key). Leaves the document dirty for `save`.
    fn install_new_public_key(
        &mut self,
        key: &keygen::GeneratedKey,
        alg: keygen::KeyAlgorithm,
        self_signed: bool,
    ) -> Result<(), String> {
        let paths = cert_paths(&self.roots).ok_or("the open document is not a certificate")?;
        let spki_nodes =
            ber::parse_forest(&key.spki, 0).map_err(|e| format!("bad generated SPKI: {}", e))?;
        let spki_node = spki_nodes.into_iter().next().ok_or("empty generated SPKI")?;
        *node_at_mut(&mut self.roots, &paths.spki).ok_or("SPKI node missing")? = spki_node;

        if self_signed {
            // The self-signature must use the new algorithm and key: update
            // both AlgorithmIdentifiers, then regenerate the signature over
            // the new tbsCertificate.
            let alg_id = ber::parse_forest(&alg.sig_alg_identifier_der(), 0)
                .map_err(|e| format!("bad algorithm identifier: {}", e))?
                .into_iter()
                .next()
                .ok_or("empty algorithm identifier")?;
            *node_at_mut(&mut self.roots, &paths.tbs_sig_alg).ok_or("tbs sigAlg missing")? =
                alg_id.clone();
            *node_at_mut(&mut self.roots, &paths.outer_sig_alg).ok_or("outer sigAlg missing")? =
                alg_id;
            self.dirty = true;
            self.rebuild();

            // Sign the canonical new tbs and install the signature.
            let der = ber::encode_forest(&self.roots);
            let signable =
                x509::parse_signable(&self.roots, &der).ok_or("re-encoded document is not a certificate")?;
            let sig = verify::sign(alg.sig_alg_oid(), &key.pkcs8, &signable.tbs)?;
            let sig_node = node_at_mut(&mut self.roots, &paths.outer_sig).ok_or("signature node missing")?;
            sig_node.value = std::iter::once(0u8).chain(sig).collect();
            sig_node.children.clear();
            sig_node.encapsulates = false;
        }
        self.dirty = true;
        self.rebuild();
        Ok(())
    }

    /// Record a freshly written key file so its key↔certificate link shows and
    /// a later re-sign can use it: plaintext keys join `key_files`; an
    /// encrypted key joins `unlocked_keys` with its password retained. The key
    /// identity is taken from the generated `SubjectPublicKeyInfo`, which
    /// always carries the public key (an Ed25519/EC private key on its own may
    /// not), matching how the certificate side computes it.
    fn register_generated_key(&mut self, path: &Path, spki: &[u8], password: &[u8]) {
        let Some(id) = public_key_id_from_spki(spki) else {
            return;
        };
        if password.is_empty() {
            self.key_files.retain(|k| k.path != path);
            self.key_files.push(x509::KeyFile { path: path.to_path_buf(), key: id });
        } else {
            self.unlocked_keys.retain(|(p, _)| p != path);
            self.unlocked_keys.push((path.to_path_buf(), id));
            self.retained_passwords.set(path.to_path_buf(), password.to_vec());
        }
    }

    /// Compose the status line summarizing what the confirmation did.
    fn pubkey_summary(
        &self,
        alg: keygen::KeyAlgorithm,
        generate: bool,
        filename: &str,
        resigned: usize,
        failures: &[String],
        self_signed: bool,
    ) -> String {
        let key_part = if generate {
            format!("wrote {} key {}", alg.short_name(), filename)
        } else {
            format!("generated a {} key (not saved)", alg.short_name())
        };
        let cert_part = if self_signed {
            "certificate re-signed with the new key"
        } else {
            "certificate's public key replaced"
        };
        let mut summary =
            format!("{}; {}; resigned {} issued object(s)", key_part, cert_part, resigned);
        if !failures.is_empty() {
            summary.push_str(&format!(" ({} failed: {})", failures.len(), failures.join("; ")));
        }
        summary.push_str(" — 's' saves this certificate");
        summary
    }

    pub fn cancel_password(&mut self) {
        self.mode = Mode::Browse;
        self.status = "decryption cancelled".to_string();
    }

    /// Apply the typed password and expose the parsed plaintext as a virtual
    /// subtree below the encrypted-data node. Returns to browse mode either
    /// way.
    pub fn submit_password(&mut self) {
        let Mode::Password(ref state) = self.mode else { return };
        let password = state.buf.clone();
        self.mode = Mode::Browse;
        // Encrypted PKCS#8 key: editable single-region reveal.
        if matches!(pkcs8::parse(&self.roots), Ok(Some(_))) {
            self.submit_pkcs8_password(password);
            return;
        }
        // PKCS#12 container: editable multi-region reveal.
        if matches!(pkcs12::parse(&self.roots), Ok(Some(_))) {
            self.submit_pkcs12_password(&password);
            return;
        }
        self.status = "nothing to decrypt".to_string();
    }

    fn submit_pkcs8_password(&mut self, password: String) {
        let password_bytes = password.as_bytes().to_vec();
        let result = match pkcs8::parse(&self.roots) {
            Ok(Some(enc)) => enc.decrypt(password.as_bytes()).and_then(|plaintext| {
                let roots = ber::parse_forest(&plaintext, 0)
                    .map_err(|e| format!("decrypted ASN.1 could not be parsed: {}", e))?;
                let ident = spec::identify(&self.spec_db, &roots);
                Ok(Decrypted {
                    encrypted_path: enc.encrypted_path,
                    plaintext,
                    roots,
                    password: password.into_bytes(),
                    ident,
                })
            }),
            Ok(None) => Err("not an encrypted private key".to_string()),
            Err(msg) => Err(msg),
        };
        match result {
            Ok(decrypted) => {
                let key = x509::public_key_id_of_private_key(&decrypted.roots);
                self.decrypted = Some(decrypted);
                self.rebuild_rows();
                self.cache_unlocked_keys(key.into_iter().collect());
                self.retained_passwords.set(self.path.clone(), password_bytes);
                self.recompute_browser_relations();
                self.status = "decrypted content is available in the ASN.1 tree".to_string();
            }
            Err(msg) => {
                self.decrypted = None;
                self.status = msg;
            }
        }
    }

    /// Decrypt every supported region of the open PKCS#12 with `password` and
    /// expose the plaintexts as editable virtual subtrees. A single wrong
    /// password fails every region's padding, which reads as a wrong-password
    /// error rather than a partial reveal.
    fn submit_pkcs12_password(&mut self, password: &str) {
        let Ok(Some(p12)) = pkcs12::parse(&self.roots) else {
            self.pkcs12 = None;
            self.status = "not a PKCS#12 container".to_string();
            return;
        };
        let mut regions = Vec::new();
        let mut failed = 0usize;
        for region in &p12.regions {
            match region.decrypt(password.as_bytes()) {
                Ok(plaintext) => {
                    // `decrypt` already confirmed a single SEQUENCE parses.
                    let roots = ber::parse_forest(&plaintext, 0).unwrap_or_default();
                    let ident = spec::identify(&self.spec_db, &roots);
                    regions.push(RevealedRegion {
                        cipher_path: region.cipher_path.clone(),
                        kind: region.kind,
                        roots,
                        ident,
                    });
                }
                Err(_) => failed += 1,
            }
        }
        if regions.is_empty() {
            self.pkcs12 = None;
            self.status = "decryption failed (wrong password?)".to_string();
            return;
        }
        let total = regions.len() + failed;
        let n = regions.len();
        // Remember each shrouded key's public key for the key↔certificate
        // links, so the connection persists after browsing away.
        let keys: Vec<x509::PublicKeyId> = regions
            .iter()
            .filter(|r| r.kind == pkcs12::RegionKind::ShroudedKey)
            .filter_map(|r| x509::public_key_id_of_private_key(&r.roots))
            .collect();
        self.pkcs12 = Some(Pkcs12Reveal {
            password: password.as_bytes().to_vec(),
            regions,
            editable: mac_editable(&p12.mac),
        });
        self.rebuild_rows();
        self.cache_unlocked_keys(keys);
        self.retained_passwords.set(self.path.clone(), password.as_bytes().to_vec());
        self.recompute_browser_relations();
        self.status = if failed == 0 {
            format!(
                "decrypted {} PKCS#12 region{} — shown in the ASN.1 tree",
                n,
                if n == 1 { "" } else { "s" }
            )
        } else {
            format!("decrypted {} of {} PKCS#12 regions ({} could not be decrypted)", n, total, failed)
        };
    }

    /// Re-derive `sig_status` for the current document against `ca_index`,
    /// after first refreshing this file's own entry in `signables`/
    /// `ca_index` from its live (possibly edited, not necessarily saved)
    /// content — replacing whatever was captured for the same path in the
    /// startup directory scan. Without that refresh, editing e.g. a
    /// certificate's signature or subject would leave stale, pre-edit data
    /// in the index: not just this file's own `sig_status` would be wrong,
    /// but so would the browser's relation arrows for any *other* file
    /// that names this one as its issuer — since those are resolved from
    /// the very same index. `recompute_browser_relations` is refreshed
    /// here too, for the same reason. Called after loading a document and
    /// after every edit (`rebuild()`). Not called when no document is
    /// open — `sig_status` just stays `None`, and the index keeps
    /// whatever the startup scan found for this path (there is no live
    /// content to prefer over it).
    fn recompute_sig_status(&mut self) {
        let der = ber::encode_forest(&self.roots);
        let own_signable = x509::parse_signable(&self.roots, &der);

        self.signables.retain(|f| f.path != self.path);
        self.ca_index.retain(|c| c.path != self.path);
        if self.file_open {
            if let Some(signable) = own_signable.clone() {
                let file = SignableFile { path: self.path.clone(), signable };
                self.ca_index.extend(x509::cert_candidates(std::slice::from_ref(&file)));
                self.signables.push(file);
            }
        }

        self.sig_status = own_signable.map(|s| verify::verify_against(&self.ca_index, &s));
        self.refresh_own_key_file();
        self.recompute_path_status();
        self.recompute_browser_relations();
    }

    /// Run OpenSSL certification-path validation for the open document when it
    /// is a certificate: the trust anchors are the certificates the user
    /// marked trusted (`trusted_certs`), and every other certificate in the
    /// scanned tree is offered as an untrusted intermediate. The open
    /// document's own live (possibly edited) content is used as the target and
    /// wherever it also appears in the pool. `None` when no document is open
    /// or it is not a certificate.
    pub fn recompute_path_status(&mut self) {
        let der = ber::encode_forest(&self.roots);
        let is_cert = self.file_open
            && x509::parse_signable(&self.roots, &der)
                .map(|s| s.kind == Kind::Certificate)
                .unwrap_or(false);
        if !is_cert {
            self.path_status = None;
            return;
        }
        let mut trusted = Vec::new();
        let mut untrusted = Vec::new();
        for file in &self.signables {
            if file.signable.kind != Kind::Certificate {
                continue;
            }
            // Prefer the live content for the open document; read the rest.
            let cert_der = if file.path == self.path {
                der.clone()
            } else {
                match read_cert_der(&file.path) {
                    Some(bytes) => bytes,
                    None => continue,
                }
            };
            if self.trusted_certs.contains(&file.path) {
                trusted.push(cert_der);
            } else {
                untrusted.push(cert_der);
            }
        }
        self.path_status = Some(pathval::validate(&der, &trusted, &untrusted));
    }

    /// `t`: toggle whether the certificate selected in the browser is a trust
    /// anchor for path validation, then re-validate the open document.
    pub fn toggle_trust(&mut self) {
        let Some(entry) = self.browser.selected_entry() else { return };
        if entry.is_dir {
            self.status = "only a certificate can be marked trusted".to_string();
            return;
        }
        let path = entry.path.clone();
        let name = entry.name.clone();
        let is_cert = self
            .signables
            .iter()
            .any(|f| f.path == path && f.signable.kind == Kind::Certificate);
        if !is_cert {
            self.status = format!("{} is not a certificate — cannot mark it trusted", name);
            return;
        }
        if self.trusted_certs.remove(&path) {
            self.status = format!("{} is no longer trusted", name);
        } else {
            self.trusted_certs.insert(path);
            self.status = format!("{} marked as trusted", name);
        }
        self.recompute_path_status();
    }

    /// Refresh this file's own entry in `key_files` from its live (possibly
    /// edited, unsaved) content — the key-file analog of the `signables`
    /// refresh above. A plaintext key edited to no longer be a valid key
    /// (its scalar corrupted, or its structure broken) loses its entry, so
    /// its key↔certificate link disappears; a key whose public key changed
    /// gets the new identity. Encrypted keys are never in `key_files`.
    fn refresh_own_key_file(&mut self) {
        self.key_files.retain(|k| k.path != self.path);
        if self.file_open {
            if let Some(key) = usable_key_id(&self.roots) {
                self.key_files.push(x509::KeyFile { path: self.path.clone(), key });
            }
        }
    }

    /// Live-preview the file currently highlighted in the browser into the
    /// tree/content panes, without requiring Enter. Called after every
    /// browser navigation key. A no-op for directories, for the file
    /// that's already loaded, and — to avoid silently discarding work —
    /// while the current document has unsaved changes (in which case
    /// `activate_browser_entry`'s confirmation dance is still required).
    pub fn preview_browser_selection(&mut self) {
        let Some(entry) = self.browser.selected_entry() else { return };
        if entry.is_dir {
            return;
        }
        let path = entry.path.clone();
        if self.file_open && (self.path == path || self.dirty) {
            return;
        }
        if let Err(e) = self.open_file(path.clone()) {
            self.status = format!("cannot preview {}: {}", path.display(), e);
        }
    }

    /// Enter/Space on the selected browser row: fold a directory, or
    /// switch focus to the document panes for a file. Since browser
    /// navigation already live-previews files (`preview_browser_selection`),
    /// the common case is just a focus switch; loading here only happens
    /// when the previewed file was skipped because of unsaved changes, in
    /// which case a first Enter arms a discard confirmation (mirroring
    /// `delete_selected`'s two-step pattern) and a second one loads.
    pub fn activate_browser_entry(&mut self) {
        let Some(entry) = self.browser.selected_entry() else { return };
        if entry.is_dir {
            self.browser.toggle_expand();
            return;
        }
        let path = entry.path.clone();
        if self.file_open && self.path == path {
            self.open_confirm = false;
            self.focus = Focus::Document;
            return;
        }
        if self.file_open && self.dirty && !self.open_confirm {
            self.open_confirm = true;
            self.status = format!(
                "unsaved changes — press Enter again to discard them and open {}",
                path.display()
            );
            return;
        }
        self.open_confirm = false;
        match self.open_file(path.clone()) {
            Ok(()) => self.focus = Focus::Document,
            Err(e) => self.status = format!("cannot open {}: {}", path.display(), e),
        }
    }

    /// Install the specification database and identify the document.
    pub fn set_spec_db(&mut self, db: SpecDb) {
        self.spec_db = db;
        self.identify();
        if let Some(ref ident) = self.ident {
            self.status = format!(
                "{} — identified as {} ({})",
                self.status, ident.type_name, ident.source
            );
        }
    }

    fn identify(&mut self) {
        self.ident = spec::identify(&self.spec_db, &self.roots);
        if let Some(ref mut decrypted) = self.decrypted {
            decrypted.ident = spec::identify(&self.spec_db, &decrypted.roots);
        }
        if let Some(ref mut reveal) = self.pkcs12 {
            for region in &mut reveal.regions {
                region.ident = spec::identify(&self.spec_db, &region.roots);
            }
        }
    }

    /// Spec label of the node at `path`, if the document was identified.
    pub fn label_at(&self, path: &[usize]) -> Option<&Label> {
        self.ident.as_ref().and_then(|i| i.labels.get(path))
    }

    pub fn label_for_row(&self, row: &Row) -> Option<&Label> {
        match row.source {
            RowSource::Document => self.label_at(&row.path),
            RowSource::Decrypted => self
                .decrypted
                .as_ref()
                .and_then(|d| d.ident.as_ref())
                .and_then(|i| i.labels.get(&row.path)),
            RowSource::DecryptedPlaceholder => None,
            RowSource::Pkcs12Revealed(idx) => self
                .pkcs12
                .as_ref()
                .and_then(|p| p.regions.get(idx))
                .and_then(|r| r.ident.as_ref())
                .and_then(|i| i.labels.get(&row.path)),
        }
    }

    pub fn node_at(&self, path: &[usize]) -> Option<&Node> {
        node_at(&self.roots, path)
    }

    pub fn node_for_row(&self, row: &Row) -> Option<&Node> {
        match row.source {
            RowSource::Document => node_at(&self.roots, &row.path),
            RowSource::Decrypted => {
                node_at(&self.decrypted.as_ref()?.roots, &row.path)
            }
            RowSource::DecryptedPlaceholder => None,
            RowSource::Pkcs12Revealed(idx) => {
                node_at(&self.pkcs12.as_ref()?.regions.get(idx)?.roots, &row.path)
            }
        }
    }

    pub fn selected_node(&self) -> Option<&Node> {
        let row = self.rows.get(self.selected)?;
        self.node_for_row(row)
    }

    pub fn selected_node_mut(&mut self) -> Option<&mut Node> {
        let row = self.rows.get(self.selected)?.clone();
        match row.source {
            RowSource::Document => node_at_mut(&mut self.roots, &row.path),
            RowSource::Decrypted => {
                node_at_mut(&mut self.decrypted.as_mut()?.roots, &row.path)
            }
            RowSource::DecryptedPlaceholder => None,
            RowSource::Pkcs12Revealed(idx) => {
                node_at_mut(&mut self.pkcs12.as_mut()?.regions.get_mut(idx)?.roots, &row.path)
            }
        }
    }

    pub fn rebuild_rows(&mut self) {
        let mut rows = Vec::new();
        let encrypted_path = pkcs8::parse(&self.roots)
            .ok()
            .flatten()
            .map(|enc| enc.encrypted_path);
        for (i, node) in self.roots.iter().enumerate() {
            collect_rows(node, vec![i], 0, RowSource::Document, &mut rows);
        }
        // A PKCS#8 encrypted key (handled by the `encrypted_path` branch) and
        // a PKCS#12 container (handled below) are mutually exclusive.
        let is_pkcs8 = encrypted_path.is_some();
        if let Some(encrypted_path) = encrypted_path {
            if let Some(encrypted_row) = rows.iter().position(|r| {
                r.source == RowSource::Document && r.path == encrypted_path
            }) {
                let depth = rows[encrypted_row].depth + 1;
                let mut virtual_rows = Vec::new();
                if let Some(decrypted) = &self.decrypted {
                    for (i, node) in decrypted.roots.iter().enumerate() {
                        collect_rows(
                            node,
                            vec![i],
                            depth,
                            RowSource::Decrypted,
                            &mut virtual_rows,
                        );
                    }
                } else {
                    virtual_rows.push(Row {
                        path: encrypted_path,
                        depth,
                        source: RowSource::DecryptedPlaceholder,
                    });
                }
                rows.splice(encrypted_row + 1..encrypted_row + 1, virtual_rows);
            }
        }
        if let Some(reveal) = &self.pkcs12 {
            // Splice each region's read-only plaintext below its ciphertext
            // node. Insert from the bottom up so earlier splice positions are
            // not shifted by later ones.
            let mut inserts: Vec<(usize, Vec<Row>)> = Vec::new();
            for (idx, region) in reveal.regions.iter().enumerate() {
                let Some(cipher_row) = rows.iter().position(|r| {
                    r.source == RowSource::Document && r.path == region.cipher_path
                }) else {
                    continue;
                };
                let depth = rows[cipher_row].depth + 1;
                let mut region_rows = Vec::new();
                for (i, node) in region.roots.iter().enumerate() {
                    collect_rows(node, vec![i], depth, RowSource::Pkcs12Revealed(idx), &mut region_rows);
                }
                inserts.push((cipher_row + 1, region_rows));
            }
            inserts.sort_by(|a, b| b.0.cmp(&a.0));
            for (at, region_rows) in inserts {
                rows.splice(at..at, region_rows);
            }
        } else if !is_pkcs8 {
            // Not yet decrypted: if this is a PKCS#12 container, show the
            // same closed-lock placeholder below each encrypted region that a
            // locked PKCS#8 `encryptedData` node shows.
            if let Ok(Some(p12)) = pkcs12::parse(&self.roots) {
                let mut inserts: Vec<(usize, Row)> = Vec::new();
                for region in &p12.regions {
                    if let Some(cipher_row) = rows.iter().position(|r| {
                        r.source == RowSource::Document && r.path == region.cipher_path
                    }) {
                        inserts.push((
                            cipher_row + 1,
                            Row {
                                path: region.cipher_path.clone(),
                                depth: rows[cipher_row].depth + 1,
                                source: RowSource::DecryptedPlaceholder,
                            },
                        ));
                    }
                }
                inserts.sort_by(|a, b| b.0.cmp(&a.0));
                for (at, row) in inserts {
                    rows.insert(at, row);
                }
            }
        }
        self.rows = rows;
        if self.selected >= self.rows.len() {
            self.selected = self.rows.len().saturating_sub(1);
        }
        self.tree_state.select(Some(self.selected));
    }

    pub fn select(&mut self, index: usize) {
        self.selected = index.min(self.rows.len().saturating_sub(1));
        self.tree_state.select(Some(self.selected));
        self.content_scroll = 0;
    }

    pub fn move_by(&mut self, delta: isize) {
        let i = self.selected as isize + delta;
        self.select(i.clamp(0, self.rows.len() as isize - 1) as usize);
    }

    pub fn toggle_expand(&mut self) {
        if let Some(node) = self.selected_node_mut() {
            if node.has_children() {
                node.expanded = !node.expanded;
                self.rebuild_rows();
            }
        }
    }

    /// Left arrow: collapse the node, or move to its parent when already
    /// collapsed (or a leaf).
    pub fn collapse_or_parent(&mut self) {
        let Some(row) = self.rows.get(self.selected).cloned() else { return };
        let collapsible = self
            .selected_node()
            .map(|n| n.has_children() && n.expanded)
            .unwrap_or(false);
        if collapsible {
            if let Some(node) = self.selected_node_mut() {
                node.expanded = false;
            }
            self.rebuild_rows();
        } else if row.source == RowSource::DecryptedPlaceholder {
            if let Some(i) = self.rows.iter().position(|r| {
                r.source == RowSource::Document && r.path == row.path
            }) {
                self.select(i);
            }
        } else if row.path.len() > 1 {
            let parent = &row.path[..row.path.len() - 1];
            if let Some(i) = self.rows.iter().position(|r| {
                r.source == row.source && r.path == parent
            }) {
                self.select(i);
            }
        } else if row.source == RowSource::Decrypted {
            if let Some(encrypted_path) = self.decrypted.as_ref().map(|d| &d.encrypted_path) {
                if let Some(i) = self.rows.iter().position(|r| {
                    r.source == RowSource::Document && &r.path == encrypted_path
                }) {
                    self.select(i);
                }
            }
        } else if let RowSource::Pkcs12Revealed(idx) = row.source {
            // A region root collapses to its outer ciphertext node.
            if let Some(cipher_path) =
                self.pkcs12.as_ref().and_then(|p| p.regions.get(idx)).map(|r| r.cipher_path.clone())
            {
                if let Some(i) = self.rows.iter().position(|r| {
                    r.source == RowSource::Document && r.path == cipher_path
                }) {
                    self.select(i);
                }
            }
        }
    }

    /// Right arrow: expand the node, or move to its first child when
    /// already expanded.
    pub fn expand_or_child(&mut self) {
        let expandable = self
            .selected_node()
            .map(|n| n.has_children() && !n.expanded)
            .unwrap_or(false);
        if expandable {
            if let Some(node) = self.selected_node_mut() {
                node.expanded = true;
            }
            self.rebuild_rows();
        } else if self
            .selected_node()
            .map(|n| n.has_children())
            .unwrap_or(false)
        {
            self.select(self.selected + 1);
        }
    }

    /// Editing actions on a PKCS#12 revealed row bail out with a message
    /// when the edited region could not be re-encrypted into a consistent
    /// file (the container's MAC cannot be recomputed). Returns `true`
    /// (having set the status) when the edit must be refused.
    fn reject_uneditable_reveal(&mut self) -> bool {
        if !matches!(
            self.rows.get(self.selected).map(|r| r.source),
            Some(RowSource::Pkcs12Revealed(_))
        ) {
            return false;
        }
        match self.pkcs12.as_ref().map(|p| p.editable.clone()) {
            Some(Err(reason)) => {
                self.status = format!("decrypted PKCS#12 content is read-only — {}", reason);
                true
            }
            _ => false,
        }
    }

    pub fn start_edit(&mut self) {
        if self.reject_uneditable_reveal() {
            return;
        }
        let Some(node) = self.selected_node() else { return };
        self.mode = Mode::Edit(EditState::hex(EditKind::Content, &node.content_octets()));
        self.status =
            "editing content octets — type hex digits, Enter applies, Esc cancels".to_string();
    }

    /// 'E' opens the edit-mode menu for the selected element.
    pub fn open_edit_menu(&mut self) {
        if self.reject_uneditable_reveal() {
            return;
        }
        if self.selected_node().is_none() {
            return;
        }
        let mut items: Vec<MenuItem> = EDIT_MENU
            .iter()
            .map(|&(action, label, desc)| MenuItem { action, label, desc })
            .collect();
        // On a certificate's subjectPublicKeyInfo, offer to re-key the cert.
        if self.selection_is_cert_spki() {
            items.push(MenuItem {
                action: MenuAction::Rekey,
                label: "Re-key this cert",
                desc: "new key pair; resign the objects this certificate issued",
            });
        }
        self.mode =
            Mode::EditMenu(MenuState { title: " EDIT — choose editing mode ", items, selected: 0 });
        self.status = "choose how to edit the selected element".to_string();
    }

    /// 'z' on a certificate or CRL: offer the cryptographic adjustments —
    /// re-signing and (for a certificate) re-keying — as a small menu.
    fn start_crypto_menu(&mut self) {
        let der = ber::encode_forest(&self.roots);
        let Some(signable) = x509::parse_signable(&self.roots, &der) else {
            self.status = "not an encrypted key, PKCS#12, certificate or CRL".to_string();
            return;
        };
        let mut items = vec![MenuItem {
            action: MenuAction::Resign,
            label: "Re-sign",
            desc: "regenerate the signature with the issuer's key",
        }];
        if signable.kind == Kind::Certificate {
            items.push(MenuItem {
                action: MenuAction::Rekey,
                label: "Re-key",
                desc: "new key pair; resign the objects this certificate issued",
            });
        }
        self.mode =
            Mode::EditMenu(MenuState { title: " CRYPTOGRAPHIC ADJUSTMENT ", items, selected: 0 });
        self.status = "choose a cryptographic adjustment".to_string();
    }

    pub fn cancel_menu(&mut self) {
        self.mode = Mode::Browse;
        self.status = "cancelled".to_string();
    }

    pub fn menu_move(&mut self, delta: isize) {
        if let Mode::EditMenu(ref mut m) = self.mode {
            let n = m.items.len().max(1) as isize;
            m.selected = (m.selected as isize + delta).rem_euclid(n) as usize;
        }
    }

    pub fn menu_confirm(&mut self) {
        let Mode::EditMenu(ref m) = self.mode else { return };
        let Some(action) = m.items.get(m.selected).map(|i| i.action) else { return };
        match action {
            MenuAction::Retag => self.start_retag(),
            MenuAction::EditHex => self.start_edit(),
            MenuAction::EditBase64 => self.start_edit_base64(),
            MenuAction::EditRaw => self.start_edit_raw(),
            MenuAction::EditTypeSpecific => self.start_edit_type_specific(),
            MenuAction::Rekey => self.start_rekey(),
            MenuAction::Resign => self.start_resign(),
        }
    }

    fn start_edit_base64(&mut self) {
        let Some(node) = self.selected_node() else { return };
        let initial = input::b64_encode(&node.content_octets());
        self.mode = Mode::Edit(EditState {
            kind: EditKind::Content,
            editor: Editor::text(TextFormat::Base64, initial),
        });
        self.status = "editing content octets as base64 — Enter applies".to_string();
    }

    fn start_edit_raw(&mut self) {
        let Some(node) = self.selected_node() else { return };
        let content = node.content_octets();
        let (initial, note) = match String::from_utf8(content) {
            Ok(s) => (s, ""),
            Err(_) => (
                String::new(),
                " (current value is not text, so the editor starts empty)",
            ),
        };
        self.mode = Mode::Edit(EditState {
            kind: EditKind::Content,
            editor: Editor::text(TextFormat::Raw, initial),
        });
        self.status = format!(
            "raw edit: typed/pasted characters become the value bytes{}",
            note
        );
    }

    /// The "type specific" edit mode ('e' and the corresponding menu
    /// entry): pick the most natural editor for the selected element's
    /// universal type. For NULL and constructed elements there is no
    /// single natural value; a status message is shown and the mode is
    /// left unchanged (browse or menu).
    pub fn start_edit_type_specific(&mut self) {
        if self.reject_uneditable_reveal() {
            return;
        }
        let Some(node) = self.selected_node() else { return };
        if node.constructed {
            self.status =
                "constructed elements have no single value — use hex/base64 or edit the children"
                    .to_string();
            return; // stay in the menu
        }
        let v = &node.value;
        let (editor, hint) = if node.class != Class::Universal {
            (Editor::hex(v), "no type information for this tag — editing as hex")
        } else {
            match node.tag {
                ber::TAG_NULL => {
                    self.status = "NULL has an empty value — nothing to edit".to_string();
                    return; // stay in the menu
                }
                ber::TAG_INTEGER | ber::TAG_ENUMERATED => {
                    let initial = ber::integer_decimal(v).unwrap_or_default();
                    (Editor::text(TextFormat::Integer, initial), "enter a decimal integer")
                }
                9 => (
                    Editor::text(TextFormat::Real, String::new()),
                    "enter a decimal number (e.g. 3.14, -2.5E3, inf)",
                ),
                ber::TAG_OID => {
                    let initial = ber::oid_arcs(v)
                        .map(|arcs| {
                            arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".")
                        })
                        .unwrap_or_default();
                    (Editor::text(TextFormat::Oid, initial), "enter the OID in dot notation")
                }
                ber::TAG_BOOLEAN => {
                    let initial =
                        if v.first().copied().unwrap_or(0) == 0 { "FALSE" } else { "TRUE" };
                    (
                        Editor::text(TextFormat::Boolean, initial.to_string()),
                        "enter TRUE or FALSE",
                    )
                }
                ber::TAG_UTC_TIME | ber::TAG_GENERALIZED_TIME => {
                    let generalized = node.tag == ber::TAG_GENERALIZED_TIME;
                    (
                        Editor::DateTime(datetime_from_value(v, generalized)),
                        "fill in the date/time fields",
                    )
                }
                28 => (
                    Editor::text(TextFormat::Text(StrEncoding::Utf32Be), decode_utf32be(v)),
                    "enter text (stored as UCS-4)",
                ),
                30 => (
                    Editor::text(TextFormat::Text(StrEncoding::Utf16Be), decode_utf16be(v)),
                    "enter text (stored as UCS-2)",
                ),
                7 | ber::TAG_UTF8_STRING | 18..=22 | 25..=27 => (
                    Editor::text(
                        TextFormat::Text(StrEncoding::Utf8),
                        String::from_utf8_lossy(v).into_owned(),
                    ),
                    "enter text",
                ),
                _ => (Editor::hex(v), "no natural form for this type — editing as hex"),
            }
        };
        self.mode = Mode::Edit(EditState { kind: EditKind::Content, editor });
        self.status = format!("{} — Enter applies, Esc cancels", hint);
    }

    /// 'i' inserts after the selected element; 'I' (`as_child`) inserts as
    /// the first child of the selected constructed element. Both open the
    /// type-picker dialog; the value is typed afterwards.
    pub fn start_insert(&mut self, as_child: bool) {
        if !self.file_open {
            self.status = "no file open — select one in the browser first".to_string();
            return;
        }
        let (parent, index, source) = if self.rows.is_empty() {
            (Vec::new(), 0, RowSource::Document) // empty document: insert the first top-level element
        } else {
            let row = self.rows[self.selected].clone();
            if row.source == RowSource::DecryptedPlaceholder {
                self.status = "decrypt the content before editing it".to_string();
                return;
            }
            if self.reject_uneditable_reveal() {
                return;
            }
            let path = row.path;
            if as_child {
                let Some(node) = self.selected_node() else { return };
                if !node.constructed && !node.encapsulates {
                    self.status =
                        "cannot insert a child into a primitive element (use 'i' for a sibling)"
                            .to_string();
                    return;
                }
                (path, 0, row.source)
            } else {
                let (last, parent) = path.split_last().expect("row paths are non-empty");
                if row.source == RowSource::Decrypted && parent.is_empty() {
                    self.status =
                        "a decrypted PKCS#8 value must remain one top-level SEQUENCE".to_string();
                    return;
                }
                if matches!(row.source, RowSource::Pkcs12Revealed(_)) && parent.is_empty() {
                    self.status =
                        "a decrypted PKCS#12 region must remain one top-level SEQUENCE".to_string();
                    return;
                }
                (parent.to_vec(), last + 1, row.source)
            }
        };
        self.mode =
            Mode::TypePicker(PickerState::new(PickerTarget::Insert { parent, index, source }));
        self.status = "choose the type of the new element".to_string();
    }

    /// 'E' opens the type-picker dialog for the selected element,
    /// pre-populated with its current type; confirming changes the
    /// identifier octets while keeping the content octets.
    pub fn start_retag(&mut self) {
        let Some(row) = self.rows.get(self.selected) else { return };
        if row.source == RowSource::DecryptedPlaceholder {
            self.status = "decrypt the content before editing it".to_string();
            return;
        }
        if self.reject_uneditable_reveal() {
            return;
        }
        let Some(row) = self.rows.get(self.selected) else { return };
        let path = row.path.clone();
        let source = row.source;
        let Some(node) = self.selected_node() else { return };
        let mut p = PickerState::new(PickerTarget::Retag { path, source });
        p.class_idx = PICKER_CLASSES
            .iter()
            .position(|(_, c)| *c == node.class)
            .unwrap_or(0);
        p.form_idx = usize::from(node.constructed);
        if node.class == Class::Universal {
            p.univ_idx = PICKER_UNIVERSAL
                .iter()
                .position(|(t, _)| *t == node.tag)
                .unwrap_or(0);
        } else {
            p.tag_digits = node.tag.to_string();
        }
        let name = node.type_name();
        self.mode = Mode::TypePicker(p);
        self.status = format!("change type of {} — the value bytes are kept", name);
    }

    pub fn cancel_picker(&mut self) {
        self.mode = Mode::Browse;
        self.status = "cancelled".to_string();
    }

    /// Move between picker columns (class / form / tag).
    pub fn picker_move_column(&mut self, delta: isize) {
        if let Mode::TypePicker(ref mut p) = self.mode {
            p.column = (p.column as isize + delta).rem_euclid(3) as usize;
        }
    }

    /// Move the selection inside the active picker column.
    pub fn picker_move_selection(&mut self, delta: isize) {
        let Mode::TypePicker(ref mut p) = self.mode else { return };
        let step = |v: usize, max: usize| -> usize {
            (v as isize + delta).clamp(0, max as isize - 1) as usize
        };
        match p.column {
            0 => p.class_idx = step(p.class_idx, PICKER_CLASSES.len()),
            1 => p.form_idx = step(p.form_idx, 2),
            _ => {
                if p.class() == Class::Universal {
                    p.univ_idx = step(p.univ_idx, PICKER_UNIVERSAL.len());
                } else {
                    // Up/down also adjusts the numeric tag.
                    let tag = (p.tag_digits.parse::<i64>().unwrap_or(0) + delta as i64).max(0);
                    p.tag_digits = tag.to_string();
                }
            }
        }
    }

    /// Digit input for the tag-number field (non-universal classes).
    pub fn picker_digit(&mut self, c: char) {
        if let Mode::TypePicker(ref mut p) = self.mode {
            if p.class() != Class::Universal && p.tag_digits.len() < 8 {
                p.tag_digits.push(c);
                p.column = 2;
            }
        }
    }

    pub fn picker_backspace(&mut self) {
        if let Mode::TypePicker(ref mut p) = self.mode {
            p.tag_digits.pop();
        }
    }

    /// Enter in the picker: proceed to value entry (insert) or apply the
    /// new type to the existing element (retag).
    pub fn picker_confirm(&mut self) {
        let Mode::TypePicker(ref p) = self.mode else { return };
        let (class, constructed, tag) = (p.class(), p.constructed(), p.tag());
        match p.target.clone() {
            PickerTarget::Insert { parent, index, source } => {
                let kind = EditKind::Insert { parent, index, class, constructed, tag, source };
                self.mode = Mode::Edit(EditState::hex(kind, &[]));
                self.status = format!(
                    "value for new {} — hex content octets (may stay empty), Enter inserts",
                    ber::type_name_of(class, tag),
                );
            }
            PickerTarget::Retag { path, source } => {
                self.apply_retag(&path, source, class, constructed, tag)
            }
        }
    }

    /// Give the element at `path` a new identifier (class/form/tag). The
    /// content octets are preserved; when switching to constructed form
    /// they must parse as a TLV series.
    fn apply_retag(
        &mut self,
        path: &[usize],
        source: RowSource,
        class: Class,
        constructed: bool,
        tag: u32,
    ) {
        if matches!(source, RowSource::Decrypted | RowSource::Pkcs12Revealed(_))
            && path.len() == 1
            && (class != Class::Universal || tag != ber::TAG_SEQUENCE || !constructed)
        {
            self.status = "the decrypted root must remain a SEQUENCE".to_string();
            return;
        }
        let roots = match source {
            RowSource::Document => &mut self.roots,
            RowSource::Decrypted => {
                let Some(decrypted) = self.decrypted.as_mut() else { return };
                &mut decrypted.roots
            }
            RowSource::Pkcs12Revealed(idx) => {
                let Some(region) =
                    self.pkcs12.as_mut().and_then(|p| p.regions.get_mut(idx))
                else {
                    return;
                };
                &mut region.roots
            }
            RowSource::DecryptedPlaceholder => return,
        };
        let Some(node) = node_at_mut(roots, path) else { return };
        if node.class == class && node.constructed == constructed && node.tag == tag {
            self.mode = Mode::Browse;
            self.status = "type unchanged".to_string();
            return;
        }
        let content = node.content_octets();
        if constructed {
            match ber::parse_forest(&content, 0) {
                Ok(children) => {
                    node.children = children;
                    node.value.clear();
                }
                Err(e) => {
                    // Stay in the picker so another choice can be made.
                    self.status = format!(
                        "cannot switch to constructed: content is not valid ASN.1 ({})",
                        e
                    );
                    return;
                }
            }
        } else {
            node.value = content;
            node.children.clear();
        }
        node.encapsulates = false; // re-detected during rebuild()
        node.class = class;
        node.constructed = constructed;
        node.tag = tag;
        self.mode = Mode::Browse;
        self.dirty = true;
        self.rebuild();
        self.status = format!(
            "type changed to {} — 's' writes the file",
            ber::type_name_of(class, tag)
        );
    }

    /// Move the selected element up (-1) or down (+1) among its siblings.
    pub fn move_selected(&mut self, delta: isize) {
        let Some(row) = self.rows.get(self.selected).cloned() else { return };
        if row.source == RowSource::DecryptedPlaceholder {
            self.status = "decrypt the content before editing it".to_string();
            return;
        }
        if self.reject_uneditable_reveal() {
            return;
        }
        let (&last, parent) = row.path.split_last().expect("row paths are non-empty");
        let roots = match row.source {
            RowSource::Document => &mut self.roots,
            RowSource::Decrypted => {
                let Some(decrypted) = self.decrypted.as_mut() else { return };
                &mut decrypted.roots
            }
            RowSource::Pkcs12Revealed(idx) => {
                let Some(region) =
                    self.pkcs12.as_mut().and_then(|p| p.regions.get_mut(idx))
                else {
                    return;
                };
                &mut region.roots
            }
            RowSource::DecryptedPlaceholder => unreachable!(),
        };
        let sibling_count = if parent.is_empty() {
            roots.len()
        } else {
            node_at(roots, parent).map(|p| p.children.len()).unwrap_or(0)
        };
        let target = last as isize + delta;
        if target < 0 || target >= sibling_count as isize {
            self.status = "element is already at the edge of its parent".to_string();
            return;
        }
        let target = target as usize;
        if parent.is_empty() {
            roots.swap(last, target);
        } else if let Some(p) = node_at_mut(roots, parent) {
            p.children.swap(last, target);
        }
        self.dirty = true;
        self.rebuild();
        let mut new_path = parent.to_vec();
        new_path.push(target);
        if let Some(i) = self
            .rows
            .iter()
            .position(|r| r.source == row.source && r.path == new_path)
        {
            self.select(i);
        }
        self.status = "element moved — 's' writes the file".to_string();
    }

    /// Delete the selected element (two-step: the first call only arms the
    /// confirmation, the second call within the same selection deletes).
    pub fn delete_selected(&mut self) {
        let Some(row) = self.rows.get(self.selected).cloned() else { return };
        if row.source == RowSource::DecryptedPlaceholder {
            self.status = "decrypt the content before editing it".to_string();
            return;
        }
        if self.reject_uneditable_reveal() {
            return;
        }
        if matches!(row.source, RowSource::Decrypted | RowSource::Pkcs12Revealed(_))
            && row.path.len() == 1
        {
            self.status = "the decrypted root cannot be deleted".to_string();
            return;
        }
        if !self.delete_confirm {
            self.delete_confirm = true;
            self.status = format!(
                "delete {} at offset {}? press d again to confirm",
                self.selected_node().map(|n| n.type_name()).unwrap_or_default(),
                self.selected_node().map(|n| n.offset).unwrap_or_default(),
            );
            return;
        }
        self.delete_confirm = false;
        let (&last, parent) = row.path.split_last().expect("row paths are non-empty");
        let roots = match row.source {
            RowSource::Document => &mut self.roots,
            RowSource::Decrypted => {
                let Some(decrypted) = self.decrypted.as_mut() else { return };
                &mut decrypted.roots
            }
            RowSource::Pkcs12Revealed(idx) => {
                let Some(region) =
                    self.pkcs12.as_mut().and_then(|p| p.regions.get_mut(idx))
                else {
                    return;
                };
                &mut region.roots
            }
            RowSource::DecryptedPlaceholder => unreachable!(),
        };
        if parent.is_empty() {
            roots.remove(last);
        } else if let Some(p) = node_at_mut(roots, parent) {
            p.children.remove(last);
        }
        self.dirty = true;
        self.rebuild();
        self.status = if self.rows.is_empty() {
            "element deleted — document is now empty ('i' inserts, 's' writes)".to_string()
        } else {
            "element deleted — 's' writes the file".to_string()
        };
    }

    pub fn cancel_edit(&mut self) {
        self.mode = Mode::Browse;
        self.status = "edit cancelled".to_string();
    }

    pub fn commit_edit(&mut self) {
        let Mode::Edit(ref edit) = self.mode else { return };
        let bytes = match edit.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                self.status = e;
                return;
            }
        };

        if matches!(&edit.kind, EditKind::Insert { .. }) {
            self.commit_insert(&bytes, edit.kind.clone());
            return;
        }

        let Some(node) = self.selected_node_mut() else { return };
        if node.constructed {
            // The content of a constructed node must itself be a valid
            // series of TLV items, otherwise the tree could not represent it.
            match ber::parse_forest(&bytes, 0) {
                Ok(children) => {
                    node.children = children;
                    node.value.clear();
                }
                Err(e) => {
                    self.status = format!("rejected: constructed content must be valid ASN.1 ({})", e);
                    return;
                }
            }
        } else {
            // Primitive: the bytes become the content octets verbatim (for
            // BIT STRING including the unused-bits octet). Encapsulation is
            // re-detected during the rebuild below.
            node.value = bytes;
            node.children.clear();
            node.encapsulates = false;
        }

        self.mode = Mode::Browse;
        self.dirty = true;
        self.rebuild();
        self.status = "value updated — 's' writes the file".to_string();
    }

    /// Apply an `EditKind::Insert` edit: build the new element from the
    /// picked type and the typed content octets, and splice it into
    /// `parent` at `index`. Identifier and length octets are generated by
    /// the encoder; the length is derived from the value automatically.
    fn commit_insert(
        &mut self,
        bytes: &[u8],
        kind: EditKind,
    ) {
        let EditKind::Insert { parent, index, class, constructed, tag, source } = kind else {
            return;
        };
        let mut node = Node {
            class,
            tag,
            constructed,
            indefinite: false,
            offset: 0,      // recomputed by rebuild()
            header_len: 0,  // recomputed by rebuild()
            content_len: bytes.len(),
            value: Vec::new(),
            children: Vec::new(),
            encapsulates: false,
            expanded: true,
        };
        if constructed {
            match ber::parse_forest(bytes, 0) {
                Ok(children) => node.children = children,
                Err(e) => {
                    self.status = format!(
                        "rejected: content of a constructed element must be valid ASN.1 ({})",
                        e
                    );
                    return;
                }
            }
        } else {
            node.value = bytes.to_vec();
        }
        let roots = match source {
            RowSource::Document => &mut self.roots,
            RowSource::Decrypted => {
                let Some(decrypted) = self.decrypted.as_mut() else { return };
                &mut decrypted.roots
            }
            RowSource::Pkcs12Revealed(idx) => {
                let Some(region) =
                    self.pkcs12.as_mut().and_then(|p| p.regions.get_mut(idx))
                else {
                    return;
                };
                &mut region.roots
            }
            RowSource::DecryptedPlaceholder => return,
        };
        if parent.is_empty() {
            roots.insert(index, node);
        } else {
            let Some(p) = node_at_mut(roots, &parent) else { return };
            p.children.insert(index, node);
            p.expanded = true; // make the insertion visible
        }
        self.mode = Mode::Browse;
        self.dirty = true;
        self.rebuild();
        let mut path = parent;
        path.push(index);
        if let Some(i) = self
            .rows
            .iter()
            .position(|r| r.source == source && r.path == path)
        {
            self.select(i);
        }
        self.status = format!(
            "inserted {} — 's' writes the file",
            ber::type_name_of(class, tag)
        );
    }

    /// Re-encode the whole tree and re-parse it so that every offset,
    /// length and encapsulation flag is consistent again after an edit.
    pub fn rebuild(&mut self) {
        let selection = self
            .rows
            .get(self.selected)
            .map(|r| (r.source, r.path.clone()));

        match selection.as_ref().map(|(source, _)| *source) {
            Some(RowSource::Decrypted) => {
                if let Err(e) = self.encrypt_decrypted_tree() {
                    self.status = format!("could not update encrypted content: {}", e);
                    return;
                }
            }
            Some(RowSource::Pkcs12Revealed(idx)) => {
                if let Err(e) = self.encrypt_pkcs12_region(idx) {
                    self.status = format!("could not update encrypted content: {}", e);
                    return;
                }
            }
            _ => {}
        }

        let data = ber::encode_forest(&self.roots);
        self.total_len = data.len();
        match ber::parse_forest(&data, 0) {
            Ok(mut new_roots) => {
                copy_expanded(&self.roots, &mut new_roots);
                self.roots = new_roots;
            }
            Err(e) => {
                // Should be unreachable: our own encoder output always parses.
                self.status = format!("internal error: re-parse failed ({})", e);
            }
        }
        if selection.as_ref().map(|(source, _)| *source) == Some(RowSource::Document) {
            self.refresh_decrypted_tree();
        }
        if self.pkcs12.is_some() {
            self.refresh_pkcs12_reveal();
        }
        self.identify();
        self.rebuild_rows();
        // Edits can make the document gain or lose conformance to a spec,
        // or break/fix its signature.
        self.recompute_sig_status();
        if let Some((source, path)) = selection {
            if let Some(i) = self
                .rows
                .iter()
                .position(|r| r.source == source && r.path == path)
            {
                self.select(i);
            }
        }
    }

    /// Serialize the edited virtual tree and replace the outer ciphertext
    /// and IV. The virtual nodes themselves remain outside `self.roots`.
    fn encrypt_decrypted_tree(&mut self) -> Result<(), String> {
        let (password, plaintext) = {
            let decrypted = self.decrypted.as_ref().ok_or("decryption is not available")?;
            (decrypted.password.clone(), ber::encode_forest(&decrypted.roots))
        };
        let encrypted = pkcs8::parse(&self.roots)?
            .ok_or("document is no longer an EncryptedPrivateKeyInfo")?;
        let (ciphertext, iv) = encrypted.encrypt(&password, &plaintext)?;

        let data_node = node_at_mut(&mut self.roots, &encrypted.encrypted_path)
            .ok_or("encryptedData node is missing")?;
        data_node.value = ciphertext;
        data_node.children.clear();
        data_node.encapsulates = false;

        let iv_node = node_at_mut(&mut self.roots, &encrypted.iv_path)
            .ok_or("cipher IV node is missing")?;
        iv_node.value = iv;
        iv_node.children.clear();
        iv_node.encapsulates = false;

        if let Some(ref mut decrypted) = self.decrypted {
            decrypted.plaintext = plaintext;
        }
        Ok(())
    }

    /// Serialize an edited PKCS#12 region, re-encrypt it with the retained
    /// password and a fresh IV, replace the outer ciphertext and IV, and
    /// recompute the container's `MacData` digest over the updated
    /// `AuthenticatedSafe` so the file stays cryptographically consistent.
    fn encrypt_pkcs12_region(&mut self, idx: usize) -> Result<(), String> {
        let (password, plaintext) = {
            let reveal = self.pkcs12.as_ref().ok_or("decryption is not available")?;
            let region = reveal.regions.get(idx).ok_or("decrypted region is missing")?;
            (reveal.password.clone(), ber::encode_forest(&region.roots))
        };
        let p12 = pkcs12::parse(&self.roots)?
            .ok_or("document is no longer a PKCS#12 container")?;
        if let pkcs12::Mac::Unsupported(reason) = &p12.mac {
            return Err(reason.clone());
        }
        let region = p12.regions.get(idx).ok_or("encrypted region is missing")?;
        let (ciphertext, iv) = region.encrypt(&password, &plaintext)?;

        let cipher_node = node_at_mut(&mut self.roots, &region.cipher_path)
            .ok_or("ciphertext node is missing")?;
        cipher_node.value = ciphertext;
        cipher_node.children.clear();
        cipher_node.encapsulates = false;

        let iv_node =
            node_at_mut(&mut self.roots, &region.iv_path).ok_or("cipher IV node is missing")?;
        iv_node.value = iv;
        iv_node.children.clear();
        iv_node.encapsulates = false;

        if let pkcs12::Mac::Supported(mac) = &p12.mac {
            let auth_safe = node_at(&self.roots, &p12.auth_safe_content_path)
                .ok_or("AuthenticatedSafe node is missing")?
                .content_octets();
            let digest = mac.compute(&password, &auth_safe)?;
            let digest_node = node_at_mut(&mut self.roots, &mac.digest_path)
                .ok_or("MAC digest node is missing")?;
            digest_node.value = digest;
            digest_node.children.clear();
            digest_node.encapsulates = false;
        }
        Ok(())
    }

    /// When the serialized representation is edited, decrypt it again with
    /// the retained password so the virtual representation immediately
    /// reflects the new ciphertext and/or PBES2 parameters.
    fn refresh_decrypted_tree(&mut self) {
        let Some(password) = self.decrypted.as_ref().map(|d| d.password.clone()) else {
            return;
        };
        let old_roots = self.decrypted.as_ref().map(|d| d.roots.clone()).unwrap_or_default();
        let refreshed = (|| {
            let encrypted = pkcs8::parse(&self.roots)?
                .ok_or("document is no longer an EncryptedPrivateKeyInfo".to_string())?;
            let plaintext = encrypted.decrypt(&password)?;
            let mut roots = ber::parse_forest(&plaintext, 0)
                .map_err(|e| format!("decrypted ASN.1 could not be parsed: {}", e))?;
            copy_expanded(&old_roots, &mut roots);
            let ident = spec::identify(&self.spec_db, &roots);
            Ok::<Decrypted, String>(Decrypted {
                encrypted_path: encrypted.encrypted_path,
                plaintext,
                roots,
                password,
                ident,
            })
        })();
        match refreshed {
            Ok(decrypted) => self.decrypted = Some(decrypted),
            Err(e) => {
                self.decrypted = None;
                self.status = format!("encrypted content changed; decryption is unavailable: {}", e);
            }
        }
    }

    /// When the outer document is edited, re-derive the read-only PKCS#12
    /// reveal from the updated ciphertexts, carrying over fold state per
    /// region. If the document no longer parses/decrypts as a PKCS#12, the
    /// reveal is discarded.
    fn refresh_pkcs12_reveal(&mut self) {
        let Some(password) = self.pkcs12.as_ref().map(|p| p.password.clone()) else {
            return;
        };
        let old: Vec<Vec<Node>> = self
            .pkcs12
            .as_ref()
            .map(|p| p.regions.iter().map(|r| r.roots.clone()).collect())
            .unwrap_or_default();
        let refreshed = (|| {
            let p12 = pkcs12::parse(&self.roots)?
                .ok_or_else(|| "document is no longer a PKCS#12 container".to_string())?;
            let mut regions = Vec::new();
            for region in &p12.regions {
                let plaintext = region.decrypt(&password)?;
                let mut roots = ber::parse_forest(&plaintext, 0)
                    .map_err(|e| format!("decrypted ASN.1 could not be parsed: {}", e))?;
                if let Some(old_roots) = old.get(regions.len()) {
                    copy_expanded(old_roots, &mut roots);
                }
                let ident = spec::identify(&self.spec_db, &roots);
                regions.push(RevealedRegion {
                    cipher_path: region.cipher_path.clone(),
                    kind: region.kind,
                    roots,
                    ident,
                });
            }
            if regions.is_empty() {
                return Err("PKCS#12 no longer has decryptable content".to_string());
            }
            Ok::<Pkcs12Reveal, String>(Pkcs12Reveal {
                password,
                regions,
                editable: mac_editable(&p12.mac),
            })
        })();
        match refreshed {
            Ok(reveal) => self.pkcs12 = Some(reveal),
            Err(e) => {
                self.pkcs12 = None;
                self.status =
                    format!("encrypted content changed; PKCS#12 decryption is unavailable: {}", e);
            }
        }
    }

    pub fn save(&mut self) {
        if !self.file_open {
            self.status = "no file open — select one in the browser first".to_string();
            return;
        }
        let der = ber::encode_forest(&self.roots);
        let out = input::wrap(&der, &self.container);
        match std::fs::write(&self.out_path, &out) {
            Ok(()) => {
                self.dirty = false;
                self.status = format!(
                    "wrote {} bytes to {}",
                    out.len(),
                    self.out_path.display()
                );
            }
            Err(e) => self.status = format!("write failed: {}", e),
        }
    }
}

/// Read a plaintext private-key file and return its PKCS#8 form (SEC1 keys
/// are wrapped), or `None` if it isn't a usable plaintext key.
fn read_plaintext_key_pkcs8(path: &Path) -> Option<Vec<u8>> {
    let raw = std::fs::read(path).ok()?;
    let (der, _) = input::load(&raw).ok()?;
    let roots = ber::parse_forest(&der, 0).ok()?;
    x509::to_pkcs8_der(&roots)
}

/// Read a certificate file and return its raw DER (unwrapping a PEM/base64/hex
/// container). `None` if it can't be read or decoded.
fn read_cert_der(path: &Path) -> Option<Vec<u8>> {
    let raw = std::fs::read(path).ok()?;
    input::load(&raw).ok().map(|(der, _)| der)
}

/// A path's final component as a display string (its file name).
fn file_name_string(path: &Path) -> String {
    path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Resign the signed-object file at `path` (a Certificate or a CRL) with
/// `key_pkcs8` under algorithm `alg`: first rewrite both `signatureAlgorithm`
/// identifiers to `alg`, then sign the re-encoded `tbsCertificate`/`tbsCertList`
/// and install the new signature. The file's original container (DER/PEM/…) is
/// preserved. Errors — a bad file, a key/algorithm mismatch — leave the file
/// untouched.
fn resign_issued_file(path: &Path, alg: keygen::KeyAlgorithm, key_pkcs8: &[u8]) -> Result<(), String> {
    let raw = std::fs::read(path).map_err(|e| e.to_string())?;
    let (der, container) = input::load(&raw).map_err(|e| e.to_string())?;
    let mut roots = ber::parse_forest(&der, 0).map_err(|e| e.to_string())?;
    let (tbs_sig_alg, outer_sig_alg, outer_sig) =
        resignable_paths(&roots).ok_or("not a certificate or CRL")?;

    let alg_id = ber::parse_forest(&alg.sig_alg_identifier_der(), 0)
        .map_err(|e| e.to_string())?
        .into_iter()
        .next()
        .ok_or("empty algorithm identifier")?;
    *node_at_mut(&mut roots, &tbs_sig_alg).ok_or("tbs sigAlg missing")? = alg_id.clone();
    *node_at_mut(&mut roots, &outer_sig_alg).ok_or("outer sigAlg missing")? = alg_id;

    // Re-encode and re-parse so the tbs bytes are canonical, then sign them.
    let updated = ber::encode_forest(&roots);
    let mut roots = ber::parse_forest(&updated, 0).map_err(|e| e.to_string())?;
    let signable = x509::parse_signable(&roots, &updated).ok_or("not a signed object after edit")?;
    let sig = verify::sign(alg.sig_alg_oid(), key_pkcs8, &signable.tbs)?;
    let sig_node = node_at_mut(&mut roots, &outer_sig).ok_or("signature node missing")?;
    sig_node.value = std::iter::once(0u8).chain(sig).collect();
    sig_node.children.clear();
    sig_node.encapsulates = false;

    let final_der = ber::encode_forest(&roots);
    let out = input::wrap(&final_der, &container);
    std::fs::write(path, out).map_err(|e| e.to_string())
}

/// The public-key identity of the private key in `roots`, but only if the key
/// is cryptographically usable — its private scalar must be consistent with
/// its public key. A structurally-valid but corrupted key returns `None`, so
/// it neither shows a key↔certificate link nor is offered for re-signing.
fn usable_key_id(roots: &[Node]) -> Option<x509::PublicKeyId> {
    let id = x509::public_key_id_of_private_key(roots)?;
    let pkcs8 = x509::to_pkcs8_der(roots)?;
    verify::private_key_usable(&pkcs8).then_some(id)
}

/// Scan `dir` for plaintext key files, keeping only cryptographically usable
/// keys — a broken key never gets a key↔certificate link.
fn scan_usable_key_files(dir: &Path) -> Vec<x509::KeyFile> {
    x509::scan_dir_key_files(dir)
        .into_iter()
        .filter(|kf| {
            read_plaintext_key_pkcs8(&kf.path)
                .map(|pkcs8| verify::private_key_usable(&pkcs8))
                .unwrap_or(false)
        })
        .collect()
}

fn collect_rows(
    node: &Node,
    path: Vec<usize>,
    base_depth: usize,
    source: RowSource,
    rows: &mut Vec<Row>,
) {
    rows.push(Row { depth: base_depth + path.len() - 1, path: path.clone(), source });
    if node.expanded {
        for (i, child) in node.children.iter().enumerate() {
            let mut child_path = path.clone();
            child_path.push(i);
            collect_rows(child, child_path, base_depth, source, rows);
        }
    }
}

/// Tree paths of the mutable signature-bearing nodes of a `Certificate`,
/// used by the public-key modification and re-signing flows.
struct CertPaths {
    /// `tbsCertificate.signature` AlgorithmIdentifier.
    tbs_sig_alg: Vec<usize>,
    /// `tbsCertificate.subjectPublicKeyInfo`.
    spki: Vec<usize>,
    /// Outer `signatureAlgorithm`.
    outer_sig_alg: Vec<usize>,
    /// Outer `signature` BIT STRING.
    outer_sig: Vec<usize>,
    /// `tbsCertificate.serialNumber`.
    serial: Vec<usize>,
}

/// Compute the [`CertPaths`] for `roots` if it structurally decodes as a
/// `Certificate` (not a CRL). The only variable is the optional leading
/// `[0] version` inside the `tbsCertificate`, which shifts every following
/// field by one.
fn cert_paths(roots: &[Node]) -> Option<CertPaths> {
    let der = ber::encode_forest(roots);
    let signable = x509::parse_signable(roots, &der)?;
    if signable.kind != Kind::Certificate {
        return None;
    }
    let tbs = &roots.first()?.children.first()?.children;
    let v = usize::from(
        tbs.first()
            .is_some_and(|c| c.class == Class::ContextSpecific && c.tag == 0 && c.constructed),
    );
    Some(CertPaths {
        serial: vec![0, 0, v],
        tbs_sig_alg: vec![0, 0, v + 1],
        spki: vec![0, 0, v + 5],
        outer_sig_alg: vec![0, 1],
        outer_sig: vec![0, 2],
    })
}

/// Tree paths of the signature-algorithm and signature nodes of a signed
/// object (Certificate *or* CRL) — the fields re-signing rewrites. The inner
/// `signature` AlgorithmIdentifier sits at a different position in a
/// `tbsCertificate` (after the `serialNumber`) than in a `tbsCertList`.
fn resignable_paths(roots: &[Node]) -> Option<(Vec<usize>, Vec<usize>, Vec<usize>)> {
    let der = ber::encode_forest(roots);
    let signable = x509::parse_signable(roots, &der)?;
    let tbs = &roots.first()?.children.first()?.children;
    let tbs_sig_alg = match signable.kind {
        Kind::Certificate => {
            // tbsCertificate: [ [0] version?, serialNumber, signature, … ]
            let v = usize::from(
                tbs.first()
                    .is_some_and(|c| c.class == Class::ContextSpecific && c.tag == 0 && c.constructed),
            );
            vec![0, 0, v + 1]
        }
        Kind::Crl => {
            // tbsCertList: [ version? INTEGER, signature, issuer, … ]
            let v = usize::from(
                tbs.first().is_some_and(|c| !c.constructed && c.is_universal(ber::TAG_INTEGER)),
            );
            vec![0, 0, v]
        }
    };
    Some((tbs_sig_alg, vec![0, 1], vec![0, 2]))
}

/// The [`x509::PublicKeyId`] of a `SubjectPublicKeyInfo` DER (`SEQUENCE {
/// AlgorithmIdentifier, subjectPublicKey BIT STRING }`) — the same identity
/// the certificate side derives, so a generated key and the certificate it
/// rekeys compare equal even when the private key omits its public part.
fn public_key_id_from_spki(spki: &[u8]) -> Option<x509::PublicKeyId> {
    let roots = ber::parse_forest(spki, 0).ok()?;
    let node = roots.first()?;
    if !node.constructed || node.children.len() != 2 {
        return None;
    }
    let oid = node.children[0].children.first()?;
    let alg = ber::oid_arcs(&oid.value)?;
    let pubkey = node.children[1].value.get(1..)?.to_vec(); // strip unused-bits octet
    x509::public_key_id(&alg, &pubkey)
}

/// The `serialNumber` of a certificate as an uppercase hex string (its DER
/// INTEGER content octets), or `None` if `roots` is not a certificate.
fn cert_serial_hex(roots: &[Node]) -> Option<String> {
    let paths = cert_paths(roots)?;
    let node = node_at(roots, &paths.serial)?;
    Some(ber::hex_pairs(&node.value))
}

pub fn node_at<'a>(roots: &'a [Node], path: &[usize]) -> Option<&'a Node> {
    let (&first, rest) = path.split_first()?;
    let mut node = roots.get(first)?;
    for &i in rest {
        node = node.children.get(i)?;
    }
    Some(node)
}

pub fn node_at_mut<'a>(roots: &'a mut [Node], path: &[usize]) -> Option<&'a mut Node> {
    let (&first, rest) = path.split_first()?;
    let mut node = roots.get_mut(first)?;
    for &i in rest {
        node = node.children.get_mut(i)?;
    }
    Some(node)
}

/// Carry the expand/collapse state over to a freshly parsed tree with the
/// same (or locally changed) structure.
fn copy_expanded(old: &[Node], new: &mut [Node]) {
    for (o, n) in old.iter().zip(new.iter_mut()) {
        n.expanded = o.expanded;
        copy_expanded(&o.children, &mut n.children);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_app(data: &[u8]) -> App {
        let roots = ber::parse_forest(data, 0).unwrap();
        App::new(
            PathBuf::from("/nonexistent/in"),
            PathBuf::from("/nonexistent/out"),
            Container::Raw,
            roots,
            data.len(),
        )
    }

    #[test]
    fn rows_follow_expansion() {
        // SEQUENCE { INTEGER 1, SEQUENCE { NULL } }
        let data = [0x30, 0x07, 0x02, 0x01, 0x01, 0x30, 0x02, 0x05, 0x00];
        let mut app = test_app(&data);
        assert_eq!(app.rows.len(), 4);
        app.select(2); // inner SEQUENCE
        app.toggle_expand();
        assert_eq!(app.rows.len(), 3);
    }

    #[test]
    fn edit_primitive_value_reencodes_lengths() {
        // SEQUENCE { OCTET STRING AA BB }
        let data = [0x30, 0x04, 0x04, 0x02, 0xAA, 0xBB];
        let mut app = test_app(&data);
        app.select(1);
        app.mode = Mode::Edit(EditState::hex(EditKind::Content, &input::hex_decode("010203").unwrap()));
        app.commit_edit();
        assert!(app.dirty);
        assert_eq!(
            ber::encode_forest(&app.roots),
            [0x30, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03]
        );
        // Offsets were refreshed by the rebuild.
        assert_eq!(app.selected_node().unwrap().offset, 2);
        assert_eq!(app.selected_node().unwrap().content_len, 3);
    }

    #[test]
    fn edit_constructed_rejects_invalid_content() {
        let data = [0x30, 0x02, 0x05, 0x00];
        let mut app = test_app(&data);
        app.select(0);
        app.mode = Mode::Edit(EditState::hex(EditKind::Content, &input::hex_decode("05").unwrap()));
        app.commit_edit();
        assert!(!app.dirty);
        assert!(matches!(app.mode, Mode::Edit(_)));
        assert_eq!(ber::encode_forest(&app.roots), data);
    }

    #[test]
    fn delete_needs_confirmation_and_reencodes_parent() {
        // SEQUENCE { INTEGER 1, NULL }
        let data = [0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00];
        let mut app = test_app(&data);
        app.select(2); // NULL
        app.delete_selected();
        assert!(!app.dirty, "first 'd' must only arm the confirmation");
        assert_eq!(ber::encode_forest(&app.roots), data);
        app.delete_selected();
        assert!(app.dirty);
        assert_eq!(ber::encode_forest(&app.roots), [0x30, 0x03, 0x02, 0x01, 0x01]);
    }

    #[test]
    fn delete_last_root_leaves_empty_document() {
        let data = [0x05, 0x00];
        let mut app = test_app(&data);
        app.delete_selected();
        app.delete_selected();
        assert!(app.rows.is_empty());
        assert!(app.selected_node().is_none());
        assert_eq!(ber::encode_forest(&app.roots), Vec::<u8>::new());
    }

    #[test]
    fn reorder_swaps_siblings_and_follows_selection() {
        // SEQUENCE { INTEGER 1, NULL }
        let data = [0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00];
        let mut app = test_app(&data);
        app.select(1); // INTEGER
        app.move_selected(1);
        assert_eq!(ber::encode_forest(&app.roots), [0x30, 0x05, 0x05, 0x00, 0x02, 0x01, 0x01]);
        // Selection follows the moved element.
        assert_eq!(app.rows[app.selected].path, vec![0, 1]);
        // Moving past the last sibling is a no-op.
        app.move_selected(1);
        assert_eq!(ber::encode_forest(&app.roots), [0x30, 0x05, 0x05, 0x00, 0x02, 0x01, 0x01]);
    }

    /// Select a universal type in the (open) picker by tag number.
    fn pick_universal(app: &mut App, tag: u32) {
        let Mode::TypePicker(ref mut p) = app.mode else { panic!("picker not open") };
        p.univ_idx = PICKER_UNIVERSAL
            .iter()
            .position(|(t, _)| *t == tag)
            .expect("tag offered by picker");
        app.picker_confirm();
    }

    fn type_value(app: &mut App, hex: &str) {
        let Mode::Edit(ref mut edit) = app.mode else { panic!("not in edit mode") };
        edit.editor = Editor::hex(&input::hex_decode(hex).unwrap());
        app.commit_edit();
    }

    #[test]
    fn insert_opens_type_picker() {
        let data = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut app = test_app(&data);
        app.select(1);
        app.start_insert(false);
        assert!(matches!(app.mode, Mode::TypePicker(_)));
        app.cancel_picker();
        assert!(matches!(app.mode, Mode::Browse));
        assert_eq!(ber::encode_forest(&app.roots), data);
    }

    #[test]
    fn insert_sibling_after_selected() {
        // SEQUENCE { INTEGER 1 }, insert a NULL behind the INTEGER.
        let data = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut app = test_app(&data);
        app.select(1); // INTEGER
        app.start_insert(false);
        pick_universal(&mut app, ber::TAG_NULL);
        type_value(&mut app, ""); // empty value is the default
        assert!(app.dirty);
        assert_eq!(
            ber::encode_forest(&app.roots),
            [0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00]
        );
        // Selection lands on the inserted element.
        assert_eq!(app.rows[app.selected].path, vec![0, 1]);
        assert!(app.selected_node().unwrap().is_universal(ber::TAG_NULL));
    }

    #[test]
    fn insert_child_into_empty_constructed() {
        let data = [0x30, 0x00]; // SEQUENCE {}
        let mut app = test_app(&data);
        app.start_insert(true);
        pick_universal(&mut app, ber::TAG_INTEGER);
        type_value(&mut app, "07");
        // Length octets of element and parent were derived automatically.
        assert_eq!(ber::encode_forest(&app.roots), [0x30, 0x03, 0x02, 0x01, 0x07]);
    }

    #[test]
    fn insert_child_into_primitive_is_refused() {
        let data = [0x02, 0x01, 0x01];
        let mut app = test_app(&data);
        app.start_insert(true);
        assert!(matches!(app.mode, Mode::Browse));
    }

    #[test]
    fn picker_forces_constructed_for_sequence() {
        let data = [0x02, 0x01, 0x01];
        let mut app = test_app(&data);
        app.start_insert(false);
        {
            let Mode::TypePicker(ref mut p) = app.mode else { panic!() };
            p.form_idx = 0; // user left "Primitive" selected
        }
        pick_universal(&mut app, ber::TAG_SEQUENCE);
        type_value(&mut app, "");
        // Encoded with the constructed bit set: 0x30, not 0x10.
        assert_eq!(ber::encode_forest(&app.roots), [0x02, 0x01, 0x01, 0x30, 0x00]);
    }

    #[test]
    fn picker_context_specific_tag_number() {
        let data = [0x30, 0x00];
        let mut app = test_app(&data);
        app.start_insert(true);
        {
            let Mode::TypePicker(ref mut p) = app.mode else { panic!() };
            p.class_idx = 2; // Context-specific
            p.form_idx = 1; // Constructed
            p.tag_digits = "3".to_string();
            assert_eq!(ber::hex_pairs(&p.identifier_preview()), "A3");
        }
        app.picker_confirm();
        type_value(&mut app, "0500"); // [3] { NULL }
        assert_eq!(ber::encode_forest(&app.roots), [0x30, 0x04, 0xA3, 0x02, 0x05, 0x00]);
    }

    #[test]
    fn insert_constructed_rejects_invalid_content() {
        let data = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut app = test_app(&data);
        app.select(1);
        app.start_insert(false);
        pick_universal(&mut app, ber::TAG_SEQUENCE);
        type_value(&mut app, "0501"); // truncated TLV as content
        assert!(matches!(app.mode, Mode::Edit(_)), "invalid insert must stay in edit mode");
        assert!(!app.dirty);
        assert_eq!(ber::encode_forest(&app.roots), data);
    }

    #[test]
    fn insert_into_empty_document() {
        let data = [0x05, 0x00];
        let mut app = test_app(&data);
        app.delete_selected();
        app.delete_selected();
        assert!(app.rows.is_empty());
        app.start_insert(false);
        pick_universal(&mut app, ber::TAG_INTEGER);
        type_value(&mut app, "0A");
        assert_eq!(ber::encode_forest(&app.roots), [0x02, 0x01, 0x0A]);
        assert_eq!(app.rows.len(), 1);
    }

    /// Open the edit menu and confirm the given entry.
    fn choose_edit_mode(app: &mut App, entry: usize) {
        app.open_edit_menu();
        let Mode::EditMenu(ref mut m) = app.mode else { panic!("menu not open") };
        m.selected = entry;
        app.menu_confirm();
    }

    fn set_text(app: &mut App, text: &str) {
        let Mode::Edit(EditState { editor: Editor::Text(ref mut t), .. }) = app.mode else {
            panic!("no text editor open")
        };
        t.buf = text.chars().collect();
        t.cursor = t.buf.len();
        app.commit_edit();
    }

    #[test]
    fn edit_menu_routes_to_retag_and_hex() {
        let data = [0x02, 0x01, 0x2A];
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 0);
        assert!(matches!(app.mode, Mode::TypePicker(_)));
        app.cancel_picker();
        choose_edit_mode(&mut app, 1);
        assert!(matches!(
            app.mode,
            Mode::Edit(EditState { editor: Editor::Hex(_), .. })
        ));
    }

    #[test]
    fn base64_edit_prefills_and_applies() {
        let data = [0x04, 0x02, 0xAA, 0xBB];
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 2);
        {
            let Mode::Edit(EditState { editor: Editor::Text(ref t), .. }) = app.mode else {
                panic!()
            };
            assert_eq!(t.format, TextFormat::Base64);
            assert_eq!(t.buf.iter().collect::<String>(), input::b64_encode(&[0xAA, 0xBB]));
        }
        set_text(&mut app, &input::b64_encode(&[1, 2, 3]));
        assert_eq!(ber::encode_forest(&app.roots), [0x04, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn base64_edit_rejects_invalid_input() {
        let data = [0x04, 0x01, 0xAA];
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 2);
        set_text(&mut app, "not base64!!");
        assert!(matches!(app.mode, Mode::Edit(_)), "invalid base64 must not commit");
        assert_eq!(ber::encode_forest(&app.roots), data);
    }

    #[test]
    fn raw_edit_takes_characters_as_bytes() {
        let data = [0x0C, 0x02, 0x48, 0x69]; // UTF8String "Hi"
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 3);
        {
            let Mode::Edit(EditState { editor: Editor::Text(ref t), .. }) = app.mode else {
                panic!()
            };
            assert_eq!(t.format, TextFormat::Raw);
            assert_eq!(t.buf.iter().collect::<String>(), "Hi");
        }
        set_text(&mut app, "ABC");
        assert_eq!(ber::encode_forest(&app.roots), [0x0C, 0x03, 0x41, 0x42, 0x43]);
    }

    #[test]
    fn type_specific_integer_prefills_decimal() {
        let data = [0x02, 0x01, 0x2A]; // INTEGER 42
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 4);
        {
            let Mode::Edit(EditState { editor: Editor::Text(ref t), .. }) = app.mode else {
                panic!()
            };
            assert_eq!(t.format, TextFormat::Integer);
            assert_eq!(t.buf.iter().collect::<String>(), "42");
        }
        set_text(&mut app, "-1");
        assert_eq!(ber::encode_forest(&app.roots), [0x02, 0x01, 0xFF]);
    }

    #[test]
    fn type_specific_integer_handles_values_beyond_i128() {
        // 17-byte INTEGER (2^128), e.g. a large certificate serial number.
        let mut data = vec![0x02, 0x11, 0x01];
        data.extend([0x00; 16]);
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 4);
        let big = "340282366920938463463374607431768211456";
        {
            let Mode::Edit(EditState { editor: Editor::Text(ref t), .. }) = app.mode else {
                panic!()
            };
            // The prefill must be the decimal value, not empty (or hex).
            assert_eq!(t.buf.iter().collect::<String>(), big);
        }
        // Applying the prefilled value back is byte-identical...
        set_text(&mut app, big);
        assert_eq!(ber::encode_forest(&app.roots), data);
        // ...and a huge new value encodes fine too.
        choose_edit_mode(&mut app, 4);
        set_text(&mut app, "-340282366920938463463374607431768211456");
        let mut expect = vec![0x02, 0x11, 0xFF];
        expect.extend([0x00; 16]);
        assert_eq!(ber::encode_forest(&app.roots), expect);
    }

    #[test]
    fn type_specific_oid_dot_notation() {
        let data = [0x06, 0x03, 0x55, 0x04, 0x03]; // 2.5.4.3
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 4);
        {
            let Mode::Edit(EditState { editor: Editor::Text(ref t), .. }) = app.mode else {
                panic!()
            };
            assert_eq!(t.buf.iter().collect::<String>(), "2.5.4.3");
        }
        set_text(&mut app, "1.2.840.113549");
        assert_eq!(
            ber::encode_forest(&app.roots),
            [0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]
        );
    }

    #[test]
    fn type_specific_boolean() {
        let data = [0x01, 0x01, 0xFF];
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 4);
        set_text(&mut app, "false");
        assert_eq!(ber::encode_forest(&app.roots), [0x01, 0x01, 0x00]);
    }

    #[test]
    fn type_specific_utf8_text() {
        let data = [0x0C, 0x02, 0x48, 0x69]; // UTF8String "Hi"
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 4);
        set_text(&mut app, "Grüße");
        assert_eq!(
            ber::encode_forest(&app.roots)[2..],
            *"Grüße".as_bytes()
        );
    }

    #[test]
    fn type_specific_bmpstring_is_ucs2() {
        let data = [0x1E, 0x02, 0x00, 0x41]; // BMPString "A"
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 4);
        set_text(&mut app, "AB");
        assert_eq!(ber::encode_forest(&app.roots), [0x1E, 0x04, 0x00, 0x41, 0x00, 0x42]);
    }

    #[test]
    fn type_specific_datetime_prefills_fields() {
        let data = *b"\x17\x0d260709115028Z"; // UTCTime
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 4);
        let Mode::Edit(EditState { editor: Editor::DateTime(ref mut d), .. }) = app.mode else {
            panic!("no date editor")
        };
        assert!(!d.generalized);
        assert_eq!(d.fields, ["2026", "07", "09", "11", "50", "28"].map(String::from));
        d.fields[1] = "12".to_string(); // month
        app.commit_edit();
        assert_eq!(&ber::encode_forest(&app.roots)[2..], b"261209115028Z");
    }

    #[test]
    fn type_specific_datetime_typing_replaces_prefilled_field() {
        let data = *b"\x17\x0d260709115028Z"; // UTCTime
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 4);
        {
            let Mode::Edit(ref mut edit) = app.mode else { panic!() };
            // Year is pre-filled to its full width ("2026"); typing must
            // replace it, not be silently dropped.
            edit.editor.insert_char('1');
            edit.editor.insert_char('9');
            edit.editor.insert_char('9');
            edit.editor.insert_char('9');
            // Move to the month field and type: also replaces.
            edit.editor.move_horizontal(1);
            edit.editor.insert_char('3');
            let Editor::DateTime(ref d) = edit.editor else { panic!() };
            assert_eq!(d.fields[0], "1999");
            assert_eq!(d.fields[1], "3");
        }
        app.commit_edit();
        assert_eq!(&ber::encode_forest(&app.roots)[2..], b"990309115028Z");
    }

    #[test]
    fn type_specific_datetime_validates_ranges() {
        let data = *b"\x17\x0d260709115028Z";
        let mut app = test_app(&data);
        choose_edit_mode(&mut app, 4);
        {
            let Mode::Edit(EditState { editor: Editor::DateTime(ref mut d), .. }) = app.mode
            else {
                panic!()
            };
            d.fields[2] = "32".to_string(); // day out of range
        }
        app.commit_edit();
        assert!(matches!(app.mode, Mode::Edit(_)), "invalid date must not commit");
        assert_eq!(ber::encode_forest(&app.roots), data);
    }

    #[test]
    fn type_specific_refused_for_constructed_and_null() {
        let data = [0x30, 0x02, 0x05, 0x00];
        let mut app = test_app(&data);
        app.select(0); // SEQUENCE
        choose_edit_mode(&mut app, 4);
        assert!(matches!(app.mode, Mode::EditMenu(_)), "constructed: stay in menu");
        app.cancel_menu();
        app.select(1); // NULL
        choose_edit_mode(&mut app, 4);
        assert!(matches!(app.mode, Mode::EditMenu(_)), "NULL: stay in menu");
    }

    #[test]
    fn editor_paste_filters_hex() {
        let data = [0x04, 0x01, 0xAA];
        let mut app = test_app(&data);
        app.start_edit();
        let Mode::Edit(ref mut edit) = app.mode else { panic!() };
        edit.editor = Editor::hex(&[]);
        edit.editor.paste("01 02:0a\n");
        app.commit_edit();
        assert_eq!(ber::encode_forest(&app.roots), [0x04, 0x03, 0x01, 0x02, 0x0A]);
    }

    #[test]
    fn retag_prepopulates_picker_with_current_type() {
        // SEQUENCE { INTEGER 1 }
        let data = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut app = test_app(&data);
        app.start_retag();
        let Mode::TypePicker(ref p) = app.mode else { panic!("picker not open") };
        assert_eq!(p.class(), Class::Universal);
        assert!(p.constructed());
        assert_eq!(p.tag(), ber::TAG_SEQUENCE);
        assert_eq!(
            p.target,
            PickerTarget::Retag { path: vec![0], source: RowSource::Document }
        );
    }

    #[test]
    fn retag_integer_to_enumerated_keeps_value() {
        let data = [0x02, 0x01, 0x2A];
        let mut app = test_app(&data);
        app.start_retag();
        pick_universal(&mut app, ber::TAG_ENUMERATED);
        assert!(app.dirty);
        assert_eq!(ber::encode_forest(&app.roots), [0x0A, 0x01, 0x2A]);
    }

    #[test]
    fn retag_universal_to_context_specific() {
        let data = [0x02, 0x01, 0x2A];
        let mut app = test_app(&data);
        app.start_retag();
        {
            let Mode::TypePicker(ref mut p) = app.mode else { panic!() };
            p.class_idx = 2; // Context-specific
            p.form_idx = 0;
            p.tag_digits = "0".to_string();
        }
        app.picker_confirm();
        assert_eq!(ber::encode_forest(&app.roots), [0x80, 0x01, 0x2A]);
    }

    #[test]
    fn retag_primitive_to_constructed_parses_content() {
        // OCTET STRING whose content is a valid NULL TLV.
        let data = [0x04, 0x02, 0x05, 0x00];
        let mut app = test_app(&data);
        app.select(0);
        app.start_retag();
        pick_universal(&mut app, ber::TAG_SEQUENCE);
        assert_eq!(ber::encode_forest(&app.roots), [0x30, 0x02, 0x05, 0x00]);
        assert!(app.node_at(&[0]).unwrap().constructed);
    }

    #[test]
    fn retag_constructed_to_primitive_keeps_content_octets() {
        // SEQUENCE { NULL } -> primitive OCTET STRING with the same
        // content bytes. The form column keeps the element's current
        // (constructed) form for types where both are legal, so the test
        // switches it to primitive like a user would.
        let data = [0x30, 0x02, 0x05, 0x00];
        let mut app = test_app(&data);
        app.select(0);
        app.start_retag();
        {
            let Mode::TypePicker(ref mut p) = app.mode else { panic!() };
            p.form_idx = 0; // primitive
        }
        pick_universal(&mut app, ber::TAG_OCTET_STRING);
        assert_eq!(ber::encode_forest(&app.roots), [0x04, 0x02, 0x05, 0x00]);
    }

    #[test]
    fn retag_to_constructed_rejects_invalid_content() {
        // INTEGER 42: content "2A" is not a TLV series.
        let data = [0x02, 0x01, 0x2A];
        let mut app = test_app(&data);
        app.start_retag();
        pick_universal(&mut app, ber::TAG_SEQUENCE);
        assert!(matches!(app.mode, Mode::TypePicker(_)), "must stay in the picker");
        assert!(!app.dirty);
        assert_eq!(ber::encode_forest(&app.roots), data);
    }

    #[test]
    fn retag_unchanged_type_is_not_dirty() {
        let data = [0x02, 0x01, 0x2A];
        let mut app = test_app(&data);
        app.start_retag();
        app.picker_confirm(); // picker pre-populated with the current type
        assert!(matches!(app.mode, Mode::Browse));
        assert!(!app.dirty);
    }

    #[test]
    fn edit_octet_string_redetects_encapsulation() {
        let data = [0x04, 0x02, 0xAA, 0xBB];
        let mut app = test_app(&data);
        app.select(0);
        // New content is a complete nested INTEGER.
        app.mode = Mode::Edit(EditState::hex(EditKind::Content, &input::hex_decode("02021234").unwrap()));
        app.commit_edit();
        let node = app.node_at(&[0]).unwrap();
        assert!(node.encapsulates);
        assert_eq!(node.children.len(), 1);
    }

    #[test]
    fn pkcs12_reveal_shows_decrypted_regions() {
        let mut app = open_real_file(std::path::Path::new("testdata/pkcs12.der"));
        // Before decryption, each encrypted region shows the same closed-lock
        // placeholder as a locked PKCS#8 key, one level below its ciphertext.
        let cipher_paths: Vec<Vec<usize>> = pkcs12::parse(&app.roots)
            .unwrap()
            .unwrap()
            .regions
            .iter()
            .map(|r| r.cipher_path.clone())
            .collect();
        assert_eq!(cipher_paths.len(), 2);
        for cipher_path in &cipher_paths {
            let cipher_row = row_of_source(&app, RowSource::Document, cipher_path);
            let placeholder = row_of_source(&app, RowSource::DecryptedPlaceholder, cipher_path);
            assert_eq!(app.rows[placeholder].depth, app.rows[cipher_row].depth + 1);
            assert_eq!(placeholder, cipher_row + 1, "placeholder sits just below the ciphertext");
        }

        // 'z' recognizes the PKCS#12 file and opens the password prompt.
        app.start_decrypt();
        assert!(matches!(app.mode, Mode::Password(_)), "password prompt for PKCS#12");
        if let Mode::Password(ref mut p) = app.mode {
            for c in "asn1editor".chars() {
                p.insert_char(c);
            }
        }
        app.submit_password();

        let reveal = app.pkcs12.as_ref().expect("decrypted");
        assert_eq!(reveal.regions.len(), 2);
        // Each region's plaintext hangs one indentation level below its
        // ciphertext node in the outer document.
        for idx in 0..reveal.regions.len() {
            let cipher_path = app.pkcs12.as_ref().unwrap().regions[idx].cipher_path.clone();
            let cipher_row = row_of_source(&app, RowSource::Document, &cipher_path);
            let root_row = row_of_source(&app, RowSource::Pkcs12Revealed(idx), &[0]);
            assert_eq!(app.rows[root_row].depth, app.rows[cipher_row].depth + 1);
        }

        // The MAC of the test container is recomputable, so the reveal is
        // editable; the decryption itself modifies nothing.
        assert!(app.pkcs12.as_ref().unwrap().editable.is_ok());
        assert!(!app.dirty, "decryption never modifies the outer document");
    }

    #[test]
    fn editing_a_pkcs12_region_reencrypts_and_recomputes_the_mac() {
        let mut app = open_real_file(std::path::Path::new("testdata/pkcs12.der"));
        app.start_decrypt();
        if let Mode::Password(ref mut p) = app.mode {
            for c in "asn1editor".chars() {
                p.insert_char(c);
            }
        }
        app.submit_password();

        let key_idx = app
            .pkcs12
            .as_ref()
            .unwrap()
            .regions
            .iter()
            .position(|r| r.kind == pkcs12::RegionKind::ShroudedKey)
            .expect("a shrouded key region");
        let p12 = pkcs12::parse(&app.roots).unwrap().unwrap();
        let region = &p12.regions[key_idx];
        let old_ciphertext = app.node_at(&region.cipher_path).unwrap().value.clone();
        let old_iv = app.node_at(&region.iv_path).unwrap().value.clone();
        let pkcs12::Mac::Supported(mac) = &p12.mac else { panic!("supported MacData") };
        let old_digest = app.node_at(&mac.digest_path).unwrap().value.clone();

        // Edit the shrouded key's PrivateKeyInfo version INTEGER (child 0).
        app.select(row_of_source(&app, RowSource::Pkcs12Revealed(key_idx), &[0, 0]));
        app.mode = Mode::Edit(EditState::hex(EditKind::Content, &[1]));
        app.commit_edit();

        assert!(app.dirty);
        let reveal = app.pkcs12.as_ref().expect("reveal survives the edit");
        assert_eq!(node_at(&reveal.regions[key_idx].roots, &[0, 0]).unwrap().value, [1]);
        // Ciphertext, IV and MAC digest were all replaced in the outer tree.
        assert_ne!(app.node_at(&region.cipher_path).unwrap().value, old_ciphertext);
        assert_ne!(app.node_at(&region.iv_path).unwrap().value, old_iv);
        assert_ne!(app.node_at(&mac.digest_path).unwrap().value, old_digest);

        // Decrypting the updated container reproduces the edited plaintext.
        let reparsed = pkcs12::parse(&app.roots).unwrap().unwrap();
        let plain = reparsed.regions[key_idx].decrypt(b"asn1editor").unwrap();
        let roots = ber::parse_forest(&plain, 0).unwrap();
        assert_eq!(roots[0].children[0].value, [1]);

        // OpenSSL itself accepts the re-encrypted, re-MAC'd container — the
        // strongest consistency check (parse verifies the MAC).
        let der = ber::encode_forest(&app.roots);
        let pfx = openssl::pkcs12::Pkcs12::from_der(&der).unwrap();
        pfx.parse2("asn1editor").expect("OpenSSL verifies the MAC and decrypts");

        // A wrong password must still fail the OpenSSL MAC check.
        let pfx = openssl::pkcs12::Pkcs12::from_der(&der).unwrap();
        assert!(pfx.parse2("wrong").is_err());
    }

    #[test]
    fn a_pkcs12_with_an_unsupported_mac_stays_read_only() {
        // Rewrite the MacData digest algorithm to MD5, which cannot be
        // recomputed; the reveal must then refuse edits.
        let raw = std::fs::read("testdata/pkcs12.der").unwrap();
        let mut roots = ber::parse_forest(&raw, 0).unwrap();
        let oid = node_at_mut(&mut roots, &[0, 2, 0, 0, 0]).unwrap();
        oid.value = ber::encode_oid("1.2.840.113549.2.5").unwrap();
        let dir = tmp_dir("p12mac");
        let path = dir.join("md5mac.der");
        std::fs::write(&path, ber::encode_forest(&roots)).unwrap();

        let mut app = open_real_file(&path);
        app.start_decrypt();
        if let Mode::Password(ref mut p) = app.mode {
            for c in "asn1editor".chars() {
                p.insert_char(c);
            }
        }
        app.submit_password();

        let reveal = app.pkcs12.as_ref().expect("regions still decrypt");
        assert!(reveal.editable.is_err());
        app.select(row_of_source(&app, RowSource::Pkcs12Revealed(0), &[0]));
        app.start_edit();
        assert!(matches!(app.mode, Mode::Browse), "no edit mode for a read-only reveal");
        assert!(app.status.contains("read-only"));
        app.delete_confirm = true;
        app.delete_selected();
        assert!(app.status.contains("read-only"));
        assert!(!app.dirty);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pkcs12_wrong_password_reveals_nothing() {
        let mut app = open_real_file(std::path::Path::new("testdata/pkcs12.der"));
        app.start_decrypt();
        if let Mode::Password(ref mut p) = app.mode {
            for c in "not the password".chars() {
                p.insert_char(c);
            }
        }
        app.submit_password();
        assert!(app.pkcs12.is_none());
        assert!(app.status.contains("wrong password") || app.status.contains("failed"));
        assert!(!app.rows.iter().any(|r| matches!(r.source, RowSource::Pkcs12Revealed(_))));
    }

    #[test]
    fn z_on_a_certificate_opens_the_crypto_menu_and_does_not_decrypt() {
        let mut app = open_real_file(std::path::Path::new("testdata/cert_ec.der"));
        app.start_decrypt();
        // 'z' on a certificate opens the cryptographic-adjustment menu with
        // both re-sign and re-key options — not a decryption.
        let Mode::EditMenu(ref m) = app.mode else { panic!("crypto menu expected") };
        assert!(m.title.contains("CRYPTOGRAPHIC"));
        let actions: Vec<MenuAction> = m.items.iter().map(|i| i.action).collect();
        assert_eq!(actions, [MenuAction::Resign, MenuAction::Rekey]);
        assert!(app.pkcs12.is_none());
        assert!(app.decrypted.is_none());

        // Choosing "Re-sign" opens the re-sign dialog.
        app.menu_confirm();
        assert!(matches!(app.mode, Mode::Resign(_)));
    }

    #[test]
    fn z_on_a_crl_offers_only_resigning() {
        let dir = copy_chain("z-crl");
        let mut app = open_real_file(&dir.join("root_crl.der"));
        app.start_decrypt();
        let Mode::EditMenu(ref m) = app.mode else { panic!("crypto menu expected") };
        let actions: Vec<MenuAction> = m.items.iter().map(|i| i.action).collect();
        assert_eq!(actions, [MenuAction::Resign], "a CRL has no public key to re-key");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- key ↔ certificate links -----------------------------------------

    fn link_names(app: &App) -> std::collections::BTreeSet<String> {
        app.browser_relations
            .key_links
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    fn browser_select_by_name(app: &mut App, name: &str) {
        let idx = app
            .browser
            .rows
            .iter()
            .position(|r| {
                app.browser.entry_at(&r.path).map(|e| e.name == name).unwrap_or(false)
            })
            .unwrap_or_else(|| panic!("no browser row named {}", name));
        app.browser.select(idx);
        app.recompute_browser_relations();
    }

    fn kl(name: &str) -> PathBuf {
        Path::new("testdata/keylink").join(name)
    }

    fn enter_password(app: &mut App, password: &str) {
        app.start_decrypt();
        if let Mode::Password(ref mut p) = app.mode {
            for c in password.chars() {
                p.insert_char(c);
            }
        }
        app.submit_password();
    }

    #[test]
    fn certificate_links_to_its_plaintext_key_files() {
        // Opening the EC certificate: its private key exists in the folder as
        // both a PKCS#8 and a SEC1 file, so both are linked. The encrypted
        // key and the PKCS#12 need a password and are not linked yet.
        let app = open_real_file(&kl("cert_ec.der"));
        let links = link_names(&app);
        assert!(links.contains("key_ec_pkcs8.der"), "{:?}", links);
        assert!(links.contains("key_ec_sec1.der"), "{:?}", links);
        assert!(!links.contains("key_ec_enc.der"));
        assert!(!links.contains("key_ec.p12"));
        // The RSA certificate links only to the RSA key.
        let app = open_real_file(&kl("cert_rsa.der"));
        let links = link_names(&app);
        assert!(links.contains("key_rsa_pkcs8.der"), "{:?}", links);
        assert!(!links.iter().any(|n| n.contains("ec")));
    }

    #[test]
    fn encrypted_key_links_to_its_certificate_after_the_password() {
        let mut app = open_real_file(&kl("key_ec_enc.der"));
        // Locked: the key is unknown, so no link yet.
        assert!(app.browser_relations.key_links.is_empty());
        enter_password(&mut app, "asn1editor");
        // The encrypted key is still the selected browser row; it now links
        // to its certificate.
        assert_eq!(link_names(&app), ["cert_ec.der".to_string()].into_iter().collect());
    }

    #[test]
    fn pkcs12_links_to_a_matching_certificate_after_the_password() {
        let mut app = open_real_file(&kl("key_ec.p12"));
        assert!(app.browser_relations.key_links.is_empty());
        enter_password(&mut app, "asn1editor");
        assert!(link_names(&app).contains("cert_ec.der"));
    }

    #[test]
    fn unlocked_key_link_persists_after_navigating_to_the_certificate() {
        let mut app = open_real_file(&kl("key_ec_enc.der"));
        enter_password(&mut app, "asn1editor");
        // Navigate to (open) the certificate — this clears the decrypted
        // state, but the recovered public key stays cached.
        app.open_file(kl("cert_ec.der")).unwrap();
        assert!(app.decrypted.is_none());
        browser_select_by_name(&mut app, "cert_ec.der");
        // The certificate still links back to the (now closed) encrypted key.
        assert!(link_names(&app).contains("key_ec_enc.der"), "{:?}", link_names(&app));
    }

    #[test]
    fn wrong_password_creates_no_key_link() {
        let mut app = open_real_file(&kl("key_ec_enc.der"));
        enter_password(&mut app, "the wrong password");
        assert!(app.browser_relations.key_links.is_empty());
        assert!(app.unlocked_keys.is_empty());
    }

    #[test]
    fn invalidating_a_plaintext_key_removes_its_certificate_link() {
        let dir = tmp_dir("keylink-invalidate");
        std::fs::copy(kl("cert_ec.der"), dir.join("cert.der")).unwrap();
        std::fs::copy(kl("key_ec_pkcs8.der"), dir.join("key.der")).unwrap();

        // The certificate links to its valid key.
        let mut app = open_real_file(&dir.join("cert.der"));
        assert!(link_names(&app).contains("key.der"), "{:?}", link_names(&app));

        // Open the key and corrupt its private scalar. The ASN.1 structure and
        // embedded public key stay intact — so the old, purely structural
        // match would still show a link — but the key is now cryptographically
        // invalid (scalar inconsistent with the public key).
        app.open_file(dir.join("key.der")).unwrap();
        let scalar = node_at_mut(&mut app.roots, &[0, 2, 0, 1]).expect("EC private scalar");
        scalar.value[0] ^= 0xFF;
        app.dirty = true;
        app.rebuild();

        // Back on the certificate, the link to the now-invalid key is gone.
        browser_select_by_name(&mut app, "cert.der");
        assert!(
            !link_names(&app).contains("key.der"),
            "an invalidated key must not link: {:?}",
            link_names(&app)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- re-signing -------------------------------------------------------

    /// Flip a bit in the certificate's serialNumber so its (unchanged)
    /// signature no longer covers the tbs, and re-parse.
    fn modify_serial(app: &mut App) {
        let serial = node_at_mut(&mut app.roots, &[0, 0, 1]).expect("serialNumber");
        let last = serial.value.len() - 1;
        serial.value[last] ^= 0x01;
        app.dirty = true;
        app.rebuild();
    }

    /// Copy the plaintext EC PKCS#8 key at `src` to `dst` with its private
    /// scalar corrupted but its embedded public key left intact. The result
    /// still *matches* the certificate by public key (so it is offered as a
    /// signing candidate) but can no longer produce a valid signature.
    fn write_corrupted_ec_pkcs8(src: &Path, dst: &Path) {
        let (der, _) = input::load(&std::fs::read(src).unwrap()).unwrap();
        let mut roots = ber::parse_forest(&der, 0).unwrap();
        // PKCS#8 privateKey OCTET STRING (encapsulates) → ECPrivateKey →
        // child [1] is the private-scalar OCTET STRING.
        let ec = &mut roots[0].children[2].children[0];
        ec.children[1].value[0] ^= 0xFF;
        std::fs::write(dst, ber::encode_forest(&roots)).unwrap();
        // Sanity: it still parses as a private key with the *same* public key,
        // so it is a candidate the resolver must try (and skip).
        let good = public_key_id_of_private_key_at(src);
        let bad = public_key_id_of_private_key_at(dst);
        assert_eq!(good, bad, "corrupted key must still match by public key");
    }

    fn public_key_id_of_private_key_at(path: &Path) -> Option<x509::PublicKeyId> {
        let (der, _) = input::load(&std::fs::read(path).unwrap()).unwrap();
        x509::public_key_id_of_private_key(&ber::parse_forest(&der, 0).unwrap())
    }

    #[test]
    fn resign_a_modified_certificate_with_a_plaintext_issuer_key() {
        let mut app = open_real_file(&kl("cert_ec.der"));
        assert!(matches!(app.sig_status, Some(SignatureStatus::Verified { .. })));
        modify_serial(&mut app);
        assert!(
            matches!(app.sig_status, Some(SignatureStatus::Invalid { .. })),
            "the modification must break the old signature"
        );
        // 'z' opens the re-sign dialog and reports the key is available.
        app.start_resign();
        let Mode::Resign(ref state) = app.mode else { panic!("re-sign dialog") };
        assert!(state.ready, "self-signed key present as plaintext: {}", state.detail);
        app.submit_resign();
        assert!(matches!(app.mode, Mode::Browse));
        assert!(app.dirty);
        assert!(
            matches!(app.sig_status, Some(SignatureStatus::Verified { .. })),
            "the new signature must verify: {}",
            app.status
        );
    }

    #[test]
    fn resign_with_an_encrypted_issuer_key_via_a_retained_password() {
        // A folder holding only the certificate and its *encrypted* key.
        let dir = tmp_dir("resign-enc");
        std::fs::copy(kl("cert_ec.der"), dir.join("cert.der")).unwrap();
        std::fs::copy(kl("key_ec_enc.der"), dir.join("key.der")).unwrap();

        // Unlock the encrypted key once (retains its password).
        let mut app = open_real_file(&dir.join("key.der"));
        enter_password(&mut app, "asn1editor");
        // Open the certificate and modify it.
        app.open_file(dir.join("cert.der")).unwrap();
        modify_serial(&mut app);
        assert!(matches!(app.sig_status, Some(SignatureStatus::Invalid { .. })));
        // The only issuer key present is encrypted, but its password is
        // retained, so re-signing is available and succeeds.
        app.start_resign();
        let Mode::Resign(ref state) = app.mode else { panic!("re-sign dialog") };
        assert!(state.ready, "encrypted issuer key via retained password: {}", state.detail);
        app.submit_resign();
        assert!(
            matches!(app.sig_status, Some(SignatureStatus::Verified { .. })),
            "re-signed with the encrypted issuer key: {}",
            app.status
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resign_falls_through_an_invalidated_key_to_a_valid_alternate() {
        // A folder holding the certificate, an *invalidated* PKCS#8 key, and
        // a valid SEC1 copy of the same key. Re-signing must skip the broken
        // key and succeed with the alternate.
        let dir = tmp_dir("resign-alt");
        std::fs::copy(kl("cert_ec.der"), dir.join("cert.der")).unwrap();
        write_corrupted_ec_pkcs8(&kl("key_ec_pkcs8.der"), &dir.join("broken.der"));
        std::fs::copy(kl("key_ec_sec1.der"), dir.join("good.der")).unwrap();

        let mut app = open_real_file(&dir.join("cert.der"));
        modify_serial(&mut app);
        assert!(matches!(app.sig_status, Some(SignatureStatus::Invalid { .. })));
        app.start_resign();
        let Mode::Resign(ref state) = app.mode else { panic!("re-sign dialog") };
        assert!(state.ready, "the valid alternate key should be found: {}", state.detail);
        app.submit_resign();
        assert!(
            matches!(app.sig_status, Some(SignatureStatus::Verified { .. })),
            "re-signed with the valid alternate key: {}",
            app.status
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resign_falls_through_an_invalidated_key_to_the_unlocked_encrypted_key() {
        // The only plaintext key present is invalidated; the sole working key
        // is the encrypted one, unlocked earlier this session. Re-signing must
        // skip the broken plaintext key and use the encrypted key.
        let dir = tmp_dir("resign-alt-enc");
        std::fs::copy(kl("cert_ec.der"), dir.join("cert.der")).unwrap();
        write_corrupted_ec_pkcs8(&kl("key_ec_pkcs8.der"), &dir.join("broken.der"));
        std::fs::copy(kl("key_ec_enc.der"), dir.join("enc.der")).unwrap();

        // Unlock the encrypted key first (retains its password).
        let mut app = open_real_file(&dir.join("enc.der"));
        enter_password(&mut app, "asn1editor");
        app.open_file(dir.join("cert.der")).unwrap();
        modify_serial(&mut app);
        app.start_resign();
        let Mode::Resign(ref state) = app.mode else { panic!("re-sign dialog") };
        assert!(state.ready, "the unlocked encrypted key should be found: {}", state.detail);
        app.submit_resign();
        assert!(
            matches!(app.sig_status, Some(SignatureStatus::Verified { .. })),
            "re-signed with the unlocked encrypted key: {}",
            app.status
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- certification-path validation -----------------------------------

    fn chain(name: &str) -> PathBuf {
        Path::new("testdata/chain").join(name)
    }

    #[test]
    fn path_validation_needs_a_trusted_anchor() {
        // The leaf's issuers are all present but none is trusted yet.
        let app = open_real_file(&chain("server.der"));
        assert!(
            matches!(app.path_status, Some(PathStatus::Invalid { .. })),
            "{:?}",
            app.path_status
        );
    }

    #[test]
    fn trusting_the_root_validates_a_leaf_certificate() {
        let mut app = open_real_file(&chain("server.der"));
        // Mark the root trusted (selected in the browser). The open leaf is
        // then validated against it, with the intermediate as an untrusted
        // candidate.
        browser_select_by_name(&mut app, "root_ca.der");
        app.toggle_trust();
        assert!(app.trusted_certs.iter().any(|p| p.ends_with("root_ca.der")));
        assert!(
            matches!(app.path_status, Some(PathStatus::Valid { .. })),
            "{:?}",
            app.path_status
        );
        // Pressing 't' again removes the anchor and the path is invalid again.
        app.toggle_trust();
        assert!(app.trusted_certs.is_empty());
        assert!(matches!(app.path_status, Some(PathStatus::Invalid { .. })));
    }

    #[test]
    fn a_crl_cannot_be_marked_trusted() {
        let mut app = open_real_file(&chain("server.der"));
        browser_select_by_name(&mut app, "root_crl.der");
        app.toggle_trust();
        assert!(app.trusted_certs.is_empty(), "a CRL is not a certificate");
        assert!(app.status.contains("not a certificate"), "{}", app.status);
    }

    #[test]
    fn a_non_certificate_document_has_no_path_status() {
        let app = open_real_file(std::path::Path::new("testdata/private_key_pkcs8.der"));
        assert!(app.path_status.is_none());
    }

    #[test]
    fn resign_dialog_reports_a_missing_issuer_key() {
        // A folder with the certificate but no key at all.
        let dir = tmp_dir("resign-nokey");
        std::fs::copy(kl("cert_ec.der"), dir.join("cert.der")).unwrap();
        let mut app = open_real_file(&dir.join("cert.der"));
        app.start_resign();
        let Mode::Resign(ref state) = app.mode else { panic!("re-sign dialog") };
        assert!(!state.ready, "no key present");
        app.submit_resign();
        // Confirming an unavailable re-sign changes nothing.
        assert!(!app.dirty);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("asn1-editor-app-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn new_dir_starts_with_no_document_and_browser_focus() {
        let dir = tmp_dir("newdir");
        std::fs::write(dir.join("a.der"), [0x05, 0x00]).unwrap();
        let app = App::new_dir(dir.clone());
        assert!(!app.file_open);
        assert!(app.rows.is_empty());
        assert!(app.selected_node().is_none());
        assert_eq!(app.focus, Focus::Browser);
        assert!(!app.browser.rows.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_and_insert_are_refused_without_a_file() {
        let dir = tmp_dir("noguard");
        let mut app = App::new_dir(dir.clone());
        app.save();
        assert!(app.status.contains("no file open"));
        app.start_insert(false);
        assert!(matches!(app.mode, Mode::Browse));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn activate_browser_entry_opens_file_and_switches_focus() {
        let dir = tmp_dir("openfile");
        std::fs::write(dir.join("a.der"), [0x05, 0x00]).unwrap(); // NULL
        let mut app = App::new_dir(dir.clone());
        app.browser.select(0); // "a.der" is the only entry
        app.activate_browser_entry();
        assert!(app.file_open);
        assert_eq!(app.focus, Focus::Document);
        assert_eq!(app.rows.len(), 1);
        assert!(app.selected_node().unwrap().is_universal(ber::TAG_NULL));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn activate_browser_entry_warns_before_discarding_unsaved_changes() {
        let dir = tmp_dir("confirm");
        std::fs::write(dir.join("a.der"), [0x05, 0x00]).unwrap();
        std::fs::write(dir.join("b.der"), [0x05, 0x00]).unwrap();
        let mut app = App::new_dir(dir.clone());
        app.browser.select(0); // "a.der"
        app.activate_browser_entry(); // open it
        app.dirty = true; // simulate an unsaved edit
        app.browser.select(1); // "b.der"
        app.activate_browser_entry(); // first Enter: only arms the confirmation
        assert!(app.open_confirm);
        assert!(app.path.ends_with("a.der"), "still on the original file");
        app.activate_browser_entry(); // second Enter: discards and opens
        assert!(app.path.ends_with("b.der"));
        assert!(!app.dirty);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn preview_loads_the_highlighted_file_without_changing_focus() {
        let dir = tmp_dir("preview");
        std::fs::write(dir.join("a.der"), [0x05, 0x00]).unwrap(); // NULL
        std::fs::write(dir.join("b.der"), [0x02, 0x01, 0x07]).unwrap(); // INTEGER 7
        let mut app = App::new_dir(dir.clone());
        assert_eq!(app.focus, Focus::Browser);

        app.browser.select(0); // "a.der"
        app.preview_browser_selection();
        assert!(app.file_open);
        assert!(app.path.ends_with("a.der"));
        assert!(app.selected_node().unwrap().is_universal(ber::TAG_NULL));
        assert_eq!(app.focus, Focus::Browser, "preview must not steal focus");

        app.browser.select(1); // "b.der"
        app.preview_browser_selection();
        assert!(app.path.ends_with("b.der"));
        assert!(app.selected_node().unwrap().is_universal(ber::TAG_INTEGER));
        assert_eq!(app.focus, Focus::Browser);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn preview_is_a_no_op_on_directories_and_on_the_already_loaded_file() {
        let dir = tmp_dir("preview-noop");
        std::fs::create_dir(dir.join("sub")).unwrap();
        // SEQUENCE { INTEGER 1, INTEGER 2 } — two rows, so a non-zero
        // document-pane selection is possible to check for a reset.
        std::fs::write(dir.join("a.der"), [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]).unwrap();
        let mut app = App::new_dir(dir.clone());

        app.browser.select(0); // "sub" (dirs sort first)
        app.preview_browser_selection();
        assert!(!app.file_open, "hovering a directory must not load anything");

        app.browser.select(1); // "a.der"
        app.preview_browser_selection();
        assert!(app.file_open);
        assert_eq!(app.rows.len(), 3); // SEQUENCE + 2 children
        app.select(2); // move the document-pane selection off the default
        app.preview_browser_selection(); // same file still highlighted: must be a true no-op
        assert_eq!(app.selected, 2, "re-preview must not reset the document selection");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn preview_does_not_discard_unsaved_changes() {
        let dir = tmp_dir("preview-dirty");
        std::fs::write(dir.join("a.der"), [0x05, 0x00]).unwrap();
        std::fs::write(dir.join("b.der"), [0x02, 0x01, 0x07]).unwrap();
        let mut app = App::new_dir(dir.clone());
        app.browser.select(0); // "a.der"
        app.preview_browser_selection();
        app.dirty = true; // simulate an unsaved edit

        app.browser.select(1); // "b.der"
        app.preview_browser_selection();
        assert!(app.path.ends_with("a.der"), "must not discard unsaved edits just by moving the cursor");
        assert!(app.dirty);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enter_on_the_previewed_file_only_switches_focus() {
        let dir = tmp_dir("enter-fastpath");
        std::fs::write(dir.join("a.der"), [0x05, 0x00]).unwrap();
        let mut app = App::new_dir(dir.clone());
        app.browser.select(0);
        app.preview_browser_selection(); // as tui.rs would do on ↑↓
        assert_eq!(app.focus, Focus::Browser);

        app.activate_browser_entry();
        assert_eq!(app.focus, Focus::Document);
        assert!(app.path.ends_with("a.der"));
    }

    fn open_real_file(path: &std::path::Path) -> App {
        let raw = std::fs::read(path).unwrap();
        let (der, container) = input::load(&raw).unwrap();
        let roots = ber::parse_forest(&der, 0).unwrap();
        App::new(path.to_path_buf(), path.to_path_buf(), container, roots, der.len())
    }

    fn row_of(app: &App, path: &[usize]) -> usize {
        app.rows
            .iter()
            .position(|r| r.source == RowSource::Document && r.path == path)
            .expect("document row exists")
    }

    fn row_of_source(app: &App, source: RowSource, path: &[usize]) -> usize {
        app.rows
            .iter()
            .position(|r| r.source == source && r.path == path)
            .expect("row exists")
    }

    fn decrypt_test_key(app: &mut App) {
        app.start_decrypt();
        let Mode::Password(ref mut p) = app.mode else { panic!("password prompt not open") };
        for c in "asn1editor".chars() {
            p.insert_char(c);
        }
        app.submit_password();
    }

    #[test]
    fn editing_the_open_document_refreshes_its_own_signature_status() {
        let dir = tmp_dir("live-status");
        std::fs::copy("testdata/chain/intermediate_ca.der", dir.join("intermediate_ca.der")).unwrap();
        std::fs::copy("testdata/chain/server.der", dir.join("server.der")).unwrap();

        let mut app = open_real_file(&dir.join("server.der"));
        assert!(
            matches!(app.sig_status, Some(SignatureStatus::Verified { .. })),
            "starts out verified against the intermediate CA in the same folder"
        );

        // Corrupt the outer `signature` BIT STRING (path [0, 2] of a
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
        // signature }) through the real edit path (select, hex-edit,
        // commit) rather than poking internal fields.
        app.select(row_of(&app, &[0, 2]));
        let node = app.selected_node().unwrap();
        assert!(node.is_universal(ber::TAG_BIT_STRING));
        let mut corrupted = node.content_octets();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xFF;
        app.mode = Mode::Edit(EditState::hex(EditKind::Content, &corrupted));
        app.commit_edit();

        assert!(app.dirty);
        assert!(
            matches!(app.sig_status, Some(SignatureStatus::Invalid { .. })),
            "must reflect the corruption immediately, without saving"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn editing_a_document_refreshes_relation_arrows_for_other_selected_browser_files() {
        // Reproduces the reported bug: editing the *open* document (in the
        // Document pane) must refresh the relation arrows shown for
        // whichever *other* file the Browser pane happens to have
        // selected — the two are independent, and the arrows are derived
        // from the same shared index the edit needs to invalidate.
        let dir = tmp_dir("live-relations");
        std::fs::copy("testdata/chain/intermediate_ca.der", dir.join("intermediate_ca.der")).unwrap();
        std::fs::copy("testdata/chain/server.der", dir.join("server.der")).unwrap();

        let mut app = open_real_file(&dir.join("server.der")); // the leaf is open...
        let ca_row = app
            .browser
            .rows
            .iter()
            .position(|r| app.browser.entry_at(&r.path).unwrap().name == "intermediate_ca.der")
            .expect("intermediate_ca.der is in the browser");
        app.browser.select(ca_row); // ...but the browser points at its issuer.
        app.recompute_browser_relations();
        assert_eq!(app.browser_relations.signs.len(), 1);
        assert!(app.browser_relations.signs[0].verified, "starts out verified");

        app.select(row_of(&app, &[0, 2])); // the leaf's `signature` BIT STRING
        let node = app.selected_node().unwrap();
        let mut corrupted = node.content_octets();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xFF;
        app.mode = Mode::Edit(EditState::hex(EditKind::Content, &corrupted));
        app.commit_edit(); // browser selection never moves during this edit

        assert_eq!(app.browser_relations.signs.len(), 1);
        assert!(
            !app.browser_relations.signs[0].verified,
            "the intermediate's outgoing arrow must go red without any navigation"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decrypt_prompts_then_reveals_the_private_key() {
        let mut app = open_real_file(std::path::Path::new("testdata/enc_pkcs8.der"));
        let placeholder = row_of_source(&app, RowSource::DecryptedPlaceholder, &[0, 1]);
        assert_eq!(app.rows[placeholder].depth, app.rows[row_of(&app, &[0, 1])].depth + 1);
        // 'z' recognizes the encrypted key and opens the password prompt.
        decrypt_test_key(&mut app);
        assert!(matches!(app.mode, Mode::Browse));
        let dec = app.decrypted.as_ref().expect("decrypted");
        assert_eq!(dec.encrypted_path, [0, 1]);
        // The plaintext is a real PrivateKeyInfo (single SEQUENCE).
        let inner = ber::parse_forest(&dec.plaintext, 0).unwrap();
        assert_eq!(inner.len(), 1);
        assert!(inner[0].is_universal(ber::TAG_SEQUENCE));
        assert!(app
            .rows
            .iter()
            .any(|r| r.source == RowSource::Decrypted && r.path == [0]));
        assert!(!app.rows.iter().any(|r| r.source == RowSource::DecryptedPlaceholder));

        let before = app.rows.len();
        app.select(row_of_source(&app, RowSource::Decrypted, &[0]));
        app.toggle_expand();
        assert!(app.rows.len() < before, "the virtual root must be foldable");
    }

    #[test]
    fn decrypt_with_wrong_password_reports_error() {
        let mut app = open_real_file(std::path::Path::new("testdata/enc_pkcs8.der"));
        app.start_decrypt();
        if let Mode::Password(ref mut p) = app.mode {
            p.insert_char('n');
            p.insert_char('o');
        }
        app.submit_password();
        assert!(matches!(app.mode, Mode::Browse));
        assert!(app.decrypted.is_none());
        assert!(app.status.contains("wrong password") || app.status.contains("failed"));
    }

    #[test]
    fn decrypt_on_a_non_encrypted_non_signed_file_is_a_no_op_with_message() {
        // A plaintext private key is neither an encrypted container nor a
        // signed object, so 'z' does nothing but report that.
        let mut app = open_real_file(std::path::Path::new("testdata/private_key_pkcs8.der"));
        app.start_decrypt();
        assert!(matches!(app.mode, Mode::Browse), "no dialog for a plaintext key");
        assert!(app.decrypted.is_none());
        assert!(app.status.contains("not an encrypted key"), "{}", app.status);
    }

    #[test]
    fn editing_decrypted_content_reencrypts_and_updates_the_outer_tree() {
        let mut app = open_real_file(std::path::Path::new("testdata/enc_pkcs8.der"));
        decrypt_test_key(&mut app);
        let old_ciphertext = app.node_at(&[0, 1]).unwrap().value.clone();
        let old_iv = app.node_at(&[0, 0, 1, 1, 1]).unwrap().value.clone();

        app.select(row_of_source(&app, RowSource::Decrypted, &[0, 0]));
        app.mode = Mode::Edit(EditState::hex(EditKind::Content, &[1]));
        app.commit_edit();

        let decrypted = app.decrypted.as_ref().expect("decryption remains available");
        assert_eq!(node_at(&decrypted.roots, &[0, 0]).unwrap().value, [1]);
        assert_ne!(app.node_at(&[0, 1]).unwrap().value, old_ciphertext);
        assert_ne!(app.node_at(&[0, 0, 1, 1, 1]).unwrap().value, old_iv);
        let encrypted = pkcs8::parse(&app.roots).unwrap().unwrap();
        assert_eq!(encrypted.decrypt(b"asn1editor").unwrap(), decrypted.plaintext);
    }

    #[test]
    fn editing_encrypted_content_refreshes_the_virtual_tree() {
        let mut app = open_real_file(std::path::Path::new("testdata/enc_pkcs8.der"));
        decrypt_test_key(&mut app);

        let encrypted = pkcs8::parse(&app.roots).unwrap().unwrap();
        let mut plaintext_roots = app.decrypted.as_ref().unwrap().roots.clone();
        plaintext_roots[0].children[0].value = vec![1];
        let plaintext = ber::encode_forest(&plaintext_roots);
        let ciphertext = encrypted
            .encrypt_with_current_iv(b"asn1editor", &plaintext)
            .unwrap();

        app.select(row_of(&app, &[0, 1]));
        app.mode = Mode::Edit(EditState::hex(EditKind::Content, &ciphertext));
        app.commit_edit();

        let decrypted = app.decrypted.as_ref().expect("ciphertext is decrypted again");
        assert_eq!(decrypted.plaintext, plaintext);
        assert_eq!(node_at(&decrypted.roots, &[0, 0]).unwrap().value, [1]);
    }

    // ---- public-key modification ('e' on subjectPublicKeyInfo) -----------

    /// Copy the committed `testdata/chain` hierarchy into a fresh scratch
    /// directory so key generation and resigning write there, not the repo.
    fn copy_chain(name: &str) -> PathBuf {
        let dir = tmp_dir(name);
        for entry in std::fs::read_dir("testdata/chain").unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                std::fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
            }
        }
        dir
    }

    fn spki_row(app: &App) -> usize {
        let paths = cert_paths(&app.roots).expect("open document is a certificate");
        row_of_source(app, RowSource::Document, &paths.spki)
    }

    fn cert_pubkey(path: &Path) -> (Vec<u64>, Vec<u8>) {
        let (der, _) = input::load(&std::fs::read(path).unwrap()).unwrap();
        let roots = ber::parse_forest(&der, 0).unwrap();
        let s = x509::parse_signable(&roots, &der).unwrap();
        (s.sig_alg, s.pubkey.unwrap())
    }

    /// Verify the certificate file at `path` under the public key `pubkey`.
    fn cert_verifies_under(path: &Path, pubkey: &[u8]) -> bool {
        let (der, _) = input::load(&std::fs::read(path).unwrap()).unwrap();
        let roots = ber::parse_forest(&der, 0).unwrap();
        let s = x509::parse_signable(&roots, &der).unwrap();
        verify::verify_signature(&s.sig_alg, pubkey, &s.tbs, &s.signature)
    }

    #[test]
    fn pressing_e_on_the_spki_opens_the_public_key_dialog() {
        let dir = copy_chain("pk-open");
        let mut app = open_real_file(&dir.join("root_ca.der"));
        // On a non-SPKI primitive element, 'e' still does the ordinary value
        // edit (the serialNumber INTEGER).
        let serial = cert_paths(&app.roots).unwrap().serial;
        app.select(row_of(&app, &serial));
        app.edit_selected();
        assert!(matches!(app.mode, Mode::Edit(_)));
        app.cancel_edit();
        // On the subjectPublicKeyInfo, it opens the modification dialog.
        app.select(spki_row(&app));
        app.edit_selected();
        let Mode::EditPubKey(ref s) = app.mode else { panic!("public-key dialog expected") };
        // The self-signed root issued the intermediate (a cert) and the root
        // CRL: certificates come first, CRLs at the end, each with a suffix.
        let entries: Vec<(&str, &str)> =
            s.issued.iter().map(|c| (c.name.as_str(), c.detail.as_str())).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "intermediate_ca.der");
        assert!(entries[0].1.starts_with('#'), "a certificate shows its serial");
        assert_eq!(entries[1], ("root_crl.der", "CRL"));
        assert!(s.issued.iter().all(|c| c.selected), "issued objects are checked by default");
        assert!(s.generate, "generate is on by default");
        assert!(s.filename.contains("p256")); // first algorithm's short name
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_edit_menu_on_the_spki_offers_rekeying() {
        let dir = copy_chain("pk-emenu");
        let mut app = open_real_file(&dir.join("root_ca.der"));
        // 'E' on an ordinary element: no re-key entry.
        app.select(row_of(&app, &cert_paths(&app.roots).unwrap().serial));
        app.open_edit_menu();
        let Mode::EditMenu(ref m) = app.mode else { panic!("edit menu") };
        assert!(!m.items.iter().any(|i| i.action == MenuAction::Rekey));
        app.cancel_menu();
        // 'E' on the subjectPublicKeyInfo: a trailing "Re-key this cert" entry
        // that opens the public-key dialog.
        app.select(spki_row(&app));
        app.open_edit_menu();
        let last = if let Mode::EditMenu(ref mut m) = app.mode {
            assert_eq!(m.items.last().unwrap().action, MenuAction::Rekey);
            let last = m.items.len() - 1;
            m.selected = last;
            last
        } else {
            panic!("edit menu");
        };
        assert_eq!(last, EDIT_MENU.len(), "re-key is the trailing entry after the base modes");
        app.menu_confirm();
        assert!(matches!(app.mode, Mode::EditPubKey(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekeying_also_resigns_a_selected_issued_crl() {
        let dir = copy_chain("pk-crl");
        let mut app = open_real_file(&dir.join("root_ca.der"));
        app.start_rekey();
        if let Mode::EditPubKey(ref mut s) = app.mode {
            s.alg_idx = keygen::ALL.iter().position(|a| *a == keygen::KeyAlgorithm::Ed25519).unwrap();
            s.filename = "root_crlkey.key".to_string();
            s.filename_auto = false;
            // Everything (the cert and the CRL) stays checked by default.
            assert!(s.issued.iter().any(|c| c.name == "root_crl.der"));
        }
        app.submit_pubkey();
        // The root CRL was resigned under the new key with the new algorithm,
        // and verifies against the certificate's new public key.
        let der = ber::encode_forest(&app.roots);
        let s = x509::parse_signable(&app.roots, &der).unwrap();
        let root_pubkey = s.pubkey.clone().unwrap();
        let crl = dir.join("root_crl.der");
        let (crl_der, _) = input::load(&std::fs::read(&crl).unwrap()).unwrap();
        let crl_roots = ber::parse_forest(&crl_der, 0).unwrap();
        let crl_signable = x509::parse_signable(&crl_roots, &crl_der).unwrap();
        assert_eq!(crl_signable.kind, Kind::Crl);
        assert_eq!(crl_signable.sig_alg, keygen::KeyAlgorithm::Ed25519.sig_alg_oid());
        assert!(verify::verify_signature(
            &crl_signable.sig_alg,
            &root_pubkey,
            &crl_signable.tbs,
            &crl_signable.signature
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekeying_a_self_signed_ca_resigns_it_and_its_issued_cert() {
        let dir = copy_chain("pk-rekey");
        let mut app = open_real_file(&dir.join("root_ca.der"));
        app.select(spki_row(&app));
        app.edit_selected();
        // Choose Ed25519 (fast), keep generate on, plaintext key.
        if let Mode::EditPubKey(ref mut s) = app.mode {
            s.alg_idx = keygen::ALL.iter().position(|a| *a == keygen::KeyAlgorithm::Ed25519).unwrap();
            s.filename = "root_new.key".to_string();
            s.filename_auto = false;
        }
        app.submit_pubkey();
        assert!(matches!(app.mode, Mode::Browse));
        assert!(app.dirty, "the rekeyed certificate is left unsaved");

        // The key file was written and is a usable plaintext PKCS#8.
        let key_path = dir.join("root_new.key");
        assert!(key_path.exists());
        assert!(read_plaintext_key_pkcs8(&key_path).is_some());

        // The open certificate now carries the new key and, being self-signed,
        // verifies under it. Save it so the on-disk copy matches.
        let new_pubkey = x509::public_key_id_of_signable(
            &x509::parse_signable(&app.roots, &ber::encode_forest(&app.roots)).unwrap(),
        )
        .unwrap();
        let der = ber::encode_forest(&app.roots);
        let s = x509::parse_signable(&app.roots, &der).unwrap();
        assert_eq!(s.sig_alg, keygen::KeyAlgorithm::Ed25519.sig_alg_oid());
        assert!(verify::verify_signature(&s.sig_alg, s.pubkey.as_ref().unwrap(), &s.tbs, &s.signature));
        app.save();

        // The issued intermediate was resigned on disk under the new key, with
        // the new signature algorithm.
        let inter = dir.join("intermediate_ca.der");
        let (inter_alg, _) = cert_pubkey(&inter);
        assert_eq!(inter_alg, keygen::KeyAlgorithm::Ed25519.sig_alg_oid());
        let root_pubkey_bytes = s.pubkey.clone().unwrap();
        assert!(cert_verifies_under(&inter, &root_pubkey_bytes), "intermediate verifies under new root key");

        // The new key registered for links matches the certificate's new key.
        assert!(app.key_files.iter().any(|k| k.path == key_path && k.key == new_pubkey));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_password_writes_an_encrypted_key_that_still_signs() {
        let dir = copy_chain("pk-enc");
        let mut app = open_real_file(&dir.join("root_ca.der"));
        app.select(spki_row(&app));
        app.edit_selected();
        if let Mode::EditPubKey(ref mut s) = app.mode {
            s.alg_idx = keygen::ALL.iter().position(|a| *a == keygen::KeyAlgorithm::Ed25519).unwrap();
            s.filename = "root_enc.key".to_string();
            s.filename_auto = false;
            s.password = "hunter2".to_string();
        }
        app.submit_pubkey();

        // The written key is an EncryptedPrivateKeyInfo openable with the
        // password, and its decrypted form matches the certificate's new key.
        let key_path = dir.join("root_enc.key");
        let (kder, _) = input::load(&std::fs::read(&key_path).unwrap()).unwrap();
        let kroots = ber::parse_forest(&kder, 0).unwrap();
        let enc = pkcs8::parse(&kroots).unwrap().expect("encrypted key");
        let plain = enc.decrypt(b"hunter2").unwrap();
        // The decrypted key is the certificate's key pair: a signature it makes
        // verifies under the certificate's new public key. (An Ed25519 private
        // key alone carries no public part, so we prove the pairing by signing.)
        let der = ber::encode_forest(&app.roots);
        let s = x509::parse_signable(&app.roots, &der).unwrap();
        let msg = b"pairing proof";
        let sig = verify::sign(&s.sig_alg, &plain, msg).unwrap();
        assert!(verify::verify_signature(&s.sig_alg, s.pubkey.as_ref().unwrap(), msg, &sig));
        // An encrypted key is registered as unlocked, with its password retained.
        assert!(app.unlocked_keys.iter().any(|(p, _)| *p == key_path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refusing_to_overwrite_an_existing_key_file() {
        let dir = copy_chain("pk-exists");
        let mut app = open_real_file(&dir.join("root_ca.der"));
        std::fs::write(dir.join("taken.key"), b"do not clobber me").unwrap();
        app.select(spki_row(&app));
        app.edit_selected();
        if let Mode::EditPubKey(ref mut s) = app.mode {
            s.filename = "taken.key".to_string();
            s.filename_auto = false;
        }
        app.submit_pubkey();
        // The dialog stays open and nothing was overwritten.
        assert!(matches!(app.mode, Mode::EditPubKey(_)));
        assert!(app.status.contains("already exists"));
        assert_eq!(std::fs::read(dir.join("taken.key")).unwrap(), b"do not clobber me");
        assert!(!app.dirty);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn not_generating_still_rekeys_but_writes_no_key_file() {
        let dir = copy_chain("pk-nogen");
        let mut app = open_real_file(&dir.join("root_ca.der"));
        app.select(spki_row(&app));
        app.edit_selected();
        let filename = if let Mode::EditPubKey(ref mut s) = app.mode {
            s.alg_idx = keygen::ALL.iter().position(|a| *a == keygen::KeyAlgorithm::Ed25519).unwrap();
            s.generate = false;
            s.filename.clone()
        } else {
            panic!("dialog");
        };
        app.submit_pubkey();
        // No key file was written, but the certificate was rekeyed (dirty) and
        // its self-signature still verifies under the discarded key.
        assert!(!dir.join(&filename).exists());
        assert!(app.dirty);
        let der = ber::encode_forest(&app.roots);
        let s = x509::parse_signable(&app.roots, &der).unwrap();
        assert!(verify::verify_signature(&s.sig_alg, s.pubkey.as_ref().unwrap(), &s.tbs, &s.signature));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
