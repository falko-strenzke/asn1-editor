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

use std::path::PathBuf;

use ratatui::widgets::ListState;

use crate::ber::{self, Class, Node};
use crate::input::{self, Container};
use crate::spec::{self, Identification, Label, SpecDb};

/// Bytes per line in the hex editor; the cursor moves in units of hex digits.
pub const EDIT_BYTES_PER_LINE: usize = 16;
pub const EDIT_DIGITS_PER_LINE: usize = EDIT_BYTES_PER_LINE * 2;

/// One visible line of the tree pane: the path of child indices from the
/// root forest down to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub path: Vec<usize>,
    pub depth: usize,
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
    Insert { parent: Vec<usize>, index: usize, class: Class, constructed: bool, tag: u32 },
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
    Insert { parent: Vec<usize>, index: usize },
    /// Change the type of the existing element at `path`, keeping its
    /// content octets.
    Retag { path: Vec<usize> },
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
        TextFormat::Integer => {
            let v: i128 = s
                .trim()
                .parse()
                .map_err(|_| "not a valid decimal integer".to_string())?;
            Ok(ber::encode_integer(v))
        }
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

/// Entries of the edit-mode menu opened with 'E'.
pub const EDIT_MENU: [(&str, &str); 5] = [
    ("Tag type", "change class / form / tag number of the element"),
    ("Hex", "edit the content octets as hex digits"),
    ("Base64", "edit the content octets as base64 text"),
    ("Raw binary", "characters become bytes verbatim (paste-friendly)"),
    ("Type specific", "number, OID, text, TRUE/FALSE, date/time fields …"),
];

pub struct MenuState {
    pub selected: usize,
}

pub enum Mode {
    Browse,
    /// Type-picker popup of the insert and retag actions.
    TypePicker(PickerState),
    /// Edit-mode chooser popup ('E').
    EditMenu(MenuState),
    Edit(EditState),
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
}

impl App {
    pub fn new(
        path: PathBuf,
        out_path: PathBuf,
        container: Container,
        roots: Vec<Node>,
        total_len: usize,
    ) -> Self {
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
        };
        app.rebuild_rows();
        app
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
    }

    /// Spec label of the node at `path`, if the document was identified.
    pub fn label_at(&self, path: &[usize]) -> Option<&Label> {
        self.ident.as_ref().and_then(|i| i.labels.get(path))
    }

    pub fn node_at(&self, path: &[usize]) -> Option<&Node> {
        node_at(&self.roots, path)
    }

    pub fn selected_node(&self) -> Option<&Node> {
        let row = self.rows.get(self.selected)?;
        node_at(&self.roots, &row.path)
    }

    pub fn selected_node_mut(&mut self) -> Option<&mut Node> {
        let path = self.rows.get(self.selected)?.path.clone();
        node_at_mut(&mut self.roots, &path)
    }

    pub fn rebuild_rows(&mut self) {
        let mut rows = Vec::new();
        for (i, node) in self.roots.iter().enumerate() {
            collect_rows(node, vec![i], &mut rows);
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
        } else if row.path.len() > 1 {
            let parent = &row.path[..row.path.len() - 1];
            if let Some(i) = self.rows.iter().position(|r| r.path == parent) {
                self.select(i);
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

    pub fn start_edit(&mut self) {
        let Some(node) = self.selected_node() else { return };
        self.mode = Mode::Edit(EditState::hex(EditKind::Content, &node.content_octets()));
        self.status =
            "editing content octets — type hex digits, Enter applies, Esc cancels".to_string();
    }

    /// 'E' opens the edit-mode menu for the selected element.
    pub fn open_edit_menu(&mut self) {
        if self.selected_node().is_none() {
            return;
        }
        self.mode = Mode::EditMenu(MenuState { selected: 0 });
        self.status = "choose how to edit the selected element".to_string();
    }

    pub fn cancel_menu(&mut self) {
        self.mode = Mode::Browse;
        self.status = "cancelled".to_string();
    }

    pub fn menu_move(&mut self, delta: isize) {
        if let Mode::EditMenu(ref mut m) = self.mode {
            m.selected = (m.selected as isize + delta)
                .rem_euclid(EDIT_MENU.len() as isize) as usize;
        }
    }

    pub fn menu_confirm(&mut self) {
        let Mode::EditMenu(ref m) = self.mode else { return };
        match m.selected {
            0 => self.start_retag(),
            1 => self.start_edit(),
            2 => self.start_edit_base64(),
            3 => self.start_edit_raw(),
            _ => self.start_edit_type_specific(),
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
                    let initial = ber::decode_integer(v).map(|i| i.to_string()).unwrap_or_default();
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
        let (parent, index) = if self.rows.is_empty() {
            (Vec::new(), 0) // empty document: insert the first top-level element
        } else {
            let path = self.rows[self.selected].path.clone();
            if as_child {
                let Some(node) = self.selected_node() else { return };
                if !node.constructed && !node.encapsulates {
                    self.status =
                        "cannot insert a child into a primitive element (use 'i' for a sibling)"
                            .to_string();
                    return;
                }
                (path, 0)
            } else {
                let (last, parent) = path.split_last().expect("row paths are non-empty");
                (parent.to_vec(), last + 1)
            }
        };
        self.mode = Mode::TypePicker(PickerState::new(PickerTarget::Insert { parent, index }));
        self.status = "choose the type of the new element".to_string();
    }

    /// 'E' opens the type-picker dialog for the selected element,
    /// pre-populated with its current type; confirming changes the
    /// identifier octets while keeping the content octets.
    pub fn start_retag(&mut self) {
        let Some(row) = self.rows.get(self.selected) else { return };
        let path = row.path.clone();
        let Some(node) = self.selected_node() else { return };
        let mut p = PickerState::new(PickerTarget::Retag { path });
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
            PickerTarget::Insert { parent, index } => {
                let kind = EditKind::Insert { parent, index, class, constructed, tag };
                self.mode = Mode::Edit(EditState::hex(kind, &[]));
                self.status = format!(
                    "value for new {} — hex content octets (may stay empty), Enter inserts",
                    ber::type_name_of(class, tag),
                );
            }
            PickerTarget::Retag { path } => self.apply_retag(&path, class, constructed, tag),
        }
    }

    /// Give the element at `path` a new identifier (class/form/tag). The
    /// content octets are preserved; when switching to constructed form
    /// they must parse as a TLV series.
    fn apply_retag(&mut self, path: &[usize], class: Class, constructed: bool, tag: u32) {
        let Some(node) = node_at_mut(&mut self.roots, path) else { return };
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
        let (&last, parent) = row.path.split_last().expect("row paths are non-empty");
        let sibling_count = if parent.is_empty() {
            self.roots.len()
        } else {
            node_at(&self.roots, parent).map(|p| p.children.len()).unwrap_or(0)
        };
        let target = last as isize + delta;
        if target < 0 || target >= sibling_count as isize {
            self.status = "element is already at the edge of its parent".to_string();
            return;
        }
        let target = target as usize;
        if parent.is_empty() {
            self.roots.swap(last, target);
        } else if let Some(p) = node_at_mut(&mut self.roots, parent) {
            p.children.swap(last, target);
        }
        self.dirty = true;
        self.rebuild();
        let mut new_path = parent.to_vec();
        new_path.push(target);
        if let Some(i) = self.rows.iter().position(|r| r.path == new_path) {
            self.select(i);
        }
        self.status = "element moved — 's' writes the file".to_string();
    }

    /// Delete the selected element (two-step: the first call only arms the
    /// confirmation, the second call within the same selection deletes).
    pub fn delete_selected(&mut self) {
        let Some(row) = self.rows.get(self.selected).cloned() else { return };
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
        if parent.is_empty() {
            self.roots.remove(last);
        } else if let Some(p) = node_at_mut(&mut self.roots, parent) {
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

        if let EditKind::Insert { parent, index, class, constructed, tag } = edit.kind.clone() {
            self.commit_insert(&bytes, parent, index, class, constructed, tag);
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
        parent: Vec<usize>,
        index: usize,
        class: Class,
        constructed: bool,
        tag: u32,
    ) {
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
        if parent.is_empty() {
            self.roots.insert(index, node);
        } else {
            let Some(p) = node_at_mut(&mut self.roots, &parent) else { return };
            p.children.insert(index, node);
            p.expanded = true; // make the insertion visible
        }
        self.mode = Mode::Browse;
        self.dirty = true;
        self.rebuild();
        let mut path = parent;
        path.push(index);
        if let Some(i) = self.rows.iter().position(|r| r.path == path) {
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
        let sel_path = self.rows.get(self.selected).map(|r| r.path.clone());
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
        self.rebuild_rows();
        // Edits can make the document gain or lose conformance to a spec.
        self.identify();
        if let Some(path) = sel_path {
            if let Some(i) = self.rows.iter().position(|r| r.path == path) {
                self.select(i);
            }
        }
    }

    pub fn save(&mut self) {
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

fn collect_rows(node: &Node, path: Vec<usize>, rows: &mut Vec<Row>) {
    rows.push(Row { depth: path.len() - 1, path: path.clone() });
    if node.expanded {
        for (i, child) in node.children.iter().enumerate() {
            let mut child_path = path.clone();
            child_path.push(i);
            collect_rows(child, child_path, rows);
        }
    }
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
        assert_eq!(p.target, PickerTarget::Retag { path: vec![0] });
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
}
