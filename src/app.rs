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

/// Universal tag numbers offered by the picker's tag column.
pub const PICKER_UNIVERSAL: [(u32, &str); 17] = [
    (1, "BOOLEAN"),
    (2, "INTEGER"),
    (3, "BIT STRING"),
    (4, "OCTET STRING"),
    (5, "NULL"),
    (6, "OBJECT IDENTIFIER"),
    (10, "ENUMERATED"),
    (12, "UTF8String"),
    (16, "SEQUENCE"),
    (17, "SET"),
    (18, "NumericString"),
    (19, "PrintableString"),
    (22, "IA5String"),
    (23, "UTCTime"),
    (24, "GeneralizedTime"),
    (26, "VisibleString"),
    (30, "BMPString"),
];

/// State of the "choose ASN.1 type" popup shown by the insert actions.
/// One column per bit field of the identifier octet: class (bits 8-7),
/// form (bit 6, primitive/constructed) and tag number (bits 5-1).
pub struct PickerState {
    pub parent: Vec<usize>,
    pub index: usize,
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
    fn new(parent: Vec<usize>, index: usize) -> Self {
        PickerState {
            parent,
            index,
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
    /// Hex digits typed so far (no spaces, upper/lower as typed).
    pub digits: Vec<char>,
    /// Cursor position in `digits` (0..=len).
    pub cursor: usize,
    /// First visible editor line, kept up to date by the renderer.
    pub scroll: usize,
}

pub enum Mode {
    Browse,
    /// Type-picker popup of the insert actions.
    TypePicker(PickerState),
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
        };
        app.rebuild_rows();
        app
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
        let digits: Vec<char> = ber::hex_pairs(&node.content_octets())
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        self.mode = Mode::Edit(EditState { kind: EditKind::Content, digits, cursor: 0, scroll: 0 });
        self.status =
            "editing content octets — type hex digits, Enter applies, Esc cancels".to_string();
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
        self.mode = Mode::TypePicker(PickerState::new(parent, index));
        self.status = "choose the type of the new element".to_string();
    }

    pub fn cancel_picker(&mut self) {
        self.mode = Mode::Browse;
        self.status = "insert cancelled".to_string();
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

    /// Enter in the picker: proceed to value entry for the chosen type.
    pub fn picker_confirm(&mut self) {
        let Mode::TypePicker(ref p) = self.mode else { return };
        let (class, constructed, tag) = (p.class(), p.constructed(), p.tag());
        let kind = EditKind::Insert {
            parent: p.parent.clone(),
            index: p.index,
            class,
            constructed,
            tag,
        };
        self.mode = Mode::Edit(EditState { kind, digits: Vec::new(), cursor: 0, scroll: 0 });
        self.status = format!(
            "value for new {} — hex content octets (may stay empty), Enter inserts",
            ber::type_name_of(class, tag),
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
        if edit.digits.len() % 2 != 0 {
            self.status = "odd number of hex digits — add or remove one".to_string();
            return;
        }
        let hex: String = edit.digits.iter().collect();
        let bytes = match input::hex_decode(&hex) {
            Ok(b) => b,
            Err(e) => {
                self.status = format!("invalid hex: {}", e);
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
        app.mode = Mode::Edit(EditState {
            kind: EditKind::Content,
            digits: "010203".chars().collect(),
            cursor: 0,
            scroll: 0,
        });
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
        app.mode = Mode::Edit(EditState {
            kind: EditKind::Content,
            digits: "05".chars().collect(), // truncated TLV
            cursor: 0,
            scroll: 0,
        });
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
        edit.digits = hex.chars().collect();
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

    #[test]
    fn edit_octet_string_redetects_encapsulation() {
        let data = [0x04, 0x02, 0xAA, 0xBB];
        let mut app = test_app(&data);
        app.select(0);
        // New content is a complete nested INTEGER.
        app.mode = Mode::Edit(EditState {
            kind: EditKind::Content,
            digits: "02021234".chars().collect(),
            cursor: 0,
            scroll: 0,
        });
        app.commit_edit();
        let node = app.node_at(&[0]).unwrap();
        assert!(node.encapsulates);
        assert_eq!(node.children.len(), 1);
    }
}
