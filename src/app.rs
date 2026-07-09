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

use crate::ber::{self, Node};
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
    /// Insert one or more new elements, typed as complete TLV encodings,
    /// at position `index` of `parent`'s children (`parent` empty = top
    /// level).
    Insert { parent: Vec<usize>, index: usize },
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
    /// the first child of the selected constructed element. The new
    /// element is typed in the hex editor as a complete TLV encoding.
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
        self.mode = Mode::Edit(EditState {
            kind: EditKind::Insert { parent, index },
            digits: Vec::new(),
            cursor: 0,
            scroll: 0,
        });
        self.status =
            "inserting: type the complete TLV encoding (tag, length, value) in hex".to_string();
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

        if let EditKind::Insert { parent, index } = edit.kind.clone() {
            self.commit_insert(&bytes, parent, index);
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

    /// Apply an `EditKind::Insert` edit: the typed bytes must be one or
    /// more complete TLV encodings; they become new children of `parent`
    /// starting at `index`.
    fn commit_insert(&mut self, bytes: &[u8], parent: Vec<usize>, index: usize) {
        let new_nodes = match ber::parse_forest(bytes, 0) {
            Ok(nodes) if !nodes.is_empty() => nodes,
            Ok(_) => {
                self.status =
                    "nothing to insert — type a complete TLV encoding (e.g. 0500 for NULL)"
                        .to_string();
                return;
            }
            Err(e) => {
                self.status = format!("rejected: not a valid TLV encoding ({})", e);
                return;
            }
        };
        let count = new_nodes.len();
        if parent.is_empty() {
            self.roots.splice(index..index, new_nodes);
        } else {
            let Some(p) = node_at_mut(&mut self.roots, &parent) else { return };
            p.children.splice(index..index, new_nodes);
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
            "inserted {} element{} — 's' writes the file",
            count,
            if count == 1 { "" } else { "s" }
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

    #[test]
    fn insert_sibling_after_selected() {
        // SEQUENCE { INTEGER 1 }
        let data = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut app = test_app(&data);
        app.select(1); // INTEGER
        app.start_insert(false);
        let Mode::Edit(ref mut edit) = app.mode else { panic!("not in edit mode") };
        edit.digits = "0500".chars().collect(); // NULL
        app.commit_edit();
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
        let Mode::Edit(ref mut edit) = app.mode else { panic!("not in edit mode") };
        edit.digits = "020107".chars().collect(); // INTEGER 7
        app.commit_edit();
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
    fn insert_rejects_incomplete_tlv() {
        let data = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut app = test_app(&data);
        app.select(1);
        app.start_insert(false);
        let Mode::Edit(ref mut edit) = app.mode else { panic!("not in edit mode") };
        edit.digits = "05".chars().collect(); // missing length octet
        app.commit_edit();
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
        let Mode::Edit(ref mut edit) = app.mode else { panic!("not in edit mode") };
        // Two top-level elements at once.
        edit.digits = "02010A0500".chars().collect();
        app.commit_edit();
        assert_eq!(ber::encode_forest(&app.roots), [0x02, 0x01, 0x0A, 0x05, 0x00]);
        assert_eq!(app.rows.len(), 2);
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
