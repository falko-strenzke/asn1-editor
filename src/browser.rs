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

//! Far-left file browser pane: a folding directory tree, independent of
//! whatever ASN.1 document (if any) is currently open. Mirrors the
//! flatten-visible-rows pattern used for the ASN.1 tree in `app.rs`
//! (`Row`/`collect_rows`/`node_at`), but over the filesystem instead of a
//! parsed forest, and with no editing.

use std::path::{Path, PathBuf};

use ratatui::widgets::ListState;

/// One entry in the directory tree. Directories are listed but their
/// children are only read from disk on first expansion.
pub struct Entry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub expanded: bool,
    pub children: Vec<Entry>,
    children_loaded: bool,
}

impl Entry {
    fn load_children(&mut self) {
        if !self.children_loaded {
            self.children = read_dir_sorted(&self.path);
            self.children_loaded = true;
        }
    }
}

/// One visible row of the browser pane: the path of child indices from the
/// top-level listing down to the entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub path: Vec<usize>,
    pub depth: usize,
}

pub struct FileBrowser {
    pub root: PathBuf,
    pub entries: Vec<Entry>,
    pub rows: Vec<Row>,
    pub selected: usize,
    pub list_state: ListState,
}

impl FileBrowser {
    pub fn new(root: PathBuf) -> Self {
        let entries = read_dir_sorted(&root);
        let mut browser =
            FileBrowser { root, entries, rows: Vec::new(), selected: 0, list_state: ListState::default() };
        browser.rebuild_rows();
        browser
    }

    fn rebuild_rows(&mut self) {
        let mut rows = Vec::new();
        for (i, e) in self.entries.iter().enumerate() {
            collect_rows(e, vec![i], &mut rows);
        }
        self.rows = rows;
        self.select(self.selected);
    }

    pub fn select(&mut self, index: usize) {
        if self.rows.is_empty() {
            self.selected = 0;
            self.list_state.select(None);
            return;
        }
        self.selected = index.min(self.rows.len() - 1);
        self.list_state.select(Some(self.selected));
    }

    pub fn move_by(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let i = (self.selected as isize + delta).clamp(0, self.rows.len() as isize - 1);
        self.select(i as usize);
    }

    pub fn selected_entry(&self) -> Option<&Entry> {
        let row = self.rows.get(self.selected)?;
        entry_at(&self.entries, &row.path)
    }

    /// The entry a given (visible) row points at.
    pub fn entry_at(&self, path: &[usize]) -> Option<&Entry> {
        entry_at(&self.entries, path)
    }

    fn selected_entry_mut(&mut self) -> Option<&mut Entry> {
        let path = self.rows.get(self.selected)?.path.clone();
        entry_at_mut(&mut self.entries, &path)
    }

    /// Fold/unfold the selected directory; a no-op on a file.
    pub fn toggle_expand(&mut self) {
        let Some(entry) = self.selected_entry_mut() else { return };
        if !entry.is_dir {
            return;
        }
        if !entry.expanded {
            entry.load_children();
        }
        entry.expanded = !entry.expanded;
        self.rebuild_rows();
    }

    /// Left arrow: collapse the directory, or move to its parent entry when
    /// already collapsed (or a file).
    pub fn collapse_or_parent(&mut self) {
        let Some(row) = self.rows.get(self.selected).cloned() else { return };
        let collapsible = self.selected_entry().map(|e| e.is_dir && e.expanded).unwrap_or(false);
        if collapsible {
            if let Some(e) = self.selected_entry_mut() {
                e.expanded = false;
            }
            self.rebuild_rows();
        } else if row.path.len() > 1 {
            let parent = &row.path[..row.path.len() - 1];
            if let Some(i) = self.rows.iter().position(|r| r.path == parent) {
                self.select(i);
            }
        }
    }

    /// Right arrow: expand the directory, or move to its first child when
    /// already expanded.
    pub fn expand_or_child(&mut self) {
        let expandable = self.selected_entry().map(|e| e.is_dir && !e.expanded).unwrap_or(false);
        if expandable {
            if let Some(e) = self.selected_entry_mut() {
                e.load_children();
                e.expanded = true;
            }
            self.rebuild_rows();
        } else if self.selected_entry().map(|e| e.is_dir).unwrap_or(false) {
            self.select(self.selected + 1);
        }
    }

    /// Select the top-level entry matching `path` (used to preselect the
    /// file the program was started with; the browser's root is always
    /// that file's parent directory, so no deep expansion is needed).
    pub fn reveal(&mut self, path: &Path) {
        let target = self.rows.iter().position(|r| {
            r.path.len() == 1 && entry_at(&self.entries, &r.path).map(|e| e.path.as_path()) == Some(path)
        });
        if let Some(i) = target {
            self.select(i);
        }
    }
}

fn collect_rows(entry: &Entry, path: Vec<usize>, rows: &mut Vec<Row>) {
    rows.push(Row { depth: path.len() - 1, path: path.clone() });
    if entry.is_dir && entry.expanded {
        for (i, child) in entry.children.iter().enumerate() {
            let mut child_path = path.clone();
            child_path.push(i);
            collect_rows(child, child_path, rows);
        }
    }
}

fn entry_at<'a>(entries: &'a [Entry], path: &[usize]) -> Option<&'a Entry> {
    let (&first, rest) = path.split_first()?;
    let mut e = entries.get(first)?;
    for &i in rest {
        e = e.children.get(i)?;
    }
    Some(e)
}

fn entry_at_mut<'a>(entries: &'a mut [Entry], path: &[usize]) -> Option<&'a mut Entry> {
    let (&first, rest) = path.split_first()?;
    let mut e = entries.get_mut(first)?;
    for &i in rest {
        e = e.children.get_mut(i)?;
    }
    Some(e)
}

fn read_dir_sorted(dir: &Path) -> Vec<Entry> {
    let mut items: Vec<Entry> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| {
                let path = e.path();
                let is_dir = path.is_dir();
                Entry {
                    name: e.file_name().to_string_lossy().into_owned(),
                    path,
                    is_dir,
                    expanded: false,
                    children: Vec::new(),
                    children_loaded: false,
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    items.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tree(dir: &Path) {
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/inner.txt"), b"x").unwrap();
        std::fs::write(dir.join("a.der"), b"x").unwrap();
        std::fs::write(dir.join("b.der"), b"x").unwrap();
    }

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("asn1-editor-browser-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn lists_dirs_first_then_alphabetical() {
        let dir = tmp_dir("sort");
        make_tree(&dir);
        let browser = FileBrowser::new(dir.clone());
        let names: Vec<&str> = browser.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["sub", "a.der", "b.der"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expand_and_collapse_toggle_subfolder_rows() {
        let dir = tmp_dir("fold");
        make_tree(&dir);
        let mut browser = FileBrowser::new(dir.clone());
        assert_eq!(browser.rows.len(), 3); // sub, a.der, b.der (collapsed)
        browser.select(0); // "sub"
        browser.toggle_expand();
        assert_eq!(browser.rows.len(), 4); // sub, sub/inner.txt, a.der, b.der
        browser.toggle_expand();
        assert_eq!(browser.rows.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expand_or_child_then_collapse_or_parent() {
        let dir = tmp_dir("nav");
        make_tree(&dir);
        let mut browser = FileBrowser::new(dir.clone());
        browser.select(0); // "sub"
        browser.expand_or_child(); // expands
        assert!(browser.selected_entry().unwrap().expanded);
        browser.expand_or_child(); // moves into child
        assert_eq!(browser.selected_entry().unwrap().name, "inner.txt");
        browser.collapse_or_parent(); // back to parent "sub"
        assert_eq!(browser.selected_entry().unwrap().name, "sub");
        browser.collapse_or_parent(); // collapses "sub"
        assert!(!browser.selected_entry().unwrap().expanded);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reveal_selects_matching_top_level_file() {
        let dir = tmp_dir("reveal");
        make_tree(&dir);
        let mut browser = FileBrowser::new(dir.clone());
        browser.reveal(&dir.join("b.der"));
        assert_eq!(browser.selected_entry().unwrap().name, "b.der");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_or_missing_directory_is_safe() {
        let dir = tmp_dir("empty");
        let mut browser = FileBrowser::new(dir.clone());
        assert!(browser.rows.is_empty());
        browser.move_by(1); // must not panic
        browser.toggle_expand();
        assert!(browser.selected_entry().is_none());

        let mut missing = FileBrowser::new(dir.join("does-not-exist"));
        assert!(missing.rows.is_empty());
        missing.move_by(-1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
