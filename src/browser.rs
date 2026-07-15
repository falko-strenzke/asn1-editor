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
//!
//! The tree is refreshed against the live filesystem (`refresh`, driven on a
//! timer by the event loop). Each entry is tagged, relative to a snapshot of
//! modification times taken at startup ([`FileBrowser::baseline`]), as
//! unchanged, newly created, modified, or deleted — so files that appear or
//! change while the program runs (e.g. a key file it just wrote) show up
//! immediately, annotated in the pane.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ratatui::widgets::ListState;

/// How an entry compares to the filesystem snapshot taken at startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileStatus {
    /// Present at startup and not modified since.
    Unchanged,
    /// Created since startup (absent from the baseline).
    New,
    /// Present at startup but with a newer modification time now.
    Modified,
    /// Present at startup but no longer on disk.
    Deleted,
}

/// Depth cap for the recursive baseline snapshot (mirrors the scan caps in
/// `x509.rs`), guarding against pathological trees and symlink cycles.
const MAX_BASELINE_DEPTH: usize = 32;

/// One entry in the directory tree. Directories are listed but their
/// children are only read from disk on first expansion.
pub struct Entry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub expanded: bool,
    pub children: Vec<Entry>,
    children_loaded: bool,
    /// Change status relative to the startup baseline.
    pub status: FileStatus,
    /// Modification time to display for `New`/`Modified` entries; `None`
    /// otherwise.
    pub changed_at: Option<SystemTime>,
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
    /// Modification times of every file/directory present under `root` at
    /// startup — the reference every later `refresh` classifies against.
    baseline: HashMap<PathBuf, SystemTime>,
}

impl FileBrowser {
    pub fn new(root: PathBuf) -> Self {
        let mut baseline = HashMap::new();
        capture_baseline(&root, 0, &mut baseline);
        let entries = read_dir_sorted(&root, &baseline);
        let mut browser = FileBrowser {
            root,
            entries,
            rows: Vec::new(),
            selected: 0,
            list_state: ListState::default(),
            baseline,
        };
        browser.rebuild_rows();
        browser
    }

    /// Re-read the loaded parts of the tree from disk and re-tag every entry
    /// against the startup baseline: newly created files are added, vanished
    /// ones marked `Deleted` (kept visible), and modification times refreshed.
    /// Returns whether anything changed, so the caller can refresh its own
    /// file-derived state only when needed. The current selection is preserved
    /// by path across the row rebuild.
    pub fn refresh(&mut self) -> bool {
        let mut changed = false;
        refresh_dir(&self.root, &mut self.entries, &self.baseline, &mut changed);
        if changed {
            let selected_path = self.selected_entry().map(|e| e.path.clone());
            self.rebuild_rows();
            if let Some(path) = selected_path {
                if let Some(i) = self
                    .rows
                    .iter()
                    .position(|r| entry_at(&self.entries, &r.path).map(|e| &e.path) == Some(&path))
                {
                    self.select(i);
                }
            }
        }
        changed
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

    /// Whether any loaded entry currently carries `status` (for the pane's
    /// change-indicator legend).
    pub fn entries_have_status(&self, status: FileStatus) -> bool {
        fn any(entries: &[Entry], status: FileStatus) -> bool {
            entries.iter().any(|e| e.status == status || any(&e.children, status))
        }
        any(&self.entries, status)
    }

    fn selected_entry_mut(&mut self) -> Option<&mut Entry> {
        let path = self.rows.get(self.selected)?.path.clone();
        entry_at_mut(&mut self.entries, &path)
    }

    /// Fold/unfold the selected directory; a no-op on a file.
    pub fn toggle_expand(&mut self) {
        let Some(path) = self.rows.get(self.selected).map(|r| r.path.clone()) else { return };
        let baseline = &self.baseline;
        let Some(entry) = entry_at_mut(&mut self.entries, &path) else { return };
        if !entry.is_dir {
            return;
        }
        if !entry.expanded {
            load_children(entry, baseline);
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
            if let Some(path) = self.rows.get(self.selected).map(|r| r.path.clone()) {
                let baseline = &self.baseline;
                if let Some(e) = entry_at_mut(&mut self.entries, &path) {
                    load_children(e, baseline);
                    e.expanded = true;
                }
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

/// Load and classify a directory entry's children on first expansion.
fn load_children(entry: &mut Entry, baseline: &HashMap<PathBuf, SystemTime>) {
    if !entry.children_loaded {
        entry.children = read_dir_sorted(&entry.path, baseline);
        entry.children_loaded = true;
    }
}

/// Classify a path against the startup `baseline` by its current
/// modification time: absent from the baseline ⇒ `New`; present but newer ⇒
/// `Modified`; otherwise `Unchanged`. Returns the status and the timestamp to
/// display (only for `New`/`Modified`).
fn classify(
    path: &Path,
    mtime: Option<SystemTime>,
    baseline: &HashMap<PathBuf, SystemTime>,
) -> (FileStatus, Option<SystemTime>) {
    match baseline.get(path) {
        None => (FileStatus::New, mtime),
        Some(&base) if mtime.is_some_and(|m| m > base) => (FileStatus::Modified, mtime),
        Some(_) => (FileStatus::Unchanged, None),
    }
}

fn mtime_of(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn read_dir_sorted(dir: &Path, baseline: &HashMap<PathBuf, SystemTime>) -> Vec<Entry> {
    let mut items: Vec<Entry> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| {
                let path = e.path();
                let is_dir = path.is_dir();
                let (status, changed_at) = classify(&path, mtime_of(&path), baseline);
                Entry {
                    name: e.file_name().to_string_lossy().into_owned(),
                    path,
                    is_dir,
                    expanded: false,
                    children: Vec::new(),
                    children_loaded: false,
                    status,
                    changed_at,
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    sort_entries(&mut items);
    items
}

fn sort_entries(items: &mut [Entry]) {
    items.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
}

/// Snapshot the modification time of every file and directory reachable under
/// `root` at startup. Symlinks are not followed (which also rules out cycles),
/// matching the directory scans in `x509.rs`.
fn capture_baseline(dir: &Path, depth: usize, out: &mut HashMap<PathBuf, SystemTime>) {
    if depth > MAX_BASELINE_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.filter_map(|e| e.ok()) {
        let Ok(file_type) = entry.file_type() else { continue };
        let path = entry.path();
        if let Ok(mtime) = entry.metadata().and_then(|m| m.modified()) {
            out.insert(path.clone(), mtime);
        }
        if file_type.is_dir() {
            capture_baseline(&path, depth + 1, out);
        }
    }
}

/// Re-read `dir` from disk and reconcile it with the already-loaded `entries`:
/// existing entries are re-tagged (recursing into loaded subdirectories),
/// vanished ones become `Deleted` (kept in place), and new ones are inserted.
/// Sets `changed` when any of that alters the tree.
fn refresh_dir(
    dir: &Path,
    entries: &mut Vec<Entry>,
    baseline: &HashMap<PathBuf, SystemTime>,
    changed: &mut bool,
) {
    // Current on-disk children, keyed by name.
    let mut current: HashMap<String, (PathBuf, bool, Option<SystemTime>)> = HashMap::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.filter_map(|e| e.ok()) {
            let path = e.path();
            let is_dir = path.is_dir();
            let mtime = mtime_of(&path);
            current.insert(e.file_name().to_string_lossy().into_owned(), (path, is_dir, mtime));
        }
    }

    // Update entries that still exist; mark the rest deleted.
    for entry in entries.iter_mut() {
        if let Some((path, is_dir, mtime)) = current.remove(&entry.name) {
            let (status, changed_at) = classify(&path, mtime, baseline);
            if entry.status != status || entry.changed_at != changed_at {
                *changed = true;
            }
            entry.status = status;
            entry.changed_at = changed_at;
            entry.is_dir = is_dir;
            if is_dir && entry.children_loaded {
                refresh_dir(&path, &mut entry.children, baseline, changed);
            }
        } else if entry.status != FileStatus::Deleted {
            entry.status = FileStatus::Deleted;
            entry.changed_at = None;
            *changed = true;
        }
    }

    // Whatever remains in `current` is newly appeared.
    let mut new_names: Vec<&String> = current.keys().collect();
    new_names.sort();
    for name in new_names {
        let (path, is_dir, mtime) = current[name].clone();
        let (status, changed_at) = classify(&path, mtime, baseline);
        entries.push(Entry {
            name: name.clone(),
            path,
            is_dir,
            expanded: false,
            children: Vec::new(),
            children_loaded: false,
            status,
            changed_at,
        });
        *changed = true;
    }

    sort_entries(entries);
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

    fn status_of<'a>(browser: &'a FileBrowser, name: &str) -> &'a Entry {
        browser.entries.iter().find(|e| e.name == name).expect("entry present")
    }

    #[test]
    fn a_new_file_appears_as_new_with_a_timestamp() {
        let dir = tmp_dir("refresh-new");
        make_tree(&dir);
        let mut browser = FileBrowser::new(dir.clone());
        // Startup files carry no change status.
        assert_eq!(status_of(&browser, "a.der").status, FileStatus::Unchanged);
        assert!(status_of(&browser, "a.der").changed_at.is_none());

        std::fs::write(dir.join("c.der"), b"new").unwrap();
        assert!(browser.refresh(), "a new file is a change");
        let c = status_of(&browser, "c.der");
        assert_eq!(c.status, FileStatus::New);
        assert!(c.changed_at.is_some(), "new files show a timestamp");
        assert!(browser.rows.iter().any(|r| browser.entry_at(&r.path).unwrap().name == "c.der"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_modified_file_is_flagged_yellow_worthy() {
        let dir = tmp_dir("refresh-mod");
        make_tree(&dir);
        let mut browser = FileBrowser::new(dir.clone());
        // Simulate an older baseline so the current mtime reads as newer,
        // which is what an on-disk modification produces.
        browser.baseline.insert(dir.join("a.der"), std::time::UNIX_EPOCH);
        assert!(browser.refresh());
        let a = status_of(&browser, "a.der");
        assert_eq!(a.status, FileStatus::Modified);
        assert!(a.changed_at.is_some());
        // An untouched file stays unchanged.
        assert_eq!(status_of(&browser, "b.der").status, FileStatus::Unchanged);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_deleted_file_stays_visible_marked_deleted() {
        let dir = tmp_dir("refresh-del");
        make_tree(&dir);
        let mut browser = FileBrowser::new(dir.clone());
        browser.reveal(&dir.join("a.der"));
        std::fs::remove_file(dir.join("a.der")).unwrap();
        assert!(browser.refresh());
        let a = status_of(&browser, "a.der");
        assert_eq!(a.status, FileStatus::Deleted);
        // Still a visible row, and the selection stayed on it.
        assert!(browser.rows.iter().any(|r| browser.entry_at(&r.path).unwrap().name == "a.der"));
        assert_eq!(browser.selected_entry().unwrap().name, "a.der");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refresh_without_changes_reports_nothing() {
        let dir = tmp_dir("refresh-noop");
        make_tree(&dir);
        let mut browser = FileBrowser::new(dir.clone());
        assert!(!browser.refresh(), "an unchanged directory is not a change");
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
