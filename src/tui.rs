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

//! ratatui front end: tree pane on the left, content/hex pane on the right,
//! status bar at the bottom.

use std::io;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, KeyboardEnhancementFlags, ModifierKeyCode, PopKeyboardEnhancementFlags,
    PushKeyboardEnhancementFlags,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

use crate::app::{
    App, DateTimeEditor, EditKind, EditState, Editor, FilterMatcher, Focus, HexEditor, Mode,
    HssPicker, PickerTarget, PubKeyState, RowSource, TextEditor, TextFormat, DATE_FIELDS, EDIT_BYTES_PER_LINE,
    EDIT_DIGITS_PER_LINE, HELP_TOPICS, PICKER_CLASSES, PICKER_UNIVERSAL, TOP_MENUS,
};
use crate::x509::{self, basic_constraints, extended_key_usage, key_usage};
use crate::browser::FileStatus;
use crate::cost;
use crate::ber::{
    self, Class, Node, TAG_BIT_STRING, TAG_BOOLEAN, TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_NULL,
    TAG_OID, TAG_UTC_TIME,
};
use crate::hashsig;
use crate::keygen;
use crate::oid;
use crate::pathval::PathStatus;
use crate::pathval_botan::BotanPathStatus;
use crate::verify::{FileRelations, SignatureStatus};

/// Total width of one [`hex_dump_lines`] line: the offset column (8 hex
/// digits + 2 spaces), the hex column (47 chars padded + 2 spaces) and the
/// `|…|` ASCII gutter (1 + 16 + 1). Long `Decoded` values wrap to this width.
const HEX_DUMP_LINE_WIDTH: usize = 10 + 47 + 2 + 1 + 16 + 1;
const DECRYPTED_LOCKED_LABEL: &str = "🔒 decrypted content not available";
const DECRYPTED_UNLOCKED_PREFIX: &str = "🔓 decrypted: ";

/// Colors of the file-browser cryptographic relation arrows.
const REL_SIGNER: Color = Color::Cyan; // incoming: a file that signed the selection
const REL_SIGNS: Color = Color::Magenta; // outgoing: a file the selection signed
const REL_BROKEN: Color = Color::Red; // claimed issuance whose signature fails to verify
const REL_KEY: Color = Color::LightGreen; // undirected: a private key and its certificate

pub fn run(mut app: App) -> io::Result<()> {
    let mut terminal = ratatui::init();
    // Bracketed paste lets clipboard content reach the value editors.
    let _ = execute!(std::io::stdout(), EnableBracketedPaste);
    // A bare Alt press — the menu bar's toggle — only reaches a program on
    // terminals that speak the kitty keyboard protocol, and only once all keys
    // are asked for as escape codes. Where that is unsupported the request is
    // simply not made and F10 / Alt+M serve instead (see [`is_menu_toggle`]).
    let enhanced =
        matches!(ratatui::crossterm::terminal::supports_keyboard_enhancement(), Ok(true));
    if enhanced {
        let _ = execute!(
            std::io::stdout(),
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::REPORT_ALL_KEYS_AS_ESCAPE_CODES)
        );
    }
    let result = event_loop(&mut terminal, &mut app);
    if enhanced {
        let _ = execute!(std::io::stdout(), PopKeyboardEnhancementFlags);
    }
    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    result
}

/// How often the browser pane is reconciled with the filesystem.
const FS_POLL_INTERVAL: Duration = Duration::from_millis(750);

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> io::Result<()> {
    let mut last_fs_poll = Instant::now();
    loop {
        terminal.draw(|f| draw(f, app))?;
        // While a background re-key runs, poll it for completion (which applies
        // the result and closes the progress window). The 250 ms poll below
        // keeps the elapsed-time display ticking meanwhile.
        if matches!(app.mode, Mode::Progress(_)) {
            app.poll_rekey_progress();
        }
        // Reconcile the browser with the filesystem on a timer (the poll below
        // wakes at least every 250 ms even when the user is idle) — but not
        // while a re-key worker is writing files, to avoid racing it.
        if !matches!(app.mode, Mode::Progress(_)) && last_fs_poll.elapsed() >= FS_POLL_INTERVAL {
            app.refresh_filesystem();
            last_fs_poll = Instant::now();
        }
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let key = match event::read()? {
            Event::Key(key) => key,
            Event::Paste(text) => {
                match app.mode {
                    Mode::Edit(_) => app.paste_into_editor(&text),
                    Mode::Password(ref mut p) => p.paste(&text),
                    Mode::EditPubKey(_) => {
                        for c in text.chars() {
                            app.pubkey_insert_char(c);
                        }
                    }
                    Mode::FilterInput => {
                        for c in text.chars() {
                            app.filter_insert_char(c);
                        }
                    }
                    _ => {}
                }
                continue;
            }
            _ => continue,
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        // The menu bar's toggle is handled before the modes, so that the same
        // key both opens and closes it. It is offered only while browsing (or
        // with the bar already open): pressing it inside a dialog or an editor
        // would discard work in progress.
        if is_menu_toggle(key) && matches!(app.mode, Mode::Browse | Mode::MenuBar(_)) {
            app.toggle_menu_bar();
            continue;
        }
        match app.mode {
            Mode::MenuBar(_) => handle_menu_bar_key(app, key),
            Mode::Help(_) => handle_help_key(app, key),
            Mode::NewFile(_) => handle_new_file_key(app, key),
            Mode::Edit(_) => handle_edit_key(app, key),
            Mode::TypePicker(_) => handle_picker_key(app, key),
            Mode::EditMenu(_) => handle_menu_key(app, key),
            Mode::Password(_) => handle_password_key(app, key),
            Mode::Resign(_) => handle_resign_key(app, key),
            Mode::EditPubKey(_) => handle_pubkey_key(app, key),
            Mode::EditBasicConstraints(_) => handle_basic_constraints_key(app, key),
            Mode::EditKeyUsage(_) => handle_key_usage_key(app, key),
            Mode::EditExtKeyUsage(_) => handle_ext_key_usage_key(app, key),
            Mode::FilterInput => handle_filter_key(app, key),
            Mode::Notice(_) => app.dismiss_notice(), // any key dismisses
            // A running re-key cannot be safely interrupted (a partial XMSS
            // state advance would be unrecoverable): ignore all input.
            Mode::Progress(_) => {}
            Mode::Browse => {
                if key.code != KeyCode::Char('q') {
                    app.quit_confirm = false;
                }
                match key.code {
                    KeyCode::Char('q') => {
                        if !app.dirty || app.quit_confirm {
                            return Ok(());
                        }
                        app.quit_confirm = true;
                        app.status = "unsaved changes — press q again to quit anyway".to_string();
                    }
                    KeyCode::Tab => app.toggle_focus(),
                    _ => match app.focus {
                        Focus::Browser => handle_browser_key(app, key),
                        Focus::Document => handle_document_key(app, key),
                    },
                }
            }
        }
    }
}

/// Whether `key` asks for the menu bar to be shown or hidden.
///
/// The Alt key itself is the documented toggle, but a bare modifier press only
/// reaches a program on terminals implementing the kitty keyboard protocol
/// (and only with the enhancement `run` asks for). F10 — the menu key of
/// terminal applications since long before that protocol — and Alt+M work
/// everywhere, so the feature is never out of reach.
fn is_menu_toggle(key: KeyEvent) -> bool {
    matches!(
        key.code,
        KeyCode::Modifier(ModifierKeyCode::LeftAlt | ModifierKeyCode::RightAlt) | KeyCode::F(10)
    ) || (key.code == KeyCode::Char('m') && key.modifiers.contains(KeyModifiers::ALT))
}

/// The menu bar has the keyboard focus while it is shown: ←→ pick a heading,
/// ↑↓ an entry of its drop-down, Enter runs it and Esc closes the bar.
fn handle_menu_bar_key(app: &mut App, key: KeyEvent) {
    let Mode::MenuBar(ref mut bar) = app.mode else { return };
    match key.code {
        KeyCode::Left => bar.move_menu(-1),
        KeyCode::Right => bar.move_menu(1),
        KeyCode::Up => bar.move_item(-1),
        KeyCode::Down => bar.move_item(1),
        KeyCode::Enter | KeyCode::Char(' ') => app.activate_menu_entry(),
        KeyCode::Esc => app.toggle_menu_bar(),
        _ => {}
    }
}

/// The help window: ↑↓ choose a topic, PageUp/PageDown (or `[` / `]`) scroll
/// the chosen topic's text, Esc closes.
fn handle_help_key(app: &mut App, key: KeyEvent) {
    let Mode::Help(ref mut help) = app.mode else { return };
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => help.move_topic(-1),
        KeyCode::Down | KeyCode::Char('j') => help.move_topic(1),
        KeyCode::PageUp | KeyCode::Char('[') => help.scroll_body(-8),
        KeyCode::PageDown | KeyCode::Char(']') => help.scroll_body(8),
        KeyCode::Home => help.scroll = 0,
        KeyCode::End => help.scroll = usize::MAX,
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.close_help(),
        _ => {}
    }
}

/// The new-file dialog: type a path, Enter creates it, Esc abandons it.
fn handle_new_file_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.cancel_new_der();
            return;
        }
        KeyCode::Enter => {
            app.commit_new_der();
            return;
        }
        _ => {}
    }
    let Mode::NewFile(ref mut state) = app.mode else { return };
    match key.code {
        KeyCode::Char(c) => state.insert_char(c),
        KeyCode::Backspace => state.backspace(),
        KeyCode::Left => state.move_cursor(-1),
        KeyCode::Right => state.move_cursor(1),
        KeyCode::Home => state.move_cursor(isize::MIN),
        KeyCode::End => state.move_cursor(isize::MAX),
        _ => {}
    }
}

/// The content pane's scroll keys, shared by both panes: `[` / `]` move by
/// four lines and their shifted forms jump to the very start / end. Returns
/// whether `key` was one of them.
///
/// Terminals disagree on how a shifted bracket arrives — as `{` / `}`, or as
/// `[` / `]` carrying the Shift modifier — so both readings are accepted.
fn handle_content_scroll_key(app: &mut App, key: KeyEvent) -> bool {
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    match key.code {
        // The end is asked for by overshooting; the draw clamps it to the
        // last screenful (see [`App::content_scroll`]).
        KeyCode::Char('{') => app.content_scroll = 0,
        KeyCode::Char('}') => app.content_scroll = usize::MAX,
        KeyCode::Char('[') if shift => app.content_scroll = 0,
        KeyCode::Char(']') if shift => app.content_scroll = usize::MAX,
        KeyCode::Char('[') => app.content_scroll = app.content_scroll.saturating_sub(4),
        KeyCode::Char(']') => app.content_scroll = app.content_scroll.saturating_add(4),
        _ => return false,
    }
    true
}

fn handle_browser_key(app: &mut App, key: KeyEvent) {
    if !matches!(key.code, KeyCode::Enter | KeyCode::Char(' ')) {
        app.open_confirm = false;
    }
    // The content pane previews the selected file from here too, so its
    // scroll keys work without switching panes — and returning early skips
    // the (costly) re-preview below, which the selection has not moved for.
    if handle_content_scroll_key(app, key) {
        return;
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => app.browser.move_by(-1),
        KeyCode::Down | KeyCode::Char('j') => app.browser.move_by(1),
        KeyCode::PageUp => app.browser.move_by(-15),
        KeyCode::PageDown => app.browser.move_by(15),
        KeyCode::Home | KeyCode::Char('g') => app.browser.select(0),
        KeyCode::End | KeyCode::Char('G') => app.browser.select(usize::MAX),
        KeyCode::Left | KeyCode::Char('h') => app.browser.collapse_or_parent(),
        KeyCode::Right | KeyCode::Char('l') => app.browser.expand_or_child(),
        KeyCode::Enter | KeyCode::Char(' ') => app.activate_browser_entry(),
        KeyCode::Char('z') => app.start_decrypt(),
        KeyCode::Char('t') => app.toggle_trust(),
        KeyCode::Char('/') => app.start_browser_search(),
        _ => {}
    }
    // Any of the above can move the browser selection; live-preview the
    // now-selected file and refresh the relation arrows.
    app.preview_browser_selection();
    app.recompute_browser_relations();
}

fn handle_document_key(app: &mut App, key: KeyEvent) {
    if key.code != KeyCode::Char('d') {
        app.delete_confirm = false;
    }
    if handle_content_scroll_key(app, key) {
        return;
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => app.move_by(-1),
        KeyCode::Down | KeyCode::Char('j') => app.move_by(1),
        KeyCode::PageUp => app.move_by(-15),
        KeyCode::PageDown => app.move_by(15),
        KeyCode::Home | KeyCode::Char('g') => app.select(0),
        KeyCode::End | KeyCode::Char('G') => app.select(usize::MAX),
        KeyCode::Left | KeyCode::Char('h') => app.collapse_or_parent(),
        KeyCode::Right | KeyCode::Char('l') => app.expand_or_child(),
        KeyCode::Enter | KeyCode::Char(' ') => app.toggle_expand(),
        KeyCode::Char('e') => app.edit_selected(),
        KeyCode::Char('E') => app.open_edit_menu(),
        KeyCode::Char('i') => app.start_insert(false),
        KeyCode::Char('I') => app.start_insert(true),
        KeyCode::Char('d') => app.delete_selected(),
        KeyCode::Char('K') => app.move_selected(-1),
        KeyCode::Char('J') => app.move_selected(1),
        KeyCode::Char('s') => app.save(),
        KeyCode::Char('z') => app.start_decrypt(),
        KeyCode::Char('/') => app.start_filter(),
        _ => {}
    }
}

fn handle_password_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.cancel_password(),
        KeyCode::Enter => app.submit_password(),
        KeyCode::Backspace => {
            if let Mode::Password(ref mut p) = app.mode {
                p.backspace();
            }
        }
        KeyCode::Char(c) => {
            if let Mode::Password(ref mut p) = app.mode {
                p.insert_char(c);
            }
        }
        _ => {}
    }
}

fn handle_resign_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.cancel_resign(),
        KeyCode::Enter => app.submit_resign(),
        _ => {}
    }
}

fn handle_pubkey_key(app: &mut App, key: KeyEvent) {
    // The HSS/LMS value-choice popup, when open, captures navigation.
    if app.pubkey_hss_picker_open() {
        match key.code {
            KeyCode::Up => app.pubkey_hss_picker_move(-1),
            KeyCode::Down => app.pubkey_hss_picker_move(1),
            KeyCode::Enter | KeyCode::Char(' ') => app.pubkey_hss_picker_confirm(),
            KeyCode::Esc => app.pubkey_hss_picker_cancel(),
            _ => {}
        }
        return;
    }
    // The file-name field's cursor-edit mode captures navigation: ←/→ move the
    // cursor, typing edits the name, Enter/Esc leave the mode (Esc keeps the
    // name — it does not cancel the whole dialog while editing).
    if app.pubkey_filename_editing() {
        match key.code {
            KeyCode::Enter | KeyCode::Esc => app.pubkey_filename_end_edit(),
            KeyCode::Left => app.pubkey_filename_move_cursor(-1),
            KeyCode::Right => app.pubkey_filename_move_cursor(1),
            KeyCode::Home => app.pubkey_filename_move_cursor(isize::MIN),
            KeyCode::End => app.pubkey_filename_move_cursor(isize::MAX),
            KeyCode::Backspace => app.pubkey_filename_backspace(),
            KeyCode::Char(c) => app.pubkey_filename_type(c),
            _ => {}
        }
        return;
    }
    // Arrow keys always navigate rows/columns; Enter applies the whole dialog.
    // In the HSS/LMS editor, Space opens a choice popup for the focused field
    // (or adds a level), and +/- add/remove a level. On the file-name column
    // Space enters its cursor-edit mode instead of toggling anything.
    let hss = app.pubkey_in_hsslms_editor();
    match key.code {
        KeyCode::Esc => app.cancel_pubkey(),
        KeyCode::Enter => app.submit_pubkey(),
        KeyCode::Left | KeyCode::BackTab => app.pubkey_move_column(-1),
        KeyCode::Right | KeyCode::Tab => app.pubkey_move_column(1),
        KeyCode::Up => app.pubkey_move_row(-1),
        KeyCode::Down => app.pubkey_move_row(1),
        KeyCode::Char('+') if hss => app.pubkey_hss_add_level(),
        KeyCode::Char('-') if hss => app.pubkey_hss_remove_level(),
        KeyCode::Char(' ') => {
            if app.pubkey_filename_focused() {
                app.pubkey_filename_begin_edit();
            } else if !app.pubkey_hss_activate() {
                app.pubkey_toggle();
            }
        }
        KeyCode::Backspace => app.pubkey_backspace(),
        KeyCode::Char(c) => app.pubkey_insert_char(c),
        _ => {}
    }
}

fn handle_basic_constraints_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.cancel_basic_constraints(),
        KeyCode::Enter => app.commit_basic_constraints(),
        KeyCode::Up | KeyCode::BackTab => app.bc_move_field(-1),
        KeyCode::Down | KeyCode::Tab => app.bc_move_field(1),
        KeyCode::Char(' ') => app.bc_toggle(),
        KeyCode::Backspace => app.bc_backspace(),
        KeyCode::Char(c) => app.bc_insert_char(c),
        _ => {}
    }
}

fn handle_key_usage_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.cancel_key_usage(),
        KeyCode::Enter => app.commit_key_usage(),
        KeyCode::Up | KeyCode::BackTab => app.ku_move_field(-1),
        KeyCode::Down | KeyCode::Tab => app.ku_move_field(1),
        KeyCode::Char(' ') => app.ku_toggle(),
        _ => {}
    }
}

fn handle_filter_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.filter_clear(),
        KeyCode::Enter | KeyCode::Tab => app.filter_accept(),
        KeyCode::Backspace => app.filter_backspace(),
        KeyCode::Delete => app.filter_delete(),
        KeyCode::Left => app.filter_move_cursor(-1),
        KeyCode::Right => app.filter_move_cursor(1),
        KeyCode::Home => app.filter_cursor_to(false),
        KeyCode::End => app.filter_cursor_to(true),
        KeyCode::Char(c) => app.filter_insert_char(c),
        _ => {}
    }
}

fn handle_ext_key_usage_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.cancel_ext_key_usage(),
        KeyCode::Enter => app.eku_enter(),
        KeyCode::Up | KeyCode::BackTab => app.eku_move_field(-1),
        KeyCode::Down | KeyCode::Tab => app.eku_move_field(1),
        KeyCode::Char(' ') => app.eku_toggle(),
        KeyCode::Backspace => app.eku_backspace(),
        KeyCode::Char(c) => app.eku_insert_char(c),
        _ => {}
    }
}

fn handle_picker_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.cancel_picker(),
        KeyCode::Enter => app.picker_confirm(),
        KeyCode::Left | KeyCode::Char('h') | KeyCode::BackTab => app.picker_move_column(-1),
        KeyCode::Right | KeyCode::Char('l') | KeyCode::Tab => app.picker_move_column(1),
        KeyCode::Up | KeyCode::Char('k') => app.picker_move_selection(-1),
        KeyCode::Down | KeyCode::Char('j') => app.picker_move_selection(1),
        KeyCode::Char(c) if c.is_ascii_digit() => app.picker_digit(c),
        KeyCode::Backspace => app.picker_backspace(),
        _ => {}
    }
}

fn handle_menu_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.cancel_menu(),
        KeyCode::Enter => app.menu_confirm(),
        KeyCode::Up | KeyCode::Char('k') => app.menu_move(-1),
        KeyCode::Down | KeyCode::Char('j') => app.menu_move(1),
        KeyCode::Char(c @ '1'..='9') => {
            let idx = (c as usize) - ('1' as usize);
            let in_range = matches!(app.mode, Mode::EditMenu(ref m) if idx < m.items.len());
            if !in_range {
                return;
            }
            if let Mode::EditMenu(ref mut m) = app.mode {
                m.selected = idx;
            }
            app.menu_confirm();
        }
        _ => {}
    }
}

fn handle_edit_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.cancel_edit();
            return;
        }
        KeyCode::Enter => {
            app.commit_edit();
            return;
        }
        _ => {}
    }
    // The Ctrl combinations have to be recognised before the plain-character
    // arm below, which would otherwise take 'a' for a hex digit.
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        // Terminals differ over whether a Ctrl combination arrives upper or
        // lower case, so fold it before matching.
        let folded = match key.code {
            KeyCode::Char(c) => KeyCode::Char(c.to_ascii_lowercase()),
            other => other,
        };
        match folded {
            KeyCode::Char('a') => {
                app.select_all_in_editor();
                return;
            }
            KeyCode::Char('c') => {
                app.copy_selection();
                return;
            }
            KeyCode::Char('x') => {
                app.cut_selection();
                return;
            }
            KeyCode::Char('v') => {
                app.paste_from_clipboard();
                return;
            }
            KeyCode::Char('z') => {
                app.undo_edit();
                return;
            }
            _ => {}
        }
    }
    // Shift turns the cursor keys into selecting ones (hex editor only).
    let extend = key.modifiers.contains(KeyModifiers::SHIFT);
    let Mode::Edit(ref mut edit) = app.mode else { return };
    match key.code {
        KeyCode::Char(c) => edit.editor.insert_char(c),
        KeyCode::Backspace => edit.editor.backspace(),
        KeyCode::Delete => edit.editor.delete(),
        KeyCode::Left | KeyCode::BackTab => edit.editor.move_horizontal(-1, extend),
        KeyCode::Right | KeyCode::Tab => edit.editor.move_horizontal(1, extend),
        KeyCode::Up => edit.editor.move_vertical(-1, extend),
        KeyCode::Down => edit.editor.move_vertical(1, extend),
        KeyCode::Home => edit.editor.home(extend),
        KeyCode::End => edit.editor.end(extend),
        _ => {}
    }
}

fn draw(frame: &mut Frame, app: &mut App) {
    // The menu bar takes the top row only while it is shown, so the panes get
    // the full height the rest of the time.
    let (menu_bar, body) = if matches!(app.mode, Mode::MenuBar(_)) {
        let [bar, body] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(3)]).areas(frame.area());
        (Some(bar), body)
    } else {
        (None, frame.area())
    };
    let [main, status] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(body);
    if app.single_file {
        // No browser pane: give the structure and content panes the full width.
        let [tree, content] =
            Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)])
                .areas(main);
        draw_tree(frame, app, tree);
        draw_content(frame, app, content);
    } else {
        let [left, content] =
            Layout::horizontal([Constraint::Percentage(54), Constraint::Percentage(46)])
                .areas(main);
        // A browser search ('/' in the Files pane) puts its input bar on top,
        // spanning the browser and tree panes.
        let global_bar = app.filter_global
            && (matches!(app.mode, Mode::FilterInput) || !app.filter.is_empty());
        let left = if global_bar {
            let [bar, rest] =
                Layout::vertical([Constraint::Length(1), Constraint::Min(3)]).areas(left);
            frame.render_widget(Paragraph::new(filter_bar_line(app, " search / ")), bar);
            rest
        } else {
            left
        };
        // 20/34 of the full width, expressed within the 54%-wide left half.
        let [browser, tree] =
            Layout::horizontal([Constraint::Ratio(20, 54), Constraint::Ratio(34, 54)])
                .areas(left);
        draw_browser(frame, app, browser);
        draw_tree(frame, app, tree);
        draw_content(frame, app, content);
    }
    draw_status(frame, app, status);
    if matches!(app.mode, Mode::TypePicker(_)) {
        draw_picker(frame, app, main);
    }
    if matches!(app.mode, Mode::EditMenu(_)) {
        draw_edit_menu(frame, app, main);
    }
    if matches!(app.mode, Mode::Password(_)) {
        draw_password(frame, app, main);
    }
    if matches!(app.mode, Mode::Resign(_)) {
        draw_resign(frame, app, main);
    }
    if matches!(app.mode, Mode::EditPubKey(_)) {
        draw_edit_pubkey(frame, app, main);
    }
    if matches!(app.mode, Mode::EditBasicConstraints(_)) {
        draw_basic_constraints(frame, app, main);
    }
    if matches!(app.mode, Mode::EditKeyUsage(_)) {
        draw_key_usage(frame, app, main);
    }
    if matches!(app.mode, Mode::EditExtKeyUsage(_)) {
        draw_ext_key_usage(frame, app, main);
    }
    if matches!(app.mode, Mode::Notice(_)) {
        draw_notice(frame, app, main);
    }
    if matches!(app.mode, Mode::Progress(_)) {
        draw_progress(frame, app, main);
    }
    if matches!(app.mode, Mode::Help(_)) {
        draw_help(frame, app, main);
    }
    if matches!(app.mode, Mode::NewFile(_)) {
        draw_new_file(frame, app, main);
    }
    // Last, so the open drop-down covers the panes beneath it.
    if let Some(bar) = menu_bar {
        draw_menu_bar(frame, app, bar, main);
    }
}

/// Colour of the menu bar and of the borders of what it opens.
const MENU_COLOR: Color = Color::LightCyan;

/// The "new file" dialog of the menu's "File ▸ New DER" entry: the directory a
/// relative name resolves against, the path field with its cursor, and — after
/// a refused attempt — why the file could not be created.
fn draw_new_file(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::NewFile(ref state) = app.mode else { return };
    let width = area.width.saturating_sub(4).clamp(30, 84);
    let inner_w = width.saturating_sub(2) as usize;

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Directory  ", Style::new().dim()),
            Span::styled(app.new_file_dir().display().to_string(), Style::new().dim()),
        ]),
        Line::default(),
    ];
    // The cursor is a reversed cell within the text, or a reversed space when
    // it sits past its end.
    let mut field = vec![Span::styled("File       ", Style::new().bold())];
    let cursor = Style::new().add_modifier(Modifier::REVERSED);
    let chars: Vec<char> = state.path.chars().collect();
    field.push(Span::raw(chars[..state.cursor.min(chars.len())].iter().collect::<String>()));
    match chars.get(state.cursor) {
        Some(&c) => {
            field.push(Span::styled(c.to_string(), cursor));
            field.push(Span::raw(chars[state.cursor + 1..].iter().collect::<String>()));
        }
        None => field.push(Span::styled(" ", cursor)),
    }
    lines.push(Line::from(field));
    lines.push(Line::default());
    if let Some(error) = &state.error {
        for chunk in wrap_text(error, inner_w) {
            lines.push(Line::from(Span::styled(chunk, Style::new().fg(Color::Red).bold())));
        }
        lines.push(Line::default());
    }
    let hint = "A relative name is created in the directory above; an absolute path is used as \
                it stands. The file is created empty — 'i' then inserts its first element.";
    for chunk in wrap_text(hint, inner_w) {
        lines.push(Line::from(Span::styled(chunk, Style::new().dim())));
    }

    let height = (lines.len() as u16 + 2).min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(MENU_COLOR))
        .title(" NEW DER FILE ")
        .title_bottom(" ⏎ create   Esc cancel ");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The menu bar in the top row, plus the drop-down of the open heading. The
/// drop-down is drawn into `below` — the area the panes occupy — starting
/// under its heading, so it reads as hanging from the bar.
fn draw_menu_bar(frame: &mut Frame, app: &App, bar: Rect, below: Rect) {
    let Mode::MenuBar(ref state) = app.mode else { return };

    // Lay the headings out left to right, remembering where the open one
    // starts so the drop-down can be aligned under it.
    let mut spans = vec![Span::raw(" ")];
    let mut column = 1u16;
    let mut open_at = 0u16;
    for (i, menu) in TOP_MENUS.iter().enumerate() {
        let label = format!(" {} ", menu.label);
        if i == state.menu {
            open_at = column;
        }
        // Selection is shown the way the rest of the interface shows it —
        // reversed — rather than with a fixed background, which would clash
        // with one terminal theme or the other.
        let style = if i == state.menu {
            Style::new().add_modifier(Modifier::REVERSED).bold()
        } else {
            Style::new().fg(MENU_COLOR).bold()
        };
        column += label.chars().count() as u16;
        spans.push(Span::styled(label, style));
        spans.push(Span::raw(" "));
        column += 1;
    }
    spans.push(Span::styled("  ←→ menu  ↑↓ entry  ⏎ run  Esc close", Style::new().dim()));
    frame.render_widget(Paragraph::new(Line::from(spans)), bar);

    // The drop-down: one row per entry, sized to the widest label + summary.
    let menu = &TOP_MENUS[state.menu];
    let label_w = menu.items.iter().map(|i| i.label.chars().count()).max().unwrap_or(0);
    let width = menu
        .items
        .iter()
        .map(|i| label_w + i.desc.chars().count() + 6)
        .max()
        .unwrap_or(20) as u16;
    let width = width.min(below.width);
    let height = (menu.items.len() as u16 + 2).min(below.height);
    let popup = Rect {
        x: below.x + open_at.min(below.width.saturating_sub(width)),
        y: below.y,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default().borders(Borders::ALL).border_style(Style::new().fg(MENU_COLOR));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let lines: Vec<Line> = menu
        .items
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let style = if i == state.item {
                Style::new().add_modifier(Modifier::REVERSED).bold()
            } else {
                Style::new().bold()
            };
            Line::from(vec![
                Span::styled(format!(" {:<width$} ", entry.label, width = label_w), style),
                Span::styled(format!(" {}", entry.desc), Style::new().dim()),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The help window: the topic list on the left, the chosen topic's text on the
/// right. Only the visible part of the text is built, and the scroll offset is
/// clamped here, where the window's height is known — as the content pane does.
fn draw_help(frame: &mut Frame, app: &mut App, area: Rect) {
    let Mode::Help(ref state) = app.mode else { return };
    let width = area.width.saturating_sub(4).clamp(24, 110);
    let height = area.height.saturating_sub(2).max(6);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(MENU_COLOR))
        .title(" HELP ")
        .title_bottom(" ↑↓ topic   PgUp/PgDn or [ ] scroll   Esc close ");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let topics_w = (HELP_TOPICS.iter().map(|t| t.title.chars().count()).max().unwrap_or(10) + 3)
        .min(inner.width as usize / 2) as u16;
    let [list, text] =
        Layout::horizontal([Constraint::Length(topics_w), Constraint::Min(10)]).areas(inner);
    let items: Vec<ListItem> = HELP_TOPICS
        .iter()
        .enumerate()
        .map(|(i, topic)| {
            let style = if i == state.topic {
                Style::new().add_modifier(Modifier::REVERSED).bold()
            } else {
                Style::new()
            };
            ListItem::new(Line::from(Span::styled(format!(" {}", topic.title), style)))
        })
        .collect();
    frame.render_widget(List::new(items), list);
    frame.render_widget(
        Block::default().borders(Borders::LEFT).border_style(Style::new().fg(MENU_COLOR)),
        text,
    );

    // Wrap the topic's paragraphs, then show the window's worth of lines.
    let body_w = text.width.saturating_sub(3) as usize;
    let mut body: Vec<Line> = Vec::new();
    for paragraph in HELP_TOPICS[state.topic].body {
        if paragraph.is_empty() {
            body.push(Line::default());
            continue;
        }
        // Pre-formatted lines (the key-binding tables) keep their layout; only
        // running prose is re-wrapped.
        if paragraph.starts_with("  ") {
            body.push(Line::from(Span::raw(paragraph.to_string())));
            continue;
        }
        for chunk in wrap_text(paragraph, body_w) {
            body.push(Line::from(Span::raw(chunk)));
        }
    }
    let rows = usize::from(text.height);
    let max_scroll = body.len().saturating_sub(rows);
    let Mode::Help(ref mut state) = app.mode else { return };
    state.scroll = state.scroll.min(max_scroll);
    let first = state.scroll;
    let view: Vec<Line> = body.drain(first..(first + rows).min(body.len())).collect();
    let text_area = Rect { x: text.x + 2, width: text.width.saturating_sub(2), ..text };
    frame.render_widget(Paragraph::new(view), text_area);
}

/// Centered popup shown while a background re-key runs: the operation title,
/// the elapsed time (ticking as the event loop redraws), and — when known —
/// the estimated total time and a progress bar.
fn draw_progress(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::Progress(ref p) = app.mode else { return };
    let width = 54.min(area.width);
    let height = 8.min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::Cyan))
        .title(" WORKING — please wait ");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let lines = progress_lines(
        &p.title,
        p.start.elapsed(),
        p.estimate,
        inner.width.saturating_sub(2) as usize,
    );
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Build the progress window's body: the title, the elapsed time, and — when
/// an estimate is known — the estimated total (clock symbol) and an
/// elapsed/estimated bar `bar_width` cells wide (capped at full, since the
/// estimate is only a guide the real time may overrun).
fn progress_lines(
    title: &str,
    elapsed: Duration,
    estimate: Option<Duration>,
    bar_width: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(title.to_string(), Style::new().bold())),
        Line::default(),
        Line::from(vec![
            Span::styled("elapsed:   ", Style::new().dim()),
            Span::raw(cost::format_hms(elapsed)),
        ]),
    ];
    match estimate {
        Some(est) => {
            lines.push(Line::from(vec![
                Span::styled("estimated: ", Style::new().dim()),
                Span::styled(
                    format!("🕐 {}", cost::format_hms(est)),
                    Style::new().fg(Color::Yellow),
                ),
            ]));
            let frac = (elapsed.as_secs_f64() / est.as_secs_f64().max(0.001)).min(1.0);
            let filled = (frac * bar_width as f64).round() as usize;
            let bar: String = std::iter::repeat_n('█', filled)
                .chain(std::iter::repeat_n('░', bar_width.saturating_sub(filled)))
                .collect();
            lines.push(Line::from(Span::styled(bar, Style::new().fg(Color::Cyan))));
        }
        None => {
            lines.push(Line::from(Span::styled("estimated: unknown", Style::new().dim())));
        }
    }
    lines
}

/// Centered popup for a dismissible informational notice (used at start-up to
/// report specification-load warnings).
fn draw_notice(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::Notice(ref n) = app.mode else { return };
    // Wrap each message line to the available width so long parser errors stay
    // readable; size the popup to the content within the terminal.
    let max_w = 96.min(area.width.saturating_sub(4).max(20)) as usize;
    let inner_w = max_w.saturating_sub(2);
    let mut body: Vec<Line> = Vec::new();
    for msg in &n.lines {
        // Problems are listed as red bullets; informational text (the
        // "Version" entry) is set as plain paragraphs.
        if !n.warning {
            if msg.is_empty() {
                body.push(Line::default());
                continue;
            }
            for chunk in wrap_text(msg, inner_w) {
                body.push(Line::from(Span::raw(chunk)));
            }
            continue;
        }
        for (i, chunk) in wrap_text(msg, inner_w).into_iter().enumerate() {
            let bullet = if i == 0 { "• " } else { "  " };
            body.push(Line::from(vec![
                Span::styled(bullet, Style::new().fg(Color::Red)),
                Span::raw(chunk),
            ]));
        }
    }
    body.push(Line::default());
    body.push(Line::from(Span::styled("press any key to dismiss", Style::new().dim())));

    let width = (max_w as u16).min(area.width);
    let height = (body.len() as u16 + 2).min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(if n.warning { Color::Yellow } else { MENU_COLOR }))
        .title(n.title.clone());
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    frame.render_widget(Paragraph::new(body), inner);
}

/// Break `text` into lines no wider than `width` display columns, splitting on
/// spaces where possible (falling back to a hard cut for over-long tokens).
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if word.chars().count() > width {
            if !cur.is_empty() {
                lines.push(std::mem::take(&mut cur));
            }
            let mut chunk = String::new();
            for c in word.chars() {
                if chunk.chars().count() == width {
                    lines.push(std::mem::take(&mut chunk));
                }
                chunk.push(c);
            }
            cur = chunk;
        } else if cur.is_empty() {
            cur = word.to_string();
        } else if cur.chars().count() + 1 + word.chars().count() <= width {
            cur.push(' ');
            cur.push_str(word);
        } else {
            lines.push(std::mem::take(&mut cur));
            cur = word.to_string();
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// The rows of the HSS/LMS structured parameter editor, one per field in
/// [`PubKeyState::hss_fields`] order: mode, hash, each level's height and
/// Winternitz (root first), and the "add level" affordance. `param_idx`
/// selects the focused row.
fn hss_editor_rows(s: &PubKeyState) -> Vec<String> {
    let lvl = |i: usize| if i == 0 { "root".to_string() } else { format!("L{}", i) };
    s.hss_fields()
        .into_iter()
        .map(|f| match f {
            crate::app::HssField::Mode => {
                format!("Mode: {}", if s.hss.is_hss { "HSS" } else { "LMS" })
            }
            crate::app::HssField::Hash => {
                format!("Hash: {}", keygen::HSS_HASHES[s.hss.hash_idx].label)
            }
            crate::app::HssField::Height(i) => {
                format!("{} H: {}", lvl(i), s.hss.levels[i].height())
            }
            crate::app::HssField::Winternitz(i) => {
                format!("{} W: {}", lvl(i), s.hss.levels[i].winternitz())
            }
            crate::app::HssField::AddLevel => "＋ add level".to_string(),
        })
        .collect()
}

/// The re-key time-estimate line(s) for the dialog's parameter column, or
/// empty for a fast algorithm (no estimate shown). The estimate covers the
/// key generation (when generating a new key) plus one signature per object
/// re-signed: the certificate itself when self-signed, and every selected
/// issued object.
fn pubkey_estimate_lines(app: &App, s: &PubKeyState, width: usize) -> Vec<Line<'static>> {
    let alg = s.dialog_algorithm();
    if !alg.shows_time_estimate() {
        return Vec::new();
    }
    let self_signed =
        matches!(app.sig_status, Some(SignatureStatus::Verified { self_signed: true, .. }));
    let n_sigs = usize::from(self_signed) + s.selected_issued_count();
    let estimate = if s.is_hsslms() {
        // HSS/LMS cost comes from its structured parameters.
        Some(cost::rekey_estimate_hsslms(&s.hss, n_sigs, !s.use_existing))
    } else {
        cost::rekey_estimate(alg, n_sigs, !s.use_existing)
    };
    let Some(estimate) = estimate else {
        return Vec::new();
    };
    clock_estimate_lines(&cost::format_hms(estimate), width)
}

/// Render `hms` prefixed with a clock symbol, on one line when it fits in
/// `width`, otherwise wrapped onto two lines (comma-separated units split
/// across them, clock on the first) so the parameter column need not widen.
fn clock_estimate_lines(hms: &str, width: usize) -> Vec<Line<'static>> {
    const CLOCK: &str = "🕐 ";
    const CLOCK_W: usize = 3; // clock emoji (~2 cells) + a space
    let style = Style::new().fg(Color::Yellow);
    if CLOCK_W + hms.chars().count() <= width {
        return vec![Line::from(Span::styled(format!("{CLOCK}{hms}"), style))];
    }
    // Pack the "x h, y mins, z secs" units greedily onto the first line
    // (after the clock), leaving one column for the trailing comma; the rest
    // go on the second line, indented under the time text.
    let tokens: Vec<&str> = hms.split(", ").collect();
    let mut idx = 0;
    let mut first = String::new();
    while idx < tokens.len() {
        let trial =
            if first.is_empty() { tokens[idx].to_string() } else { format!("{first}, {}", tokens[idx]) };
        let has_more = idx + 1 < tokens.len();
        if !first.is_empty() && CLOCK_W + trial.chars().count() + usize::from(has_more) > width {
            break;
        }
        first = trial;
        idx += 1;
    }
    let rest = tokens[idx..].join(", ");
    let mut out = Vec::new();
    if rest.is_empty() {
        out.push(Line::from(Span::styled(format!("{CLOCK}{first}"), style)));
    } else {
        out.push(Line::from(Span::styled(format!("{CLOCK}{first},"), style)));
        out.push(Line::from(Span::styled(format!("   {rest}"), style)));
    }
    out
}

/// Centered four-column popup for the public-key modification dialog:
/// algorithm family | parameters | key-generation options | issued
/// certificates to resign.
fn draw_edit_pubkey(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::EditPubKey(ref s) = app.mode else { return };
    let width = 96.min(area.width);
    let height = 22.min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::Yellow))
        .title(" MODIFY PUBLIC KEY — new key pair, resign issued objects ");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    // A full-width key-file row sits between the columns and the hint (only in
    // generate mode), so a long file name / path stays fully visible instead of
    // being clipped inside the narrow key-options column.
    let key_file_rows: u16 = if s.use_existing { 0 } else { 2 };
    let [cols_area, keyfile_area, hint_area] = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(key_file_rows),
        Constraint::Length(1),
    ])
    .areas(inner);
    let [alg_col, param_col, opt_col, issued_col] = Layout::horizontal([
        Constraint::Length(12),
        // Wide enough for the longest parameter row (the HSS/LMS editor's
        // " Hash: SHAKE-256/256 ").
        Constraint::Length(22),
        Constraint::Length(32),
        Constraint::Min(18),
    ])
    .areas(cols_area);

    let header = |text: &str, active: bool| {
        let style = if active {
            Style::new().fg(Color::Yellow).underlined().bold()
        } else {
            Style::new().underlined()
        };
        Line::from(Span::styled(text.to_string(), style))
    };
    // A selectable row: reversed when it is the active cell.
    let row = |text: String, selected: bool, active: bool| {
        let mut style = Style::new();
        if selected && active {
            style = style.add_modifier(Modifier::REVERSED).bold();
        } else if selected {
            style = style.bold().fg(Color::Yellow);
        }
        Line::from(Span::styled(format!(" {} ", text), style))
    };

    // Column 0: the algorithm families (all five fit without scrolling).
    let mut alg_lines = vec![header("Algorithm", s.column == 0)];
    for (i, family) in keygen::FAMILIES.iter().enumerate() {
        alg_lines.push(row(family.label.to_string(), i == s.family_idx, s.column == 0));
    }
    frame.render_widget(Paragraph::new(alg_lines), alg_col);

    // Column 1: the chosen family's parameters (curve, RSA key size,
    // parameter set) plus, for RSA, a free-entry custom-size row; scrolled so
    // the selection stays visible. HSS/LMS has a dedicated structured editor.
    let family = &keygen::FAMILIES[s.family_idx];
    let mut param_rows: Vec<String> = if s.is_hsslms() {
        hss_editor_rows(s)
    } else {
        family.members.iter().map(|alg| alg.param_label().to_string()).collect()
    };
    if family.custom_modulus {
        param_rows.push(format!("custom: {}", field_value(&s.custom_rsa_bits)));
    }
    let mut param_lines = vec![header("Parameters", s.column == 1)];
    // For the slow families (XMSS, SLH-DSA), estimate the whole re-key's
    // wall-clock for the current parameter set and object selection, shown
    // below the list with a clock symbol. It reserves room at the bottom of
    // the column so the parameter list scrolls above it.
    let estimate_lines = pubkey_estimate_lines(app, s, param_col.width as usize);
    let reserve = if estimate_lines.is_empty() { 0 } else { estimate_lines.len() + 1 };
    let visible =
        (param_col.height as usize).saturating_sub(1).saturating_sub(reserve).max(1);
    let start = s
        .param_idx
        .saturating_sub(visible.saturating_sub(1))
        .min(param_rows.len().saturating_sub(visible));
    for (i, label) in param_rows.into_iter().enumerate().skip(start).take(visible) {
        param_lines.push(row(label, i == s.param_idx, s.column == 1));
    }
    if !estimate_lines.is_empty() {
        param_lines.push(Line::default());
        param_lines.extend(estimate_lines);
    }
    frame.render_widget(Paragraph::new(param_lines), param_col);

    // Column 2: key-source radio, then either the generate fields (file name,
    // password) or the list of existing keys fitting the chosen algorithm.
    let active1 = s.column == 2;
    let radio_active = active1 && s.option_field == 0;
    let gen_mark = if s.use_existing { "( )" } else { "(•)" };
    let use_mark = if s.use_existing { "(•)" } else { "( )" };
    let mut opt_lines = vec![
        header("New private key", active1),
        row(format!("{} generate new private key", gen_mark), !s.use_existing, radio_active),
        row(format!("{} use existing key", use_mark), s.use_existing, radio_active),
        Line::default(),
    ];
    if !s.use_existing {
        let mask: String = "•".repeat(s.password.chars().count());
        // The file name lives in its own column (the full-width row below), so
        // this column carries just the source radio and the password.
        opt_lines.push(Line::from(Span::styled(" password (blank = unencrypted)", Style::new().dim())));
        opt_lines.push(row(field_value(&mask), s.option_field == 1, active1));
    } else {
        let fitting = s.fitting_keys();
        if fitting.is_empty() {
            opt_lines.push(Line::from(Span::styled(" (no matching key available)", Style::new().dim())));
        } else {
            // Scroll so the selected key stays visible (4 header/radio rows above).
            let visible = (opt_col.height as usize).saturating_sub(5).max(1);
            let sel = s.option_field.saturating_sub(1);
            let start = sel.saturating_sub(visible.saturating_sub(1)).min(fitting.len().saturating_sub(visible));
            for (i, k) in fitting.iter().enumerate().skip(start).take(visible) {
                opt_lines.push(row(k.label.clone(), s.option_field == i + 1, active1));
            }
        }
    }
    frame.render_widget(Paragraph::new(opt_lines), opt_col);

    // Column 3: issued certificates and CRLs with resign checkboxes.
    let mut issued_lines = vec![header("Resign issued objects", s.column == 3)];
    if s.issued.is_empty() {
        issued_lines.push(Line::from(Span::styled(" (none found)", Style::new().dim())));
    } else {
        let visible = (issued_col.height as usize).saturating_sub(1).max(1);
        let start = s.issued_idx.saturating_sub(visible.saturating_sub(1));
        for (i, cert) in s.issued.iter().enumerate().skip(start).take(visible) {
            let box_ = if cert.selected { "[x]" } else { "[ ]" };
            let label = format!("{} {}  {}", box_, cert.name, cert.detail);
            issued_lines.push(row(label, i == s.issued_idx, s.column == 3));
        }
    }
    frame.render_widget(Paragraph::new(issued_lines), issued_col);

    // Full-width key-file row: its own column (index 4, reached with ←/→ past
    // the issued-objects column). The file name plus its CWD-relative path,
    // wrapped to the whole dialog width so nothing is cut off. Focused-but-idle
    // it is reversed as a whole (like the active cells in the columns above);
    // in cursor-edit mode only the character under the cursor is reversed.
    if !s.use_existing && keyfile_area.height > 0 {
        let path = app.rekey_key_path_display(&s.filename);
        let value = if s.filename_editing {
            // The file name is the trailing segment of the shown path; place a
            // block cursor within it at `filename_cursor`.
            let prefix_len = path.chars().count().saturating_sub(s.filename.chars().count());
            let cursor = Style::new().add_modifier(Modifier::REVERSED).bold();
            let mut spans = Vec::new();
            let mut before = String::new();
            let mut under = String::new();
            let mut after = String::new();
            for (i, c) in path.chars().enumerate() {
                match (i).cmp(&(prefix_len + s.filename_cursor)) {
                    std::cmp::Ordering::Less => before.push(c),
                    std::cmp::Ordering::Equal => under.push(c),
                    std::cmp::Ordering::Greater => after.push(c),
                }
            }
            spans.push(Span::raw(before));
            // Cursor at end of the name: show a reversed space as the block.
            spans.push(Span::styled(if under.is_empty() { " ".to_string() } else { under }, cursor));
            if !after.is_empty() {
                spans.push(Span::raw(after));
            }
            spans
        } else {
            let style = if s.column == 4 {
                Style::new().add_modifier(Modifier::REVERSED).bold()
            } else {
                Style::new()
            };
            vec![Span::styled(field_value(&path), style)]
        };
        let lines = header_field("Key file: ", value, keyfile_area.width as usize);
        frame.render_widget(Paragraph::new(lines), keyfile_area);
    }

    let hint_text = if s.hss_picker.is_some() {
        "↑↓ choose  Space/⏎ select  Esc cancel"
    } else if s.filename_editing {
        "←→ cursor  Home/End  type to edit the file name  ⏎/Esc leave field"
    } else if s.column == 4 {
        "Space edit file name  ←→ column  ⏎ apply  Esc cancel"
    } else if s.is_hsslms() && s.column == 1 {
        "↑↓ field  ←→ column  Space edit value  + add level  - remove level  ⏎ apply  Esc cancel"
    } else {
        "←→ column  ↑↓ move  Space toggle  type to edit size/password  ⏎ apply  Esc cancel"
    };
    let hint = Line::from(Span::styled(hint_text, Style::new().dim()));
    frame.render_widget(Paragraph::new(hint), hint_area);

    // The HSS/LMS value-choice popup sits on top of the dialog.
    if let Some(ref picker) = s.hss_picker {
        draw_hss_picker(frame, s, picker, area);
    }
}

/// Centered popup listing the choices for one HSS/LMS field, opened with Enter
/// on a value field so the arrow keys stay free for dialog navigation.
fn draw_hss_picker(frame: &mut Frame, s: &PubKeyState, picker: &HssPicker, area: Rect) {
    let choices = s.hss_field_choices(picker.field);
    let title = format!(" {} ", PubKeyState::hss_field_name(picker.field));
    let inner_w = choices.iter().map(|c| c.chars().count()).max().unwrap_or(4).max(title.len());
    let width = (inner_w as u16 + 4).min(area.width);
    let height = (choices.len() as u16 + 2).min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::Cyan))
        .title(title);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let lines: Vec<Line> = choices
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            let mut style = Style::new();
            if i == picker.selected {
                style = style.add_modifier(Modifier::REVERSED).bold();
            }
            Line::from(Span::styled(format!(" {} ", c), style))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Render a text-field value, showing a single-space placeholder when empty so
/// the highlighted row still has width.
fn field_value(value: &str) -> String {
    if value.is_empty() {
        " ".to_string()
    } else {
        value.to_string()
    }
}

/// Centered popup for the re-sign dialog: whether the issuer's signing key is
/// available and, if so, an offer to create a new signature.
fn draw_resign(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::Resign(ref state) = app.mode else { return };
    let width = 66.min(area.width);
    let height = 8.min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let border = if state.ready { Color::Green } else { Color::Yellow };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border))
        .title(" RE-SIGN — regenerate the signature ");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let (status_word, status_color) = if state.ready {
        ("available", Color::Green)
    } else {
        ("not available", Color::Yellow)
    };
    let mut lines = vec![Line::from(vec![
        Span::styled("signing key: ", Style::new().dim()),
        Span::styled(status_word, Style::new().fg(status_color).bold()),
    ])];
    if !state.issuer_summary.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("issuer:      ", Style::new().dim()),
            Span::raw(state.issuer_summary.clone()),
        ]));
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::raw(state.detail.clone())));
    lines.push(Line::default());
    let hint = if state.ready {
        "⏎ create new signature   Esc cancel"
    } else {
        "Esc close"
    };
    lines.push(Line::from(Span::styled(hint, Style::new().dim())));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

/// Centered popup prompting for the decrypt password (masked).
fn draw_password(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::Password(ref p) = app.mode else { return };
    let width = 54.min(area.width);
    let height = 5.min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::Yellow))
        .title(" DECRYPT — enter password ");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let masked: String = "•".repeat(p.buf.chars().count());
    let lines = vec![
        Line::from(vec![
            Span::styled("password: ", Style::new().dim()),
            Span::styled(masked, Style::new().bold()),
            Span::styled("▏", Style::new().fg(Color::Yellow)),
        ]),
        Line::default(),
        Line::from(Span::styled("⏎ decrypt   Esc cancel", Style::new().dim())),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Centered popup for the "As Basic Constraints" structured editor: a small
/// form with the `cA` boolean and the optional `pathLenConstraint`.
fn draw_basic_constraints(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::EditBasicConstraints(ref s) = app.mode else { return };
    let width = 62.min(area.width);
    let height = 11.min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::Cyan))
        .title(" EDIT — Basic Constraints ");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    // Highlight the active field; dim the pathLen rows when cA = FALSE, where
    // the constraint has no meaning and is dropped on encoding.
    let active = |f: usize| {
        if s.field == f {
            Style::new().add_modifier(Modifier::REVERSED).bold()
        } else {
            Style::new().bold()
        }
    };
    let path_len_dim = if s.ca { Style::new() } else { Style::new().dim() };
    let checkbox = |on: bool| if on { "[x]" } else { "[ ]" };
    let present_label = if s.path_len_present { "present" } else { "absent" };
    let value_text = if s.path_len.is_empty() { " ".to_string() } else { s.path_len.clone() };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("cA                 ", Style::new().dim()),
            Span::styled(
                format!("{} {}", checkbox(s.ca), if s.ca { "TRUE" } else { "FALSE" }),
                active(0),
            ),
        ]),
        Line::default(),
        Line::from(vec![
            Span::styled("pathLenConstraint  ", path_len_dim),
            Span::styled(
                format!("{} {}", checkbox(s.path_len_present), present_label),
                active(1).patch(path_len_dim),
            ),
        ]),
        Line::from(vec![
            Span::styled("  value            ", path_len_dim),
            Span::styled(value_text, active(2).patch(path_len_dim)),
        ]),
    ];
    if !s.ca {
        lines.push(Line::from(Span::styled(
            "pathLenConstraint applies only when cA = TRUE",
            Style::new().dim().fg(Color::Yellow),
        )));
    }
    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled("critical: ", Style::new().dim()),
        Span::raw(if s.critical { "yes" } else { "no" }),
        Span::styled("  (a property of the Extension, edited elsewhere)", Style::new().dim()),
    ]));
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        "↑↓ field   Space toggle   digits set value   ⏎ apply   Esc cancel",
        Style::new().dim(),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Centered popup for the "As Key Usage" structured editor: one checkbox per
/// named KeyUsage bit.
fn draw_key_usage(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::EditKeyUsage(ref s) = app.mode else { return };
    let width = 46.min(area.width);
    let height = (key_usage::NUM_BITS as u16 + 6).min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::Cyan))
        .title(" EDIT — Key Usage ");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut lines: Vec<Line> = Vec::new();
    for (i, (name, _)) in key_usage::BITS.iter().enumerate() {
        let checkbox = if s.bits[i] { "[x]" } else { "[ ]" };
        let style = if s.field == i {
            Style::new().add_modifier(Modifier::REVERSED).bold()
        } else {
            Style::new().bold()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{checkbox} "), style),
            Span::styled(format!("({i}) {name}"), style),
        ]));
    }
    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled("critical: ", Style::new().dim()),
        Span::raw(if s.critical { "yes" } else { "no" }),
        Span::styled("  (a property of the Extension)", Style::new().dim()),
    ]));
    lines.push(Line::from(Span::styled(
        "↑↓ select bit   Space toggle   ⏎ apply   Esc cancel",
        Style::new().dim(),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Centered popup for the "As Extended Key Usage" structured editor: one
/// checkbox per well-known key purpose, one per custom OID already present, and
/// a dot-notation input field for adding new OIDs.
fn draw_ext_key_usage(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::EditExtKeyUsage(ref s) = app.mode else { return };
    let p = extended_key_usage::NUM_PREDEFINED;
    let active = |f: usize| {
        if s.field == f {
            Style::new().add_modifier(Modifier::REVERSED).bold()
        } else {
            Style::new().bold()
        }
    };
    let checkbox = |on: bool| if on { "[x]" } else { "[ ]" };

    let mut lines: Vec<Line> = Vec::new();
    for (i, (arcs, name, _)) in extended_key_usage::PURPOSES.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(format!("{} {name}", checkbox(s.predefined[i])), active(i)),
            Span::styled(format!("  ({})", oid::dotted(arcs)), Style::new().dim()),
        ]));
    }
    if !s.custom.is_empty() {
        lines.push(Line::from(Span::styled("additional OIDs:", Style::new().dim())));
        for (j, c) in s.custom.iter().enumerate() {
            lines.push(Line::from(Span::styled(
                format!("{} {}", checkbox(c.enabled), c.dotted),
                active(p + j),
            )));
        }
    }
    lines.push(Line::default());
    let focused = s.on_input();
    let mut input_spans = vec![Span::styled(
        "add OID: ",
        if focused { Style::new().bold() } else { Style::new().dim() },
    )];
    input_spans.push(Span::styled(s.input.clone(), Style::new().bold()));
    if focused {
        input_spans.push(Span::styled("▏", Style::new().fg(Color::Cyan)));
    }
    lines.push(Line::from(input_spans));
    lines.push(Line::from(Span::styled(
        "(type an OID in dot notation, then Enter to add it)",
        Style::new().dim(),
    )));
    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled("critical: ", Style::new().dim()),
        Span::raw(if s.critical { "yes" } else { "no" }),
        Span::styled("  (a property of the Extension)", Style::new().dim()),
    ]));
    lines.push(Line::from(Span::styled(
        "↑↓ select   Space toggle   ⏎ add / apply   Esc cancel",
        Style::new().dim(),
    )));

    let width = 60.min(area.width);
    let height = (lines.len() as u16 + 2).min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::Cyan))
        .title(" EDIT — Extended Key Usage ");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Border style cue for which pane currently has keyboard focus.
fn pane_border_style(active: bool) -> Style {
    if active {
        Style::new().fg(Color::White).bold()
    } else {
        Style::new().dim()
    }
}

/// Width of one relation-arrow gutter cell, in characters.
const ARROW_GUTTER_W: usize = 4;

/// The routed relation arrows of the browser pane: one optional
/// `(cell text, color)` per visible row and side. Every cell is
/// `ARROW_GUTTER_W` characters wide.
///
/// Arrows really travel from their source row to their destination row as
/// elbow connectors with two 90° turns (rounded corners), one horizontal
/// stub at each end and a vertical trunk between them:
///
/// * left side — the incoming "signed by" edge, drawn from the signer row
///   into the selected row (arrowhead `►` entering the selection);
/// * right side — the outgoing "signs" edges, drawn from the selected row
///   into each signed file (arrowheads `◄` entering the targets); the
///   targets share one vertical trunk, branching with `┤` junctions;
/// * far-left `keylink` gutter — the undirected key↔certificate links, drawn
///   with the same rounded elbows but **no arrowheads** (a private key is not
///   "signed by" its certificate), in a distinct color, sharing one trunk
///   that branches to every linked file with `├` junctions.
struct ArrowGutters {
    keylink: Vec<Option<(String, Color)>>,
    left: Vec<Option<(String, Color)>>,
    right: Vec<Option<(String, Color)>>,
}

/// Route the relation arrows for the current selection. `row_paths` holds
/// the file path of every *visible* browser row; edges whose other end is
/// not visible (inside a collapsed directory) are skipped — there is no
/// row to draw them to.
/// Map a relation endpoint to the browser row it should be drawn at: the
/// row of the path itself or — when the file is hidden inside a collapsed
/// directory — the deepest *visible* ancestor directory row, so the
/// association is still indicated (the arrow points at the folder the
/// counterpart lives in). `None` when no row covers the path at all.
fn endpoint_row(row_paths: &[&std::path::Path], p: &std::path::Path) -> Option<usize> {
    if let Some(i) = row_paths.iter().position(|q| *q == p) {
        return Some(i);
    }
    // Only directory rows can be a proper prefix of a file path, and of the
    // visible ancestors the deepest one is the collapsed dir hiding the file.
    let mut best: Option<(usize, usize)> = None; // (row, ancestor depth)
    for (i, q) in row_paths.iter().enumerate() {
        if p.starts_with(q) {
            let depth = q.components().count();
            if best.is_none_or(|(_, d)| depth > d) {
                best = Some((i, depth));
            }
        }
    }
    best.map(|(i, _)| i)
}

fn arrow_gutters(row_paths: &[&std::path::Path], selected: usize, rel: &FileRelations) -> ArrowGutters {
    let n = row_paths.len();
    let mut g =
        ArrowGutters { keylink: vec![None; n], left: vec![None; n], right: vec![None; n] };
    if selected >= n {
        return g;
    }

    // Key↔certificate links, dedicated leftmost gutter. Undirected: a trunk
    // in the leftmost column with a plain `── ` stub (no arrowhead) into the
    // selected row and each linked file:
    //   ╭──  linked file
    //   │
    //   ├──  another linked file
    //   ╰──  selected
    let mut endpoints: Vec<usize> = rel
        .key_links
        .iter()
        .filter_map(|p| endpoint_row(row_paths, p))
        .filter(|&i| i != selected)
        .collect();
    endpoints.sort_unstable();
    endpoints.dedup();
    if !endpoints.is_empty() {
        endpoints.push(selected);
        let lo = *endpoints.iter().min().unwrap();
        let hi = *endpoints.iter().max().unwrap();
        for row in lo..=hi {
            let cell = match (row == lo, row == hi, endpoints.contains(&row)) {
                (true, _, _) => "╭── ", // top corner (always an endpoint)
                (_, true, _) => "╰── ", // bottom corner
                (_, _, true) => "├── ", // intermediate linked file
                _ => "│   ",            // trunk passing through
            };
            g.keylink[row] = Some((cell.to_string(), REL_KEY));
        }
    }

    // Incoming edge, left gutter (trunk in the leftmost column):
    //   ╭──  signer            ╭─►  selected
    //   │                  or  │
    //   ╰─►  selected          ╰──  signer
    if let Some(edge) = &rel.signed_by {
        if let Some(src) = endpoint_row(row_paths, &edge.other) {
            if src != selected {
                let color = if edge.verified { REL_SIGNER } else { REL_BROKEN };
                let (top, bottom) = (src.min(selected), src.max(selected));
                for row in top..=bottom {
                    let cell = match (row == top, row == bottom, row == selected) {
                        (true, _, true) => "╭─► ",  // selection on top
                        (true, _, false) => "╭── ", // signer on top
                        (_, true, true) => "╰─► ",  // selection at bottom
                        (_, true, false) => "╰── ", // signer at bottom
                        _ => "│   ",                // trunk passing through
                    };
                    g.left[row] = Some((cell.to_string(), color));
                }
            }
        }
    }

    // Outgoing edges, right gutter (shared trunk in the rightmost column):
    //   selected  ───╮
    //   target   ◄──┤
    //   other        │
    //   target   ◄──╯
    // Several hidden edges may resolve to the same collapsed-directory row;
    // merge them (the merged stub is red only when every covered edge is).
    let mut targets: Vec<(usize, bool)> = Vec::new();
    for e in &rel.signs {
        let Some(i) = endpoint_row(row_paths, &e.other).filter(|i| *i != selected) else {
            continue;
        };
        match targets.iter_mut().find(|(row, _)| *row == i) {
            Some((_, verified)) => *verified = *verified || e.verified,
            None => targets.push((i, e.verified)),
        }
    }
    if !targets.is_empty() {
        let rows_min = targets.iter().map(|(i, _)| *i).min().unwrap().min(selected);
        let rows_max = targets.iter().map(|(i, _)| *i).max().unwrap().max(selected);
        // Trunk shows red only when every drawn edge is broken; a mix keeps
        // the "signs" color, with the broken targets' stubs red.
        let trunk_color =
            if targets.iter().all(|(_, v)| !v) { REL_BROKEN } else { REL_SIGNS };
        for row in rows_min..=rows_max {
            let junction = match (row == rows_min, row == rows_max) {
                (true, _) => '╮', // trunk continues downward only
                (_, true) => '╯', // trunk continues upward only
                _ => '┤',         // trunk passes through, branch to the left
            };
            let cell = if row == selected {
                Some((format!("───{}", junction), trunk_color))
            } else if let Some((_, verified)) = targets.iter().find(|(i, _)| *i == row) {
                let color = if *verified { REL_SIGNS } else { REL_BROKEN };
                Some((format!("◄──{}", junction), color))
            } else {
                Some(("   │".to_string(), trunk_color))
            };
            g.right[row] = cell;
        }
    }
    g
}

/// Color for the open-file marker when it has unsaved changes.
const DIRTY_MARKER: Color = Color::Yellow;

/// Glyph for the open-file marker when it has unsaved changes: U+1F5AB
/// WHITE HARD SHELL FLOPPY DISK, versus the plain dot `•` used when
/// there's nothing to save — so the distinction survives monochrome
/// terminals too. Unicode classifies it East Asian Width "Neutral" (not
/// "Wide"), and `unicode-width` — the same crate ratatui's own renderer
/// uses for cell layout — reports it as a single display column, so it
/// needs no special handling in this pane's column-alignment math (which
/// otherwise assumes `str::chars().count()` == display width).
const DIRTY_GLYPH: &str = "\u{1F5AB}";

/// Split `text` into up to 3 spans so that the single character at
/// `marker_offset` gets its own `marker_style`, distinct from the rest of
/// the row (which keeps `style`). Used to recolor just the open/dirty
/// marker glyph without disturbing the row's width/truncation math, which
/// operates on the plain, unsplit `text`. A no-op (single span) when
/// `marker_style` is `None` or the marker fell outside `text` (e.g.
/// truncated away in an extremely narrow pane).
fn styled_with_marker(
    text: &str,
    style: Style,
    marker_offset: usize,
    marker_style: Option<Style>,
) -> Vec<Span<'static>> {
    let Some(marker_style) = marker_style else {
        return vec![Span::styled(text.to_string(), style)];
    };
    let chars: Vec<char> = text.chars().collect();
    if marker_offset >= chars.len() {
        return vec![Span::styled(text.to_string(), style)];
    }
    let before: String = chars[..marker_offset].iter().collect();
    let marker: String = chars[marker_offset..marker_offset + 1].iter().collect();
    let after: String = chars[marker_offset + 1..].iter().collect();
    let mut spans = Vec::new();
    if !before.is_empty() {
        spans.push(Span::styled(before, style));
    }
    spans.push(Span::styled(marker, marker_style));
    if !after.is_empty() {
        spans.push(Span::styled(after, style));
    }
    spans
}

/// Width of the browser's leftmost change-time column: `HH:MM:SS` + a space.
const TIMESTAMP_W: usize = 9;

/// A prepared browser row: its display text and style, the open/dirty marker
/// position, and the optional change-time cell.
struct BrowserRow {
    text: String,
    style: Style,
    marker_offset: usize,
    marker_style: Option<Style>,
    timestamp: Option<(String, Color)>,
}

/// Format a modification time as local `HH:MM:SS` via the platform's
/// `localtime` (std alone cannot resolve the local timezone). POSIX exposes
/// `localtime_r(time, tm)`; the Windows CRT exposes `localtime_s(tm, time)`
/// with the arguments reversed.
fn format_hms(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as libc::time_t;
    // SAFETY: `localtime_r`/`localtime_s` fill a caller-provided `tm`; both
    // pointers are valid for the duration of the call.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        #[cfg(unix)]
        libc::localtime_r(&secs, &mut tm);
        #[cfg(windows)]
        libc::localtime_s(&mut tm, &secs);
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

fn draw_browser(frame: &mut Frame, app: &mut App, area: Rect) {
    let active = app.focus == Focus::Browser;
    let open_path = app.file_open.then_some(app.path.as_path());

    // Row texts and styles first, so the right-hand arrow trunk can be
    // aligned one column past the longest visible name. `marker_style`,
    // when set, recolors just the single open-marker glyph at
    // `marker_offset` (see `styled_with_marker`).
    let texts: Vec<BrowserRow> = app
        .browser
        .rows
        .iter()
        .map(|row| {
            let entry = app.browser.entry_at(&row.path).expect("row paths are valid");
            let fold_marker = if entry.is_dir {
                if entry.expanded { "▾ " } else { "▸ " }
            } else {
                "  "
            };
            let is_open = open_path == Some(entry.path.as_path());
            let dirty_open = is_open && app.dirty;
            let deleted = entry.status == FileStatus::Deleted;
            let mut style = if deleted {
                // A vanished file: gray and struck through, whatever it was.
                Style::new().fg(Color::DarkGray).add_modifier(Modifier::CROSSED_OUT)
            } else if entry.is_dir {
                Style::new().fg(Color::Green).bold()
            } else {
                Style::new()
            };
            if is_open && !deleted {
                style = style.fg(Color::LightGreen).bold();
            }
            let prefix = if dirty_open {
                format!("{} ", DIRTY_GLYPH)
            } else if is_open {
                "• ".to_string()
            } else {
                "  ".to_string()
            };
            // Certificates the user trusts get a trailing marker.
            let trust = if app.trusted_certs.contains(&entry.path) {
                "  [trusted]"
            } else {
                ""
            };
            let text = format!(
                "{}{}{}{}{}",
                "  ".repeat(row.depth),
                fold_marker,
                prefix,
                entry.name,
                trust
            );
            let marker_offset = row.depth * 2 + fold_marker.chars().count();
            let marker_style = dirty_open.then(|| Style::new().fg(DIRTY_MARKER).bold());
            // Leftmost change-time column: green for a new file, yellow for a
            // modified one; absent (unchanged / deleted) leaves it blank.
            let timestamp = match (entry.status, entry.changed_at) {
                (FileStatus::New, Some(t)) => Some((format_hms(t), Color::Green)),
                (FileStatus::Modified, Some(t)) => Some((format_hms(t), Color::Yellow)),
                _ => None,
            };
            BrowserRow { text, style, marker_offset, marker_style, timestamp }
        })
        .collect();
    let name_width = texts.iter().map(|r| r.text.chars().count()).max().unwrap_or(0);
    // The change-time column is shown only when some visible row carries one.
    let has_timestamp = texts.iter().any(|r| r.timestamp.is_some());
    let ts_w = if has_timestamp { TIMESTAMP_W } else { 0 };

    let row_paths: Vec<&std::path::Path> = app
        .browser
        .rows
        .iter()
        .map(|row| {
            app.browser
                .entry_at(&row.path)
                .expect("row paths are valid")
                .path
                .as_path()
        })
        .collect();
    let gutters = arrow_gutters(&row_paths, app.browser.selected, &app.browser_relations);
    // The gutters only take up columns while there is an arrow to show.
    let has_keylink = gutters.keylink.iter().any(|c| c.is_some());
    let has_left = gutters.left.iter().any(|c| c.is_some());
    let has_right = gutters.right.iter().any(|c| c.is_some());

    // Column the right-hand arrows start in: one past the longest name,
    // but never past the pane edge — long names are truncated with '…' so
    // the vertical trunk stays visible inside the pane.
    let left_w = usize::from(has_keylink) * ARROW_GUTTER_W + usize::from(has_left) * ARROW_GUTTER_W;
    let inner_w = area.width.saturating_sub(2) as usize; // pane borders
    let name_col_w = name_width
        .min(inner_w.saturating_sub(left_w + ts_w + ARROW_GUTTER_W))
        .max(1);

    let items: Vec<ListItem> = texts
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let BrowserRow { text, style, marker_offset, marker_style, timestamp } = r;
            let mut spans = Vec::new();
            // Leftmost column: the file's change time, or blank padding.
            if has_timestamp {
                match timestamp {
                    Some((ts, color)) => {
                        spans.push(Span::styled(format!("{:<w$}", ts, w = TIMESTAMP_W), Style::new().fg(color)));
                    }
                    None => spans.push(Span::raw(" ".repeat(TIMESTAMP_W))),
                }
            }
            let gutter_span = |cell: &Option<(String, Color)>| match cell {
                Some((text, color)) => Span::styled(text.clone(), Style::new().fg(*color).bold()),
                None => Span::raw(" ".repeat(ARROW_GUTTER_W)),
            };
            if has_keylink {
                spans.push(gutter_span(&gutters.keylink[i]));
            }
            if has_left {
                spans.push(gutter_span(&gutters.left[i]));
            }
            if has_right {
                // Pad (or truncate) the name so every right-hand cell
                // starts in the same column and the trunk lines up.
                let len = text.chars().count();
                if len > name_col_w {
                    let cut: String = text.chars().take(name_col_w.saturating_sub(1)).collect();
                    spans.extend(styled_with_marker(&format!("{}…", cut), style, marker_offset, marker_style));
                } else {
                    spans.extend(styled_with_marker(&text, style, marker_offset, marker_style));
                    spans.push(Span::raw(" ".repeat(name_col_w - len)));
                }
                if let Some((cell, color)) = &gutters.right[i] {
                    spans.push(Span::styled(cell.clone(), Style::new().fg(*color).bold()));
                }
            } else {
                spans.extend(styled_with_marker(&text, style, marker_offset, marker_style));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let title = format!(" Files — {} ", app.browser.root.display());
    let mut legend_spans = vec![
        Span::styled(format!(" {} unsaved ", DIRTY_GLYPH), Style::new().fg(DIRTY_MARKER)),
        Span::styled("─► signer ", Style::new().fg(REL_SIGNER)),
        Span::styled("─► signs ", Style::new().fg(REL_SIGNS)),
        Span::styled("─► bad ", Style::new().fg(REL_BROKEN)),
        Span::styled("── key ", Style::new().fg(REL_KEY)),
    ];
    // Only advertise the change indicators once something has changed on disk.
    let any_new = app.browser.entries_have_status(FileStatus::New);
    let any_mod = app.browser.entries_have_status(FileStatus::Modified);
    let any_del = app.browser.entries_have_status(FileStatus::Deleted);
    if any_new {
        legend_spans.push(Span::styled("new ", Style::new().fg(Color::Green)));
    }
    if any_mod {
        legend_spans.push(Span::styled("modified ", Style::new().fg(Color::Yellow)));
    }
    if any_del {
        legend_spans.push(Span::styled(
            "deleted ",
            Style::new().fg(Color::DarkGray).add_modifier(Modifier::CROSSED_OUT),
        ));
    }
    let legend = Line::from(legend_spans);
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(active))
                .title(title)
                .title_bottom(legend),
        )
        .highlight_style(if active {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new().add_modifier(Modifier::UNDERLINED)
        });
    frame.render_stateful_widget(list, area, &mut app.browser.list_state);
}

fn class_style(node: &Node) -> Style {
    let style = match node.class {
        Class::Universal => {
            if node.constructed {
                Style::new().fg(Color::Green)
            } else {
                Style::new().fg(Color::Cyan)
            }
        }
        Class::ContextSpecific => Style::new().fg(Color::Yellow),
        Class::Application => Style::new().fg(Color::Magenta),
        Class::Private => Style::new().fg(Color::Red),
    };
    if node.constructed || node.encapsulates {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    }
}

/// Short one-line preview of a node's value for the tree pane.
/// Value summary for the tree pane: like [`summary`], but a long INTEGER's
/// decimal value is clipped to 12 digits with an ellipsis so it does not crowd
/// the narrow pane. The content pane's `Decoded` line still shows it in full.
fn tree_summary(node: &Node) -> String {
    if node.is_universal(TAG_INTEGER) && !node.encapsulates {
        if let Some(dec) = ber::integer_decimal(&node.value) {
            let (sign, digits) = dec.strip_prefix('-').map_or(("", dec.as_str()), |r| ("-", r));
            if digits.len() > 12 {
                return format!(" {}{}…", sign, &digits[..12]);
            }
        }
    }
    summary(node)
}

fn summary(node: &Node) -> String {
    if node.constructed {
        return format!(" ({} elem)", node.children.len());
    }
    if node.encapsulates {
        return ", encapsulates".to_string();
    }
    let v = &node.value;
    let text = if node.class != Class::Universal {
        preview_text_or_hex(v)
    } else {
        match node.tag {
            TAG_BOOLEAN => {
                if v.first().copied().unwrap_or(0) == 0 { "FALSE".into() } else { "TRUE".into() }
            }
            // Arbitrary precision: 20-octet serial numbers and the like
            // must show in decimal too, exactly like freshly edited values.
            TAG_INTEGER => ber::integer_decimal(v)
                .unwrap_or_else(|| preview_text_or_hex(v)),
            TAG_NULL => String::new(),
            TAG_OID => ber::oid_arcs(v)
                .map(|arcs| {
                    oid::lookup(&arcs)
                        .map(|entry| entry.short_name.to_string())
                        .unwrap_or_else(|| oid::dotted(&arcs))
                })
                .unwrap_or_else(|| preview_text_or_hex(v)),
            TAG_UTC_TIME | TAG_GENERALIZED_TIME => {
                ber::format_time(v, node.tag == TAG_GENERALIZED_TIME)
                    .unwrap_or_else(|| preview_text_or_hex(v))
            }
            TAG_BIT_STRING => match v.split_first() {
                Some((unused, rest)) => {
                    let mut s = preview_text_or_hex(rest);
                    if *unused != 0 {
                        s.push_str(&format!(" ({} unused bits)", unused));
                    }
                    s
                }
                None => String::new(),
            },
            _ => preview_text_or_hex(v),
        }
    };
    if text.is_empty() { text } else { format!(" {}", text) }
}

/// The content pane's `Decoded` line(s) for a node, empty when there is
/// nothing to decode (constructed nodes, empty values). A long INTEGER's
/// decimal value (e.g. an RSA modulus) is wrapped to the width of the hex
/// dump below it, with continuation lines indented to align under the value;
/// every other value stays on a single line.
fn decoded_lines(node: &Node) -> Vec<Line<'static>> {
    const LABEL: &str = "Decoded ";
    let decoded = summary(node);
    let text = decoded.trim();
    if text.is_empty() || node.constructed {
        return Vec::new();
    }
    let value_w = HEX_DUMP_LINE_WIDTH - LABEL.len();
    if !node.is_universal(TAG_INTEGER) || text.chars().count() <= value_w {
        return vec![Line::from(vec![
            Span::styled(LABEL, Style::new().dim()),
            Span::raw(text.to_string()),
        ])];
    }
    wrap_text(text, value_w)
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            if i == 0 {
                Line::from(vec![Span::styled(LABEL, Style::new().dim()), Span::raw(chunk)])
            } else {
                Line::from(Span::raw(format!("{}{}", " ".repeat(LABEL.len()), chunk)))
            }
        })
        .collect()
}

/// Render a labeled header field — a dim `label` followed by the styled
/// `value` spans — wrapped so no line exceeds `width` display columns (the
/// hex-dump width). The label sits on the first line; continuation lines are
/// padded to the label width so the value stays in one column. Each span's
/// style is preserved across wraps; wrapping breaks at spaces where possible
/// and hard-breaks over-long tokens.
fn header_field(label: &str, value: Vec<Span<'static>>, width: usize) -> Vec<Line<'static>> {
    let label_w = label.chars().count();
    let avail = width.saturating_sub(label_w).max(1);
    let chars: Vec<(char, Style)> = value
        .iter()
        .flat_map(|s| {
            let style = s.style;
            s.content.chars().map(move |c| (c, style))
        })
        .collect();
    wrap_styled_chars(&chars, avail)
        .into_iter()
        .enumerate()
        .map(|(i, row)| {
            let mut spans = Vec::with_capacity(row.len() + 1);
            spans.push(if i == 0 {
                Span::styled(label.to_string(), Style::new().dim())
            } else {
                Span::raw(" ".repeat(label_w))
            });
            // Coalesce runs of equal style back into spans.
            let mut j = 0;
            while j < row.len() {
                let style = row[j].1;
                let mut text = String::new();
                while j < row.len() && row[j].1 == style {
                    text.push(row[j].0);
                    j += 1;
                }
                spans.push(Span::styled(text, style));
            }
            Line::from(spans)
        })
        .collect()
}

/// Greedy word-wrap a run of styled characters into rows of at most `width`
/// columns, breaking at the last space when one fits and hard-breaking an
/// over-long token otherwise. Styles ride along with their characters.
fn wrap_styled_chars(chars: &[(char, Style)], width: usize) -> Vec<Vec<(char, Style)>> {
    let width = width.max(1);
    let mut rows: Vec<Vec<(char, Style)>> = Vec::new();
    let mut cur: Vec<(char, Style)> = Vec::new();
    for &(c, style) in chars {
        if cur.len() >= width {
            match cur.iter().rposition(|(ch, _)| *ch == ' ') {
                // Break after the last space (dropped as the line break), but
                // only if it leaves a non-empty first line.
                Some(idx) if idx > 0 => {
                    let mut tail = cur.split_off(idx);
                    tail.remove(0); // the break space itself
                    rows.push(std::mem::take(&mut cur));
                    cur = tail;
                }
                _ => rows.push(std::mem::take(&mut cur)),
            }
        }
        cur.push((c, style));
    }
    if !cur.is_empty() {
        rows.push(cur);
    }
    if rows.is_empty() {
        rows.push(Vec::new());
    }
    rows
}

/// Dot notation and, when known, the full textual resolution for an OID node.
fn oid_details(node: &Node) -> Option<(String, Option<String>)> {
    if !node.is_universal(TAG_OID) {
        return None;
    }
    let arcs = ber::oid_arcs(&node.value)?;
    let entry = oid::lookup(&arcs);
    Some((
        oid::dotted(&arcs),
        entry.map(|entry| entry.long_name()),
    ))
}

fn preview_text_or_hex(v: &[u8]) -> String {
    const MAX: usize = 24;
    if v.is_empty() {
        return String::new();
    }
    if ber::is_printable_ascii(v) {
        let s: String = String::from_utf8_lossy(v).chars().take(MAX).collect();
        let ellipsis = if v.len() > MAX { "…" } else { "" };
        format!("'{}{}'", s, ellipsis)
    } else {
        let shown = &v[..v.len().min(8)];
        let ellipsis = if v.len() > 8 { "…" } else { "" };
        format!("{}{}", ber::hex_pairs(shown), ellipsis)
    }
}

/// The tree-filter / browser-search input line: label, the filter text with
/// a reversed-cell cursor while the field is focused, and a short key hint.
fn filter_bar_line(app: &App, label: &str) -> Line<'static> {
    let filter_editing = matches!(app.mode, Mode::FilterInput);
    let mut spans = vec![Span::styled(label.to_string(), Style::new().fg(Color::Cyan).bold())];
    if filter_editing {
        // Show the cursor position: the character under it is reversed
        // (a reversed space when the cursor sits at the end).
        let chars: Vec<char> = app.filter.chars().collect();
        let cur = app.filter_cursor.min(chars.len());
        let cursor_style = Style::new().add_modifier(Modifier::REVERSED).bold();
        spans.push(Span::styled(chars[..cur].iter().collect::<String>(), Style::new().bold()));
        match chars.get(cur) {
            Some(c) => {
                spans.push(Span::styled(c.to_string(), cursor_style));
                spans.push(Span::styled(
                    chars[cur + 1..].iter().collect::<String>(),
                    Style::new().bold(),
                ));
            }
            None => spans.push(Span::styled(" ", cursor_style)),
        }
        spans.push(Span::styled(
            "  (←→ move, ⏎/Tab navigate, Esc clears)",
            Style::new().dim(),
        ));
    } else {
        spans.push(Span::raw(app.filter.clone()));
    }
    Line::from(spans)
}

fn draw_tree(frame: &mut Frame, app: &mut App, area: Rect) {
    // The filter bar sits above the tree while the field has focus or holds
    // a non-empty filter string — unless the filter is the browser search,
    // whose bar spans the browser+tree panes and is drawn by `draw` instead.
    let filter_editing = matches!(app.mode, Mode::FilterInput);
    let area = if !app.filter_global && (filter_editing || !app.filter.is_empty()) {
        let [bar, rest] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(3)]).areas(area);
        frame.render_widget(Paragraph::new(filter_bar_line(app, " filter / ")), bar);
        rest
    } else {
        area
    };
    let items: Vec<ListItem> = app
        .rows
        .iter()
        .map(|row| {
            if row.elided {
                // A run of elements the tree filter omitted.
                return ListItem::new(Line::from(vec![
                    Span::raw("  ".repeat(row.depth + 1)),
                    Span::styled("[...]", Style::new().fg(Color::DarkGray)),
                ]));
            }
            if row.source == RowSource::DecryptedPlaceholder {
                return ListItem::new(Line::from(vec![
                    Span::raw("  ".repeat(row.depth + 1)),
                    Span::styled(
                        DECRYPTED_LOCKED_LABEL,
                        Style::new().fg(Color::Yellow).italic(),
                    ),
                ]));
            }
            let node = app.node_for_row(row).expect("row paths are valid");
            let marker = if node.has_children() {
                if node.expanded { "▾ " } else { "▸ " }
            } else {
                "  "
            };
            let mut spans =
                vec![Span::raw(format!("{}{}", "  ".repeat(row.depth), marker))];
            if row.source == RowSource::Decrypted && row.path.len() == 1 {
                spans.push(Span::styled(
                    DECRYPTED_UNLOCKED_PREFIX,
                    Style::new().fg(Color::Green).bold(),
                ));
            }
            if let RowSource::Pkcs12Revealed(idx) = row.source {
                if row.path.len() == 1 {
                    let kind = app
                        .pkcs12
                        .as_ref()
                        .and_then(|p| p.regions.get(idx))
                        .map(|r| r.kind.label())
                        .unwrap_or("decrypted");
                    spans.push(Span::styled(
                        format!("🔓 {}: ", kind),
                        Style::new().fg(Color::Green).bold(),
                    ));
                }
            }
            if row.source == RowSource::CmsRevealed && row.path.len() == 1 {
                spans.push(Span::styled(
                    "🔓 decrypted: ",
                    Style::new().fg(Color::Green).bold(),
                ));
            }
            let label = app.label_for_row(row);
            if let Some(field) = label.and_then(|l| l.field.as_deref()) {
                spans.push(Span::styled(
                    format!("{}: ", field),
                    Style::new().fg(Color::LightCyan).italic(),
                ));
            }
            spans.push(Span::styled(node.type_name(), class_style(node)));
            spans.push(Span::styled(tree_summary(node), Style::new().dim()));
            if let Some(l) = label {
                // Show the spec type name when it adds information beyond
                // the raw ASN.1 type already printed.
                if l.type_name != node.type_name() {
                    spans.push(Span::styled(
                        format!("  ·{}", l.type_name),
                        Style::new().fg(Color::LightGreen).dim(),
                    ));
                }
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let title = if app.file_open {
        let ident_note = app
            .ident
            .as_ref()
            .map(|i| format!(" — {}", i.type_name))
            .unwrap_or_default();
        format!(" Structure — {}{} ", app.path.display(), ident_note)
    } else {
        " Structure ".to_string()
    };
    let active = app.focus == Focus::Document;
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(active))
                .title(title),
        )
        .highlight_style(if active {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new().add_modifier(Modifier::UNDERLINED)
        });
    frame.render_stateful_widget(list, area, &mut app.tree_state);
}

/// Style for content bytes matched by the tree filter's hex reading.
const HEX_MATCH_STYLE: Style =
    Style::new().fg(Color::Black).bg(Color::Yellow);

/// Selected octets or characters (Shift + cursor keys, Ctrl+A).
const HEX_SELECTION_STYLE: Style = Style::new().fg(Color::White).bg(Color::Blue);
/// Content just added — typed, pasted, or brought back by an undo — until
/// the selection changes or the editor closes.
const HEX_FRESH_STYLE: Style = Style::new().fg(Color::Black).bg(Color::LightYellow);

/// Style for a selected cell, which the cursor may also be on.
///
/// A selection outranks the cursor here, rather than the other way round:
/// reversing the cursor cell would punch a hole in the marked run, leaving
/// half an octet coloured. The cursor stays findable inside the selection by
/// being underlined instead.
fn cursor_within_selection(at_cursor: bool) -> Style {
    if at_cursor {
        HEX_SELECTION_STYLE.add_modifier(Modifier::UNDERLINED | Modifier::BOLD)
    } else {
        HEX_SELECTION_STYLE
    }
}

/// The two colours the hex dump alternates between when a value's fields are
/// known ([`hashsig::describe_node`]), so that consecutive fields — and the
/// tokens naming them in the right-hand gutter — are told apart at a glance.
const FIELD_COLORS: [Color; 2] = [Color::Cyan, Color::Magenta];

/// The colour of the `i`-th field of a decoded value.
fn field_color(i: usize) -> Style {
    Style::new().fg(FIELD_COLORS[i % FIELD_COLORS.len()])
}

/// Per-byte flags marking every occurrence of `needle` in `bytes` (the tree
/// filter's hex reading), for dump highlighting.
fn hex_match_marks(bytes: &[u8], needle: &[u8]) -> Vec<bool> {
    let mut marks = vec![false; bytes.len()];
    if needle.is_empty() || needle.len() > bytes.len() {
        return marks;
    }
    for start in 0..=bytes.len() - needle.len() {
        if &bytes[start..start + needle.len()] == needle {
            for m in marks.iter_mut().skip(start).take(needle.len()) {
                *m = true;
            }
        }
    }
    marks
}

/// Which field of a decoded value byte `i` belongs to, as an index into
/// `fields`. The fields are sorted and non-overlapping, so a binary search
/// finds the candidate and one bounds check confirms it.
fn field_owner(fields: &[hashsig::Field], i: usize) -> Option<usize> {
    let k = fields.partition_point(|f| f.start <= i).checked_sub(1)?;
    (i < fields[k].start + fields[k].len).then_some(k)
}

/// The number of hex-dump lines `len` content octets occupy.
fn hex_dump_row_count(len: usize) -> usize {
    len.div_ceil(16)
}

/// Hex dump of the `rows` (16-byte lines) of `bytes` — the caller renders only
/// the lines the content pane can show, so the cost of a dump does not grow
/// with the size of the value. Positions flagged in `marks` (from the tree
/// filter's hex reading) are highlighted in both the hex and the right-hand
/// column; pass an empty slice for a plain dump.
///
/// With `fields` non-empty — a value `hashsig.rs` could decode — each byte
/// takes its field's colour, and the gutter lists the fields *starting* on
/// that line by name instead of showing the bytes' ASCII reading: for these
/// long concatenations of hash values the ASCII column carries no information,
/// while the field names show where each component begins.
fn hex_dump_lines(
    bytes: &[u8],
    marks: &[bool],
    fields: &[hashsig::Field],
    rows: std::ops::Range<usize>,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let marked = |i: usize| marks.get(i).copied().unwrap_or(false);
    let windowed = bytes
        .chunks(16)
        .enumerate()
        .skip(rows.start)
        .take(rows.end.saturating_sub(rows.start));
    for (i, chunk) in windowed {
        let mut spans = vec![Span::styled(format!("{:08X}  ", i * 16), Style::new().dim())];
        for (j, b) in chunk.iter().enumerate() {
            let style = if marked(i * 16 + j) {
                HEX_MATCH_STYLE
            } else {
                field_owner(fields, i * 16 + j).map(field_color).unwrap_or_default()
            };
            spans.push(Span::styled(format!("{:02X}", b), style));
            if j + 1 < chunk.len() {
                spans.push(Span::raw(" "));
            }
        }
        // Pad the hex column to its full width (16*3-1) plus the separator.
        let hex_w = chunk.len() * 3 - 1;
        spans.push(Span::raw(" ".repeat(47 - hex_w + 2)));
        if fields.is_empty() {
            spans.push(Span::styled("|", Style::new().dim()));
            for (j, &b) in chunk.iter().enumerate() {
                let c = if (0x20..=0x7E).contains(&b) { b as char } else { '.' };
                let style = if marked(i * 16 + j) { HEX_MATCH_STYLE } else { Style::new().dim() };
                spans.push(Span::styled(c.to_string(), style));
            }
            spans.push(Span::styled("|", Style::new().dim()));
        } else {
            let line_end = i * 16 + chunk.len();
            let starting = fields
                .iter()
                .enumerate()
                .filter(|(_, f)| (i * 16..line_end).contains(&f.start));
            for (n, (k, field)) in starting.enumerate() {
                if n > 0 {
                    spans.push(Span::raw(" "));
                }
                spans.push(Span::styled(field.short.clone(), field_color(k)));
            }
        }
        lines.push(Line::from(spans));
    }
    lines
}

fn draw_content(frame: &mut Frame, app: &mut App, area: Rect) {
    match &app.mode {
        Mode::Edit(_) => draw_content_edit(frame, app, area),
        _ => draw_content_browse(frame, app, area),
    }
}

/// Centered popup for choosing the type of a new element: one column per
/// bit field of the identifier octet (class, form, tag number).
fn draw_picker(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::TypePicker(ref p) = app.mode else { return };

    let width = 64.min(area.width);
    let height = (PICKER_UNIVERSAL.len() as u16 + 5).min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let title = match p.target {
        PickerTarget::Insert { .. } => " INSERT — choose ASN.1 type ",
        PickerTarget::Retag { .. } => " EDIT TYPE — choose new ASN.1 type ",
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::Yellow))
        .title(title);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let [cols_area, preview_area] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);
    let [class_col, form_col, tag_col] = Layout::horizontal([
        Constraint::Length(20),
        Constraint::Length(16),
        Constraint::Min(20),
    ])
    .areas(cols_area);

    let header = |text: &str, active: bool| {
        let style = if active {
            Style::new().fg(Color::Yellow).underlined().bold()
        } else {
            Style::new().underlined()
        };
        Line::from(Span::styled(text.to_string(), style))
    };
    let item = |text: &str, selected: bool, active_col: bool, disabled: bool| {
        let mut style = Style::new();
        if disabled {
            style = style.dim().crossed_out();
        } else if selected && active_col {
            style = style.add_modifier(Modifier::REVERSED).bold();
        } else if selected {
            style = style.bold().fg(Color::Yellow);
        }
        Line::from(Span::styled(format!(" {} ", text), style))
    };

    // Column 0: class bits (8-7).
    let mut class_lines = vec![header("Class (bits 8-7)", p.column == 0)];
    for (i, (name, _)) in PICKER_CLASSES.iter().enumerate() {
        class_lines.push(item(name, i == p.class_idx, p.column == 0, false));
    }
    frame.render_widget(Paragraph::new(class_lines), class_col);

    // Column 1: form bit (6). A forced form disables the other choice.
    let effective_form = usize::from(p.constructed());
    let mut form_lines = vec![header("Form (bit 6)", p.column == 1)];
    for (i, name) in ["Primitive", "Constructed"].iter().enumerate() {
        let disabled = p.forced_form().is_some() && i != effective_form;
        form_lines.push(item(name, i == effective_form, p.column == 1, disabled));
    }
    frame.render_widget(Paragraph::new(form_lines), form_col);

    // Column 2: tag number (bits 5-1).
    let mut tag_lines = vec![header("Tag number (bits 5-1)", p.column == 2)];
    if p.class() == Class::Universal {
        // Scroll window so the selection stays visible.
        let visible = (tag_col.height as usize).saturating_sub(1).max(1);
        let start = p.univ_idx.saturating_sub(visible.saturating_sub(1));
        for (i, (tag, name)) in PICKER_UNIVERSAL.iter().enumerate().skip(start).take(visible) {
            tag_lines.push(item(
                &format!("{:2}  {}", tag, name),
                i == p.univ_idx,
                p.column == 2,
                false,
            ));
        }
    } else {
        tag_lines.push(item(
            &format!("number: {}_", p.tag_digits),
            true,
            p.column == 2,
            false,
        ));
        tag_lines.push(Line::from(Span::styled(
            " type digits, ↑↓ adjusts",
            Style::new().dim(),
        )));
    }
    frame.render_widget(Paragraph::new(tag_lines), tag_col);

    let preview = Line::from(vec![
        Span::styled("identifier octets: ", Style::new().dim()),
        Span::styled(ber::hex_pairs(&p.identifier_preview()), Style::new().bold()),
        Span::styled(
            format!("  ({})", ber::type_name_of(p.class(), p.tag())),
            Style::new().dim(),
        ),
        Span::styled("   ⏎ continue  Esc cancel", Style::new().dim()),
    ]);
    frame.render_widget(Paragraph::new(preview), preview_area);
}

/// Render a bit-field box: one entry per column, each column holding
/// [bit positions (embedded in the top border), bit values, field label,
/// decoded meaning]. Returns 5 rows of box-drawing text.
fn bitfield_box(cols: &[[String; 4]]) -> Vec<String> {
    let widths: Vec<usize> =
        cols.iter().map(|c| c.iter().map(|s| s.chars().count()).max().unwrap()).collect();
    let last = cols.len() - 1;
    let border = |left: char, mid: char, right: char, with_positions: bool| {
        let mut out = String::from(left);
        for (i, w) in widths.iter().enumerate() {
            let content = if with_positions { cols[i][0].as_str() } else { "" };
            out.push_str(content);
            out.extend(std::iter::repeat_n('─', w - content.chars().count()));
            out.push(if i < last { mid } else { right });
        }
        out
    };
    let row = |idx: usize| {
        let mut out = String::from("│");
        for (i, col) in cols.iter().enumerate() {
            out.push_str(&col[idx]);
            out.extend(std::iter::repeat_n(' ', widths[i] - col[idx].chars().count()));
            out.push('│');
        }
        out
    };
    vec![
        border('┌', '┬', '┐', true),
        row(1),
        row(2),
        row(3),
        border('└', '┴', '┘', false),
    ]
}

/// Text rows of the tag bit-field diagram: which bits of the identifier
/// octet(s) hold which field, how wide each field is, and what it decodes
/// to. Row order: top border, bit values, field labels, decoded meaning,
/// bottom border, then one row per continuation octet (long form).
pub fn tag_layout_strings(node: &Node) -> Vec<String> {
    let ids = ber::identifier_octets(node.class, node.tag, node.constructed);
    let b0 = ids[0];
    let bit = |i: u8| (b0 >> i) & 1;
    let class_name = match node.class {
        Class::Universal => "universal",
        Class::Application => "application",
        Class::ContextSpecific => "context-specific",
        Class::Private => "private",
    };
    let form = if node.constructed { "constructed" } else { "primitive" };
    let long_form = ids.len() > 1;
    let tag_decoded = if long_form {
        "31 = long form ↓".to_string()
    } else if node.class == Class::Universal {
        format!("{} = {}", node.tag, ber::universal_tag_name(node.tag))
    } else {
        format!("{}", node.tag)
    };

    // One entry per column: [bit positions, bit values, label, decoded].
    let cols: Vec<[String; 4]> = vec![
        [
            " 8 7 ".into(),
            format!(" {} {} ", bit(7), bit(6)),
            " class (2 bits) ".into(),
            format!(" {} ", class_name),
        ],
        [
            " 6 ".into(),
            format!(" {} ", bit(5)),
            " P/C (1 bit) ".into(),
            format!(" {} ", form),
        ],
        [
            " 5 4 3 2 1 ".into(),
            format!(" {} {} {} {} {} ", bit(4), bit(3), bit(2), bit(1), bit(0)),
            " tag number (5 bits) ".into(),
            format!(" {} ", tag_decoded),
        ],
    ];
    let mut lines = bitfield_box(&cols);
    if long_form {
        for (i, &b) in ids[1..].iter().enumerate() {
            lines.push(format!(
                "octet {}:  {} {:07b}   (bit 8 = {}, bits 7-1 = tag bits)",
                i + 2,
                b >> 7,
                b & 0x7F,
                if b & 0x80 != 0 { "1: more octets follow" } else { "0: last octet" },
            ));
        }
        lines.push(format!("tag number = {}", node.tag));
    }
    lines
}

/// Length octets of a node as they appear in its (canonical) encoding.
pub fn node_length_octets(node: &Node) -> Vec<u8> {
    if node.indefinite {
        vec![0x80]
    } else {
        ber::length_octets(node.content_len)
    }
}

/// Text rows of the length bit-field diagram, in the same style as
/// `tag_layout_strings`: first length octet as a box (form bit + 7-bit
/// field), then one row per value octet in the long form.
pub fn length_layout_strings(node: &Node) -> Vec<String> {
    let octets = node_length_octets(node);
    let b0 = octets[0];
    let bit = |i: u8| (b0 >> i) & 1;
    let long_form = b0 & 0x80 != 0;
    let bits7: String = (0..7).rev().map(|i| format!("{} ", bit(i))).collect();

    let (label, decoded) = if !long_form {
        (
            " content length (7 bits) ".to_string(),
            format!(" {} = content length ", node.content_len),
        )
    } else if node.indefinite {
        (
            " # of length octets (7 bits) ".to_string(),
            " 0 = indefinite length ".to_string(),
        )
    } else {
        (
            " # of length octets (7 bits) ".to_string(),
            format!(" {} octets follow ↓ ", octets.len() - 1),
        )
    };
    let cols: Vec<[String; 4]> = vec![
        [
            " 8 ".into(),
            format!(" {} ", bit(7)),
            " form (1 bit) ".into(),
            format!(" {} form ", if long_form { "long" } else { "short" }),
        ],
        [" 7 6 5 4 3 2 1 ".into(), format!(" {}", bits7), label, decoded],
    ];
    let mut lines = bitfield_box(&cols);
    if long_form && !node.indefinite {
        for (i, &b) in octets[1..].iter().enumerate() {
            lines.push(format!(
                "octet {}:  {:08b}   (= 0x{:02X}, big-endian value byte)",
                i + 2,
                b,
                b,
            ));
        }
        lines.push(format!("content length = {}", node.content_len));
    }
    if node.indefinite {
        lines.push("content ends with end-of-contents octets (00 00)".to_string());
    }
    lines
}

/// The signature verification result for the whole open document — shown
/// once in the content pane header, right below "Spec", regardless of
/// which node is currently selected.
fn signature_status_lines(status: &SignatureStatus, width: usize) -> Vec<Line<'static>> {
    let (text, style) = match status {
        SignatureStatus::Verified { issuer_path, issuer_summary, self_signed } => (
            if *self_signed {
                format!("verified — self-signed ({})", issuer_summary)
            } else {
                format!("verified — signed by {} ({})", issuer_summary, issuer_path.display())
            },
            Style::new().fg(Color::Green),
        ),
        SignatureStatus::Invalid { issuer_path, issuer_summary } => (
            format!(
                "does NOT verify — claimed issuer {} ({})",
                issuer_summary,
                issuer_path.display()
            ),
            Style::new().fg(Color::Red).bold(),
        ),
        SignatureStatus::IssuerNotFound => (
            "issuer certificate not found in this directory".to_string(),
            Style::new().fg(Color::Yellow),
        ),
        SignatureStatus::UnsupportedAlgorithm(name) => (
            format!("issuer found, but signature algorithm {} is not supported", name),
            Style::new().fg(Color::Yellow),
        ),
    };
    header_field("Signature ", vec![Span::styled(text, style)], width)
}

/// The OpenSSL path-validation field ([`PathStatus`]), under the given label.
fn path_status_lines(label: &str, status: &PathStatus, width: usize) -> Vec<Line<'static>> {
    let (text, style) = match status {
        PathStatus::Valid { depth } => (
            format!("valid — path of {} certificate(s) to a trusted anchor", depth),
            Style::new().fg(Color::Green),
        ),
        PathStatus::Revoked { subject } => (
            format!("revoked — {} is listed on a CRL from its issuer", subject),
            Style::new().fg(Color::Red).bold(),
        ),
        PathStatus::Invalid { reason } => {
            (format!("no valid path — {}", reason), Style::new().fg(Color::Red).bold())
        }
        PathStatus::Error { detail } => {
            (format!("could not validate — {}", detail), Style::new().fg(Color::Yellow))
        }
    };
    header_field(label, vec![Span::styled(text, style)], width)
}

/// The Botan path-validation field ([`BotanPathStatus`]), under the given
/// label. Botan returns no chain depth, so a valid path is reported without one.
fn botan_path_status_lines(
    label: &str,
    status: &BotanPathStatus,
    width: usize,
) -> Vec<Line<'static>> {
    let (text, style) = match status {
        BotanPathStatus::Valid => {
            ("valid — path to a trusted anchor".to_string(), Style::new().fg(Color::Green))
        }
        BotanPathStatus::Revoked => (
            "revoked — a certificate on the path is on a CRL".to_string(),
            Style::new().fg(Color::Red).bold(),
        ),
        // Botan's path-validation policy rejects a signature whose hash is not
        // on its trusted-hash allow-list. That fires for post-quantum
        // signatures (SLH-DSA/XMSS), whose hash is not on Botan's classical
        // default list, even though the signature is valid — so annotate this
        // case rather than showing the bare message, which reads like a
        // certificate defect.
        BotanPathStatus::Invalid { reason } if reason.to_lowercase().contains("too weak") => (
            "Botan policy rejects the signature's hash — expected for \
             post-quantum signatures (e.g. SLH-DSA/XMSS); OpenSSL accepts it"
                .to_string(),
            Style::new().fg(Color::Yellow),
        ),
        BotanPathStatus::Invalid { reason } => {
            (format!("no valid path — {}", reason), Style::new().fg(Color::Red).bold())
        }
        BotanPathStatus::Error { detail } => {
            (format!("could not validate — {}", detail), Style::new().fg(Color::Yellow))
        }
    };
    header_field(label, vec![Span::styled(text, style)], width)
}

fn draw_content_browse(frame: &mut Frame, app: &mut App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    // Content octets, filter marks and decoded fields of the selected element,
    // set below and turned into dump lines only for the rows on screen.
    let mut dump: Option<(Vec<u8>, Vec<bool>, Vec<hashsig::Field>)> = None;
    let selected_row = app.rows.get(app.selected);
    if selected_row.is_some_and(|r| r.elided) {
        lines.push(Line::from(Span::styled(
            "Elements hidden by the tree filter",
            Style::new().fg(Color::DarkGray).bold(),
        )));
        lines.push(Line::default());
        lines.push(Line::from("'/' edits the filter; Esc there clears it and shows the full tree."));
    } else if selected_row.map(|r| r.source) == Some(RowSource::DecryptedPlaceholder) {
        lines.push(Line::from(Span::styled(
            "Decrypted content not available",
            Style::new().fg(Color::Yellow).bold(),
        )));
        lines.push(Line::default());
        // Password-based containers (PKCS#8/PKCS#12) prompt directly; a CMS
        // EnvelopedData is decrypted with a recipient key via the 'z' menu.
        let hint = if x509::find_enveloped(&app.roots).is_some() {
            "Press 'z' and choose \"Decrypt message\" (needs the recipient's key)."
        } else {
            "Press 'z' and enter the password to decrypt it."
        };
        lines.push(Line::from(hint));
    } else if let Some(node) = app.selected_node() {
        let w = HEX_DUMP_LINE_WIDTH;
        lines.extend(header_field(
            "Type    ",
            vec![Span::styled(node.type_name(), class_style(node))],
            w,
        ));
        if let Some(row) = selected_row {
            if let Some(label) = app.label_for_row(row) {
                let ident = match row.source {
                    RowSource::Document => app.ident.as_ref(),
                    RowSource::Decrypted => app.decrypted.as_ref().and_then(|d| d.ident.as_ref()),
                    RowSource::DecryptedPlaceholder => None,
                    RowSource::Pkcs12Revealed(idx) => app
                        .pkcs12
                        .as_ref()
                        .and_then(|p| p.regions.get(idx))
                        .and_then(|r| r.ident.as_ref()),
                    RowSource::CmsRevealed => {
                        app.cms_reveal.as_ref().and_then(|r| r.ident.as_ref())
                    }
                }
                .expect("label implies identification");
                let field = label.field.as_deref().unwrap_or("-");
                lines.extend(header_field(
                    "Spec    ",
                    vec![
                        Span::styled(field.to_string(), Style::new().fg(Color::LightCyan)),
                        Span::raw(" : "),
                        Span::styled(label.type_name.clone(), Style::new().fg(Color::LightGreen)),
                        Span::styled(
                            format!("   (document: {}, {})", ident.type_name, ident.source),
                            Style::new().dim(),
                        ),
                    ],
                    w,
                ));
            }
        }
        if let Some(status) = &app.sig_status {
            lines.extend(signature_status_lines(status, w));
        }
        if let Some(status) = &app.path_status {
            lines.extend(path_status_lines("Path/OpenSSL ", status, w));
        }
        if let Some(status) = &app.path_status_botan {
            lines.extend(botan_path_status_lines("Path/Botan   ", status, w));
        }
        let ids = ber::identifier_octets(node.class, node.tag, node.constructed);
        lines.extend(header_field(
            "Tag     ",
            vec![Span::raw(format!(
                "identifier octet{}: {}",
                if ids.len() == 1 { "" } else { "s" },
                ber::hex_pairs(&ids)
            ))],
            w,
        ));
        // Bit values (row 1) and decoded meaning (row 3) stand out;
        // borders and labels stay dim.
        let diagram_style = |i: usize| match i {
            1 => Style::new().bold(),
            0 | 2 | 4 => Style::new().dim(),
            _ => Style::new(), // decoded row and extra octet rows
        };
        for (i, text) in tag_layout_strings(node).into_iter().enumerate() {
            lines.push(Line::from(Span::styled(text, diagram_style(i))));
        }
        let plural = |n: usize| if n == 1 { "" } else { "s" };
        let len_octets = node_length_octets(node);
        lines.extend(header_field(
            "Length  ",
            vec![Span::raw(format!(
                "length octet{}: {}",
                plural(len_octets.len()),
                ber::hex_pairs(&len_octets)
            ))],
            w,
        ));
        for (i, text) in length_layout_strings(node).into_iter().enumerate() {
            lines.push(Line::from(Span::styled(text, diagram_style(i))));
        }
        lines.extend(header_field(
            "Offset  ",
            vec![Span::raw(format!(
                "{}   header: {} byte{}   content: {} byte{}{}",
                node.offset,
                node.header_len,
                plural(node.header_len),
                node.content_len,
                plural(node.content_len),
                if node.indefinite { "   (indefinite length)" } else { "" }
            ))],
            w,
        ));
        if node.encapsulates {
            lines.extend(header_field(
                "",
                vec![Span::styled(
                    "Encapsulates nested ASN.1 (shown as children in the tree)",
                    Style::new().fg(Color::Yellow),
                )],
                w,
            ));
        }
        lines.extend(decoded_lines(node));
        if let Some((dotted, long_name)) = oid_details(node) {
            lines.extend(header_field("OID     ", vec![Span::raw(dotted)], w));
            if let Some(long_name) = long_name {
                lines.extend(header_field("Name    ", vec![Span::raw(long_name)], w));
            }
        }
        // Plain-language interpretation of a recognised extension, shown
        // between the header information and the raw content octets.
        let extension_section = |heading: &str, body: Vec<String>| {
            // Cap at the hex-dump width so these sections, like the header
            // fields above, never run wider than the content below them.
            let inner_w =
                (area.width.saturating_sub(2) as usize).clamp(20, HEX_DUMP_LINE_WIDTH);
            let mut out = vec![
                Line::default(),
                Line::from(Span::styled(heading.to_string(), Style::new().fg(Color::LightCyan).bold())),
            ];
            for text in body {
                for chunk in wrap_text(&text, inner_w) {
                    out.push(Line::from(Span::raw(chunk)));
                }
            }
            out
        };
        if let Some(bc) = basic_constraints::parse(node) {
            lines.extend(extension_section(
                "Basic Constraints (RFC 5280 §4.2.1.9)",
                basic_constraints::describe(&bc),
            ));
        } else if let Some(ku) = key_usage::parse(node) {
            lines.extend(extension_section(
                "Key Usage (RFC 5280 §4.2.1.3)",
                key_usage::describe(&ku),
            ));
        } else if let Some(eku) = extended_key_usage::parse(node) {
            lines.extend(extension_section(
                "Extended Key Usage (RFC 5280 §4.2.1.12)",
                extended_key_usage::describe(&eku),
            ));
        }
        // XMSS / HSS-LMS values have no ASN.1 inside to show their structure,
        // so document it here and let the dump below colour the fields.
        let hash_based = hashsig::describe_node(node);
        if let Some(described) = &hash_based {
            let mut notes = described.notes.clone();
            notes.push(
                "In the dump below each field takes one of two alternating colours, and the \
                 column on the right — where a plain dump shows the bytes' ASCII reading — \
                 names the fields that begin on that line."
                    .to_string(),
            );
            lines.extend(extension_section(&described.heading, notes));
        }
        lines.push(Line::default());
        let content = node.content_octets();
        lines.push(Line::from(Span::styled(
            format!(
                "Content octets ({} byte{}) — 'e' edits, 'E' for all edit modes:",
                content.len(),
                if content.len() == 1 { "" } else { "s" }
            ),
            Style::new().underlined(),
        )));
        // While the tree filter is set and reads as hex, highlight every
        // occurrence of those bytes in the dump.
        let marks = (!app.filter.is_empty())
            .then(|| FilterMatcher::new(&app.filter))
            .and_then(|m| m.hex_bytes().map(|n| hex_match_marks(&content, n)))
            .unwrap_or_default();
        // The dump itself is rendered last, one screenful at a time — see
        // below — so that showing a multi-megabyte value costs no more than
        // showing a short one.
        dump = Some((content, marks, hash_based.map(|d| d.fields).unwrap_or_default()));
    } else if !app.file_open {
        lines.push(Line::from(
            "no file open — move ↑↓ over a file in the Files pane on the left to preview it",
        ));
    } else {
        lines.push(Line::from("no element selected"));
    }

    // The pane scrolls by dropping leading lines rather than through
    // `Paragraph::scroll`, so the whole value — however large — stays
    // reachable (that offset is a `u16`) and unseen lines are never built.
    let rows = usize::from(area.height.saturating_sub(2)); // borders
    let header = lines.len();
    let total = header + dump.as_ref().map_or(0, |(c, ..)| hex_dump_row_count(c.len()));
    // Clamping here, where the pane's height and the line count are both
    // known, is what stops scrolling past the end: the last screenful is as
    // far as it goes, and 'shift + ]' just asks for more than there is.
    app.content_scroll = app.content_scroll.min(total.saturating_sub(rows));
    let first = app.content_scroll;
    let last = first.saturating_add(rows).min(total);

    let mut view: Vec<Line> = lines.drain(first.min(header)..last.min(header)).collect();
    if let Some((content, marks, fields)) = &dump {
        view.extend(hex_dump_lines(
            content,
            marks,
            fields,
            first.saturating_sub(header)..last.saturating_sub(header),
        ));
    }
    let para = Paragraph::new(view).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(pane_border_style(app.focus == Focus::Document))
            .title(" Content "),
    );
    frame.render_widget(para, area);
}

/// First line of every value editor: live feedback from `to_bytes()`.
fn feedback_line(edit: &EditState) -> Line<'static> {
    match edit.to_bytes() {
        Ok(bytes) => Line::from(Span::styled(
            format!("→ {} byte{}", bytes.len(), if bytes.len() == 1 { "" } else { "s" }),
            Style::new().fg(Color::Green),
        )),
        Err(e) => Line::from(Span::styled(format!("✗ {}", e), Style::new().fg(Color::Red))),
    }
}

fn editor_title_hint(edit: &EditState) -> (String, &'static str) {
    if let EditKind::Insert { class, tag, constructed, .. } = edit.kind {
        return (
            format!(
                " INSERT — value for new {} (hex{}) ",
                ber::type_name_of(class, tag),
                if constructed { ", must be valid TLVs, may stay empty" } else { ", may stay empty" },
            ),
            "[Enter] insert  [Esc] cancel  [Shift+←→↑↓] select  [Ctrl+] A all  C copy  X cut  V paste  Z undo",
        );
    }
    match edit.editor {
        Editor::Hex(_) => (
            " EDIT — content octets (hex) ".to_string(),
            "[Enter] apply  [Esc] cancel  [Shift+←→↑↓] select  [Ctrl+] A all  C copy  X cut  V paste  Z undo",
        ),
        Editor::Text(ref t) => match t.format {
            TextFormat::Base64 => (
                " EDIT — content octets (base64) ".to_string(),
                "[Enter] apply   [Esc] cancel   standard base64, whitespace ignored",
            ),
            TextFormat::Raw => (
                " EDIT — raw value (characters → bytes) ".to_string(),
                "[Enter] apply   [Esc] cancel   typed/pasted characters become UTF-8 bytes",
            ),
            TextFormat::Integer => (
                " EDIT — INTEGER value (decimal) ".to_string(),
                "[Enter] apply   [Esc] cancel   decimal integer, '-' allowed",
            ),
            TextFormat::Real => (
                " EDIT — REAL value (decimal) ".to_string(),
                "[Enter] apply   [Esc] cancel   e.g. 3.14, -2.5E3, inf, -inf",
            ),
            TextFormat::Oid => (
                " EDIT — OBJECT IDENTIFIER (dot notation) ".to_string(),
                "[Enter] apply   [Esc] cancel   e.g. 1.2.840.113549",
            ),
            TextFormat::Boolean => (
                " EDIT — BOOLEAN value ".to_string(),
                "[Enter] apply   [Esc] cancel   TRUE or FALSE (also 1 / 0)",
            ),
            TextFormat::Text(_) => (
                " EDIT — text value ".to_string(),
                "[Enter] apply   [Esc] cancel   text is encoded per the string type",
            ),
        },
        Editor::DateTime(_) => (
            " EDIT — date / time ".to_string(),
            "[←→/Tab] field   [↑↓] adjust   digits overwrite the field   [Enter] apply   [Esc] cancel",
        ),
    }
}

fn hex_editor_lines(h: &mut HexEditor, text_rows: usize) -> Vec<Line<'static>> {
    let cursor_row = h.cursor / EDIT_DIGITS_PER_LINE;
    if cursor_row < h.scroll {
        h.scroll = cursor_row;
    } else if text_rows > 0 && cursor_row >= h.scroll + text_rows {
        h.scroll = cursor_row + 1 - text_rows;
    }
    let mut lines = Vec::new();
    let total_rows = h.digits.len() / EDIT_DIGITS_PER_LINE + 1;
    for row in h.scroll..total_rows.min(h.scroll + text_rows.max(1)) {
        let start = row * EDIT_DIGITS_PER_LINE;
        let end = (start + EDIT_DIGITS_PER_LINE).min(h.digits.len());
        let mut spans: Vec<Span> = vec![Span::styled(
            format!("{:08X}  ", row * EDIT_BYTES_PER_LINE),
            Style::new().dim(),
        )];
        for i in start..=end {
            if i < end {
                let style = if h.is_selected(i) {
                    cursor_within_selection(i == h.cursor)
                } else if i == h.cursor {
                    Style::new().add_modifier(Modifier::REVERSED)
                } else if h.is_fresh(i) {
                    HEX_FRESH_STYLE
                } else {
                    Style::new()
                };
                spans.push(Span::styled(h.digits[i].to_string(), style));
                if i % 2 == 1 && i + 1 < end {
                    // Keep a run of marked octets visually continuous by
                    // marking the space between them too.
                    let gap = if h.is_selected(i) && h.is_selected(i + 1) {
                        HEX_SELECTION_STYLE
                    } else if h.is_fresh(i) && h.is_fresh(i + 1) {
                        HEX_FRESH_STYLE
                    } else {
                        Style::new()
                    };
                    spans.push(Span::styled(" ", gap));
                }
            } else if i == h.cursor && i == h.digits.len() {
                // Cursor sitting after the last digit.
                spans.push(Span::styled(" ", Style::new().add_modifier(Modifier::REVERSED)));
            }
        }
        lines.push(Line::from(spans));
    }
    lines
}

fn text_editor_lines(t: &TextEditor, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut spans: Vec<Span> = Vec::new();
    let mut col = 0;
    for (i, &c) in t.buf.iter().enumerate() {
        let display = if c == '\n' { '␤' } else if c.is_control() { '·' } else { c };
        // As in the hex editor: a selection outranks the cursor, and both
        // outrank the "just added" marking.
        let style = if t.is_selected(i) {
            cursor_within_selection(i == t.cursor)
        } else if i == t.cursor {
            Style::new().add_modifier(Modifier::REVERSED)
        } else if t.is_fresh(i) {
            HEX_FRESH_STYLE
        } else {
            Style::new()
        };
        spans.push(Span::styled(display.to_string(), style));
        col += 1;
        if col >= width || c == '\n' {
            lines.push(Line::from(std::mem::take(&mut spans)));
            col = 0;
        }
    }
    if t.cursor == t.buf.len() {
        spans.push(Span::styled(" ", Style::new().add_modifier(Modifier::REVERSED)));
    }
    lines.push(Line::from(spans));
    lines
}

fn datetime_editor_lines(d: &DateTimeEditor) -> Vec<Line<'static>> {
    let mut date_spans: Vec<Span> = Vec::new();
    let mut time_spans: Vec<Span> = Vec::new();
    for (i, label) in DATE_FIELDS.iter().enumerate() {
        let target = if i < 3 { &mut date_spans } else { &mut time_spans };
        target.push(Span::styled(format!("{:<7}", label), Style::new().dim()));
        let style = if i == d.active {
            Style::new().add_modifier(Modifier::REVERSED).bold()
        } else {
            Style::new().bold()
        };
        let width = if i == 0 { 4 } else { 2 };
        target.push(Span::styled(format!("[{:>w$}]", d.fields[i], w = width), style));
        target.push(Span::raw("   "));
    }
    vec![
        Line::default(),
        Line::from(date_spans),
        Line::default(),
        Line::from(time_spans),
        Line::default(),
        Line::from(Span::styled(
            if d.generalized {
                "GeneralizedTime — encoded as YYYYMMDDHHMMSSZ"
            } else {
                "UTCTime — encoded as YYMMDDHHMMSSZ (years 1950..2049)"
            },
            Style::new().dim(),
        )),
    ]
}

fn draw_content_edit(frame: &mut Frame, app: &mut App, area: Rect) {
    let Mode::Edit(ref mut edit) = app.mode else { return };
    let inner_height = area.height.saturating_sub(2) as usize; // borders
    let inner_width = area.width.saturating_sub(2) as usize;
    let text_rows = inner_height.saturating_sub(2); // feedback + hint line

    let (title, hint) = editor_title_hint(edit);
    let mut lines: Vec<Line> = vec![feedback_line(edit)];
    match edit.editor {
        Editor::Hex(ref mut h) => lines.extend(hex_editor_lines(h, text_rows)),
        Editor::Text(ref t) => lines.extend(text_editor_lines(t, inner_width)),
        Editor::DateTime(ref d) => lines.extend(datetime_editor_lines(d)),
    }
    lines.push(Line::from(Span::styled(hint, Style::new().dim())));

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(Color::Yellow))
            .title(title),
    );
    frame.render_widget(para, area);
}

/// Centered popup listing a menu's entries ('E' edit menu, 'z' cryptographic
/// adjustment menu).
fn draw_edit_menu(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::EditMenu(ref m) = app.mode else { return };
    let width = 78.min(area.width);
    let height = (m.items.len() as u16 + 3).min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::Yellow))
        .title(m.title);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let mut lines: Vec<Line> = Vec::new();
    for (i, item) in m.items.iter().enumerate() {
        let style = if i == m.selected {
            Style::new().add_modifier(Modifier::REVERSED).bold()
        } else {
            Style::new().bold()
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {} {:<16}", i + 1, item.label), style),
            Span::styled(format!(" {}", item.desc), Style::new().dim()),
        ]));
    }
    lines.push(Line::from(Span::styled(
        " ↑↓/1-9 select   ⏎ choose   Esc cancel",
        Style::new().dim(),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let dirty = if app.dirty { " [modified]" } else { "" };
    let hints = match app.mode {
        // Single-file mode: no browser pane, no re-signing — trimmed hints.
        Mode::Browse if app.single_file => {
            "q quit  Alt+m menu  ↑↓ move  ←→ fold  ⏎ toggle  e edit  E edit-menu  i/I insert  d delete  J/K reorder  s save  z decrypt  [ ] scroll  { } start/end"
        }
        Mode::Browse if app.focus == Focus::Browser => {
            "q quit  Alt+m menu  Tab switch pane  ↑↓ move+preview  ←→ fold  ⏎ switch to file/fold  z decrypt/re-sign  t trust"
        }
        Mode::Browse => {
            "q quit  Alt+m menu  Tab switch pane  ↑↓ move  ←→ fold  ⏎ toggle  e edit  E edit-menu  i/I insert  d delete  J/K reorder  s save  z decrypt/re-sign  [ ] scroll  { } start/end"
        }
        Mode::MenuBar(_) => "←→ menu  ↑↓ entry  ⏎ run  Esc close",
        Mode::NewFile(_) => "type a path  ←→ cursor  ⏎ create  Esc cancel",
        Mode::Help(_) => "↑↓ topic  PgUp/PgDn or [ ] scroll  Esc close",
        Mode::TypePicker(_) => "←→ column  ↑↓ select  0-9 tag number  ⏎ continue  Esc cancel",
        Mode::EditMenu(_) => "↑↓ or 1-5 select  ⏎ choose  Esc cancel",
        Mode::Edit(EditState { editor: Editor::DateTime(_), .. }) => "Enter apply  Esc cancel",
        Mode::Edit(_) => {
            "Enter apply  Esc cancel  Shift+arrows select  Ctrl+A all  Ctrl+C/X/V copy/cut/paste  Ctrl+Z undo"
        }
        Mode::Password(_) => "type password  ⏎ decrypt  Esc cancel",
        Mode::Resign(_) => "⏎ create new signature (if available)  Esc cancel",
        Mode::EditPubKey(_) => {
            "←→ column  ↑↓ move  Space toggle  type size/name/password  ⏎ apply  Esc cancel"
        }
        Mode::EditBasicConstraints(_) => {
            "↑↓ field  Space toggle  digits set pathLen  ⏎ apply  Esc cancel"
        }
        Mode::EditKeyUsage(_) => "↑↓ select bit  Space toggle  ⏎ apply  Esc cancel",
        Mode::EditExtKeyUsage(_) => {
            "↑↓ select  Space toggle  type OID + ⏎ add  ⏎ apply  Esc cancel"
        }
        Mode::FilterInput => "type to filter (hex/text/int/OID)  ⏎/Tab navigate  Esc clear",
        Mode::Notice(_) => "press any key to dismiss",
        Mode::Progress(_) => "working — the operation cannot be interrupted",
    };
    let line = Line::from(vec![
        Span::styled(dirty, Style::new().fg(Color::Red).bold()),
        Span::raw(format!(" {} ", app.status)),
        Span::styled(format!("| {}", hints), Style::new().dim()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::parse_forest;
    use crate::verify::RelationEdge;
    use std::path::{Path, PathBuf};

    fn edge(path: &str, verified: bool) -> RelationEdge {
        RelationEdge { other: PathBuf::from(path), verified }
    }

    /// Cell text (without color) per row, for one side of the gutters.
    fn cells(side: &[Option<(String, Color)>]) -> Vec<Option<&str>> {
        side.iter().map(|c| c.as_ref().map(|(s, _)| s.as_str())).collect()
    }

    #[test]
    fn decrypted_tree_labels_start_with_matching_lock_symbols() {
        assert_eq!(DECRYPTED_LOCKED_LABEL, "🔒 decrypted content not available");
        assert_eq!(DECRYPTED_UNLOCKED_PREFIX, "🔓 decrypted: ");
        assert_eq!(DECRYPTED_LOCKED_LABEL.chars().next(), Some('🔒'));
        assert_eq!(DECRYPTED_UNLOCKED_PREFIX.chars().next(), Some('🔓'));
    }

    #[test]
    fn styled_with_marker_splits_out_just_the_marker_glyph() {
        let base = Style::new().fg(Color::LightGreen);
        let marker = Style::new().fg(DIRTY_MARKER);
        // "  ● a.der" — marker glyph "●" sits at char offset 2.
        let spans = styled_with_marker("  ● a.der", base, 2, Some(marker));
        let texts: Vec<&str> = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(texts, ["  ", "●", " a.der"]);
        assert_eq!(spans[0].style, base);
        assert_eq!(spans[1].style, marker);
        assert_eq!(spans[2].style, base);
    }

    #[test]
    fn styled_with_marker_is_a_single_span_without_a_marker_style() {
        let base = Style::new().fg(Color::LightGreen);
        let spans = styled_with_marker("  • a.der", base, 2, None);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content.as_ref(), "  • a.der");
        assert_eq!(spans[0].style, base);
    }

    #[test]
    fn styled_with_marker_degrades_gracefully_if_offset_is_out_of_range() {
        let base = Style::new();
        let marker = Style::new().fg(DIRTY_MARKER);
        // Simulates the marker having been truncated away in a narrow pane.
        let spans = styled_with_marker("ab", base, 5, Some(marker));
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content.as_ref(), "ab");
    }

    #[test]
    fn styled_with_marker_omits_empty_before_segment() {
        // Marker at offset 0: no "before" span should be emitted.
        let marker = Style::new().fg(DIRTY_MARKER);
        let spans = styled_with_marker("●x", Style::new(), 0, Some(marker));
        let texts: Vec<&str> = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(texts, ["●", "x"]);
    }

    #[test]
    fn incoming_arrow_routes_from_signer_below_to_selection() {
        let rows = [Path::new("a"), Path::new("b"), Path::new("c")];
        let rel = FileRelations { signed_by: Some(edge("c", true)), signs: vec![], key_links: vec![] };
        let g = arrow_gutters(&rows, 0, &rel);
        // Elbow with two corners: out of "c", up the trunk, into "a".
        assert_eq!(cells(&g.left), [Some("╭─► "), Some("│   "), Some("╰── ")]);
        assert!(g.left.iter().flatten().all(|(_, c)| *c == REL_SIGNER));
        assert!(g.right.iter().all(|c| c.is_none()));
    }

    #[test]
    fn incoming_arrow_from_signer_above_points_down_into_selection() {
        let rows = [Path::new("a"), Path::new("b"), Path::new("c")];
        let rel = FileRelations { signed_by: Some(edge("a", false)), signs: vec![], key_links: vec![] };
        let g = arrow_gutters(&rows, 2, &rel);
        assert_eq!(cells(&g.left), [Some("╭── "), Some("│   "), Some("╰─► ")]);
        // Unverified issuance renders red.
        assert!(g.left.iter().flatten().all(|(_, c)| *c == REL_BROKEN));
    }

    #[test]
    fn outgoing_arrows_share_a_trunk_and_branch_into_targets() {
        let rows = [Path::new("a"), Path::new("b"), Path::new("c"), Path::new("d")];
        let rel = FileRelations {
            signed_by: None,
            signs: vec![edge("a", true), edge("d", false)],
            key_links: vec![],
        };
        let g = arrow_gutters(&rows, 1, &rel);
        assert!(g.left.iter().all(|c| c.is_none()));
        // Selection "b" is the source; targets above ("a") and below ("d"),
        // with "c" passed through by the trunk.
        assert_eq!(
            cells(&g.right),
            [Some("◄──╮"), Some("───┤"), Some("   │"), Some("◄──╯")]
        );
        // Broken target's stub is red; the rest keep the "signs" color.
        let colors: Vec<Color> = g.right.iter().flatten().map(|(_, c)| *c).collect();
        assert_eq!(colors, [REL_SIGNS, REL_SIGNS, REL_SIGNS, REL_BROKEN]);
    }

    #[test]
    fn all_broken_targets_turn_the_whole_trunk_red() {
        let rows = [Path::new("a"), Path::new("b")];
        let rel = FileRelations { signed_by: None, signs: vec![edge("b", false)], key_links: vec![] };
        let g = arrow_gutters(&rows, 0, &rel);
        assert_eq!(cells(&g.right), [Some("───╮"), Some("◄──╯")]);
        assert!(g.right.iter().flatten().all(|(_, c)| *c == REL_BROKEN));
    }

    #[test]
    fn edges_to_invisible_rows_are_skipped() {
        let rows = [Path::new("a"), Path::new("b")];
        let rel = FileRelations {
            signed_by: Some(edge("hidden/x", true)),
            signs: vec![edge("hidden/y", true)],
            key_links: vec![PathBuf::from("hidden/z")],
        };
        let g = arrow_gutters(&rows, 0, &rel);
        assert!(g.keylink.iter().all(|c| c.is_none()));
        assert!(g.left.iter().all(|c| c.is_none()));
        assert!(g.right.iter().all(|c| c.is_none()));
    }

    #[test]
    fn key_links_route_as_a_headless_trunk() {
        let rows = [Path::new("a"), Path::new("b"), Path::new("c"), Path::new("d")];
        let rel = FileRelations {
            signed_by: None,
            signs: vec![],
            key_links: vec![PathBuf::from("a"), PathBuf::from("d")],
        };
        let g = arrow_gutters(&rows, 1, &rel); // selection "b"
        // Elbow from "b" to the linked files above ("a") and below ("d"),
        // with "c" passed through by the trunk. No arrowheads.
        assert_eq!(
            cells(&g.keylink),
            [Some("╭── "), Some("├── "), Some("│   "), Some("╰── ")]
        );
        assert!(g.keylink.iter().flatten().all(|(_, c)| *c == REL_KEY));
        assert!(g
            .keylink
            .iter()
            .flatten()
            .all(|(cell, _)| !cell.contains('►') && !cell.contains('◄')));
        // The signature gutters are independent and untouched.
        assert!(g.left.iter().all(|c| c.is_none()));
        assert!(g.right.iter().all(|c| c.is_none()));
    }

    #[test]
    fn tree_summary_shows_large_integers_in_decimal() {
        // 17-byte INTEGER (2^128): beyond i128, previously fell back to hex.
        let mut data = vec![0x02, 0x11, 0x01];
        data.extend([0x00; 16]);
        let forest = parse_forest(&data, 0).unwrap();
        // The content-pane summary keeps the full value…
        assert_eq!(summary(&forest[0]), " 340282366920938463463374607431768211456");
        // …while the tree clips it to 12 digits with an ellipsis.
        assert_eq!(tree_summary(&forest[0]), " 340282366920…");
    }

    #[test]
    fn tree_summary_clips_only_over_long_integers() {
        // Exactly 12 digits: shown in full (no ellipsis).
        let forest = parse_forest(&ber::encode_node(&ber::univ(
            TAG_INTEGER,
            false,
            ber::encode_integer(123_456_789_012),
        )), 0)
        .unwrap();
        assert_eq!(tree_summary(&forest[0]), " 123456789012");

        // A negative long integer keeps its sign, then 12 digits.
        let neg = ber::encode_node(&ber::univ(
            TAG_INTEGER,
            false,
            ber::encode_integer(-987_654_321_098_765),
        ));
        let forest = parse_forest(&neg, 0).unwrap();
        assert_eq!(tree_summary(&forest[0]), " -987654321098…");

        // A short integer is untouched.
        let forest = parse_forest(&[0x02, 0x01, 0x2A], 0).unwrap();
        assert_eq!(tree_summary(&forest[0]), " 42");
    }

    #[test]
    fn known_oid_uses_short_tree_name_and_full_content_details() {
        let value = ber::encode_oid("1.2.840.113549.1.5.13").unwrap();
        let mut der = vec![0x06, value.len() as u8];
        der.extend(value);
        let forest = parse_forest(&der, 0).unwrap();
        let node = &forest[0];

        assert_eq!(summary(node), " PBES2");
        assert_eq!(
            oid_details(node),
            Some((
                "1.2.840.113549.1.5.13".to_string(),
                Some("iso.member-body.us.rsadsi.pkcs.pkcs-5.PBES2".to_string())
            ))
        );
    }

    #[test]
    fn unknown_oid_keeps_dot_notation_without_inventing_a_name() {
        let value = ber::encode_oid("1.2.3.4.987654").unwrap();
        let mut der = vec![0x06, value.len() as u8];
        der.extend(value);
        let forest = parse_forest(&der, 0).unwrap();
        let node = &forest[0];

        assert_eq!(summary(node), " 1.2.3.4.987654");
        assert_eq!(
            oid_details(node),
            Some(("1.2.3.4.987654".to_string(), None))
        );
    }

    #[test]
    fn tag_layout_for_sequence() {
        let forest = parse_forest(&[0x30, 0x00], 0).unwrap();
        let rows = tag_layout_strings(&forest[0]);
        assert_eq!(rows.len(), 5);
        // Bit positions embedded in the top border.
        assert!(rows[0].contains(" 8 7 ") && rows[0].contains(" 6 ") && rows[0].contains(" 5 4 3 2 1 "));
        // 0x30 = 00 1 10000.
        assert!(rows[1].contains("│ 0 0 ") && rows[1].contains("│ 1 ") && rows[1].contains("│ 1 0 0 0 0 "));
        // Field sizes in bits.
        assert!(rows[2].contains("class (2 bits)"));
        assert!(rows[2].contains("P/C (1 bit)"));
        assert!(rows[2].contains("tag number (5 bits)"));
        // Decoded meaning.
        assert!(rows[3].contains("universal"));
        assert!(rows[3].contains("constructed"));
        assert!(rows[3].contains("16 = SEQUENCE"));
        // All box rows are equally wide.
        let w = rows[0].chars().count();
        assert!(rows[1..5].iter().all(|r| r.chars().count() == w));
    }

    #[test]
    fn tag_layout_for_context_primitive() {
        let forest = parse_forest(&[0x80, 0x00], 0).unwrap();
        let rows = tag_layout_strings(&forest[0]);
        assert!(rows[1].contains("│ 1 0 "));
        assert!(rows[3].contains("context-specific"));
        assert!(rows[3].contains("primitive"));
        assert!(rows[3].contains(" 0 "));
    }

    #[test]
    fn length_layout_short_form() {
        // OCTET STRING with 5 content bytes: length octet 0x05.
        let forest = parse_forest(&[0x04, 0x05, 1, 2, 3, 4, 5], 0).unwrap();
        let rows = length_layout_strings(&forest[0]);
        assert_eq!(rows.len(), 5);
        assert!(rows[0].contains(" 8 ") && rows[0].contains(" 7 6 5 4 3 2 1 "));
        // 0x05 = 0 0000101.
        assert!(rows[1].contains("│ 0 ") && rows[1].contains("│ 0 0 0 0 1 0 1"));
        assert!(rows[2].contains("form (1 bit)"));
        assert!(rows[2].contains("content length (7 bits)"));
        assert!(rows[3].contains("short form"));
        assert!(rows[3].contains("5 = content length"));
    }

    #[test]
    fn length_layout_long_form() {
        // OCTET STRING with 200 content bytes: length octets 0x81 0xC8.
        let mut data = vec![0x04, 0x81, 0xC8];
        data.extend(std::iter::repeat_n(0u8, 200));
        let forest = parse_forest(&data, 0).unwrap();
        let rows = length_layout_strings(&forest[0]);
        // 0x81 = 1 0000001.
        assert!(rows[1].contains("│ 1 ") && rows[1].contains("│ 0 0 0 0 0 0 1"));
        assert!(rows[2].contains("# of length octets (7 bits)"));
        assert!(rows[3].contains("long form"));
        assert!(rows[3].contains("1 octets follow"));
        assert!(rows[5].contains("octet 2:  11001000") && rows[5].contains("0xC8"));
        assert_eq!(rows[6], "content length = 200");
    }

    #[test]
    fn length_layout_indefinite() {
        let forest = parse_forest(&[0x30, 0x80, 0x05, 0x00, 0x00, 0x00], 0).unwrap();
        assert_eq!(node_length_octets(&forest[0]), [0x80]);
        let rows = length_layout_strings(&forest[0]);
        assert!(rows[1].contains("│ 1 ") && rows[1].contains("│ 0 0 0 0 0 0 0"));
        assert!(rows[3].contains("long form"));
        assert!(rows[3].contains("0 = indefinite length"));
        assert!(rows[5].contains("end-of-contents"));
    }

    #[test]
    fn tag_layout_long_form() {
        // [APPLICATION 1000] primitive: 0x5F 0x87 0x68.
        let forest = parse_forest(&[0x5F, 0x87, 0x68, 0x00], 0).unwrap();
        let rows = tag_layout_strings(&forest[0]);
        assert!(rows[1].contains("│ 1 1 1 1 1 "));
        assert!(rows[3].contains("31 = long form"));
        assert!(rows[5].contains("octet 2:  1 0000111"));
        assert!(rows[5].contains("more octets follow"));
        assert!(rows[6].contains("octet 3:  0 1101000"));
        assert!(rows[6].contains("last octet"));
        assert_eq!(rows[7], "tag number = 1000");
    }

    /// Build an app over a certificate fixture with the first row matching
    /// `pred` (applied to the selected node) selected.
    fn app_selecting(rel: &str, pred: impl Fn(&Node) -> bool) -> App {
        use crate::input::Container;
        let der =
            std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap();
        let roots = parse_forest(&der, 0).unwrap();
        let mut app = App::new(
            PathBuf::from("/nonexistent/in"),
            PathBuf::from("/nonexistent/out"),
            Container::Raw,
            roots,
            der.len(),
        );
        let n = app.rows.len();
        let idx = (0..n)
            .find(|&i| {
                app.select(i);
                app.selected_node().is_some_and(&pred)
            })
            .expect("matching extension row");
        app.select(idx);
        app
    }

    fn app_on_basic_constraints(rel: &str) -> App {
        app_selecting(rel, |n| basic_constraints::value_index(n).is_some())
    }

    fn app_on_key_usage(rel: &str) -> App {
        app_selecting(rel, |n| key_usage::value_index(n).is_some())
    }

    fn app_on_ext_key_usage(rel: &str) -> App {
        app_selecting(rel, |n| extended_key_usage::value_index(n).is_some())
    }

    /// Interactive dir-mode flow: arrows render as the selection moves.
    #[test]
    fn dir_mode_renders_issuer_arrows_interactively() {
        use ratatui::{backend::TestBackend, Terminal};
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/chain");
        let mut app = App::new_dir(dir);
        let mut term = Terminal::new(TestBackend::new(170, 30)).unwrap();
        // Simulate the real event loop: draw, then key presses via the handler.
        term.draw(|f| draw(f, &mut app)).unwrap();
        let down = KeyEvent::new(KeyCode::Down, event::KeyModifiers::NONE);
        for _ in 0..5 {
            handle_browser_key(&mut app, down);
            term.draw(|f| draw(f, &mut app)).unwrap();
            let text = buffer_text(term.backend().buffer());
            assert!(
                text.contains('►') || text.contains('◄'),
                "issuer arrows should render for {:?}",
                app.browser.selected_entry().map(|e| e.name.clone())
            );
        }
    }

    #[test]
    fn long_integer_decoded_value_wraps_to_the_hex_dump_width() {
        // A 257-octet INTEGER (an RSA-2048 modulus with its leading 0x00):
        // its ~617-digit decimal expansion far exceeds one hex-dump line.
        let mut der = vec![0x02, 0x82, 0x01, 0x01, 0x00];
        der.extend(std::iter::repeat_n(0xAB, 256));
        let roots = parse_forest(&der, 0).unwrap();
        let lines = decoded_lines(&roots[0]);
        assert!(lines.len() > 1, "a long modulus needs several lines");
        let flat: Vec<String> = lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>())
            .collect();
        assert!(flat[0].starts_with("Decoded "));
        for (i, line) in flat.iter().enumerate() {
            assert!(
                line.chars().count() <= HEX_DUMP_LINE_WIDTH,
                "line {} wider than the hex dump: {} chars",
                i,
                line.chars().count()
            );
            if i > 0 {
                assert!(
                    line.starts_with("        ") && !line[8..].starts_with(' '),
                    "continuation lines align under the value: {:?}",
                    line
                );
            }
        }
        // Full lines are exactly the hex dump's width, and reassembling the
        // chunks yields the whole decimal value — nothing is lost.
        assert_eq!(flat[0].chars().count(), HEX_DUMP_LINE_WIDTH);
        // Every line carries an 8-char prefix: the "Decoded " label or the
        // matching indent.
        let digits: String = flat.iter().map(|l| &l[8..]).collect();
        assert_eq!(digits, crate::ber::integer_decimal(&roots[0].value).unwrap());
    }

    #[test]
    fn short_decoded_integers_stay_on_one_line() {
        let roots = parse_forest(&[0x02, 0x01, 0x2A], 0).unwrap();
        let lines = decoded_lines(&roots[0]);
        assert_eq!(lines.len(), 1);
        let text: String = lines[0].spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, "Decoded 42");
    }

    fn line_text(l: &Line) -> String {
        l.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn header_field_wraps_within_width_and_preserves_label_and_styles() {
        // A long multi-span value forces wrapping.
        let value = vec![
            Span::styled("commonName", Style::new().fg(Color::LightCyan)),
            Span::raw(" : "),
            Span::styled(
                "a rather long resolved value that certainly exceeds the hex dump width by a fair margin",
                Style::new().fg(Color::LightGreen),
            ),
        ];
        let lines = header_field("Spec    ", value, HEX_DUMP_LINE_WIDTH);
        assert!(lines.len() > 1, "the long value must wrap");
        for (i, line) in lines.iter().enumerate() {
            let text = line_text(line);
            assert!(
                text.chars().count() <= HEX_DUMP_LINE_WIDTH,
                "line {} exceeds the hex width: {:?}",
                i,
                text
            );
            if i == 0 {
                assert!(text.starts_with("Spec    "), "label on the first line");
            } else {
                // Continuation lines are padded to the label width, not labeled.
                assert!(text.starts_with("        "), "continuation indent: {:?}", text);
                assert!(!text.starts_with("Spec"), "no repeated label");
            }
        }
        // The cyan/green styling survives wrapping (both colors still present).
        let styles: Vec<Color> = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .filter_map(|s| s.style.fg)
            .collect();
        assert!(styles.contains(&Color::LightCyan) && styles.contains(&Color::LightGreen));
    }

    #[test]
    fn botan_hash_too_weak_is_annotated_but_other_reasons_are_verbatim() {
        // The "too weak" hash rejection (post-quantum signatures) is reworded
        // so it doesn't read as a certificate defect.
        let weak = botan_path_status_lines(
            "Path/Botan   ",
            &BotanPathStatus::Invalid {
                reason: "Hash function used is considered too weak for security".to_string(),
            },
            HEX_DUMP_LINE_WIDTH,
        );
        let weak_text: String = weak.iter().map(line_text).collect::<Vec<_>>().join(" ");
        assert!(weak_text.contains("post-quantum"), "annotated: {weak_text}");
        assert!(weak_text.contains("OpenSSL accepts it"), "annotated: {weak_text}");
        assert!(!weak_text.contains("too weak"), "raw message hidden: {weak_text}");

        // Any other rejection reason is shown verbatim.
        let other = botan_path_status_lines(
            "Path/Botan   ",
            &BotanPathStatus::Invalid { reason: "certificate has expired".to_string() },
            HEX_DUMP_LINE_WIDTH,
        );
        let other_text: String = other.iter().map(line_text).collect::<Vec<_>>().join(" ");
        assert!(other_text.contains("no valid path — certificate has expired"), "{other_text}");
    }

    #[test]
    fn header_field_keeps_a_short_value_on_one_line() {
        let lines = header_field("Type    ", vec![Span::raw("SEQUENCE")], HEX_DUMP_LINE_WIDTH);
        assert_eq!(lines.len(), 1);
        assert_eq!(line_text(&lines[0]), "Type    SEQUENCE");
    }

    #[test]
    fn rekey_dialog_shows_key_file_path_full_width_not_clipped() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        let der =
            std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/cert_rsa.der"))
                .unwrap();
        let roots = parse_forest(&der, 0).unwrap();
        let mut app = App::new(
            PathBuf::from("cert_rsa.der"),
            PathBuf::from("cert_rsa.der"),
            Container::Raw,
            roots,
            der.len(),
        );
        app.start_rekey();
        // A name far longer than the ~32-wide key-options column.
        let long = "a_very_long_generated_key_file_name_that_the_column_would_clip.der";
        if let Mode::EditPubKey(ref mut s) = app.mode {
            s.filename = long.to_string();
            s.filename_auto = false;
        }
        let mut term = Terminal::new(TestBackend::new(120, 30)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        // The full path is visible in the wide key-file row, uncut.
        assert!(text.contains("Key file:"), "key-file row label:\n{text}");
        assert!(text.contains(long), "full file name must be visible:\n{text}");

        // The file name is reachable with ←/→ as the 5th column (index 4),
        // past the four visible columns.
        for _ in 0..6 {
            app.pubkey_move_column(1);
        }
        assert!(app.pubkey_filename_focused(), "→ should stop on the file-name column");

        // Focused but idle, typing does nothing — the field is modal.
        app.pubkey_insert_char('Z');
        if let Mode::EditPubKey(ref s) = app.mode {
            assert_eq!(s.filename, long, "typing before entering edit mode is inert");
        }

        // Space enters cursor-edit mode; the cursor starts at the end, so typing
        // appends and ← inserts one position to the left.
        app.pubkey_filename_begin_edit();
        assert!(app.pubkey_filename_editing());
        // The cursor-rendering branch must draw the (still complete) name.
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(buffer_text(term.backend().buffer()).contains(long), "name visible while editing");
        app.pubkey_filename_type('X');
        app.pubkey_filename_move_cursor(-1); // step left over the 'X'
        app.pubkey_filename_type('Y'); // …insert 'Y' before it
        if let Mode::EditPubKey(ref s) = app.mode {
            assert_eq!(s.filename, format!("{long}YX"), "cursor-positioned editing");
        }

        // While editing, ← is a cursor move, not a column change.
        app.pubkey_filename_move_cursor(-100);
        if let Mode::EditPubKey(ref s) = app.mode {
            assert_eq!(s.column, 4, "editing keeps the file-name column focused");
            assert_eq!(s.filename_cursor, 0, "Home-style jump to the start");
        }

        // Enter leaves edit mode without cancelling the dialog; then ← changes
        // column again.
        app.pubkey_filename_end_edit();
        assert!(!app.pubkey_filename_editing());
        assert!(matches!(app.mode, Mode::EditPubKey(_)), "leaving edit keeps the dialog open");
        app.pubkey_move_column(-1);
        if let Mode::EditPubKey(ref s) = app.mode {
            assert_eq!(s.column, 3, "← now leaves the file-name column");
        }
    }

    #[test]
    fn rekey_dialog_renders_the_hsslms_structured_editor() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        let der =
            std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/cert_rsa.der"))
                .unwrap();
        let roots = parse_forest(&der, 0).unwrap();
        let mut app = App::new(
            PathBuf::from("cert_rsa.der"),
            PathBuf::from("cert_rsa.der"),
            Container::Raw,
            roots,
            der.len(),
        );
        app.start_rekey();
        // Navigate the family column to HSS/LMS.
        let hss = keygen::FAMILIES.iter().position(|f| f.label == "HSS/LMS").unwrap();
        for _ in 0..hss {
            app.pubkey_move_row(1);
        }
        let mut term = Terminal::new(TestBackend::new(120, 30)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        // The structured editor's fields render.
        assert!(text.contains("Mode: LMS"), "mode field:\n{text}");
        assert!(text.contains("Hash: SHA-256"), "hash field:\n{text}");
        assert!(text.contains("root H:"), "root level height:\n{text}");
        assert!(text.contains('🕐'), "HSS/LMS shows a time estimate");

        // Enter the parameter column, focus the Hash field, and press Space:
        // a choice popup appears (arrow keys never edited the value inline).
        app.pubkey_move_column(1);
        app.pubkey_move_row(1); // Mode -> Hash
        assert!(app.pubkey_hss_activate()); // the Space action
        term.draw(|f| draw(f, &mut app)).unwrap();
        let popup = buffer_text(term.backend().buffer());
        assert!(popup.contains("SHAKE-256/256"), "hash choice popup:\n{popup}");
        assert!(popup.contains("SHA-256/192"), "hash choice popup:\n{popup}");
    }

    #[test]
    fn rekey_dialog_shows_time_estimate_for_xmss_but_not_ecdsa() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        let der =
            std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/cert_rsa.der"))
                .unwrap();
        let roots = parse_forest(&der, 0).unwrap();
        let mut app = App::new(
            PathBuf::from("cert_rsa.der"),
            PathBuf::from("cert_rsa.der"),
            Container::Raw,
            roots,
            der.len(),
        );
        app.start_rekey();
        assert!(matches!(app.mode, Mode::EditPubKey(_)), "rekey dialog: {}", app.status);
        let mut term = Terminal::new(TestBackend::new(120, 30)).unwrap();
        // ECDSA (the default family) is fast — no clock estimate.
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(
            !buffer_text(term.backend().buffer()).contains('🕐'),
            "no estimate should show for a fast algorithm"
        );
        // Move the family selection down to XMSS; the estimate appears.
        let xmss = keygen::FAMILIES.iter().position(|f| f.label == "XMSS").unwrap();
        for _ in 0..xmss {
            app.pubkey_move_row(1);
        }
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(
            buffer_text(term.backend().buffer()).contains('🕐'),
            "clock estimate should show for XMSS"
        );
    }

    #[test]
    fn content_pane_shows_both_path_validation_fields() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        let chain = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/chain");
        let path = chain.join("server.der");
        let raw = std::fs::read(&path).unwrap();
        let (der, _) = crate::input::load(&raw).unwrap();
        let roots = parse_forest(&der, 0).unwrap();
        let mut app =
            App::new(path.clone(), path.clone(), Container::Raw, roots, der.len());
        app.trusted_certs.insert(chain.join("root_ca.der"));
        app.recompute_path_status();
        app.select(0); // a node must be selected for the header to render
        let mut term = Terminal::new(TestBackend::new(90, 40)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("Path/OpenSSL"), "OpenSSL path field:\n{text}");
        assert!(text.contains("Path/Botan"), "Botan path field:\n{text}");
    }

    #[test]
    fn progress_lines_show_elapsed_estimate_and_a_capped_bar() {
        let lines = progress_lines(
            "Re-keying to XMSS-SHA2_16_512",
            Duration::from_secs(90),
            Some(Duration::from_secs(180)),
            20,
        );
        let joined: Vec<String> = lines.iter().map(line_text).collect();
        assert!(joined[0].contains("XMSS-SHA2_16_512"), "title");
        assert!(joined.iter().any(|l| l.contains("elapsed:") && l.contains("1 mins, 30 secs")));
        assert!(joined.iter().any(|l| l.contains("estimated:") && l.contains("🕐 3 mins")));
        // Halfway through the estimate → about half the 20-cell bar filled.
        let bar = joined.last().unwrap();
        assert_eq!(bar.chars().count(), 20, "bar spans the width: {bar}");
        assert_eq!(bar.chars().filter(|&c| c == '█').count(), 10);
        // A running job with no estimate degrades gracefully.
        let unknown = progress_lines("x", Duration::from_secs(1), None, 20);
        assert!(line_text(unknown.last().unwrap()).contains("unknown"));
    }

    #[test]
    fn clock_estimate_stays_on_one_line_when_it_fits() {
        let lines = clock_estimate_lines("41 secs", 18);
        assert_eq!(lines.len(), 1);
        let t = line_text(&lines[0]);
        assert!(t.starts_with("🕐 ") && t.ends_with("41 secs"), "{t}");
    }

    #[test]
    fn clock_estimate_wraps_to_two_lines_instead_of_widening() {
        // "2 h, 2 mins, 5 secs" (19 chars) + clock exceeds an 18-col column.
        let lines = clock_estimate_lines("2 h, 2 mins, 5 secs", 18);
        assert_eq!(lines.len(), 2, "should wrap rather than widen");
        let l0 = line_text(&lines[0]);
        let l1 = line_text(&lines[1]);
        assert!(l0.starts_with("🕐 "), "clock on the first line: {l0}");
        // Every unit survives the split across the two lines, in order.
        for tok in ["2 h", "2 mins", "5 secs"] {
            assert!(l0.contains(tok) || l1.contains(tok), "lost unit {tok}");
        }
        // Each line's rendered width (clock counts as two cells) fits the column.
        for (i, l) in [&l0, &l1].iter().enumerate() {
            let cells = l.chars().map(|c| if c == '🕐' { 2 } else { 1 }).sum::<usize>();
            assert!(cells <= 18, "line {i} too wide ({cells} cells): {l}");
        }
    }

    #[test]
    fn endpoint_row_resolves_exact_and_deepest_visible_ancestor() {
        let rows =
            [Path::new("/d/a.der"), Path::new("/d/sub"), Path::new("/d/sub/deep"), Path::new("/d/b.der")];
        // Exact match wins.
        assert_eq!(endpoint_row(&rows, Path::new("/d/b.der")), Some(3));
        // Hidden inside a collapsed dir: the deepest visible ancestor row.
        assert_eq!(endpoint_row(&rows, Path::new("/d/sub/x.der")), Some(1));
        assert_eq!(endpoint_row(&rows, Path::new("/d/sub/deep/y.der")), Some(2));
        // No covering row at all.
        assert_eq!(endpoint_row(&rows, Path::new("/elsewhere/z.der")), None);
    }

    /// A signer hidden inside a collapsed directory still gets an arrow —
    /// routed to the directory row (regression: the user's playground held a
    /// duplicate copy of the issuer inside an unexpanded subdirectory, and
    /// the issuer edge silently vanished).
    #[test]
    fn hidden_signer_routes_arrow_to_collapsed_directory_row() {
        let rows = [Path::new("/d/server.der"), Path::new("/d/sub")];
        let rel = FileRelations {
            signed_by: Some(edge("/d/sub/ca.der", true)),
            signs: vec![],
            key_links: vec![],
        };
        let g = arrow_gutters(&rows, 0, &rel);
        assert_eq!(cells(&g.left), [Some("╭─► "), Some("╰── ")]);
    }

    /// Multiple hidden signed objects inside the same collapsed directory
    /// merge into a single stub on the directory row.
    #[test]
    fn hidden_signs_edges_merge_on_the_directory_row() {
        let rows = [Path::new("/d/ca.der"), Path::new("/d/sub")];
        let rel = FileRelations {
            signed_by: None,
            signs: vec![edge("/d/sub/leaf1.der", true), edge("/d/sub/leaf2.der", false)],
            key_links: vec![],
        };
        let g = arrow_gutters(&rows, 0, &rel);
        assert_eq!(cells(&g.right), [Some("───╮"), Some("◄──╯")]);
        // Merged stub keeps the healthy color while any covered edge verifies.
        assert_eq!(g.right[1].as_ref().unwrap().1, REL_SIGNS);
    }

    #[test]
    fn cms_message_content_pane_shows_signature_and_path_lines() {
        use ratatui::{backend::TestBackend, Terminal};
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let dir = root.join("testdata");
        let mut app = App::new_dir(dir.clone());
        let idx = app
            .browser
            .rows
            .iter()
            .position(|r| {
                app.browser.entry_at(&r.path).map(|e| e.name == "cms_signed.der").unwrap_or(false)
            })
            .expect("cms row");
        app.browser.select(idx);
        app.preview_browser_selection();
        app.trusted_certs.insert(dir.join("keylink/cert_ec.der"));
        app.recompute_path_status();
        let mut term = Terminal::new(TestBackend::new(150, 14)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        // Both the raw-signature line and the certification-path line are in
        // the content-pane header, exactly like for a certificate.
        assert!(text.contains("Signature verified"), "signature line missing:\n{text}");
        assert!(
            text.contains("Path/OpenSSL") && text.contains("valid — path of"),
            "OpenSSL path line missing:\n{text}"
        );
        assert!(text.contains("Path/Botan"), "Botan path line missing:\n{text}");
    }

    #[test]
    fn undecrypted_enveloped_cms_renders_the_locked_placeholder() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        let der =
            std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/enveloped.der"))
                .unwrap();
        let roots = parse_forest(&der, 0).unwrap();
        // Single-file mode is enough — the placeholder is purely structural.
        let mut app = App::new_single_file(
            PathBuf::from("enveloped.der"),
            PathBuf::from("/nonexistent/out"),
            Container::Raw,
            roots,
            der.len(),
        );
        let mut term = Terminal::new(TestBackend::new(150, 30)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(
            text.contains("decrypted content not available"),
            "locked placeholder missing:\n{text}"
        );
    }

    #[test]
    fn decrypted_cms_reveal_renders_below_its_ciphertext() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        // A scratch folder with a signed-then-encrypted message and the RSA
        // recipient key, so decryption succeeds.
        let dir = std::env::temp_dir().join(format!("ae-cms-reveal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let td = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata");
        std::fs::copy(td.join("signed_then_encrypted.der"), dir.join("msg.der")).unwrap();
        std::fs::copy(td.join("keylink/key_rsa_pkcs8.der"), dir.join("k.der")).unwrap();
        let der = std::fs::read(dir.join("msg.der")).unwrap();
        let roots = parse_forest(&der, 0).unwrap();
        let mut app = App::new(
            dir.join("msg.der"),
            dir.join("msg.der"),
            Container::Raw,
            roots,
            der.len(),
        );
        app.decrypt_cms_message();
        assert!(app.cms_reveal.is_some(), "decrypted: {}", app.status);
        let mut term = Terminal::new(TestBackend::new(150, 40)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        // The reveal's root carries the unlock prefix, and the nested
        // SignedData structure is visible below the ciphertext. (The emoji is
        // stored across buffer cells, so match the trailing label text.)
        assert!(text.contains("decrypted: "), "reveal prefix missing:\n{text}");
        assert!(text.contains("signedData"), "nested SignedData not shown:\n{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn browser_search_bar_spans_and_narrows_the_file_list() {
        use ratatui::{backend::TestBackend, Terminal};
        let dir = std::env::temp_dir()
            .join(format!("asn1-editor-tui-search-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // match.der contains the UTF8String "hello"; other.der does not.
        let doc = [
            0x30, 0x10, 0x02, 0x02, 0x04, 0xD2, 0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            0x06, 0x03, 0x55, 0x04, 0x03,
        ];
        std::fs::write(dir.join("match.der"), doc).unwrap();
        std::fs::write(dir.join("other.der"), [0x30, 0x03, 0x02, 0x01, 0x07]).unwrap();
        let mut app = App::new_dir(dir.clone());
        app.start_browser_search();
        for c in "hello".chars() {
            app.filter_insert_char(c);
        }
        let mut term = Terminal::new(TestBackend::new(170, 30)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("search / hello"), "search bar missing:\n{text}");
        assert!(text.contains("match.der"), "matching file missing");
        assert!(!text.contains("other.der"), "non-matching file should be hidden:\n{text}");
        // The bar sits above the Files pane (spanning it), not inside the tree
        // pane only: it must appear before the Files border on the same rows.
        let bar_row = text.lines().position(|l| l.contains("search / hello")).unwrap();
        let files_row = text.lines().position(|l| l.contains("Files")).unwrap();
        assert!(bar_row < files_row, "the bar spans above the Files pane");
        // The tree pane must not additionally show its own filter bar.
        assert_eq!(text.matches("filter /").count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hex_match_marks_flags_every_occurrence() {
        let bytes = [0xAA, 0xBB, 0xCC, 0xAA, 0xBB, 0xDD];
        assert_eq!(
            hex_match_marks(&bytes, &[0xAA, 0xBB]),
            [true, true, false, true, true, false]
        );
        // No occurrence / empty needle → nothing marked.
        assert!(hex_match_marks(&bytes, &[0xEE]).iter().all(|&m| !m));
        assert!(hex_match_marks(&bytes, &[]).iter().all(|&m| !m));
        // Needle longer than the buffer.
        assert!(hex_match_marks(&[0xAA], &[0xAA, 0xBB]).iter().all(|&m| !m));
    }

    #[test]
    fn hex_filter_highlights_matched_bytes_in_the_content_pane() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        // SEQUENCE { INTEGER 1234, UTF8String "hello", OID 2.5.4.3 }
        let doc = [
            0x30, 0x10, 0x02, 0x02, 0x04, 0xD2, 0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            0x06, 0x03, 0x55, 0x04, 0x03,
        ];
        let roots = parse_forest(&doc, 0).unwrap();
        let mut app = App::new_single_file(
            PathBuf::from("doc.der"),
            PathBuf::from("/nonexistent/out"),
            Container::Raw,
            roots,
            doc.len(),
        );
        app.start_filter();
        for c in "04 D2".chars() {
            app.filter_insert_char(c); // hex reading of the INTEGER's value
        }
        app.filter_accept();
        let highlighted = |term: &Terminal<TestBackend>| {
            let buf = term.backend().buffer();
            let area = buf.area;
            (0..area.height)
                .flat_map(|y| (0..area.width).map(move |x| (x, y)))
                .filter(|&(x, y)| buf[(x, y)].style().bg == Some(Color::Yellow))
                .count()
        };
        let mut term = Terminal::new(TestBackend::new(160, 30)).unwrap();
        // Root selected: its content octets contain 04 D2 → highlighted in
        // both the hex and the ASCII column (2 bytes ×3 cells... hex "04",
        // "D2" = 4 cells + 2 ascii cells).
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(highlighted(&term), 6, "04 D2 highlighted while the filter is set");
        // The highlight survives leaving the filter field (filter still set),
        // and vanishes once the filter is cleared.
        app.start_filter();
        app.filter_clear();
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(highlighted(&term), 0, "no highlight without a filter");
    }

    /// The three keys that reach the menu bar, and nothing else.
    #[test]
    fn the_hex_editor_paints_the_selection_blue_and_a_fresh_paste_yellow() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        // OCTET STRING of four bytes.
        let doc = [0x04, 0x04, 0x11, 0x22, 0x33, 0x44];
        let mut app = App::new_single_file(
            PathBuf::from("doc.der"),
            PathBuf::from("/nonexistent/out"),
            Container::Raw,
            parse_forest(&doc, 0).unwrap(),
            doc.len(),
        );
        app.start_edit();
        let mut term = Terminal::new(TestBackend::new(120, 20)).unwrap();
        let count = |term: &Terminal<TestBackend>, bg: Color| {
            let buf = term.backend().buffer();
            let area = buf.area;
            (0..area.height)
                .flat_map(|y| (0..area.width).map(move |x| (x, y)))
                .filter(|&(x, y)| buf[(x, y)].style().bg == Some(bg))
                .count()
        };

        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(count(&term, Color::Blue), 0, "nothing is selected to begin with");

        // Shift+Right selects by octet, so twice takes the first two: four
        // digits plus the space between them.
        let shift_right = KeyEvent::new(KeyCode::Right, event::KeyModifiers::SHIFT);
        for _ in 0..2 {
            handle_edit_key(&mut app, shift_right);
        }
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(count(&term, Color::Blue), 5, "four digits and the gap between the octets");
        assert_eq!(count(&term, Color::LightYellow), 0);

        // Pasting over the selection marks what arrived, and unmarks the rest.
        app.paste_into_editor("AABBCC");
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(app.status.contains("pasted 3 octets over 2"), "{}", app.status);
        assert_eq!(count(&term, Color::Blue), 0, "the selection is consumed by the paste");
        // Six digits plus the two gaps inside them; the cursor now sits just
        // past the pasted run, so it takes none of those cells.
        assert_eq!(count(&term, Color::LightYellow), 8);

        // Selecting anything ends the "just pasted" marking.
        handle_edit_key(&mut app, shift_right);
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(count(&term, Color::LightYellow), 0, "the marking is gone");
        assert!(count(&term, Color::Blue) > 0);
    }

    /// A hex selection must never show half an octet — neither by covering
    /// one digit of a pair, nor by the cursor punching a hole in the marked
    /// run when it sits inside it.
    #[test]
    fn a_hex_selection_is_always_marked_in_whole_octets() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        let doc = [0x04, 0x04, 0x11, 0x22, 0x33, 0x44];
        let mut app = App::new_single_file(
            PathBuf::from("doc.der"),
            PathBuf::from("/nonexistent/out"),
            Container::Raw,
            parse_forest(&doc, 0).unwrap(),
            doc.len(),
        );
        app.start_edit();
        let mut term = Terminal::new(TestBackend::new(120, 20)).unwrap();
        let none = event::KeyModifiers::NONE;
        let shift = event::KeyModifiers::SHIFT;
        // Every digit of the dump that carries the selection background.
        let blue_digits = |term: &Terminal<TestBackend>| {
            let buf = term.backend().buffer();
            let area = buf.area;
            (0..area.height)
                .flat_map(|y| (0..area.width).map(move |x| (x, y)))
                .filter(|&(x, y)| buf[(x, y)].style().bg == Some(Color::Blue))
                .map(|(x, y)| buf[(x, y)].symbol().to_string())
                .filter(|s| s != " ")
                .collect::<Vec<_>>()
        };

        // Selecting leftwards puts the cursor on the first selected digit.
        handle_edit_key(&mut app, KeyEvent::new(KeyCode::End, none));
        handle_edit_key(&mut app, KeyEvent::new(KeyCode::Left, shift));
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(blue_digits(&term), ["4", "4"], "the whole octet under the cursor is marked");

        // Shift+Home from between two digits takes the octet the cursor is on
        // whole, rather than the single digit to its left.
        handle_edit_key(&mut app, KeyEvent::new(KeyCode::Home, none));
        handle_edit_key(&mut app, KeyEvent::new(KeyCode::Right, none));
        handle_edit_key(&mut app, KeyEvent::new(KeyCode::Right, none));
        handle_edit_key(&mut app, KeyEvent::new(KeyCode::Right, none));
        let Mode::Edit(EditState { editor: Editor::Hex(ref h), .. }) = app.mode else { panic!() };
        assert_eq!(h.cursor, 3, "the cursor sits inside the second octet");
        handle_edit_key(&mut app, KeyEvent::new(KeyCode::Home, shift));
        let Mode::Edit(EditState { editor: Editor::Hex(ref h), .. }) = app.mode else { panic!() };
        assert_eq!(h.selection(), Some((0, 4)), "both octets, not one and a half");
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(blue_digits(&term), ["1", "1", "2", "2"]);

        // The same going the other way: Shift+End from mid-octet.
        handle_edit_key(&mut app, KeyEvent::new(KeyCode::Home, none));
        for _ in 0..5 {
            handle_edit_key(&mut app, KeyEvent::new(KeyCode::Right, none));
        }
        handle_edit_key(&mut app, KeyEvent::new(KeyCode::End, shift));
        let Mode::Edit(EditState { editor: Editor::Hex(ref h), .. }) = app.mode else { panic!() };
        assert_eq!(h.selection(), Some((4, 8)));
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(blue_digits(&term), ["3", "3", "4", "4"]);

        // What a half-octet selection would have deleted is a whole one.
        handle_edit_key(&mut app, KeyEvent::new(KeyCode::Delete, none));
        let Mode::Edit(EditState { editor: Editor::Hex(ref h), .. }) = app.mode else { panic!() };
        assert_eq!(h.digits.iter().collect::<String>(), "1122");
    }

    /// The integer / OID / text editors show a selection and a fresh addition
    /// exactly as the hex editor does, over characters rather than octets.
    #[test]
    fn the_text_editors_paint_the_selection_and_fresh_input_too() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        let doc = [0x02, 0x02, 0x04, 0xD2]; // INTEGER 1234
        let mut app = App::new_single_file(
            PathBuf::from("doc.der"),
            PathBuf::from("/nonexistent/out"),
            Container::Raw,
            parse_forest(&doc, 0).unwrap(),
            doc.len(),
        );
        app.edit_selected(); // the decimal editor
        let mut term = Terminal::new(TestBackend::new(120, 20)).unwrap();
        let count = |term: &Terminal<TestBackend>, bg: Color| {
            let buf = term.backend().buffer();
            let area = buf.area;
            (0..area.height)
                .flat_map(|y| (0..area.width).map(move |x| (x, y)))
                .filter(|&(x, y)| buf[(x, y)].style().bg == Some(bg))
                .count()
        };

        // Shift+Left from the end selects the last two characters.
        let shift_left = KeyEvent::new(KeyCode::Left, event::KeyModifiers::SHIFT);
        handle_edit_key(&mut app, shift_left);
        handle_edit_key(&mut app, shift_left);
        let Mode::Edit(EditState { editor: Editor::Text(ref t), .. }) = app.mode else { panic!() };
        assert_eq!(t.selection(), Some((2, 4)));
        term.draw(|f| draw(f, &mut app)).unwrap();
        // Selecting leftwards leaves the cursor on the first selected
        // character; it must still be shown as selected, not punched out of
        // the marked run.
        assert_eq!(count(&term, Color::Blue), 2, "both selected characters are marked");

        // Typing over the selection replaces it and marks what was typed.
        handle_edit_key(&mut app, KeyEvent::new(KeyCode::Char('7'), event::KeyModifiers::NONE));
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("127"), "the value was replaced:\n{text}");
        assert_eq!(count(&term, Color::Blue), 0, "the selection is consumed");
        // The typed character is under the cursor, which outranks the marking,
        // so move off it to see the mark (plain movement keeps the marking).
        handle_edit_key(&mut app, KeyEvent::new(KeyCode::Home, event::KeyModifiers::NONE));
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(count(&term, Color::LightYellow), 1, "the typed character is new");
    }

    #[test]
    fn the_menu_toggle_accepts_alt_f10_and_alt_m_only() {
        let none = event::KeyModifiers::NONE;
        let alt = event::KeyModifiers::ALT;
        assert!(is_menu_toggle(KeyEvent::new(KeyCode::F(10), none)));
        assert!(is_menu_toggle(KeyEvent::new(KeyCode::Char('m'), alt)));
        assert!(is_menu_toggle(KeyEvent::new(
            KeyCode::Modifier(ModifierKeyCode::LeftAlt),
            alt
        )));
        assert!(is_menu_toggle(KeyEvent::new(
            KeyCode::Modifier(ModifierKeyCode::RightAlt),
            alt
        )));
        // A plain 'm' types; other modifier keys and function keys do not open
        // the bar.
        assert!(!is_menu_toggle(KeyEvent::new(KeyCode::Char('m'), none)));
        assert!(!is_menu_toggle(KeyEvent::new(KeyCode::F(9), none)));
        assert!(!is_menu_toggle(KeyEvent::new(
            KeyCode::Modifier(ModifierKeyCode::LeftShift),
            none
        )));
    }

    fn menu_app() -> App {
        use crate::input::Container;
        // SEQUENCE { INTEGER 1234 }
        let doc = [0x30, 0x04, 0x02, 0x02, 0x04, 0xD2];
        App::new_single_file(
            PathBuf::from("doc.der"),
            PathBuf::from("/nonexistent/out"),
            Container::Raw,
            parse_forest(&doc, 0).unwrap(),
            doc.len(),
        )
    }

    #[test]
    fn the_menu_bar_appears_in_the_top_row_and_navigates_with_the_arrow_keys() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = menu_app();
        let mut term = Terminal::new(TestBackend::new(120, 24)).unwrap();
        let key = |c| KeyEvent::new(c, event::KeyModifiers::NONE);

        term.draw(|f| draw(f, &mut app)).unwrap();
        let without = buffer_text(term.backend().buffer());
        assert!(!without.contains("About"), "no menu bar until it is asked for");

        app.toggle_menu_bar();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        let top = text.lines().next().unwrap();
        assert!(top.contains("File") && top.contains("About"), "menu bar row: {top:?}");
        // The first heading opens with it, so ↑↓ work straight away.
        assert!(text.contains("New DER"), "the File menu should be open:\n{text}");
        assert!(text.contains("start an empty document"), "entries carry a summary");

        // → opens the next heading, and the entry selection restarts there.
        handle_menu_bar_key(&mut app, key(KeyCode::Right));
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("Help") && text.contains("Version"), "About should be open:\n{text}");
        assert!(!text.contains("New DER"), "only one drop-down at a time");
        let Mode::MenuBar(ref bar) = app.mode else { panic!("still on the bar") };
        assert_eq!((bar.menu, bar.item), (1, 0));

        // ↓ moves within the drop-down, and both directions wrap.
        handle_menu_bar_key(&mut app, key(KeyCode::Down));
        let Mode::MenuBar(ref bar) = app.mode else { panic!("still on the bar") };
        assert_eq!(bar.item, 1);
        handle_menu_bar_key(&mut app, key(KeyCode::Down));
        let Mode::MenuBar(ref bar) = app.mode else { panic!("still on the bar") };
        assert_eq!(bar.item, 0, "the entry selection wraps");
        handle_menu_bar_key(&mut app, key(KeyCode::Right));
        let Mode::MenuBar(ref bar) = app.mode else { panic!("still on the bar") };
        assert_eq!(bar.menu, 0, "the headings wrap too");

        // Esc closes the bar and gives the panes their row back.
        handle_menu_bar_key(&mut app, key(KeyCode::Esc));
        assert!(matches!(app.mode, Mode::Browse));
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(buffer_text(term.backend().buffer()), without);
    }

    #[test]
    fn the_file_menu_asks_where_the_new_document_goes_and_creates_it_there() {
        let dir = std::env::temp_dir().join(format!("ae-new-der-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("taken.der"), [0x05u8, 0x00]).unwrap();
        let mut app = App::new_dir(dir.clone());
        assert!(!app.file_open);
        let key = |c| KeyEvent::new(c, event::KeyModifiers::NONE);
        let type_in = |app: &mut App, text: &str| {
            for c in text.chars() {
                handle_new_file_key(app, key(KeyCode::Char(c)));
            }
        };

        app.toggle_menu_bar();
        app.activate_menu_entry(); // File ▸ New DER
        let Mode::NewFile(ref state) = app.mode else { panic!("the path dialog opens") };
        assert_eq!(state.path, "untitled.der", "a name the directory does not hold is offered");
        assert!(!app.file_open, "nothing is created until the dialog is accepted");

        // A name already taken is refused, with the reason, and the dialog stays.
        for _ in 0..state.path.chars().count() {
            handle_new_file_key(&mut app, key(KeyCode::Backspace));
        }
        type_in(&mut app, "taken.der");
        handle_new_file_key(&mut app, key(KeyCode::Enter));
        let Mode::NewFile(ref state) = app.mode else { panic!("the dialog stays open") };
        assert!(state.error.as_ref().unwrap().contains("already exists"), "{:?}", state.error);
        assert_eq!(std::fs::read(dir.join("taken.der")).unwrap(), [0x05, 0x00], "untouched");

        // So is a name under a directory that does not exist.
        for _ in 0..state.path.chars().count() {
            handle_new_file_key(&mut app, key(KeyCode::Backspace));
        }
        type_in(&mut app, "no/such/dir/x.der");
        handle_new_file_key(&mut app, key(KeyCode::Enter));
        let Mode::NewFile(ref state) = app.mode else { panic!("the dialog stays open") };
        assert!(
            state.error.as_ref().unwrap().contains("not an existing directory"),
            "{:?}",
            state.error
        );

        // A usable path creates the file straight away…
        for _ in 0..state.path.chars().count() {
            handle_new_file_key(&mut app, key(KeyCode::Backspace));
        }
        type_in(&mut app, "fresh.der");
        // The cursor is editable: put "my-" in front of the name.
        handle_new_file_key(&mut app, key(KeyCode::Home));
        type_in(&mut app, "my-");
        let Mode::NewFile(ref state) = app.mode else { panic!("the dialog stays open") };
        assert_eq!((state.path.as_str(), state.cursor), ("my-fresh.der", 3));
        handle_new_file_key(&mut app, key(KeyCode::Enter));

        assert!(matches!(app.mode, Mode::Browse));
        let created = dir.join("my-fresh.der");
        assert!(created.exists(), "the file is created at once: {}", app.status);
        assert_eq!(app.out_path, created);
        assert!(app.file_open && app.roots.is_empty() && !app.dirty);
        // …and shows up in the Files pane, selected, without waiting for a poll.
        assert_eq!(
            app.browser.selected_entry().map(|e| e.path.clone()),
            Some(created.clone()),
            "the new file must be the browser's selection"
        );
        assert_eq!(app.focus, Focus::Document, "editing is what comes next");

        // An empty document is navigable (it used to panic) and editable.
        app.move_by(1);
        app.move_by(-1);
        app.start_insert(false);
        assert!(matches!(app.mode, Mode::TypePicker(_)));
        app.mode = Mode::Browse;
        app.save();
        assert!(!app.dirty, "{}", app.status);

        // The empty file re-opens as the same empty document.
        app.open_file(created).expect("an empty file is an empty forest");
        assert!(app.roots.is_empty());

        // An absolute path is taken as it stands, not joined to the directory.
        let elsewhere = dir.join("sub");
        std::fs::create_dir_all(&elsewhere).unwrap();
        app.toggle_menu_bar();
        app.activate_menu_entry();
        let Mode::NewFile(ref state) = app.mode else { panic!("the path dialog opens") };
        for _ in 0..state.path.chars().count() {
            handle_new_file_key(&mut app, key(KeyCode::Backspace));
        }
        type_in(&mut app, &elsewhere.join("deep.der").display().to_string());
        handle_new_file_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.out_path, elsewhere.join("deep.der"));
        assert!(app.out_path.exists());

        // Esc abandons the dialog without creating anything.
        app.toggle_menu_bar();
        app.activate_menu_entry();
        handle_new_file_key(&mut app, key(KeyCode::Esc));
        assert!(matches!(app.mode, Mode::Browse));
        assert!(!dir.join("untitled.der").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_about_menu_reports_how_this_binary_was_built() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = menu_app();
        let key = |c| KeyEvent::new(c, event::KeyModifiers::NONE);
        app.toggle_menu_bar();
        handle_menu_bar_key(&mut app, key(KeyCode::Right)); // About
        handle_menu_bar_key(&mut app, key(KeyCode::Down)); // Version
        handle_menu_bar_key(&mut app, key(KeyCode::Enter));

        let mut term = Terminal::new(TestBackend::new(120, 24)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("VERSION"), "the popup is titled:\n{text}");
        // Whichever kind of build this is, it names itself the same way the
        // version module does.
        let id = crate::version::build_id();
        let head = id.split(" + ").next().unwrap();
        assert!(text.contains(head), "the build id {head:?} is missing:\n{text}");
        // Any key dismisses it, as with the start-up notice.
        app.dismiss_notice();
        assert!(matches!(app.mode, Mode::Browse));
    }

    #[test]
    fn the_help_window_lists_topics_and_scrolls_the_chosen_one() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = menu_app();
        let key = |c| KeyEvent::new(c, event::KeyModifiers::NONE);
        app.toggle_menu_bar();
        handle_menu_bar_key(&mut app, key(KeyCode::Right)); // About
        handle_menu_bar_key(&mut app, key(KeyCode::Enter)); // Help
        assert!(matches!(app.mode, Mode::Help(_)));

        let mut term = Terminal::new(TestBackend::new(120, 26)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("HELP"));
        // Every topic is listed on the left…
        for topic in HELP_TOPICS {
            assert!(text.contains(topic.title), "topic {:?} missing:\n{text}", topic.title);
        }
        // …and the first one's text is on the right.
        assert!(text.contains("asn1-editor shows a BER/DER encoding as a tree"), "{text}");

        // ↓ picks the next topic and starts its text at the top again.
        handle_help_key(&mut app, key(KeyCode::PageDown));
        let Mode::Help(ref help) = app.mode else { panic!("still in help") };
        assert_eq!(help.scroll, 8);
        handle_help_key(&mut app, key(KeyCode::Down));
        let Mode::Help(ref help) = app.mode else { panic!("still in help") };
        assert_eq!((help.topic, help.scroll), (1, 0));
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(buffer_text(term.backend().buffer()).contains("the directory tree"));

        // Topics wrap, so ↑ from the first reaches the last — the key-binding
        // tables, which are longer than any window.
        handle_help_key(&mut app, key(KeyCode::Up));
        handle_help_key(&mut app, key(KeyCode::Up));
        let Mode::Help(ref help) = app.mode else { panic!("still in help") };
        assert_eq!(help.topic, HELP_TOPICS.len() - 1);

        // End clamps to the last screenful rather than scrolling past it.
        handle_help_key(&mut app, key(KeyCode::End));
        term.draw(|f| draw(f, &mut app)).unwrap();
        let Mode::Help(ref help) = app.mode else { panic!("still in help") };
        let at_end = help.scroll;
        assert!(at_end > 0 && at_end < usize::MAX, "the scroll must be clamped: {at_end}");
        let bottom = buffer_text(term.backend().buffer());
        assert!(bottom.contains("Esc cancels"), "the end of the topic:\n{bottom}");
        handle_help_key(&mut app, key(KeyCode::PageDown));
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(buffer_text(term.backend().buffer()), bottom, "the end is the end");

        handle_help_key(&mut app, key(KeyCode::Esc));
        assert!(matches!(app.mode, Mode::Browse));
    }

    #[test]
    fn the_content_pane_dumps_every_byte_and_scrolls_no_further_than_the_end() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        // An OCTET STRING far longer than one screen: 8 KiB = 512 dump lines.
        // 0xAB bytes cannot be read as nested ASN.1, so the value stays a
        // single primitive element.
        let doc = ber::encode_node(&ber::univ(ber::TAG_OCTET_STRING, false, vec![0xAB; 8192]));
        let roots = parse_forest(&doc, 0).unwrap();
        let mut app = App::new_single_file(
            PathBuf::from("big.der"),
            PathBuf::from("/nonexistent/out"),
            Container::Raw,
            roots,
            doc.len(),
        );
        let mut term = Terminal::new(TestBackend::new(160, 30)).unwrap();
        let press = |app: &mut App, c: char, mods: event::KeyModifiers| {
            handle_document_key(app, KeyEvent::new(KeyCode::Char(c), mods));
            // The clamp lives in the draw, so every press is followed by one,
            // exactly as the event loop does it.
        };
        let plain = event::KeyModifiers::NONE;
        let shift = event::KeyModifiers::SHIFT;

        term.draw(|f| draw(f, &mut app)).unwrap();
        let top = buffer_text(term.backend().buffer());
        assert!(top.contains("Content octets (8192 bytes)"), "header missing:\n{top}");
        assert!(!top.contains("not shown"), "the dump must not be truncated:\n{top}");
        assert!(top.contains("00000000  AB"), "the dump must start at offset 0:\n{top}");

        // 'shift + ]' jumps to the very end: the last line of the dump is the
        // one at offset 8192 − 16 = 0x1FF0, and the header has scrolled off.
        press(&mut app, '}', shift);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let bottom = buffer_text(term.backend().buffer());
        assert!(bottom.contains("00001FF0  AB"), "the last dump line is missing:\n{bottom}");
        assert!(!bottom.contains("Content octets"), "the header should be scrolled past");
        let at_end = app.content_scroll;
        assert!(at_end > 0);

        // Scrolling further down changes nothing — the end is the end.
        for _ in 0..20 {
            press(&mut app, ']', plain);
            term.draw(|f| draw(f, &mut app)).unwrap();
        }
        assert_eq!(app.content_scroll, at_end, "the scroll must stop at the last screenful");
        assert_eq!(buffer_text(term.backend().buffer()), bottom, "the view must not move");

        // 'shift + [' goes back to the very beginning.
        press(&mut app, '{', shift);
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(app.content_scroll, 0);
        assert_eq!(buffer_text(term.backend().buffer()), top);

        // Terminals that report a shifted bracket as the bracket itself plus
        // the Shift modifier reach the same two ends.
        press(&mut app, ']', shift);
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(app.content_scroll, at_end, "shift + ] must jump to the end");
        press(&mut app, '[', shift);
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(app.content_scroll, 0, "shift + [ must jump to the start");

        // Unshifted, the same keys still step by four lines.
        press(&mut app, ']', plain);
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(app.content_scroll, 4);
        press(&mut app, '[', plain);
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(app.content_scroll, 0);
    }

    /// The content pane previews the file the Files pane is on, so its scroll
    /// keys have to work without switching panes.
    #[test]
    fn the_content_pane_scrolls_while_the_files_pane_has_focus() {
        use ratatui::{backend::TestBackend, Terminal};
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/chain");
        let mut app = App::new_dir(dir);
        let mut term = Terminal::new(TestBackend::new(160, 30)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        // Move onto a file, so the content pane has something long to show.
        let down = KeyEvent::new(KeyCode::Down, event::KeyModifiers::NONE);
        for _ in 0..20 {
            if app.file_open {
                break;
            }
            handle_browser_key(&mut app, down);
        }
        assert!(app.file_open, "no file to preview in testdata/chain");
        assert_eq!(app.focus, Focus::Browser);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let top = buffer_text(term.backend().buffer());

        let press = |app: &mut App, c: char| {
            handle_browser_key(app, KeyEvent::new(KeyCode::Char(c), event::KeyModifiers::SHIFT));
        };
        press(&mut app, '}');
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(app.content_scroll > 0, "shift + ] must scroll the preview to its end");
        assert_ne!(buffer_text(term.backend().buffer()), top, "the view must move");
        press(&mut app, '{');
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(app.content_scroll, 0);
        assert_eq!(buffer_text(term.backend().buffer()), top);
    }

    #[test]
    fn content_pane_documents_an_lms_public_key_and_names_its_fields_in_the_dump() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        // Single-level LMS, tree height 5, Winternitz width 8 — the fastest
        // parameter set, and one whose whole key fits in three dump lines.
        let (_, spki) = crate::hsslms::generate("SHA-256,HW(5,8)").unwrap();
        let roots = parse_forest(&spki, 0).unwrap();
        let mut app = App::new(
            PathBuf::from("/nonexistent/in"),
            PathBuf::from("/nonexistent/out"),
            Container::Raw,
            roots,
            spki.len(),
        );
        let idx = (0..app.rows.len())
            .find(|&i| {
                app.select(i);
                app.selected_node().is_some_and(|n| n.is_universal(TAG_BIT_STRING))
            })
            .expect("the subjectPublicKey BIT STRING");
        app.select(idx);
        let mut term = Terminal::new(TestBackend::new(200, 60)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let buf = term.backend().buffer().clone();
        let text = buffer_text(&buf);

        // The prose resolves the typecodes to their parameters.
        assert!(text.contains("HSS/LMS public key (RFC 8554"), "heading missing:\n{text}");
        assert!(text.contains("LMS_SHA256_M32_H5"), "LMS parameter set missing:\n{text}");
        assert!(text.contains("tree height h = 5"), "tree height missing:\n{text}");
        assert!(text.contains("LMOTS_SHA256_N32_W8"), "LM-OTS parameter set missing:\n{text}");
        assert!(text.contains("Winternitz w = 8 bits"), "Winternitz width missing:\n{text}");

        // The dump's right-hand column names the fields starting on each line
        // instead of showing the (meaningless) ASCII reading of hash bytes.
        let row = text
            .lines()
            .find(|l| l.contains("L lmsType otsType I"))
            .unwrap_or_else(|| panic!("no dump line names the first fields:\n{text}"));
        assert!(!row.contains('|'), "the ASCII gutter must be replaced:\n{row}");
        assert!(
            text.lines().any(|l| l.contains("00000010  ") && l.contains("T[1]  ")),
            "the root node's field name missing from the second dump line:\n{text}"
        );

        // Consecutive fields alternate between the two colours, in the hex
        // bytes as well as in the tokens naming them.
        let y = text.lines().position(|l| l.contains("L lmsType otsType I")).unwrap() as u16;
        let fg = |x: usize| buf[(x as u16, y)].style().fg;
        // Cell columns, not byte offsets: the row carries multi-byte borders.
        let column = |needle: &str| {
            let at = row.find(needle).expect("substring on the dump line");
            row[..at].chars().count()
        };
        let hex = column("00000000  ") + 10;
        // Content octet 0 is the BIT STRING's unused-bits octet (no field);
        // L, lmsType and otsType are the next three four-byte fields.
        assert!(
            !FIELD_COLORS.contains(&fg(hex).unwrap_or(Color::Reset)),
            "the unused-bits octet belongs to no field"
        );
        assert_eq!(fg(hex + 3), Some(FIELD_COLORS[0]), "L takes the first colour");
        assert_eq!(fg(hex + 15), Some(FIELD_COLORS[1]), "lmsType takes the second");
        assert_eq!(fg(hex + 27), Some(FIELD_COLORS[0]), "otsType alternates back");
        let tokens = column("L lmsType otsType I");
        assert_eq!(fg(tokens), Some(FIELD_COLORS[0]), "the token matches its bytes");
        assert_eq!(fg(tokens + 2), Some(FIELD_COLORS[1]));
        assert_eq!(fg(tokens + 10), Some(FIELD_COLORS[0]));
    }

    #[test]
    fn tree_filter_renders_bar_and_elision_placeholders() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        // SEQUENCE { INTEGER 1234, UTF8String "hello", OID 2.5.4.3 }
        let doc = [
            0x30, 0x10, 0x02, 0x02, 0x04, 0xD2, 0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            0x06, 0x03, 0x55, 0x04, 0x03,
        ];
        let roots = parse_forest(&doc, 0).unwrap();
        let mut app = App::new_single_file(
            PathBuf::from("doc.der"),
            PathBuf::from("/nonexistent/out"),
            Container::Raw,
            roots,
            doc.len(),
        );
        app.start_filter();
        for c in "1234".chars() {
            app.filter_insert_char(c);
        }
        let mut term = Terminal::new(TestBackend::new(160, 30)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("filter / 1234"), "filter bar missing:\n{text}");
        assert!(text.contains("[...]"), "elision placeholder missing:\n{text}");
        assert!(text.contains("INTEGER"), "matching row missing");
        // The UTF8String tree row is hidden (its bytes still appear in the
        // content pane's hex dump of the selected root, which is fine).
        assert!(!text.contains("UTF8String"), "non-matching row should be hidden");

        // The bar stays visible after Tab (field unfocused, filter non-empty).
        app.filter_accept();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("filter / 1234"), "bar should persist while non-empty");

        // Clearing the filter hides the bar again.
        app.start_filter();
        app.filter_clear();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(!text.contains("filter /"), "bar should vanish when the filter is empty");
        assert!(text.contains("UTF8String"), "full tree restored");
    }

    #[test]
    fn single_file_mode_hides_the_browser_pane() {
        use crate::input::Container;
        use ratatui::{backend::TestBackend, Terminal};
        let der =
            std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/cert_ec.der"))
                .unwrap();
        let roots = parse_forest(&der, 0).unwrap();
        let mut app = App::new_single_file(
            PathBuf::from("cert_ec.der"),
            PathBuf::from("/nonexistent/out"),
            Container::Raw,
            roots,
            der.len(),
        );
        let mut term = Terminal::new(TestBackend::new(160, 30)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("Structure"), "the structure pane is shown:\n{text}");
        assert!(text.contains("Content"), "the content pane is shown");
        assert!(!text.contains("Files"), "the file browser pane must be hidden:\n{text}");
    }

    /// Flatten a rendered buffer to text, one line per row.
    fn buffer_text(buf: &ratatui::buffer::Buffer) -> String {
        let area = buf.area;
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn content_pane_renders_basic_constraints_interpretation() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = app_on_basic_constraints("testdata/chain/intermediate_ca.der");
        let mut term = Terminal::new(TestBackend::new(200, 40)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("Basic Constraints"), "heading missing:\n{text}");
        assert!(text.contains("cA = TRUE"), "cA interpretation missing:\n{text}");
        assert!(
            text.contains("pathLenConstraint = 0"),
            "pathLen interpretation missing:\n{text}"
        );
    }

    #[test]
    fn basic_constraints_editor_popup_renders_fields() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = app_on_basic_constraints("testdata/chain/intermediate_ca.der");
        app.start_basic_constraints();
        let mut term = Terminal::new(TestBackend::new(200, 40)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("EDIT — Basic Constraints"), "popup title missing:\n{text}");
        assert!(text.contains("cA"), "cA field missing");
        assert!(text.contains("pathLenConstraint"), "pathLen field missing");
    }

    #[test]
    fn content_pane_renders_key_usage_interpretation() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = app_on_key_usage("testdata/chain/root_ca.der");
        let mut term = Terminal::new(TestBackend::new(200, 40)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("Key Usage"), "heading missing:\n{text}");
        assert!(text.contains("keyCertSign"), "keyCertSign usage missing:\n{text}");
        assert!(text.contains("cRLSign"), "cRLSign usage missing:\n{text}");
    }

    #[test]
    fn key_usage_editor_popup_renders_bits() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = app_on_key_usage("testdata/chain/server.der");
        app.start_key_usage();
        let mut term = Terminal::new(TestBackend::new(200, 40)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("EDIT — Key Usage"), "popup title missing:\n{text}");
        assert!(text.contains("digitalSignature"), "digitalSignature bit missing");
        assert!(text.contains("decipherOnly"), "decipherOnly bit missing");
        assert!(text.contains("[x]"), "the set bit should render checked");
    }

    #[test]
    fn content_pane_renders_ext_key_usage_interpretation() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = app_on_ext_key_usage("testdata/chain/server.der");
        let mut term = Terminal::new(TestBackend::new(200, 40)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("Extended Key Usage"), "heading missing:\n{text}");
        assert!(text.contains("serverAuth"), "serverAuth purpose missing:\n{text}");
        assert!(
            text.contains("TLS server authentication"),
            "meaning missing:\n{text}"
        );
    }

    #[test]
    fn ext_key_usage_editor_popup_renders_purposes_and_input() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = app_on_ext_key_usage("testdata/chain/server.der");
        app.start_ext_key_usage();
        let mut term = Terminal::new(TestBackend::new(200, 40)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = buffer_text(term.backend().buffer());
        assert!(text.contains("EDIT — Extended Key Usage"), "title missing:\n{text}");
        assert!(text.contains("serverAuth"), "predefined purpose missing");
        assert!(text.contains("codeSigning"), "unchecked predefined purpose missing");
        assert!(text.contains("add OID:"), "OID input field missing");
    }
}
