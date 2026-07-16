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
};
use ratatui::crossterm::execute;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

use crate::app::{
    App, DateTimeEditor, EditKind, EditState, Editor, FilterMatcher, Focus, HexEditor, Mode,
    PickerTarget, RowSource, TextEditor, TextFormat, DATE_FIELDS, EDIT_BYTES_PER_LINE,
    EDIT_DIGITS_PER_LINE, PICKER_CLASSES, PICKER_UNIVERSAL,
};
use crate::x509::{self, basic_constraints, extended_key_usage, key_usage};
use crate::browser::FileStatus;
use crate::ber::{
    self, Class, Node, TAG_BIT_STRING, TAG_BOOLEAN, TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_NULL,
    TAG_OID, TAG_UTC_TIME,
};
use crate::keygen;
use crate::oid;
use crate::pathval::PathStatus;
use crate::verify::{FileRelations, SignatureStatus};

/// Bytes of hex shown in the browse-mode content pane before truncating.
const CONTENT_HEX_LIMIT: usize = 4096;
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
    let result = event_loop(&mut terminal, &mut app);
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
        // Reconcile the browser with the filesystem on a timer (the poll below
        // wakes at least every 250 ms even when the user is idle).
        if last_fs_poll.elapsed() >= FS_POLL_INTERVAL {
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
                    Mode::Edit(ref mut edit) => edit.editor.paste(&text),
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
        match app.mode {
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

fn handle_browser_key(app: &mut App, key: KeyEvent) {
    if !matches!(key.code, KeyCode::Enter | KeyCode::Char(' ')) {
        app.open_confirm = false;
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
        KeyCode::Char('[') => app.content_scroll = app.content_scroll.saturating_sub(4),
        KeyCode::Char(']') => app.content_scroll = app.content_scroll.saturating_add(4),
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
    match key.code {
        KeyCode::Esc => app.cancel_pubkey(),
        KeyCode::Enter => app.submit_pubkey(),
        KeyCode::Left | KeyCode::BackTab => app.pubkey_move_column(-1),
        KeyCode::Right | KeyCode::Tab => app.pubkey_move_column(1),
        KeyCode::Up => app.pubkey_move_row(-1),
        KeyCode::Down => app.pubkey_move_row(1),
        KeyCode::Char(' ') => app.pubkey_toggle(),
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
    let Mode::Edit(ref mut edit) = app.mode else { return };
    match key.code {
        KeyCode::Char(c) => edit.editor.insert_char(c),
        KeyCode::Backspace => edit.editor.backspace(),
        KeyCode::Delete => edit.editor.delete(),
        KeyCode::Left | KeyCode::BackTab => edit.editor.move_horizontal(-1),
        KeyCode::Right | KeyCode::Tab => edit.editor.move_horizontal(1),
        KeyCode::Up => edit.editor.move_vertical(-1),
        KeyCode::Down => edit.editor.move_vertical(1),
        KeyCode::Home => edit.editor.home(),
        KeyCode::End => edit.editor.end(),
        _ => {}
    }
}

fn draw(frame: &mut Frame, app: &mut App) {
    let [main, status] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());
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
        .border_style(Style::new().fg(Color::Yellow))
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

/// Centered three-column popup for the public-key modification dialog:
/// algorithm choice | key-generation options | issued certificates to resign.
fn draw_edit_pubkey(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::EditPubKey(ref s) = app.mode else { return };
    let width = 92.min(area.width);
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
    let [cols_area, hint_area] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);
    let [alg_col, opt_col, issued_col] = Layout::horizontal([
        Constraint::Length(26),
        Constraint::Length(34),
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

    // Column 0: algorithm list, scrolled so the selection stays visible
    // (there are more algorithms than the popup is tall).
    let mut alg_lines = vec![header("Algorithm", s.column == 0)];
    let visible = (alg_col.height as usize).saturating_sub(1).max(1);
    let start = s.alg_idx.saturating_sub(visible.saturating_sub(1)).min(
        keygen::ALL.len().saturating_sub(visible),
    );
    for (i, alg) in keygen::ALL.iter().enumerate().skip(start).take(visible) {
        alg_lines.push(row(alg.label().to_string(), i == s.alg_idx, s.column == 0));
    }
    frame.render_widget(Paragraph::new(alg_lines), alg_col);

    // Column 1: key-source radio, then either the generate fields (file name,
    // password) or the list of existing keys fitting the chosen algorithm.
    let active1 = s.column == 1;
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
        opt_lines.push(Line::from(Span::styled(" file name", Style::new().dim())));
        opt_lines.push(row(field_value(&s.filename), s.option_field == 1, active1));
        opt_lines.push(Line::default());
        opt_lines.push(Line::from(Span::styled(" password (blank = unencrypted)", Style::new().dim())));
        opt_lines.push(row(field_value(&mask), s.option_field == 2, active1));
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

    // Column 2: issued certificates and CRLs with resign checkboxes.
    let mut issued_lines = vec![header("Resign issued objects", s.column == 2)];
    if s.issued.is_empty() {
        issued_lines.push(Line::from(Span::styled(" (none found)", Style::new().dim())));
    } else {
        let visible = (issued_col.height as usize).saturating_sub(1).max(1);
        let start = s.issued_idx.saturating_sub(visible.saturating_sub(1));
        for (i, cert) in s.issued.iter().enumerate().skip(start).take(visible) {
            let box_ = if cert.selected { "[x]" } else { "[ ]" };
            let label = format!("{} {}  {}", box_, cert.name, cert.detail);
            issued_lines.push(row(label, i == s.issued_idx, s.column == 2));
        }
    }
    frame.render_widget(Paragraph::new(issued_lines), issued_col);

    let hint = Line::from(Span::styled(
        "←→ column  ↑↓ move  Space toggle  type to edit name/password  ⏎ apply  Esc cancel",
        Style::new().dim(),
    ));
    frame.render_widget(Paragraph::new(hint), hint_area);
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

/// Per-byte flags marking every occurrence of `needle` in the shown prefix
/// of `bytes` (the tree filter's hex reading), for dump highlighting.
fn hex_match_marks(bytes: &[u8], needle: &[u8]) -> Vec<bool> {
    let shown = bytes.len().min(CONTENT_HEX_LIMIT);
    let mut marks = vec![false; shown];
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

/// Hex dump of `bytes`; positions flagged in `marks` (from the tree filter's
/// hex reading) are highlighted in both the hex and the ASCII column. Pass an
/// empty slice for a plain dump.
fn hex_dump_lines(bytes: &[u8], marks: &[bool]) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let shown = bytes.len().min(CONTENT_HEX_LIMIT);
    let marked = |i: usize| marks.get(i).copied().unwrap_or(false);
    for (i, chunk) in bytes[..shown].chunks(16).enumerate() {
        let mut spans = vec![Span::styled(format!("{:08X}  ", i * 16), Style::new().dim())];
        for (j, b) in chunk.iter().enumerate() {
            let style = if marked(i * 16 + j) { HEX_MATCH_STYLE } else { Style::new() };
            spans.push(Span::styled(format!("{:02X}", b), style));
            if j + 1 < chunk.len() {
                spans.push(Span::raw(" "));
            }
        }
        // Pad the hex column to its full width (16*3-1) plus the separator.
        let hex_w = chunk.len() * 3 - 1;
        spans.push(Span::raw(" ".repeat(47 - hex_w + 2)));
        spans.push(Span::styled("|", Style::new().dim()));
        for (j, &b) in chunk.iter().enumerate() {
            let c = if (0x20..=0x7E).contains(&b) { b as char } else { '.' };
            let style = if marked(i * 16 + j) { HEX_MATCH_STYLE } else { Style::new().dim() };
            spans.push(Span::styled(c.to_string(), style));
        }
        spans.push(Span::styled("|", Style::new().dim()));
        lines.push(Line::from(spans));
    }
    if shown < bytes.len() {
        lines.push(Line::from(Span::styled(
            format!("… {} more bytes not shown …", bytes.len() - shown),
            Style::new().dim().italic(),
        )));
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
fn signature_status_line(status: &SignatureStatus) -> Line<'static> {
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
    Line::from(vec![
        Span::styled("Signature ", Style::new().dim()),
        Span::styled(text, style),
    ])
}

fn path_status_line(status: &PathStatus) -> Line<'static> {
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
    Line::from(vec![
        Span::styled("Path      ", Style::new().dim()),
        Span::styled(text, style),
    ])
}

fn draw_content_browse(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
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
        lines.push(Line::from(vec![
            Span::styled("Type    ", Style::new().dim()),
            Span::styled(node.type_name(), class_style(node)),
        ]));
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
                lines.push(Line::from(vec![
                    Span::styled("Spec    ", Style::new().dim()),
                    Span::styled(field.to_string(), Style::new().fg(Color::LightCyan)),
                    Span::raw(" : "),
                    Span::styled(label.type_name.clone(), Style::new().fg(Color::LightGreen)),
                    Span::styled(
                        format!("   (document: {}, {})", ident.type_name, ident.source),
                        Style::new().dim(),
                    ),
                ]));
            }
        }
        if let Some(status) = &app.sig_status {
            lines.push(signature_status_line(status));
        }
        if let Some(status) = &app.path_status {
            lines.push(path_status_line(status));
        }
        let ids = ber::identifier_octets(node.class, node.tag, node.constructed);
        lines.push(Line::from(vec![
            Span::styled("Tag     ", Style::new().dim()),
            Span::raw(format!(
                "identifier octet{}: {}",
                if ids.len() == 1 { "" } else { "s" },
                ber::hex_pairs(&ids)
            )),
        ]));
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
        lines.push(Line::from(vec![
            Span::styled("Length  ", Style::new().dim()),
            Span::raw(format!(
                "length octet{}: {}",
                plural(len_octets.len()),
                ber::hex_pairs(&len_octets)
            )),
        ]));
        for (i, text) in length_layout_strings(node).into_iter().enumerate() {
            lines.push(Line::from(Span::styled(text, diagram_style(i))));
        }
        lines.push(Line::from(vec![
            Span::styled("Offset  ", Style::new().dim()),
            Span::raw(format!(
                "{}   header: {} byte{}   content: {} byte{}{}",
                node.offset,
                node.header_len,
                plural(node.header_len),
                node.content_len,
                plural(node.content_len),
                if node.indefinite { "   (indefinite length)" } else { "" }
            )),
        ]));
        if node.encapsulates {
            lines.push(Line::from(Span::styled(
                "Encapsulates nested ASN.1 (shown as children in the tree)",
                Style::new().fg(Color::Yellow),
            )));
        }
        let decoded = summary(node);
        if !decoded.trim().is_empty() && !node.constructed {
            lines.push(Line::from(vec![
                Span::styled("Decoded ", Style::new().dim()),
                Span::raw(decoded.trim().to_string()),
            ]));
        }
        if let Some((dotted, long_name)) = oid_details(node) {
            lines.push(Line::from(vec![
                Span::styled("OID     ", Style::new().dim()),
                Span::raw(dotted),
            ]));
            if let Some(long_name) = long_name {
                lines.push(Line::from(vec![
                    Span::styled("Name    ", Style::new().dim()),
                    Span::raw(long_name),
                ]));
            }
        }
        // Plain-language interpretation of a recognised extension, shown
        // between the header information and the raw content octets.
        let extension_section = |heading: &str, body: Vec<String>| {
            let inner_w = area.width.saturating_sub(2).max(20) as usize;
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
        lines.extend(hex_dump_lines(&content, &marks));
    } else if !app.file_open {
        lines.push(Line::from(
            "no file open — move ↑↓ over a file in the Files pane on the left to preview it",
        ));
    } else {
        lines.push(Line::from("no element selected"));
    }
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(app.focus == Focus::Document))
                .title(" Content "),
        )
        .scroll((app.content_scroll, 0));
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
            "[Enter] insert   [Esc] cancel   length octets are computed automatically",
        );
    }
    match edit.editor {
        Editor::Hex(_) => (
            " EDIT — content octets (hex) ".to_string(),
            "[Enter] apply   [Esc] cancel   [←→↑↓] move   type hex digits to insert",
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
                let style = if i == h.cursor {
                    Style::new().add_modifier(Modifier::REVERSED)
                } else {
                    Style::new()
                };
                spans.push(Span::styled(h.digits[i].to_string(), style));
                if i % 2 == 1 && i + 1 < end {
                    spans.push(Span::raw(" "));
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
        let style = if i == t.cursor {
            Style::new().add_modifier(Modifier::REVERSED)
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
            "q quit  ↑↓ move  ←→ fold  ⏎ toggle  e edit  E edit-menu  i/I insert  d delete  J/K reorder  s save  z decrypt  [ ] scroll"
        }
        Mode::Browse if app.focus == Focus::Browser => {
            "q quit  Tab switch pane  ↑↓ move+preview  ←→ fold  ⏎ switch to file/fold  z decrypt/re-sign  t trust"
        }
        Mode::Browse => {
            "q quit  Tab switch pane  ↑↓ move  ←→ fold  ⏎ toggle  e edit  E edit-menu  i/I insert  d delete  J/K reorder  s save  z decrypt/re-sign  [ ] scroll"
        }
        Mode::TypePicker(_) => "←→ column  ↑↓ select  0-9 tag number  ⏎ continue  Esc cancel",
        Mode::EditMenu(_) => "↑↓ or 1-5 select  ⏎ choose  Esc cancel",
        Mode::Edit(_) => "Enter apply  Esc cancel",
        Mode::Password(_) => "type password  ⏎ decrypt  Esc cancel",
        Mode::Resign(_) => "⏎ create new signature (if available)  Esc cancel",
        Mode::EditPubKey(_) => {
            "←→ column  ↑↓ move  Space toggle  type name/password  ⏎ apply  Esc cancel"
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
            text.contains("Path") && text.contains("valid — path of"),
            "path line missing:\n{text}"
        );
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
