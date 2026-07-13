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
use std::time::Duration;

use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use crate::app::{
    App, DateTimeEditor, EditKind, EditState, Editor, Focus, HexEditor, Mode, PickerTarget,
    TextEditor, TextFormat, DATE_FIELDS, EDIT_BYTES_PER_LINE, EDIT_DIGITS_PER_LINE, EDIT_MENU,
    PICKER_CLASSES, PICKER_UNIVERSAL,
};
use crate::dump;
use crate::ber::{
    self, Class, Node, TAG_BIT_STRING, TAG_BOOLEAN, TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_NULL,
    TAG_OID, TAG_UTC_TIME,
};
use crate::verify::{FileRelations, SignatureStatus};

/// Bytes of hex shown in the browse-mode content pane before truncating.
const CONTENT_HEX_LIMIT: usize = 4096;

/// Colors of the file-browser cryptographic relation arrows.
const REL_SIGNER: Color = Color::Cyan; // incoming: a file that signed the selection
const REL_SIGNS: Color = Color::Magenta; // outgoing: a file the selection signed
const REL_BROKEN: Color = Color::Red; // claimed issuance whose signature fails to verify

pub fn run(mut app: App) -> io::Result<()> {
    let mut terminal = ratatui::init();
    // Bracketed paste lets clipboard content reach the value editors.
    let _ = execute!(std::io::stdout(), EnableBracketedPaste);
    let result = event_loop(&mut terminal, &mut app);
    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let key = match event::read()? {
            Event::Key(key) => key,
            Event::Paste(text) => {
                match app.mode {
                    Mode::Edit(ref mut edit) => edit.editor.paste(&text),
                    Mode::Password(ref mut p) => p.paste(&text),
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
        KeyCode::Char('e') => app.start_edit_type_specific(),
        KeyCode::Char('E') => app.open_edit_menu(),
        KeyCode::Char('i') => app.start_insert(false),
        KeyCode::Char('I') => app.start_insert(true),
        KeyCode::Char('d') => app.delete_selected(),
        KeyCode::Char('K') => app.move_selected(-1),
        KeyCode::Char('J') => app.move_selected(1),
        KeyCode::Char('s') => app.save(),
        KeyCode::Char('z') => app.start_decrypt(),
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
        KeyCode::Char(c @ '1'..='5') => {
            if let Mode::EditMenu(ref mut m) = app.mode {
                m.selected = (c as usize) - ('1' as usize);
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
    let [browser, tree, content] = Layout::horizontal([
        Constraint::Percentage(20),
        Constraint::Percentage(34),
        Constraint::Percentage(46),
    ])
    .areas(main);
    draw_browser(frame, app, browser);
    draw_tree(frame, app, tree);
    draw_content(frame, app, content);
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
///   targets share one vertical trunk, branching with `┤` junctions.
struct ArrowGutters {
    left: Vec<Option<(String, Color)>>,
    right: Vec<Option<(String, Color)>>,
}

/// Route the relation arrows for the current selection. `row_paths` holds
/// the file path of every *visible* browser row; edges whose other end is
/// not visible (inside a collapsed directory) are skipped — there is no
/// row to draw them to.
fn arrow_gutters(row_paths: &[&std::path::Path], selected: usize, rel: &FileRelations) -> ArrowGutters {
    let n = row_paths.len();
    let mut g = ArrowGutters { left: vec![None; n], right: vec![None; n] };
    if selected >= n {
        return g;
    }

    // Incoming edge, left gutter (trunk in the leftmost column):
    //   ╭──  signer            ╭─►  selected
    //   │                  or  │
    //   ╰─►  selected          ╰──  signer
    if let Some(edge) = &rel.signed_by {
        if let Some(src) = row_paths.iter().position(|p| *p == edge.other) {
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
    let targets: Vec<(usize, bool)> = rel
        .signs
        .iter()
        .filter_map(|e| {
            row_paths
                .iter()
                .position(|p| *p == e.other)
                .filter(|i| *i != selected)
                .map(|i| (i, e.verified))
        })
        .collect();
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

fn draw_browser(frame: &mut Frame, app: &mut App, area: Rect) {
    let active = app.focus == Focus::Browser;
    let open_path = app.file_open.then_some(app.path.as_path());

    // Row texts and styles first, so the right-hand arrow trunk can be
    // aligned one column past the longest visible name. `marker_style`,
    // when set, recolors just the single open-marker glyph at
    // `marker_offset` (see `styled_with_marker`).
    let texts: Vec<(String, Style, usize, Option<Style>)> = app
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
            let mut style = if entry.is_dir {
                Style::new().fg(Color::Green).bold()
            } else {
                Style::new()
            };
            if is_open {
                style = style.fg(Color::LightGreen).bold();
            }
            let prefix = if dirty_open {
                format!("{} ", DIRTY_GLYPH)
            } else if is_open {
                "• ".to_string()
            } else {
                "  ".to_string()
            };
            let text =
                format!("{}{}{}{}", "  ".repeat(row.depth), fold_marker, prefix, entry.name);
            let marker_offset = row.depth * 2 + fold_marker.chars().count();
            let marker_style = dirty_open.then(|| Style::new().fg(DIRTY_MARKER).bold());
            (text, style, marker_offset, marker_style)
        })
        .collect();
    let name_width = texts.iter().map(|(t, ..)| t.chars().count()).max().unwrap_or(0);

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
    let has_left = gutters.left.iter().any(|c| c.is_some());
    let has_right = gutters.right.iter().any(|c| c.is_some());

    // Column the right-hand arrows start in: one past the longest name,
    // but never past the pane edge — long names are truncated with '…' so
    // the vertical trunk stays visible inside the pane.
    let left_w = if has_left { ARROW_GUTTER_W } else { 0 };
    let inner_w = area.width.saturating_sub(2) as usize; // pane borders
    let name_col_w = name_width
        .min(inner_w.saturating_sub(left_w + ARROW_GUTTER_W))
        .max(1);

    let items: Vec<ListItem> = texts
        .into_iter()
        .enumerate()
        .map(|(i, (text, style, marker_offset, marker_style))| {
            let mut spans = Vec::new();
            if has_left {
                spans.push(match &gutters.left[i] {
                    Some((cell, color)) => {
                        Span::styled(cell.clone(), Style::new().fg(*color).bold())
                    }
                    None => Span::raw(" ".repeat(ARROW_GUTTER_W)),
                });
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
    let legend = Line::from(vec![
        Span::styled(format!(" {} unsaved ", DIRTY_GLYPH), Style::new().fg(DIRTY_MARKER)),
        Span::styled("─► signer ", Style::new().fg(REL_SIGNER)),
        Span::styled("─► signs ", Style::new().fg(REL_SIGNS)),
        Span::styled("─► bad ", Style::new().fg(REL_BROKEN)),
    ]);
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
                    arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".")
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

fn draw_tree(frame: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .rows
        .iter()
        .map(|row| {
            let node = app.node_at(&row.path).expect("row paths are valid");
            let marker = if node.has_children() {
                if node.expanded { "▾ " } else { "▸ " }
            } else {
                "  "
            };
            let mut spans =
                vec![Span::raw(format!("{}{}", "  ".repeat(row.depth), marker))];
            let label = app.label_at(&row.path);
            if let Some(field) = label.and_then(|l| l.field.as_deref()) {
                spans.push(Span::styled(
                    format!("{}: ", field),
                    Style::new().fg(Color::LightCyan).italic(),
                ));
            }
            spans.push(Span::styled(node.type_name(), class_style(node)));
            spans.push(Span::styled(summary(node), Style::new().dim()));
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

fn hex_dump_lines(bytes: &[u8]) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let shown = bytes.len().min(CONTENT_HEX_LIMIT);
    for (i, chunk) in bytes[..shown].chunks(16).enumerate() {
        let hex = chunk
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..=0x7E).contains(&b) { b as char } else { '.' })
            .collect();
        lines.push(Line::from(vec![
            Span::styled(format!("{:08X}  ", i * 16), Style::new().dim()),
            Span::raw(format!("{:<47}  ", hex)),
            Span::styled(format!("|{}|", ascii), Style::new().dim()),
        ]));
    }
    if shown < bytes.len() {
        lines.push(Line::from(Span::styled(
            format!("… {} more bytes not shown …", bytes.len() - shown),
            Style::new().dim().italic(),
        )));
    }
    lines
}

/// Render decrypted plaintext as a dumpasn1-style tree (it is a
/// `PrivateKeyInfo`); fall back to a hex dump if it somehow doesn't parse.
fn decrypted_lines(plaintext: &[u8]) -> Vec<Line<'static>> {
    match ber::parse_forest(plaintext, 0) {
        Ok(roots) => dump::dump(&roots, plaintext.len())
            .lines()
            .map(|l| Line::from(Span::styled(l.to_string(), Style::new().fg(Color::LightGreen))))
            .collect(),
        Err(_) => hex_dump_lines(plaintext),
    }
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

fn draw_content_browse(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    if let Some(node) = app.selected_node() {
        lines.push(Line::from(vec![
            Span::styled("Type    ", Style::new().dim()),
            Span::styled(node.type_name(), class_style(node)),
        ]));
        if let Some(row) = app.rows.get(app.selected) {
            if let Some(label) = app.label_at(&row.path) {
                let ident = app.ident.as_ref().expect("label implies identification");
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
        // Decrypted private key, shown for the encryptedData node once a
        // password has been supplied — between the header and the raw hex.
        if let Some(dec) = &app.decrypted {
            if app.rows.get(app.selected).map(|r| r.path.as_slice()) == Some(dec.encrypted_path.as_slice()) {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    format!("Decrypted content ({} bytes):", dec.plaintext.len()),
                    Style::new().fg(Color::Green).underlined(),
                )));
                lines.extend(decrypted_lines(&dec.plaintext));
            }
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
        lines.extend(hex_dump_lines(&content));
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

/// Centered popup listing the edit modes ('E').
fn draw_edit_menu(frame: &mut Frame, app: &App, area: Rect) {
    let Mode::EditMenu(ref m) = app.mode else { return };
    let width = 66.min(area.width);
    let height = (EDIT_MENU.len() as u16 + 3).min(area.height);
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
        .title(" EDIT — choose editing mode ");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let mut lines: Vec<Line> = Vec::new();
    for (i, (name, desc)) in EDIT_MENU.iter().enumerate() {
        let style = if i == m.selected {
            Style::new().add_modifier(Modifier::REVERSED).bold()
        } else {
            Style::new().bold()
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {} {:<14}", i + 1, name), style),
            Span::styled(format!(" {}", desc), Style::new().dim()),
        ]));
    }
    lines.push(Line::from(Span::styled(
        " ↑↓/1-5 select   ⏎ choose   Esc cancel",
        Style::new().dim(),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let dirty = if app.dirty { " [modified]" } else { "" };
    let hints = match app.mode {
        Mode::Browse if app.focus == Focus::Browser => {
            "q quit  Tab switch pane  ↑↓ move+preview  ←→ fold  ⏎ switch to file/fold  z decrypt"
        }
        Mode::Browse => {
            "q quit  Tab switch pane  ↑↓ move  ←→ fold  ⏎ toggle  e edit  E edit-menu  i/I insert  d delete  J/K reorder  s save  z decrypt  [ ] scroll"
        }
        Mode::TypePicker(_) => "←→ column  ↑↓ select  0-9 tag number  ⏎ continue  Esc cancel",
        Mode::EditMenu(_) => "↑↓ or 1-5 select  ⏎ choose  Esc cancel",
        Mode::Edit(_) => "Enter apply  Esc cancel",
        Mode::Password(_) => "type password  ⏎ decrypt  Esc cancel",
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
        let rel = FileRelations { signed_by: Some(edge("c", true)), signs: vec![] };
        let g = arrow_gutters(&rows, 0, &rel);
        // Elbow with two corners: out of "c", up the trunk, into "a".
        assert_eq!(cells(&g.left), [Some("╭─► "), Some("│   "), Some("╰── ")]);
        assert!(g.left.iter().flatten().all(|(_, c)| *c == REL_SIGNER));
        assert!(g.right.iter().all(|c| c.is_none()));
    }

    #[test]
    fn incoming_arrow_from_signer_above_points_down_into_selection() {
        let rows = [Path::new("a"), Path::new("b"), Path::new("c")];
        let rel = FileRelations { signed_by: Some(edge("a", false)), signs: vec![] };
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
        let rel = FileRelations { signed_by: None, signs: vec![edge("b", false)] };
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
        };
        let g = arrow_gutters(&rows, 0, &rel);
        assert!(g.left.iter().all(|c| c.is_none()));
        assert!(g.right.iter().all(|c| c.is_none()));
    }

    #[test]
    fn tree_summary_shows_large_integers_in_decimal() {
        // 17-byte INTEGER (2^128): beyond i128, previously fell back to hex.
        let mut data = vec![0x02, 0x11, 0x01];
        data.extend([0x00; 16]);
        let forest = parse_forest(&data, 0).unwrap();
        assert_eq!(summary(&forest[0]), " 340282366920938463463374607431768211456");
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
}
