//! ratatui front end: tree pane on the left, content/hex pane on the right,
//! status bar at the bottom.

use std::io;
use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use crate::app::{App, Mode, EDIT_BYTES_PER_LINE, EDIT_DIGITS_PER_LINE};
use crate::ber::{
    self, Class, Node, TAG_BIT_STRING, TAG_BOOLEAN, TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_NULL,
    TAG_OID, TAG_UTC_TIME,
};

/// Bytes of hex shown in the browse-mode content pane before truncating.
const CONTENT_HEX_LIMIT: usize = 4096;

pub fn run(mut app: App) -> io::Result<()> {
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else { continue };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        let editing = matches!(app.mode, Mode::Edit(_));
        if editing {
            handle_edit_key(app, key);
        } else if handle_browse_key(app, key) {
            return Ok(());
        }
    }
}

/// Returns true when the application should quit.
fn handle_browse_key(app: &mut App, key: KeyEvent) -> bool {
    if key.code != KeyCode::Char('q') {
        app.quit_confirm = false;
    }
    match key.code {
        KeyCode::Char('q') => {
            if !app.dirty || app.quit_confirm {
                return true;
            }
            app.quit_confirm = true;
            app.status = "unsaved changes — press q again to quit anyway".to_string();
        }
        KeyCode::Up | KeyCode::Char('k') => app.move_by(-1),
        KeyCode::Down | KeyCode::Char('j') => app.move_by(1),
        KeyCode::PageUp => app.move_by(-15),
        KeyCode::PageDown => app.move_by(15),
        KeyCode::Home | KeyCode::Char('g') => app.select(0),
        KeyCode::End | KeyCode::Char('G') => app.select(usize::MAX),
        KeyCode::Left | KeyCode::Char('h') => app.collapse_or_parent(),
        KeyCode::Right | KeyCode::Char('l') => app.expand_or_child(),
        KeyCode::Enter | KeyCode::Char(' ') => app.toggle_expand(),
        KeyCode::Char('e') => app.start_edit(),
        KeyCode::Char('s') => app.save(),
        KeyCode::Char('[') => app.content_scroll = app.content_scroll.saturating_sub(4),
        KeyCode::Char(']') => app.content_scroll = app.content_scroll.saturating_add(4),
        _ => {}
    }
    false
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
        KeyCode::Char(c) if c.is_ascii_hexdigit() => {
            edit.digits.insert(edit.cursor, c.to_ascii_uppercase());
            edit.cursor += 1;
        }
        KeyCode::Backspace => {
            if edit.cursor > 0 {
                edit.cursor -= 1;
                edit.digits.remove(edit.cursor);
            }
        }
        KeyCode::Delete => {
            if edit.cursor < edit.digits.len() {
                edit.digits.remove(edit.cursor);
            }
        }
        KeyCode::Left => edit.cursor = edit.cursor.saturating_sub(1),
        KeyCode::Right => edit.cursor = (edit.cursor + 1).min(edit.digits.len()),
        KeyCode::Up => edit.cursor = edit.cursor.saturating_sub(EDIT_DIGITS_PER_LINE),
        KeyCode::Down => edit.cursor = (edit.cursor + EDIT_DIGITS_PER_LINE).min(edit.digits.len()),
        KeyCode::Home => edit.cursor = 0,
        KeyCode::End => edit.cursor = edit.digits.len(),
        _ => {}
    }
}

fn draw(frame: &mut Frame, app: &mut App) {
    let [main, status] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).areas(main);
    draw_tree(frame, app, left);
    draw_content(frame, app, right);
    draw_status(frame, app, status);
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
            TAG_INTEGER => ber::decode_integer(v)
                .map(|i| i.to_string())
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
            let line = Line::from(vec![
                Span::raw(format!("{}{}", "  ".repeat(row.depth), marker)),
                Span::styled(node.type_name(), class_style(node)),
                Span::styled(summary(node), Style::new().dim()),
            ]);
            ListItem::new(line)
        })
        .collect();
    let title = format!(" Structure — {} ", app.path.display());
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
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

fn draw_content(frame: &mut Frame, app: &mut App, area: Rect) {
    match &app.mode {
        Mode::Browse => draw_content_browse(frame, app, area),
        Mode::Edit(_) => draw_content_edit(frame, app, area),
    }
}

fn draw_content_browse(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    if let Some(node) = app.selected_node() {
        let class = match node.class {
            Class::Universal => "universal",
            Class::Application => "application",
            Class::ContextSpecific => "context-specific",
            Class::Private => "private",
        };
        lines.push(Line::from(vec![
            Span::styled("Type    ", Style::new().dim()),
            Span::styled(node.type_name(), class_style(node)),
            Span::raw(format!(
                "   class: {}, tag: {}, {}",
                class,
                node.tag,
                if node.constructed { "constructed" } else { "primitive" }
            )),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Offset  ", Style::new().dim()),
            Span::raw(format!(
                "{}   header: {} bytes   content: {} bytes{}",
                node.offset,
                node.header_len,
                node.content_len,
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
        lines.push(Line::default());
        let content = node.content_octets();
        lines.push(Line::from(Span::styled(
            format!("Content octets ({} bytes) — 'e' to edit as hex:", content.len()),
            Style::new().underlined(),
        )));
        lines.extend(hex_dump_lines(&content));
    } else {
        lines.push(Line::from("no element selected"));
    }
    let para = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Content "))
        .scroll((app.content_scroll, 0));
    frame.render_widget(para, area);
}

fn draw_content_edit(frame: &mut Frame, app: &mut App, area: Rect) {
    let Mode::Edit(ref mut edit) = app.mode else { return };
    let inner_height = area.height.saturating_sub(2) as usize; // borders
    let text_rows = inner_height.saturating_sub(2); // header + hint line

    let cursor_row = edit.cursor / EDIT_DIGITS_PER_LINE;
    if cursor_row < edit.scroll {
        edit.scroll = cursor_row;
    } else if text_rows > 0 && cursor_row >= edit.scroll + text_rows {
        edit.scroll = cursor_row + 1 - text_rows;
    }

    let byte_count = edit.digits.len() / 2;
    let odd = edit.digits.len() % 2 != 0;
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(
            format!("{} byte{}", byte_count, if byte_count == 1 { "" } else { "s" }),
            if odd { Style::new().fg(Color::Red) } else { Style::new().fg(Color::Green) },
        ),
        Span::styled(
            if odd { " + 1 dangling digit" } else { "" },
            Style::new().fg(Color::Red),
        ),
    ]));

    let total_rows = edit.digits.len() / EDIT_DIGITS_PER_LINE + 1;
    for row in edit.scroll..total_rows.min(edit.scroll + text_rows.max(1)) {
        let start = row * EDIT_DIGITS_PER_LINE;
        let end = (start + EDIT_DIGITS_PER_LINE).min(edit.digits.len());
        let mut spans: Vec<Span> = vec![Span::styled(
            format!("{:08X}  ", row * EDIT_BYTES_PER_LINE),
            Style::new().dim(),
        )];
        for i in start..=end {
            if i < end {
                let style = if i == edit.cursor {
                    Style::new().add_modifier(Modifier::REVERSED)
                } else {
                    Style::new()
                };
                spans.push(Span::styled(edit.digits[i].to_string(), style));
                if i % 2 == 1 && i + 1 < end {
                    spans.push(Span::raw(" "));
                }
            } else if i == edit.cursor && i == edit.digits.len() {
                // Cursor sitting after the last digit.
                spans.push(Span::styled(" ", Style::new().add_modifier(Modifier::REVERSED)));
            }
        }
        lines.push(Line::from(spans));
    }

    lines.push(Line::from(Span::styled(
        "[Enter] apply   [Esc] cancel   [←→↑↓] move   type hex digits to insert",
        Style::new().dim(),
    )));

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(Color::Yellow))
            .title(" EDIT — content octets (hex) "),
    );
    frame.render_widget(para, area);
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let dirty = if app.dirty { " [modified]" } else { "" };
    let hints = match app.mode {
        Mode::Browse => "q quit  ↑↓ move  ←→ fold  ⏎ toggle  e edit  s save  [ ] scroll",
        Mode::Edit(_) => "Enter apply  Esc cancel",
    };
    let line = Line::from(vec![
        Span::styled(dirty, Style::new().fg(Color::Red).bold()),
        Span::raw(format!(" {} ", app.status)),
        Span::styled(format!("| {}", hints), Style::new().dim()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}
