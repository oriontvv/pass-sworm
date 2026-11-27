//! Rendering for every screen and overlay.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table};

use crate::tui::app::{App, Editor, HistoryOverlay, Overlay, Screen};
use crate::tui::input::Input;
use pass_sworm::timefmt::format_utc;

pub fn draw(app: &mut App, frame: &mut Frame) {
    if matches!(&app.screen, Screen::Unlock(_)) {
        draw_unlock(app, frame);
    } else {
        draw_vault(app, frame);
    }
    if app.overlay.is_some() {
        draw_overlay(app, frame);
    }
}

fn field_line(label: &str, input: &Input, mask: bool, focused: bool) -> Line<'static> {
    let mut spans = vec![Span::styled(
        format!("{label:>9}: "),
        Style::default().fg(Color::DarkGray),
    )];
    spans.extend(input.line(mask, focused).spans);
    Line::from(spans)
}

// ----- unlock -------------------------------------------------------------

fn draw_unlock(app: &App, frame: &mut Frame) {
    let Screen::Unlock(u) = &app.screen else {
        return;
    };
    let height = if u.create { 11 } else { 9 };
    let area = centered_rect(56, height, frame.area());

    let title = if u.create {
        " pass-sworm · new vault "
    } else {
        " pass-sworm · unlock "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_alignment(Alignment::Center);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = vec![Line::from("")];
    let password_focused = !u.create || !u.focus_confirm;
    lines.push(field_line("Password", &u.password, true, password_focused));
    if u.create {
        lines.push(field_line("Confirm", &u.confirm, true, u.focus_confirm));
    }

    if u.busy {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "deriving key (argon2id)…",
            Style::default().fg(Color::Yellow),
        )));
    } else if let Some(error) = &u.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(Color::Red),
        )));
    } else {
        lines.push(Line::from(""));
        let hint = if u.create {
            "Enter create · Tab switch field · Esc quit"
        } else {
            "Enter unlock · Esc quit"
        };
        lines.push(Line::from(Span::styled(
            hint,
            Style::default().fg(Color::DarkGray),
        )));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

// ----- vault --------------------------------------------------------------

fn draw_vault(app: &mut App, frame: &mut Frame) {
    let rows = app.rows();
    let [header, main, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .areas(frame.area());

    draw_header(app, frame, header, rows.len());
    let [list, details] =
        Layout::horizontal([Constraint::Percentage(38), Constraint::Percentage(62)]).areas(main);
    draw_list(app, frame, list, &rows);
    draw_details(app, frame, details);
    draw_footer(app, frame, footer);
}

fn draw_header(app: &App, frame: &mut Frame, area: Rect, count: usize) {
    let name = app
        .store
        .path()
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".into());
    let line = Line::from(vec![
        Span::styled(
            " pass-sworm ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  {name}  ")),
        Span::styled(
            format!("{count} entries"),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_list(app: &mut App, frame: &mut Frame, area: Rect, rows: &[(uuid::Uuid, String, String)]) {
    let title = if app.filter_editing {
        format!(" filter: {}_ ", app.filter.value)
    } else if !app.filter.value.is_empty() {
        format!(" filter: {} ", app.filter.value)
    } else {
        " entries ".to_string()
    };

    let items: Vec<Row> = rows
        .iter()
        .map(|(_, name, username)| {
            Row::new(vec![Cell::from(name.clone()), Cell::from(username.clone())])
        })
        .collect();

    let table = Table::new(
        items,
        [Constraint::Percentage(60), Constraint::Percentage(40)],
    )
    .block(Block::default().borders(Borders::ALL).title(title))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol("> ");

    let index = app.selected_index(rows);
    app.table_state.select(index);
    frame.render_stateful_widget(table, area, &mut app.table_state);
}

fn draw_details(app: &App, frame: &mut Frame, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" details ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(u) = &app.unlocked else {
        return;
    };
    let Some(entry) = app.selected.and_then(|id| u.vault.get(id)) else {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "no entry selected — press a to add one",
                Style::default().fg(Color::DarkGray),
            )),
            inner,
        );
        return;
    };

    let mut lines = vec![
        Line::from(Span::styled(
            entry.name.value.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Username  ", Style::default().fg(Color::DarkGray)),
            Span::raw(entry.username.value.clone()),
        ]),
        Line::from(vec![
            Span::styled("Password  ", Style::default().fg(Color::DarkGray)),
            Span::raw("•".repeat(entry.password.value.chars().count().max(8))),
        ]),
    ];

    if let Some(url) = &entry.url.value {
        lines.push(Line::from(vec![
            Span::styled("URL       ", Style::default().fg(Color::DarkGray)),
            Span::raw(url.clone()),
        ]));
    }
    if !entry.tags.value.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Tags      ", Style::default().fg(Color::DarkGray)),
            Span::raw(entry.tags.value.join(", ")),
        ]));
    }
    if let Some(notes) = &entry.notes.value {
        lines.push(Line::from(vec![
            Span::styled("Notes     ", Style::default().fg(Color::DarkGray)),
            Span::raw(notes.clone()),
        ]));
    }
    if !entry.history.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("history: {} previous version(s)", entry.history.len()),
            Style::default().fg(Color::DarkGray),
        )));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_footer(app: &App, frame: &mut Frame, area: Rect) {
    let [hints_area, status_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);

    let hints = if app.filter_editing {
        "type to filter · Enter/Esc finish"
    } else {
        "y copy · e edit · c clone · d delete · a add · / filter · h history · Ctrl-L lock · ? help · q quit"
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            format!(" {hints}"),
            Style::default().fg(Color::DarkGray),
        )),
        hints_area,
    );

    let mut status = format!(" {}", app.status);
    if let Some(left) = app.clipboard_seconds_left() {
        status.push_str(&format!("   ·   clipboard wipes in {left}s"));
    }
    frame.render_widget(
        Paragraph::new(Span::styled(status, Style::default().fg(Color::Yellow))),
        status_area,
    );
}

// ----- overlays -----------------------------------------------------------

fn draw_overlay(app: &App, frame: &mut Frame) {
    match app.overlay.as_ref() {
        Some(Overlay::Editor(editor)) => draw_editor(app, frame, editor),
        Some(Overlay::ConfirmDelete { name, .. }) => draw_confirm(
            frame,
            &format!("delete \"{name}\"?"),
            "y/Enter delete · n/Esc cancel",
        ),
        Some(Overlay::History(history)) => draw_history(app, frame, history),
        Some(Overlay::Help) => draw_help(frame),
        None => {}
    }
}

fn draw_editor(app: &App, frame: &mut Frame, editor: &Editor) {
    let _ = app;
    let height = editor.fields.len() as u16 + 4;
    let area = centered_rect(70, height, frame.area());
    frame.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(if editor.id.is_some() {
            " edit entry "
        } else {
            " new entry "
        });
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();
    for (index, field) in editor.fields.iter().enumerate() {
        let focused = index == editor.focus;
        let mask = field.secret && !editor.reveal;
        lines.push(field_line(field.label, &field.input, mask, focused));
    }
    if let Some(error) = &editor.error {
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(Color::Red),
        )));
    }
    lines.push(Line::from(Span::styled(
        "Tab next · Ctrl-G generate · Ctrl-R reveal · Enter save · Esc cancel",
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_history(app: &App, frame: &mut Frame, history: &HistoryOverlay) {
    let area = centered_rect(72, 16, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default().borders(Borders::ALL).title(" history ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();
    if let Some(entry) = app.unlocked.as_ref().and_then(|u| u.vault.get(history.id)) {
        for (index, snapshot) in entry.history.iter().enumerate() {
            let marker = if index == history.index { ">" } else { " " };
            let text = format!(
                "{marker} {}  {:<24}  {:<20}  {}",
                format_utc(snapshot.at.wall_ms),
                truncate(&snapshot.name, 24),
                truncate(&snapshot.username, 20),
                "•".repeat(snapshot.password.chars().count().max(4))
            );
            let style = if index == history.index {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            lines.push(Line::from(Span::styled(text, style)));
        }
    }
    if lines.is_empty() {
        lines.push(Line::from("no previous versions"));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "j/k select · Enter restore · Esc close",
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn draw_confirm(frame: &mut Frame, question: &str, hint: &str) {
    let area = centered_rect(52, 7, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default().borders(Borders::ALL).title(" confirm ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            question.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            hint.to_string(),
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), inner);
}

fn draw_help(frame: &mut Frame) {
    let area = centered_rect(56, 16, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default().borders(Borders::ALL).title(" keys ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = [
        ("j / k, ↑ / ↓", "move selection"),
        ("g / G", "first / last entry"),
        ("/", "fuzzy filter"),
        ("a", "add entry"),
        ("e, Enter", "edit entry"),
        ("c", "clone entry"),
        ("d", "delete entry"),
        ("h", "view / restore history"),
        ("y", "copy password to clipboard"),
        ("Ctrl-G", "generate password (in editor)"),
        ("Ctrl-L", "lock the vault"),
        ("?", "toggle this help"),
        ("q, Ctrl-C", "quit"),
    ];
    let lines: Vec<Line> = rows
        .iter()
        .map(|(key, action)| {
            Line::from(vec![
                Span::styled(format!("{key:>14}  "), Style::default().fg(Color::Cyan)),
                Span::raw(*action),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let [_, middle, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(height.min(area.height)),
        Constraint::Fill(1),
    ])
    .areas(area);
    let [_, middle, _] = Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .areas(middle);
    middle
}
