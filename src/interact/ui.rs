use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Terminal,
};
use rusqlite::Connection;
use std::io;

use crate::interact::app::{parse_command, Command};
use crate::interact::db::{find_by_status, list_all_results, ScanResultRow};
use crate::interact::replay::replay_request;

pub struct TuiApp {
    rows: Vec<ScanResultRow>,
    filtered_rows: Vec<ScanResultRow>,
    state: TableState,
    search: String,
    search_mode: bool,
    status_bar: String,
    command_input: String,
    command_mode: bool,
    detail_view: Option<ScanResultRow>,
}

impl TuiApp {
    pub fn new(rows: Vec<ScanResultRow>) -> Self {
        let filtered_rows = rows.clone();
        let mut state = TableState::default();
        if !filtered_rows.is_empty() {
            state.select(Some(0));
        }
        Self {
            rows,
            filtered_rows,
            state,
            search: String::new(),
            search_mode: false,
            status_bar: String::from("Press ? for help | q to quit | / to search | r to replay"),
            command_input: String::new(),
            command_mode: false,
            detail_view: None,
        }
    }

    fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.filtered_rows.len().saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.filtered_rows.len().saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn selected_row(&self) -> Option<&ScanResultRow> {
        self.state.selected().and_then(|i| self.filtered_rows.get(i))
    }

    fn apply_search(&mut self) {
        if self.search.is_empty() {
            self.filtered_rows = self.rows.clone();
        } else {
            let q = self.search.to_lowercase();
            self.filtered_rows = self.rows
                .iter()
                .filter(|r| r.url.to_lowercase().contains(&q) || r.method.to_lowercase().contains(&q))
                .cloned()
                .collect();
        }
        self.state.select(if self.filtered_rows.is_empty() { None } else { Some(0) });
    }
}

pub async fn run_tui(db_path: &str) -> Result<()> {
    let conn = Connection::open(db_path)?;
    let rows = list_all_results(&conn).unwrap_or_default();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(rows);
    let mut replay_output: Option<String> = None;

    loop {
        terminal.draw(|f| {
            let size = f.area();

            if let Some(ref detail) = app.detail_view {
                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(format!("Detail: [{}] {} {}", detail.id, detail.method, detail.url));
                let text = format!(
                    "ID: {}\nURL: {}\nMethod: {}\nStatus: {}\nPort: {}\nHeaders:\n{}\nBody snippet:\n{}",
                    detail.id,
                    detail.url,
                    detail.method,
                    detail.status,
                    detail.port,
                    detail.headers.as_deref().unwrap_or(""),
                    detail.response_body.as_deref().map(|b| &b[..b.len().min(500)]).unwrap_or(""),
                );
                let para = Paragraph::new(text).block(block);
                f.render_widget(para, size);
                return;
            }

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(5),
                    Constraint::Length(3),
                    Constraint::Length(3),
                ])
                .split(size);

            let header_cells = ["ID", "URL", "Method", "Status", "Port"]
                .iter()
                .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
            let header = Row::new(header_cells).height(1);

            let rows_widget: Vec<Row> = app.filtered_rows.iter().map(|r| {
                let url_truncated: String = r.url.chars().take(60).collect();
                Row::new(vec![
                    Cell::from(r.id.to_string()),
                    Cell::from(url_truncated),
                    Cell::from(r.method.clone()),
                    Cell::from(r.status.to_string()),
                    Cell::from(r.port.to_string()),
                ])
            }).collect();

            let table = Table::new(rows_widget, [
                Constraint::Length(6),
                Constraint::Min(40),
                Constraint::Length(8),
                Constraint::Length(7),
                Constraint::Length(6),
            ])
            .header(header)
            .block(Block::default().borders(Borders::ALL).title(format!(
                "Scan Results ({} shown / {} total)",
                app.filtered_rows.len(),
                app.rows.len()
            )))
            .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD));

            f.render_stateful_widget(table, chunks[0], &mut app.state);

            let status_para = Paragraph::new(app.status_bar.clone())
                .block(Block::default().borders(Borders::ALL).title("Status"));
            f.render_widget(status_para, chunks[1]);

            let input_text = if app.search_mode {
                format!("Search: {}", app.search)
            } else if app.command_mode {
                format!("Command: {}", app.command_input)
            } else if let Some(ref out) = replay_output {
                format!("Replay: {}", out)
            } else {
                String::from("Ready")
            };
            let input_para = Paragraph::new(input_text)
                .block(Block::default().borders(Borders::ALL).title("Input"));
            f.render_widget(input_para, chunks[2]);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // Escape always cancels special modes or detail view
                if key.code == KeyCode::Esc {
                    if app.detail_view.is_some() {
                        app.detail_view = None;
                    } else if app.search_mode {
                        app.search_mode = false;
                    } else if app.command_mode {
                        app.command_mode = false;
                        app.command_input.clear();
                    }
                    replay_output = None;
                    continue;
                }

                // Search mode
                if app.search_mode {
                    match key.code {
                        KeyCode::Enter => {
                            app.search_mode = false;
                            app.apply_search();
                            app.status_bar = format!("Showing {} results for '{}'", app.filtered_rows.len(), app.search);
                        }
                        KeyCode::Backspace => {
                            app.search.pop();
                        }
                        KeyCode::Char(c) => {
                            app.search.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                // Command mode (for : commands)
                if app.command_mode {
                    match key.code {
                        KeyCode::Enter => {
                            let cmd_str = format!(":{}", app.command_input.clone());
                            app.command_mode = false;
                            app.command_input.clear();
                            let cmd = parse_command(&cmd_str);
                            match cmd {
                                Command::Open(id) => {
                                    // Find and show detail
                                    if let Some(row) = app.rows.iter().find(|r| r.id == id) {
                                        app.detail_view = Some(row.clone());
                                    } else {
                                        app.status_bar = format!("ID {} not found", id);
                                    }
                                }
                                Command::Replay(id) => {
                                    if let Some(row) = app.rows.iter().find(|r| r.id == id) {
                                        let url = row.url.clone();
                                        let method = row.method.clone();
                                        let headers = row.request_headers.clone().unwrap_or_default();
                                        let result = replay_request(&url, &method, &headers).await;
                                        replay_output = Some(result.unwrap_or_else(|e| e.to_string()));
                                        app.status_bar = String::from("Replay complete. Press Esc to clear.");
                                    } else {
                                        app.status_bar = format!("ID {} not found", id);
                                    }
                                }
                                Command::FilterStatus(code) => {
                                    app.filtered_rows = find_by_status(&conn, code).unwrap_or_default();
                                    app.state.select(if app.filtered_rows.is_empty() { None } else { Some(0) });
                                    app.status_bar = format!("Filtered to status {}: {} results", code, app.filtered_rows.len());
                                }
                                Command::Quit => break,
                                Command::Help => {
                                    app.status_bar = String::from("Keys: ↑↓ navigate | Enter detail | r replay | / search | :open <id> | :replay <id> | :filter status <code> | q quit");
                                }
                                _ => {
                                    app.status_bar = format!("Unknown command");
                                }
                            }
                        }
                        KeyCode::Backspace => {
                            app.command_input.pop();
                        }
                        KeyCode::Char(c) => {
                            app.command_input.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                // Normal mode key handling
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('?') => {
                        app.status_bar = String::from("Keys: ↑↓ navigate | Enter detail | r replay | / search | : command | q quit");
                    }
                    KeyCode::Char('/') => {
                        app.search_mode = true;
                        app.search.clear();
                    }
                    KeyCode::Char(':') => {
                        app.command_mode = true;
                        app.command_input.clear();
                    }
                    KeyCode::Char('r') => {
                        if let Some(row) = app.selected_row() {
                            let url = row.url.clone();
                            let method = row.method.clone();
                            let headers = row.request_headers.clone().unwrap_or_default();
                            let result = replay_request(&url, &method, &headers).await;
                            replay_output = Some(result.unwrap_or_else(|e| e.to_string()));
                            app.status_bar = String::from("Replay complete. Press Esc to clear.");
                        }
                    }
                    KeyCode::Down => app.next(),
                    KeyCode::Up => app.previous(),
                    KeyCode::Enter => {
                        if let Some(row) = app.selected_row() {
                            app.detail_view = Some(row.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
