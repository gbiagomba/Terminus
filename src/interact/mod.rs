pub mod app;
pub mod db;
pub mod replay;
pub mod ui;

use anyhow::{Result, Context};
use rusqlite::{Connection, params};
use std::collections::HashSet;
use std::io::{self, Write};

struct PageState {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    index: usize,
}

#[allow(dead_code)]
pub fn run_interact(db_path: &str) -> Result<()> {
    run_interact_with_opts(db_path, false)
}

#[tokio::main]
pub async fn run_interact_tui(db_path: &str) -> Result<()> {
    ui::run_tui(db_path).await
}

pub fn run_interact_with_opts(db_path: &str, no_tui: bool) -> Result<()> {
    if !no_tui {
        return run_interact_tui(db_path);
    }

    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open SQLite database: {}", db_path))?;

    validate_terminus_db(&conn)?;

    println!("Terminus SQLite interactive mode. Type 'help' for commands.");
    let stdin = io::stdin();
    let mut last_page: Option<PageState> = None;

    loop {
        print!("terminus> ");
        io::stdout().flush()?;
        let mut input = String::new();
        if stdin.read_line(&mut input).is_err() {
            break;
        }
        let line = input.trim();

        if line.is_empty() {
            continue;
        }

        if line.eq_ignore_ascii_case("exit") {
            break;
        }

        if line.eq_ignore_ascii_case("help") {
            println!("Available commands:");
            println!("  help");
            println!("  list urls");
            println!("  list methods");
            println!("  find status <CODE>");
            println!("  find exploit <TYPE>");
            println!("  show scan <ID>");
            println!("  show raw <ID>");
            println!("  --more");
            println!("  exit");
            println!();
            println!("Exploit types:");
            println!("  http2_desync, host_injection, xff_bypass, csrf, ssrf, reflection, arbitrary_method");
            continue;
        }

        if line == "--more" {
            if let Some(state) = last_page.as_mut() {
                let has_more = print_next_page(state);
                if !has_more {
                    last_page = None;
                }
            } else {
                println!("No more results.");
            }
            continue;
        }

        if line.eq_ignore_ascii_case("list urls") {
            let mut stmt = conn.prepare("SELECT DISTINCT url FROM scan_results ORDER BY url")?;
            let rows_iter = stmt.query_map([], |row| Ok(vec![row.get::<_, String>(0)?]))?;
            let mut rows = Vec::new();
            for row in rows_iter {
                rows.push(row?);
            }
            last_page = Some(PageState { headers: vec!["url".to_string()], rows, index: 0 });
            if let Some(state) = last_page.as_mut() {
                let has_more = print_next_page(state);
                if !has_more {
                    last_page = None;
                }
            }
            continue;
        }

        if line.eq_ignore_ascii_case("list methods") {
            let mut stmt = conn.prepare("SELECT DISTINCT method FROM scan_results ORDER BY method")?;
            let rows_iter = stmt.query_map([], |row| Ok(vec![row.get::<_, String>(0)?]))?;
            let mut rows = Vec::new();
            for row in rows_iter {
                rows.push(row?);
            }
            last_page = Some(PageState { headers: vec!["method".to_string()], rows, index: 0 });
            if let Some(state) = last_page.as_mut() {
                let has_more = print_next_page(state);
                if !has_more {
                    last_page = None;
                }
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("find status ") {
            let code: u16 = match rest.trim().parse() {
                Ok(c) => c,
                Err(_) => {
                    println!("Invalid status code.");
                    continue;
                }
            };
            let mut stmt = conn.prepare(
                "SELECT id, url, method, status, port FROM scan_results WHERE status = ?1 ORDER BY id"
            )?;
            let rows_iter = stmt.query_map(params![code as i64], |row| {
                Ok(vec![
                    row.get::<_, i64>(0)?.to_string(),
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?.to_string(),
                    row.get::<_, i64>(4)?.to_string(),
                ])
            })?;
            let mut rows = Vec::new();
            for row in rows_iter {
                rows.push(row?);
            }
            last_page = Some(PageState {
                headers: vec!["id".to_string(), "url".to_string(), "method".to_string(), "status".to_string(), "port".to_string()],
                rows,
                index: 0
            });
            if let Some(state) = last_page.as_mut() {
                let has_more = print_next_page(state);
                if !has_more {
                    last_page = None;
                }
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("find exploit ") {
            let exploit = rest.trim().to_lowercase();
            let query = match exploit.as_str() {
                "http2_desync" => "SELECT id, url, method, status, port FROM scan_results WHERE http2_desync_detected = 1 ORDER BY id",
                "host_injection" => "SELECT id, url, method, status, port FROM scan_results WHERE host_injection_suspected = 1 ORDER BY id",
                "xff_bypass" => "SELECT id, url, method, status, port FROM scan_results WHERE xff_bypass_suspected = 1 ORDER BY id",
                "csrf" => "SELECT id, url, method, status, port FROM scan_results WHERE csrf_suspected = 1 ORDER BY id",
                "ssrf" => "SELECT id, url, method, status, port FROM scan_results WHERE ssrf_suspected = 1 ORDER BY id",
                "reflection" => "SELECT id, url, method, status, port FROM scan_results WHERE reflection_detected = 1 ORDER BY id",
                "arbitrary_method" => "SELECT id, url, method, status, port FROM scan_results WHERE arbitrary_method_used IS NOT NULL AND arbitrary_method_used <> '' ORDER BY id",
                _ => {
                    println!("Unknown exploit type: {}", exploit);
                    continue;
                }
            };

            let mut stmt = conn.prepare(query)?;
            let rows_iter = stmt.query_map([], |row| {
                Ok(vec![
                    row.get::<_, i64>(0)?.to_string(),
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?.to_string(),
                    row.get::<_, i64>(4)?.to_string(),
                ])
            })?;

            let mut rows = Vec::new();
            for row in rows_iter {
                rows.push(row?);
            }
            last_page = Some(PageState {
                headers: vec!["id".to_string(), "url".to_string(), "method".to_string(), "status".to_string(), "port".to_string()],
                rows,
                index: 0
            });
            if let Some(state) = last_page.as_mut() {
                let has_more = print_next_page(state);
                if !has_more {
                    last_page = None;
                }
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("show scan ") {
            let id: i64 = match rest.trim().parse() {
                Ok(v) => v,
                Err(_) => {
                    println!("Invalid scan ID.");
                    continue;
                }
            };

            let mut stmt = conn.prepare(
                "SELECT id, scan_timestamp, url, method, arbitrary_method_used, status, port, headers, error, body_preview,
                        matched_patterns, extracted_links, request_headers, response_body,
                        sec_headers_missing, sec_headers_present, sec_headers_issues, detected_errors,
                        reflection_detected,
                        http2_desync_detected, http2_http1_status, http2_http2_status, http2_status_mismatch, http2_response_diff, http2_issues,
                        host_injection_suspected, host_reflected_in_location, host_reflected_in_vary, host_reflected_in_set_cookie, host_injected_host, host_issues,
                        xff_bypass_suspected, xff_baseline_status, xff_xff_status, xff_status_changed, xff_response_diff, xff_issues,
                        csrf_suspected, csrf_accepts_without_origin, csrf_accepts_with_fake_origin, csrf_missing_samesite, csrf_missing_x_frame_options, csrf_missing_csp, csrf_issues,
                        ssrf_suspected, ssrf_vulnerable_params, ssrf_tested_payloads, ssrf_response_indicators, ssrf_issues, created_at
                 FROM scan_results WHERE id = ?1"
            )?;

            let row_result = stmt.query_row(params![id], |row| {
                let mut rows = Vec::new();
                let fields = [
                    "id","scan_timestamp","url","method","arbitrary_method_used","status","port","headers","error","body_preview",
                    "matched_patterns","extracted_links","request_headers","response_body",
                    "sec_headers_missing","sec_headers_present","sec_headers_issues","detected_errors",
                    "reflection_detected",
                    "http2_desync_detected","http2_http1_status","http2_http2_status","http2_status_mismatch","http2_response_diff","http2_issues",
                    "host_injection_suspected","host_reflected_in_location","host_reflected_in_vary","host_reflected_in_set_cookie","host_injected_host","host_issues",
                    "xff_bypass_suspected","xff_baseline_status","xff_xff_status","xff_status_changed","xff_response_diff","xff_issues",
                    "csrf_suspected","csrf_accepts_without_origin","csrf_accepts_with_fake_origin","csrf_missing_samesite","csrf_missing_x_frame_options","csrf_missing_csp","csrf_issues",
                    "ssrf_suspected","ssrf_vulnerable_params","ssrf_tested_payloads","ssrf_response_indicators","ssrf_issues","created_at"
                ];

                for (idx, field) in fields.iter().enumerate() {
                    let value: rusqlite::types::Value = row.get(idx)?;
                    let rendered = match value {
                        rusqlite::types::Value::Null => String::new(),
                        rusqlite::types::Value::Integer(i) => i.to_string(),
                        rusqlite::types::Value::Real(f) => f.to_string(),
                        rusqlite::types::Value::Text(t) => t,
                        rusqlite::types::Value::Blob(_) => "<blob>".to_string(),
                    };
                    rows.push(vec![field.to_string(), rendered]);
                }
                Ok(rows)
            });

            match row_result {
                Ok(rows) => {
                    print_table(&vec!["field".to_string(), "value".to_string()], &rows);
                }
                Err(_) => {
                    println!("Scan ID not found.");
                }
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("show raw ") {
            let id: i64 = match rest.trim().parse() {
                Ok(v) => v,
                Err(_) => {
                    println!("Invalid scan ID.");
                    continue;
                }
            };

            let mut stmt = conn.prepare(
                "SELECT request_headers, headers, response_body FROM scan_results WHERE id = ?1"
            )?;
            let row_result = stmt.query_row(params![id], |row| {
                let req_headers: Option<String> = row.get(0)?;
                let resp_headers: Option<String> = row.get(1)?;
                let resp_body: Option<String> = row.get(2)?;
                Ok((req_headers, resp_headers, resp_body))
            });

            match row_result {
                Ok((req_headers, resp_headers, resp_body)) => {
                    println!("Request Headers:");
                    println!("{}", req_headers.unwrap_or_default());
                    println!();
                    println!("Response Headers:");
                    println!("{}", resp_headers.unwrap_or_default());
                    println!();
                    println!("Response Body:");
                    println!("{}", resp_body.unwrap_or_default());
                }
                Err(_) => {
                    println!("Scan ID not found.");
                }
            }
            continue;
        }

        println!("Unknown command. Type 'help' for available commands.");
    }

    Ok(())
}

fn validate_terminus_db(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_results'"
    )?;
    let mut rows = stmt.query([])?;
    if rows.next()?.is_none() {
        anyhow::bail!("Not a Terminus SQLite database: missing scan_results table.");
    }

    let mut stmt = conn.prepare("PRAGMA table_info(scan_results)")?;
    let cols = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut col_set = HashSet::new();
    for col in cols {
        if let Ok(name) = col {
            col_set.insert(name);
        }
    }

    let required_columns = vec![
        "id", "scan_timestamp", "url", "method", "arbitrary_method_used", "status", "port",
        "headers", "error", "body_preview", "matched_patterns", "extracted_links", "request_headers",
        "response_body", "sec_headers_missing", "sec_headers_present", "sec_headers_issues",
        "detected_errors", "reflection_detected", "http2_desync_detected", "http2_http1_status",
        "http2_http2_status", "http2_status_mismatch", "http2_response_diff", "http2_issues",
        "host_injection_suspected", "host_reflected_in_location", "host_reflected_in_vary",
        "host_reflected_in_set_cookie", "host_injected_host", "host_issues",
        "xff_bypass_suspected", "xff_baseline_status", "xff_xff_status", "xff_status_changed",
        "xff_response_diff", "xff_issues", "csrf_suspected", "csrf_accepts_without_origin",
        "csrf_accepts_with_fake_origin", "csrf_missing_samesite", "csrf_missing_x_frame_options",
        "csrf_missing_csp", "csrf_issues", "ssrf_suspected", "ssrf_vulnerable_params",
        "ssrf_tested_payloads", "ssrf_response_indicators", "ssrf_issues", "created_at"
    ];

    for col in required_columns {
        if !col_set.contains(col) {
            anyhow::bail!("Not a Terminus SQLite database: missing column '{}'.", col);
        }
    }

    Ok(())
}

fn print_next_page(state: &mut PageState) -> bool {
    const PAGE_SIZE: usize = 20;
    let end = std::cmp::min(state.index + PAGE_SIZE, state.rows.len());
    let slice = &state.rows[state.index..end];
    print_table(&state.headers, slice);
    state.index = end;
    if state.index < state.rows.len() {
        println!("--more");
        true
    } else {
        false
    }
}

fn print_table(headers: &[String], rows: &[Vec<String>]) {
    if headers.is_empty() {
        return;
    }

    let max_width: usize = 60;
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len().min(max_width)).collect();

    for row in rows {
        for (idx, cell) in row.iter().enumerate() {
            let len = cell.chars().count();
            let capped = if len > max_width { max_width } else { len };
            if let Some(w) = widths.get_mut(idx) {
                if capped > *w {
                    *w = capped;
                }
            }
        }
    }

    let mut header_line = String::new();
    for (idx, header) in headers.iter().enumerate() {
        let cell = truncate_cell(header, widths[idx]);
        header_line.push_str(&format!("{:<width$}", cell, width = widths[idx]));
        if idx + 1 < headers.len() {
            header_line.push_str(" | ");
        }
    }
    println!("{}", header_line);

    let mut separator = String::new();
    for (idx, width) in widths.iter().enumerate() {
        separator.push_str(&"-".repeat(*width));
        if idx + 1 < widths.len() {
            separator.push_str("-+-");
        }
    }
    println!("{}", separator);

    for row in rows {
        let mut line = String::new();
        for (idx, cell) in row.iter().enumerate() {
            let cell = truncate_cell(cell, widths[idx]);
            line.push_str(&format!("{:<width$}", cell, width = widths[idx]));
            if idx + 1 < headers.len() {
                line.push_str(" | ");
            }
        }
        println!("{}", line);
    }
}

fn truncate_cell(s: &str, max_width: usize) -> String {
    let len = s.chars().count();
    if len <= max_width {
        return s.to_string();
    }
    if max_width <= 3 {
        return s.chars().take(max_width).collect();
    }
    let truncated: String = s.chars().take(max_width - 3).collect();
    format!("{}...", truncated)
}
