#![allow(dead_code)]

use rusqlite::{params, Connection};

/// A lightweight row representing a scan result for TUI display.
#[derive(Debug, Clone)]
pub struct ScanResultRow {
    pub id: i64,
    pub url: String,
    pub method: String,
    pub status: i64,
    pub port: i64,
    pub headers: Option<String>,
    pub error: Option<String>,
    pub request_headers: Option<String>,
    pub response_body: Option<String>,
    pub arbitrary_method_used: Option<String>,
}

/// List all scan results.
pub fn list_all_results(conn: &Connection) -> rusqlite::Result<Vec<ScanResultRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, url, method, status, port, headers, error, request_headers, response_body, arbitrary_method_used \
         FROM scan_results ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(ScanResultRow {
            id: row.get(0)?,
            url: row.get(1)?,
            method: row.get(2)?,
            status: row.get(3)?,
            port: row.get(4)?,
            headers: row.get(5)?,
            error: row.get(6)?,
            request_headers: row.get(7)?,
            response_body: row.get(8)?,
            arbitrary_method_used: row.get(9)?,
        })
    })?;
    rows.collect()
}

/// Find scan results by HTTP status code.
pub fn find_by_status(conn: &Connection, status: u16) -> rusqlite::Result<Vec<ScanResultRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, url, method, status, port, headers, error, request_headers, response_body, arbitrary_method_used \
         FROM scan_results WHERE status = ?1 ORDER BY id",
    )?;
    let rows = stmt.query_map(params![status as i64], |row| {
        Ok(ScanResultRow {
            id: row.get(0)?,
            url: row.get(1)?,
            method: row.get(2)?,
            status: row.get(3)?,
            port: row.get(4)?,
            headers: row.get(5)?,
            error: row.get(6)?,
            request_headers: row.get(7)?,
            response_body: row.get(8)?,
            arbitrary_method_used: row.get(9)?,
        })
    })?;
    rows.collect()
}

/// Find scan results by exploit type (matching the column flags).
pub fn find_by_exploit(conn: &Connection, exploit_type: &str) -> rusqlite::Result<Vec<ScanResultRow>> {
    let col = match exploit_type.to_lowercase().as_str() {
        "http2_desync" => "http2_desync_detected",
        "host_injection" => "host_injection_suspected",
        "xff_bypass" => "xff_bypass_suspected",
        "csrf" => "csrf_suspected",
        "ssrf" => "ssrf_suspected",
        "reflection" => "reflection_detected",
        _ => return Ok(Vec::new()),
    };

    let query = format!(
        "SELECT id, url, method, status, port, headers, error, request_headers, response_body, arbitrary_method_used \
         FROM scan_results WHERE {} = 1 ORDER BY id",
        col
    );

    let mut stmt = conn.prepare(&query)?;
    let rows = stmt.query_map([], |row| {
        Ok(ScanResultRow {
            id: row.get(0)?,
            url: row.get(1)?,
            method: row.get(2)?,
            status: row.get(3)?,
            port: row.get(4)?,
            headers: row.get(5)?,
            error: row.get(6)?,
            request_headers: row.get(7)?,
            response_body: row.get(8)?,
            arbitrary_method_used: row.get(9)?,
        })
    })?;
    rows.collect()
}

/// Retrieve a single scan result by ID.
pub fn get_scan_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<ScanResultRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, url, method, status, port, headers, error, request_headers, response_body, arbitrary_method_used \
         FROM scan_results WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(params![id], |row| {
        Ok(ScanResultRow {
            id: row.get(0)?,
            url: row.get(1)?,
            method: row.get(2)?,
            status: row.get(3)?,
            port: row.get(4)?,
            headers: row.get(5)?,
            error: row.get(6)?,
            request_headers: row.get(7)?,
            response_body: row.get(8)?,
            arbitrary_method_used: row.get(9)?,
        })
    })?;
    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
}
