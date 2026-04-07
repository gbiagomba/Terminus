use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::models::ScanResult;

pub fn load_sqlite(path: &str) -> Result<Vec<ScanResult>> {
    let conn = Connection::open(path)
        .with_context(|| format!("Failed to open SQLite database: {}", path))?;

    let mut stmt = conn.prepare(
        "SELECT url, method, arbitrary_method_used, status, port, headers, error, body_preview,
                matched_patterns, extracted_links, request_headers, response_body,
                detected_errors, reflection_detected
         FROM scan_results",
    )?;

    let mut rows = stmt.query([])?;
    let mut results = Vec::new();
    while let Some(row) = rows.next()? {
        let matched_patterns: Option<String> = row.get(8)?;
        let extracted_links: Option<String> = row.get(9)?;
        let detected_errors: Option<String> = row.get(12)?;
        let reflection_detected: Option<i32> = row.get(13)?;

        let result = ScanResult {
            url: row.get(0)?,
            method: row.get(1)?,
            arbitrary_method_used: row.get(2)?,
            arbitrary_method_accepted: None,
            method_confusion_suspected: None,
            status: row.get::<_, i64>(3)? as u16,
            port: row.get::<_, i64>(4)? as u16,
            headers: row.get(5)?,
            error: row.get(6)?,
            body_preview: row.get(7)?,
            matched_patterns: parse_json_vec(matched_patterns),
            extracted_links: parse_json_vec(extracted_links),
            security_headers: None,
            detected_errors: parse_json_vec(detected_errors),
            reflection_detected: reflection_detected.map(|v| v != 0),
            http2_desync: None,
            host_injection: None,
            xff_bypass: None,
            csrf_result: None,
            ssrf_result: None,
            request_headers: row.get(10)?,
            response_body: row.get(11)?,
        };
        results.push(result);
    }

    Ok(results)
}

fn parse_json_vec(value: Option<String>) -> Option<Vec<String>> {
    value.and_then(|v| serde_json::from_str(&v).ok())
}
