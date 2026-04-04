use anyhow::{Context, Result};
use rusqlite::Connection;
use url::Url;

use crate::ai::types::EvidenceRecord;

pub fn load_evidence(db_path: &str, max_records: usize) -> Result<Vec<EvidenceRecord>> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open SQLite database: {}", db_path))?;

    let mut stmt = conn.prepare(
        "SELECT url, method, status, port, headers, response_body, scan_timestamp
         FROM scan_results ORDER BY id DESC LIMIT ?1",
    )?;

    let mut rows = stmt.query([max_records as i64])?;
    let mut evidence = Vec::new();

    while let Some(row) = rows.next()? {
        let url: String = row.get(0)?;
        let method: String = row.get(1)?;
        let status: i64 = row.get(2)?;
        let port: i64 = row.get(3)?;
        let headers: Option<String> = row.get(4)?;
        let body: Option<String> = row.get(5)?;
        let timestamp: String = row.get(6)?;

        let parsed = Url::parse(&url).ok();
        let host = parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("").to_string();
        let scheme = parsed.as_ref().map(|u| u.scheme()).unwrap_or("").to_string();

        let headers_hash = headers.as_deref().map(hash_string);
        let body_hash = body.as_deref().map(hash_string);
        let body_len = body.as_ref().map(|b| b.len());

        evidence.push(EvidenceRecord {
            scan_id: db_path.to_string(),
            url: url.clone(),
            host,
            scheme,
            port: port as u16,
            method,
            exploit_family: None,
            payload_location: None,
            payload_value: None,
            baseline_status: None,
            variant_status: status as u16,
            baseline_headers_hash: None,
            variant_headers_hash: headers_hash,
            baseline_body_hash: None,
            variant_body_hash: body_hash,
            baseline_content_length: None,
            variant_content_length: body_len,
            body_markers: Vec::new(),
            reflected_markers: Vec::new(),
            environment_markers: Vec::new(),
            auth_markers: Vec::new(),
            redirect_location: None,
            confidence_seed: 0.5,
            timestamp,
        });
    }

    Ok(evidence)
}

fn hash_string(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}
