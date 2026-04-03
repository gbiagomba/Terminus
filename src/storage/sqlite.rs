use anyhow::{Context, Result};
use rusqlite::{Connection, params};

use crate::models::ScanResult;

pub fn output_sqlite(results: &[ScanResult], output_base: Option<&str>) -> Result<()> {
    let filename = format!("{}.db", output_base.unwrap_or("terminus_results"));
    let conn = Connection::open(&filename)
        .context(format!("Failed to create SQLite database: {}", filename))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_timestamp TEXT NOT NULL,
            url TEXT NOT NULL,
            method TEXT NOT NULL,
            arbitrary_method_used TEXT,
            status INTEGER NOT NULL,
            port INTEGER NOT NULL,
            headers TEXT,
            error TEXT,
            body_preview TEXT,
            matched_patterns TEXT,
            extracted_links TEXT,
            request_headers TEXT,
            response_body TEXT,
            sec_headers_missing TEXT,
            sec_headers_present TEXT,
            sec_headers_issues TEXT,
            detected_errors TEXT,
            reflection_detected INTEGER DEFAULT 0,
            http2_desync_detected INTEGER DEFAULT 0,
            http2_http1_status INTEGER,
            http2_http2_status INTEGER,
            http2_status_mismatch INTEGER DEFAULT 0,
            http2_response_diff TEXT,
            http2_issues TEXT,
            host_injection_suspected INTEGER DEFAULT 0,
            host_reflected_in_location INTEGER DEFAULT 0,
            host_reflected_in_vary INTEGER DEFAULT 0,
            host_reflected_in_set_cookie INTEGER DEFAULT 0,
            host_injected_host TEXT,
            host_issues TEXT,
            xff_bypass_suspected INTEGER DEFAULT 0,
            xff_baseline_status INTEGER,
            xff_xff_status INTEGER,
            xff_status_changed INTEGER DEFAULT 0,
            xff_response_diff TEXT,
            xff_issues TEXT,
            csrf_suspected INTEGER DEFAULT 0,
            csrf_accepts_without_origin INTEGER DEFAULT 0,
            csrf_accepts_with_fake_origin INTEGER DEFAULT 0,
            csrf_missing_samesite INTEGER DEFAULT 0,
            csrf_missing_x_frame_options INTEGER DEFAULT 0,
            csrf_missing_csp INTEGER DEFAULT 0,
            csrf_issues TEXT,
            ssrf_suspected INTEGER DEFAULT 0,
            ssrf_vulnerable_params TEXT,
            ssrf_tested_payloads TEXT,
            ssrf_response_indicators TEXT,
            ssrf_issues TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    ensure_sqlite_schema(&conn)?;

    conn.execute("CREATE INDEX IF NOT EXISTS idx_url ON scan_results(url)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON scan_results(status)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_results(scan_timestamp)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities ON scan_results(http2_desync_detected, host_injection_suspected, xff_bypass_suspected, csrf_suspected, ssrf_suspected, reflection_detected)", [])?;

    let scan_timestamp = chrono::Utc::now().to_rfc3339();

    for result in results {
        let to_json = |opt_vec: &Option<Vec<String>>| -> Option<String> {
            opt_vec.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default())
        };

        let (sec_missing, sec_present, sec_issues) = result.security_headers.as_ref()
            .map(|sh| (
                to_json(&Some(sh.missing.clone())),
                to_json(&Some(sh.present.clone())),
                to_json(&Some(sh.issues.clone()))
            ))
            .unwrap_or((None, None, None));

        let http2 = result.http2_desync.as_ref();
        let host = result.host_injection.as_ref();
        let xff = result.xff_bypass.as_ref();
        let csrf = result.csrf_result.as_ref();
        let ssrf = result.ssrf_result.as_ref();

        conn.execute(
            "INSERT INTO scan_results (
                scan_timestamp, url, method, arbitrary_method_used, status, port, headers, error, body_preview,
                matched_patterns, extracted_links, request_headers, response_body,
                sec_headers_missing, sec_headers_present, sec_headers_issues, detected_errors,
                reflection_detected,
                http2_desync_detected, http2_http1_status, http2_http2_status,
                http2_status_mismatch, http2_response_diff, http2_issues,
                host_injection_suspected, host_reflected_in_location, host_reflected_in_vary,
                host_reflected_in_set_cookie, host_injected_host, host_issues,
                xff_bypass_suspected, xff_baseline_status, xff_xff_status,
                xff_status_changed, xff_response_diff, xff_issues,
                csrf_suspected, csrf_accepts_without_origin, csrf_accepts_with_fake_origin,
                csrf_missing_samesite, csrf_missing_x_frame_options, csrf_missing_csp, csrf_issues,
                ssrf_suspected, ssrf_vulnerable_params, ssrf_tested_payloads,
                ssrf_response_indicators, ssrf_issues
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30,
                ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46, ?47, ?48
            )",
            params![
                scan_timestamp,
                result.url,
                result.method,
                result.arbitrary_method_used,
                result.status,
                result.port,
                result.headers,
                result.error,
                result.body_preview,
                to_json(&result.matched_patterns),
                to_json(&result.extracted_links),
                result.request_headers,
                result.response_body,
                sec_missing,
                sec_present,
                sec_issues,
                to_json(&result.detected_errors),
                result.reflection_detected.unwrap_or(false) as i32,
                http2.map(|h| h.desync_detected as i32),
                http2.map(|h| h.http1_status as i32),
                http2.map(|h| h.http2_status as i32),
                http2.map(|h| h.status_mismatch as i32),
                http2.and_then(|h| h.response_diff.clone()),
                http2.map(|h| serde_json::to_string(&h.issues).unwrap_or_default()),
                host.map(|h| h.injection_suspected as i32),
                host.map(|h| h.reflected_in_location as i32),
                host.map(|h| h.reflected_in_vary as i32),
                host.map(|h| h.reflected_in_set_cookie as i32),
                host.map(|h| h.injected_host.clone()),
                host.map(|h| serde_json::to_string(&h.issues).unwrap_or_default()),
                xff.map(|x| x.bypass_suspected as i32),
                xff.map(|x| x.baseline_status as i32),
                xff.map(|x| x.xff_status as i32),
                xff.map(|x| x.status_changed as i32),
                xff.and_then(|x| x.response_diff.clone()),
                xff.map(|x| serde_json::to_string(&x.issues).unwrap_or_default()),
                csrf.map(|c| c.csrf_suspected as i32),
                csrf.map(|c| c.accepts_without_origin as i32),
                csrf.map(|c| c.accepts_with_fake_origin as i32),
                csrf.map(|c| c.missing_samesite as i32),
                csrf.map(|c| c.missing_x_frame_options as i32),
                csrf.map(|c| c.missing_csp as i32),
                csrf.map(|c| serde_json::to_string(&c.issues).unwrap_or_default()),
                ssrf.map(|s| s.ssrf_suspected as i32),
                ssrf.map(|s| serde_json::to_string(&s.vulnerable_params).unwrap_or_default()),
                ssrf.map(|s| serde_json::to_string(&s.tested_payloads).unwrap_or_default()),
                ssrf.map(|s| serde_json::to_string(&s.response_indicators).unwrap_or_default()),
                ssrf.map(|s| serde_json::to_string(&s.issues).unwrap_or_default()),
            ],
        )?;
    }

    eprintln!("Results written to {} ({} records)", filename, results.len());
    Ok(())
}

fn ensure_sqlite_schema(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(scan_results)")?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut has_arbitrary_method = false;

    for col in columns {
        if let Ok(name) = col {
            if name == "arbitrary_method_used" {
                has_arbitrary_method = true;
                break;
            }
        }
    }

    if !has_arbitrary_method {
        conn.execute(
            "ALTER TABLE scan_results ADD COLUMN arbitrary_method_used TEXT",
            [],
        )?;
    }

    Ok(())
}
