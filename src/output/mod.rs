use anyhow::Result;
use std::fs::OpenOptions;
use std::io::Write;

use crate::models::{OutputFormat, ScanResult};
use crate::storage::sqlite::output_sqlite;
use crate::output::types::OutputRow;

pub mod types;

pub fn output_results(results: &[ScanResult], format: OutputFormat, output_base: Option<&str>, verbose: bool) -> Result<()> {
    let rows = build_output_rows(results);
    match format {
        OutputFormat::Stdout => {
            if !verbose {
                output_stdout(&rows, verbose);
            }
        }
        OutputFormat::Txt => output_txt(&rows, output_base, verbose)?,
        OutputFormat::Json => output_json(results, output_base)?,
        OutputFormat::Html => output_html(&rows, output_base)?,
        OutputFormat::Csv => output_csv(&rows, output_base, verbose)?,
        OutputFormat::Sqlite => output_sqlite(results, output_base)?,
        OutputFormat::All => {
            if !verbose {
                output_stdout(&rows, verbose);
            }
            output_txt(&rows, output_base, verbose)?;
            output_json(results, output_base)?;
            output_html(&rows, output_base)?;
            output_csv(&rows, output_base, verbose)?;
            output_sqlite(results, output_base)?;
        }
    }
    Ok(())
}

fn build_output_rows(results: &[ScanResult]) -> Vec<OutputRow> {
    results
        .iter()
        .map(|result| {
            let indicators = collect_vuln_indicators(result);
            OutputRow::from_scan(result, indicators)
        })
        .collect()
}

pub fn collect_vuln_indicators(result: &ScanResult) -> Vec<String> {
    let mut indicators = Vec::new();

    if let Some(ref desync) = result.http2_desync {
        if desync.desync_detected {
            indicators.push("[HTTP/2 Desync Detected]".to_string());
        }
    }

    if let Some(ref host_inj) = result.host_injection {
        if host_inj.injection_suspected {
            indicators.push("[Host Injection Suspected]".to_string());
        }
    }

    if let Some(ref xff) = result.xff_bypass {
        if xff.bypass_suspected {
            indicators.push("[XFF Bypass Suspected]".to_string());
        }
    }

    if let Some(ref csrf) = result.csrf_result {
        if csrf.csrf_suspected {
            indicators.push("[CSRF Suspected]".to_string());
        }
    }

    if let Some(ref ssrf) = result.ssrf_result {
        if ssrf.ssrf_suspected {
            indicators.push("[SSRF Suspected]".to_string());
        }
    }

    if let Some(true) = result.reflection_detected {
        indicators.push("[Reflection Detected]".to_string());
    }

    if let Some(true) = result.arbitrary_method_accepted {
        indicators.push("[Arbitrary Method Accepted]".to_string());
    }

    if let Some(true) = result.method_confusion_suspected {
        indicators.push("[Method Confusion Suspected]".to_string());
    }

    if let Some(ref sec_headers) = result.security_headers {
        if !sec_headers.issues.is_empty() {
            for issue in &sec_headers.issues {
                indicators.push(format!("[Security: {}]", issue));
            }
        }
    }

    if let Some(ref errors) = result.detected_errors {
        if !errors.is_empty() {
            for error in errors {
                indicators.push(format!("[Error: {}]", error));
            }
        }
    }

    indicators
}

pub fn output_stdout(results: &[OutputRow], verbose: bool) {
    for result in results {
        if let Some(error) = &result.error {
            eprintln!("Error on {}:{} using {}: {}", result.url, result.port, result.method, error);
        } else {
            let indicators_str = if !result.indicators.is_empty() {
                format!(" {}", result.indicators.join(" "))
            } else {
                String::new()
            };

            if verbose {
                if let Some(headers) = &result.headers {
                    println!("URL: {}, Method: {}, Status: {}, Port: {}, Headers: {}{}",
                        result.url, result.method, result.status, result.port, headers, indicators_str);
                } else {
                    println!("URL: {}, Method: {}, Status: {}, Port: {}{}",
                        result.url, result.method, result.status, result.port, indicators_str);
                }
            } else {
                println!("{} [{}:{}]{}",
                    result.url, result.method, result.status, indicators_str);
            }
        }
    }
}

pub fn output_txt(results: &[OutputRow], output_base: Option<&str>, verbose: bool) -> Result<()> {
    let filename = format!("{}.txt", output_base.unwrap_or("terminus_results"));
    let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(&filename)?;

    for result in results {
        if let Some(error) = &result.error {
            writeln!(file, "Error on {}:{} using {}: {}", result.url, result.port, result.method, error)?;
        } else {
            let indicators_str = if !result.indicators.is_empty() {
                format!(" {}", result.indicators.join(" "))
            } else {
                String::new()
            };

            if verbose {
                if let Some(headers) = &result.headers {
                    writeln!(file, "URL: {}, Method: {}, Status: {}, Port: {}, Headers: {}{}",
                        result.url, result.method, result.status, result.port, headers, indicators_str)?;
                } else {
                    writeln!(file, "URL: {}, Method: {}, Status: {}, Port: {}{}",
                        result.url, result.method, result.status, result.port, indicators_str)?;
                }
            } else {
                writeln!(file, "URL: {}, Method: {}, Status: {}, Port: {}{}",
                    result.url, result.method, result.status, result.port, indicators_str)?;
            }
        }
    }

    eprintln!("Results written to {}", filename);
    Ok(())
}

pub fn output_json(results: &[ScanResult], output_base: Option<&str>) -> Result<()> {
    let filename = format!("{}.json", output_base.unwrap_or("terminus_results"));
    let json = serde_json::to_string_pretty(results)?;
    std::fs::write(&filename, json)?;
    eprintln!("Results written to {}", filename);
    Ok(())
}

pub fn output_html(results: &[OutputRow], output_base: Option<&str>) -> Result<()> {
    let filename = format!("{}.html", output_base.unwrap_or("terminus_results"));

    let total_results = results.len();
    let mut vuln_counts = std::collections::HashMap::new();
    vuln_counts.insert("http2_desync", 0);
    vuln_counts.insert("host_injection", 0);
    vuln_counts.insert("xff_bypass", 0);
    vuln_counts.insert("csrf", 0);
    vuln_counts.insert("ssrf", 0);
    vuln_counts.insert("reflection", 0);
    vuln_counts.insert("arbitrary_method", 0);
    vuln_counts.insert("method_confusion", 0);
    vuln_counts.insert("security_issues", 0);
    vuln_counts.insert("error_messages", 0);

    for result in results {
        for indicator in &result.indicators {
            if indicator.contains("HTTP/2 Desync") {
                *vuln_counts.get_mut("http2_desync").unwrap() += 1;
            }
            if indicator.contains("Host Injection") {
                *vuln_counts.get_mut("host_injection").unwrap() += 1;
            }
            if indicator.contains("XFF Bypass") {
                *vuln_counts.get_mut("xff_bypass").unwrap() += 1;
            }
            if indicator.contains("CSRF") {
                *vuln_counts.get_mut("csrf").unwrap() += 1;
            }
            if indicator.contains("SSRF") {
                *vuln_counts.get_mut("ssrf").unwrap() += 1;
            }
            if indicator.contains("Reflection") {
                *vuln_counts.get_mut("reflection").unwrap() += 1;
            }
            if indicator.contains("Arbitrary Method Accepted") {
                *vuln_counts.get_mut("arbitrary_method").unwrap() += 1;
            }
            if indicator.contains("Method Confusion") {
                *vuln_counts.get_mut("method_confusion").unwrap() += 1;
            }
            if indicator.contains("Security:") {
                *vuln_counts.get_mut("security_issues").unwrap() += 1;
            }
            if indicator.contains("Error:") {
                *vuln_counts.get_mut("error_messages").unwrap() += 1;
            }
        }
    }

    let mut html = String::from("<!DOCTYPE html>\n<html>\n<head>\n<meta charset='UTF-8'>\n<title>Terminus Scan Results</title>\n");

    html.push_str("<style>\n");
    html.push_str("body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5;}\n");
    html.push_str("h1{color:#2c3e50;}\n");
    html.push_str(".summary{background:#fff;padding:20px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,0.1);}\n");
    html.push_str(".summary h2{margin-top:0;color:#2c3e50;}\n");
    html.push_str(".stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-top:15px;}\n");
    html.push_str(".stat-card{background:#f8f9fa;padding:15px;border-radius:6px;border-left:4px solid #4CAF50;}\n");
    html.push_str(".stat-card.vuln{border-left-color:#e74c3c;}\n");
    html.push_str(".stat-label{font-size:12px;color:#7f8c8d;text-transform:uppercase;}\n");
    html.push_str(".stat-value{font-size:24px;font-weight:bold;color:#2c3e50;margin-top:5px;}\n");
    html.push_str(".filters{background:#fff;padding:15px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,0.1);}\n");
    html.push_str(".filter-group{display:inline-block;margin-right:15px;margin-bottom:10px;}\n");
    html.push_str(".filter-group label{margin-left:5px;}\n");
    html.push_str("table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 2px 4px rgba(0,0,0,0.1);table-layout:fixed;}\n");
    html.push_str("th,td{border:1px solid #ddd;padding:12px;text-align:left;max-width:300px;word-break:break-word;overflow-wrap:break-word;}\n");
    html.push_str("th{background-color:#4CAF50;color:white;position:sticky;top:0;}\n");
    html.push_str("tr:nth-child(even){background-color:#f8f9fa;}\n");
    html.push_str("tr:hover{background-color:#e8f5e9;}\n");
    html.push_str(".error{color:#e74c3c;font-weight:bold;}\n");
    html.push_str(".vuln-badge{display:inline-block;background:#e74c3c;color:white;padding:4px 8px;border-radius:4px;font-size:11px;margin:2px;}\n");
    html.push_str(".vuln-badge.security{background:#f39c12;}\n");
    html.push_str(".hidden{display:none;}\n");
    html.push_str("td:first-child{max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}\n");
    html.push_str("td:first-child:hover{white-space:normal;overflow:visible;}\n");
    html.push_str("</style>\n");

    html.push_str("<script>\n");
    html.push_str("function filterTable() {\n");
    html.push_str("  const filters = {\n");
    html.push_str("    http2: document.getElementById('filter-http2').checked,\n");
    html.push_str("    host: document.getElementById('filter-host').checked,\n");
    html.push_str("    xff: document.getElementById('filter-xff').checked,\n");
    html.push_str("    csrf: document.getElementById('filter-csrf').checked,\n");
    html.push_str("    ssrf: document.getElementById('filter-ssrf').checked,\n");
    html.push_str("    reflection: document.getElementById('filter-reflection').checked,\n");
    html.push_str("    arbitrary: document.getElementById('filter-arbitrary').checked,\n");
    html.push_str("    confusion: document.getElementById('filter-confusion').checked,\n");
    html.push_str("    security: document.getElementById('filter-security').checked,\n");
    html.push_str("    errors: document.getElementById('filter-errors').checked,\n");
    html.push_str("    clean: document.getElementById('filter-clean').checked\n");
    html.push_str("  };\n");
    html.push_str("  const anyFilterActive = Object.values(filters).some(v => v);\n");
    html.push_str("  const rows = document.querySelectorAll('.data-row');\n");
    html.push_str("  rows.forEach(row => {\n");
    html.push_str("    if (!anyFilterActive) { row.classList.remove('hidden'); return; }\n");
    html.push_str("    const vulns = row.dataset.vulns.split(',').filter(v => v);\n");
    html.push_str("    const hasClean = vulns.length === 0;\n");
    html.push_str("    const shouldShow = (filters.http2 && vulns.includes('http2')) ||\n");
    html.push_str("      (filters.host && vulns.includes('host')) ||\n");
    html.push_str("      (filters.xff && vulns.includes('xff')) ||\n");
    html.push_str("      (filters.csrf && vulns.includes('csrf')) ||\n");
    html.push_str("      (filters.ssrf && vulns.includes('ssrf')) ||\n");
    html.push_str("      (filters.reflection && vulns.includes('reflection')) ||\n");
    html.push_str("      (filters.arbitrary && vulns.includes('arbitrary')) ||\n");
    html.push_str("      (filters.confusion && vulns.includes('confusion')) ||\n");
    html.push_str("      (filters.security && vulns.includes('security')) ||\n");
    html.push_str("      (filters.errors && vulns.includes('errors')) ||\n");
    html.push_str("      (filters.clean && hasClean);\n");
    html.push_str("    if (shouldShow) { row.classList.remove('hidden'); }\n");
    html.push_str("    else { row.classList.add('hidden'); }\n");
    html.push_str("  });\n");
    html.push_str("}\n");
    html.push_str("</script>\n");

    html.push_str("</head>\n<body>\n");

    html.push_str("<h1>Terminus Scan Results</h1>\n");

    html.push_str("<div class='summary'>\n");
    html.push_str("<h2>Scan Summary</h2>\n");
    html.push_str("<div class='stat-grid'>\n");
    html.push_str(&format!("<div class='stat-card'><div class='stat-label'>Total Endpoints</div><div class='stat-value'>{}</div></div>\n", total_results));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>HTTP/2 Desync</div><div class='stat-value'>{}</div></div>\n", vuln_counts["http2_desync"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>Host Injection</div><div class='stat-value'>{}</div></div>\n", vuln_counts["host_injection"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>XFF Bypass</div><div class='stat-value'>{}</div></div>\n", vuln_counts["xff_bypass"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>CSRF</div><div class='stat-value'>{}</div></div>\n", vuln_counts["csrf"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>SSRF</div><div class='stat-value'>{}</div></div>\n", vuln_counts["ssrf"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>Reflection</div><div class='stat-value'>{}</div></div>\n", vuln_counts["reflection"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>Arbitrary Method Accepted</div><div class='stat-value'>{}</div></div>\n", vuln_counts["arbitrary_method"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>Method Confusion</div><div class='stat-value'>{}</div></div>\n", vuln_counts["method_confusion"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>Security Issues</div><div class='stat-value'>{}</div></div>\n", vuln_counts["security_issues"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>Error Messages</div><div class='stat-value'>{}</div></div>\n", vuln_counts["error_messages"]));
    html.push_str("</div>\n</div>\n");

    html.push_str("<div class='filters'>\n");
    html.push_str("<strong>Filter by Vulnerability:</strong><br>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-http2' onchange='filterTable()'><label for='filter-http2'>HTTP/2 Desync</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-host' onchange='filterTable()'><label for='filter-host'>Host Injection</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-xff' onchange='filterTable()'><label for='filter-xff'>XFF Bypass</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-csrf' onchange='filterTable()'><label for='filter-csrf'>CSRF</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-ssrf' onchange='filterTable()'><label for='filter-ssrf'>SSRF</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-reflection' onchange='filterTable()'><label for='filter-reflection'>Reflection</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-arbitrary' onchange='filterTable()'><label for='filter-arbitrary'>Arbitrary Method Accepted</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-confusion' onchange='filterTable()'><label for='filter-confusion'>Method Confusion</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-security' onchange='filterTable()'><label for='filter-security'>Security Issues</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-errors' onchange='filterTable()'><label for='filter-errors'>Error Messages</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-clean' onchange='filterTable()'><label for='filter-clean'>Clean (No Issues)</label></div>\n");
    html.push_str("</div>\n");

    html.push_str("<table>\n");
    html.push_str("<tr><th>URL</th><th>Method</th><th>Arbitrary Method</th><th>Status</th><th>Port</th><th>Vulnerabilities</th><th>Request</th><th>Response</th><th>Error</th></tr>\n");

    for result in results {
        let mut vuln_tags: Vec<String> = Vec::new();
        let mut data_vulns = Vec::new();

        for indicator in &result.indicators {
            if indicator.contains("HTTP/2 Desync") {
                vuln_tags.push("<span class='vuln-badge'>HTTP/2 Desync</span>".to_string());
                data_vulns.push("http2");
            }
            if indicator.contains("Host Injection") {
                vuln_tags.push("<span class='vuln-badge'>Host Injection</span>".to_string());
                data_vulns.push("host");
            }
            if indicator.contains("XFF Bypass") {
                vuln_tags.push("<span class='vuln-badge'>XFF Bypass</span>".to_string());
                data_vulns.push("xff");
            }
            if indicator.contains("CSRF") {
                vuln_tags.push("<span class='vuln-badge'>CSRF</span>".to_string());
                data_vulns.push("csrf");
            }
            if indicator.contains("SSRF") {
                vuln_tags.push("<span class='vuln-badge'>SSRF</span>".to_string());
                data_vulns.push("ssrf");
            }
            if indicator.contains("Reflection") {
                vuln_tags.push("<span class='vuln-badge'>Reflection</span>".to_string());
                data_vulns.push("reflection");
            }
            if indicator.contains("Arbitrary Method Accepted") {
                vuln_tags.push("<span class='vuln-badge'>Arbitrary Method Accepted</span>".to_string());
                data_vulns.push("arbitrary");
            }
            if indicator.contains("Method Confusion") {
                vuln_tags.push("<span class='vuln-badge'>Method Confusion</span>".to_string());
                data_vulns.push("confusion");
            }
            if indicator.contains("[Security:") {
                vuln_tags.push(format!("<span class='vuln-badge security' title='Security Issue'>{}</span>", html_escape(indicator)));
                data_vulns.push("security");
            }
            if indicator.contains("[Error:") {
                vuln_tags.push(format!("<span class='vuln-badge security' title='Error Detected'>{}</span>", html_escape(indicator)));
                data_vulns.push("errors");
            }
        }

        let vuln_display = if vuln_tags.is_empty() {
            "<span style='color:#27ae60;'>✓ Clean</span>".to_string()
        } else {
            vuln_tags.join(" ")
        };

        let data_vulns_str = data_vulns.join(",");

        html.push_str(&format!("<tr class='data-row' data-vulns='{}'>", data_vulns_str));
        html.push_str(&format!("<td>{}</td>", html_escape(&result.url)));
        html.push_str(&format!("<td>{}</td>", html_escape(&result.method)));
        html.push_str(&format!("<td>{}</td>", html_escape(result.arbitrary_method_used.as_deref().unwrap_or(""))));
        html.push_str(&format!("<td>{}</td>", result.status));
        let port_display = if result.port == 0 {
            "N/A".to_string()
        } else {
            result.port.to_string()
        };
        html.push_str(&format!("<td>{}</td>", port_display));
        html.push_str(&format!("<td>{}</td>", vuln_display));

        let req_headers_display = result.request_headers.as_deref().unwrap_or("");
        html.push_str("<td style='font-size:0.8em; max-width:300px;'>");
        if !req_headers_display.is_empty() {
            html.push_str("<details><summary style='cursor:pointer; color:#3498db;'>View Headers</summary>");
            html.push_str(&format!("<pre style='margin:5px 0; padding:10px; background:#f8f9fa; border-radius:4px; overflow-x:auto; max-height:300px; font-size:0.9em;'>{}</pre>", html_escape(req_headers_display)));
            html.push_str("</details>");
        }
        html.push_str("</td>");

        let resp_headers_display = result.headers.as_deref().unwrap_or("");
        let resp_body_display = result.response_body.as_deref().unwrap_or("");
        html.push_str("<td style='font-size:0.8em; max-width:400px;'>");
        if !resp_headers_display.is_empty() || !resp_body_display.is_empty() {
            html.push_str("<details><summary style='cursor:pointer; color:#3498db;'>View Response</summary>");
            if !resp_headers_display.is_empty() {
                html.push_str("<strong>Response Headers:</strong>");
                html.push_str(&format!("<pre style='margin:5px 0; padding:10px; background:#e8f4f8; border-radius:4px; overflow-x:auto; max-height:200px; font-size:0.9em;'>{}</pre>", html_escape(resp_headers_display)));
            }
            if !resp_body_display.is_empty() {
                html.push_str("<strong>Response Body:</strong>");
                html.push_str(&format!("<pre style='margin:5px 0; padding:10px; background:#f8f9fa; border-radius:4px; overflow-x:auto; max-height:300px; font-size:0.9em;'>{}</pre>", html_escape(resp_body_display)));
            }
            html.push_str("</details>");
        }
        html.push_str("</td>");

        html.push_str(&format!("<td class='error'>{}</td>", html_escape(result.error.as_deref().unwrap_or(""))));
        html.push_str("</tr>\n");
    }

    html.push_str("</table>\n</body>\n</html>");
    std::fs::write(&filename, html)?;
    eprintln!("Results written to {}", filename);
    Ok(())
}

pub fn output_csv(results: &[OutputRow], output_base: Option<&str>, verbose: bool) -> Result<()> {
    let filename = format!("{}.csv", output_base.unwrap_or("terminus_results"));
    let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(&filename)?;

    if verbose {
        writeln!(file, "URL,Method,Arbitrary Method,Status,Port,Response Headers,Vulnerabilities,Request Headers,Error")?;
    } else {
        writeln!(file, "URL,Method,Arbitrary Method,Status,Port,Vulnerabilities,Request Headers,Error")?;
    }

    for result in results {
        let url = csv_escape(&result.url);
        let method = csv_escape(&result.method);
        let status = result.status.to_string();
        let port = result.port.to_string();
        let error = csv_escape(result.error.as_deref().unwrap_or(""));
        let arbitrary_method_used = csv_escape(result.arbitrary_method_used.as_deref().unwrap_or(""));
        let vulnerabilities = csv_escape(&result.indicators.join("; "));

        let request_headers = csv_escape(result.request_headers.as_deref().unwrap_or(""));

        if verbose {
            let response_headers = csv_escape(result.headers.as_deref().unwrap_or(""));
            writeln!(file, "{},{},{},{},{},{},{},{},{}", url, method, arbitrary_method_used, status, port, response_headers, vulnerabilities, request_headers, error)?;
        } else {
            writeln!(file, "{},{},{},{},{},{},{},{}", url, method, arbitrary_method_used, status, port, vulnerabilities, request_headers, error)?;
        }
    }

    eprintln!("Results written to {}", filename);
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn csv_escape(s: &str) -> String {
    let cleaned = s
        .replace('\r', "")
        .replace('\n', " ")
        .replace('\t', " ")
        .replace('\0', "");

    if cleaned.contains(',') || cleaned.contains('"') {
        format!("\"{}\"", cleaned.replace('"', "\"\""))
    } else {
        cleaned
    }
}
