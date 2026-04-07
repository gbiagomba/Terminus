use anyhow::Result;
use std::fs::File;
use std::io::Write;

use crate::diff::DiffReport;
use crate::storage::sqlite::output_diff_sqlite;

pub fn render_diff(report: &DiffReport, format: &str, output_base: Option<&str>) -> Result<()> {
    match format {
        "stdout" => render_stdout(report),
        "json" => render_json(report, output_base)?,
        "csv" => render_csv(report, output_base)?,
        "html" => render_html(report, output_base)?,
        "sqlite" | "db" => output_diff_sqlite(report, output_base, &report.base_id, &report.compare_id)?,
        _ => render_stdout(report),
    }
    Ok(())
}

fn render_stdout(report: &DiffReport) {
    println!("\n{}", "=".repeat(80));
    println!("TERMINUS DIFF RESULTS");
    println!("Base: {}", report.base_id);
    println!("Compare: {}", report.compare_id);
    println!("{}\n", "=".repeat(80));

    if !report.new_endpoints.is_empty() {
        println!("NEW ENDPOINTS ({}):", report.new_endpoints.len());
        for entry in &report.new_endpoints {
            println!("  [+] {}:{} {} -> {}", entry.url, entry.port, entry.method, entry.new_status.unwrap_or(0));
        }
        println!();
    }

    if !report.removed_endpoints.is_empty() {
        println!("REMOVED ENDPOINTS ({}):", report.removed_endpoints.len());
        for entry in &report.removed_endpoints {
            println!("  [-] {}:{} {} (was {})", entry.url, entry.port, entry.method, entry.old_status.unwrap_or(0));
        }
        println!();
    }

    if !report.changed_endpoints.is_empty() {
        println!("CHANGED ENDPOINTS ({}):", report.changed_endpoints.len());
        for entry in &report.changed_endpoints {
            println!("  [~] {}:{} {} status {} -> {}", entry.url, entry.port, entry.method, entry.old_status.unwrap_or(0), entry.new_status.unwrap_or(0));
        }
        println!();
    }

    if !report.method_behavior_changes.is_empty() {
        println!("METHOD BEHAVIOR CHANGES ({}):", report.method_behavior_changes.len());
        for change in &report.method_behavior_changes {
            println!("  [*] {}", change);
        }
        println!();
    }

    if report.new_endpoints.is_empty() && report.removed_endpoints.is_empty() && report.changed_endpoints.is_empty() {
        println!("No differences found between scans.\n");
    }
}

fn render_json(report: &DiffReport, output_base: Option<&str>) -> Result<()> {
    let filename = format!("{}.json", output_base.unwrap_or("terminus_diff"));
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(&filename, json)?;
    eprintln!("Results written to {}", filename);
    Ok(())
}

fn render_csv(report: &DiffReport, output_base: Option<&str>) -> Result<()> {
    let filename = format!("{}.csv", output_base.unwrap_or("terminus_diff"));
    let mut file = File::create(&filename)?;
    writeln!(file, "url,method,port,old_status,new_status,status_changed,indicators_changed,headers_changed,body_changed,arbitrary_method_delta")?;
    for entry in &report.changed_endpoints {
        writeln!(
            file,
            "{},{},{},{},{},{},{},{},{},{}",
            entry.url,
            entry.method,
            entry.port,
            entry.old_status.unwrap_or(0),
            entry.new_status.unwrap_or(0),
            entry.status_changed,
            entry.indicators_changed,
            entry.headers_changed,
            entry.body_changed,
            entry.arbitrary_method_delta
        )?;
    }
    eprintln!("Results written to {}", filename);
    Ok(())
}

fn render_html(report: &DiffReport, output_base: Option<&str>) -> Result<()> {
    let filename = format!("{}.html", output_base.unwrap_or("terminus_diff"));
    let mut html = String::from("<html><body><h1>Terminus Diff</h1>");
    html.push_str(&format!("<p>Base: {}</p><p>Compare: {}</p>", report.base_id, report.compare_id));
    html.push_str("<h2>Changed Endpoints</h2><table><tr><th>URL</th><th>Method</th><th>Port</th><th>Old Status</th><th>New Status</th></tr>");
    for entry in &report.changed_endpoints {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            entry.url,
            entry.method,
            entry.port,
            entry.old_status.unwrap_or(0),
            entry.new_status.unwrap_or(0)
        ));
    }
    html.push_str("</table></body></html>");
    std::fs::write(&filename, html)?;
    eprintln!("Results written to {}", filename);
    Ok(())
}
