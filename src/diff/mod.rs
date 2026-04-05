use anyhow::Result;
use clap::ArgMatches;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod json;
mod render;
mod sqlite;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub key: String,
    pub url: String,
    pub method: String,
    pub port: u16,
    pub old_status: Option<u16>,
    pub new_status: Option<u16>,
    pub status_changed: bool,
    pub old_indicators: Vec<String>,
    pub new_indicators: Vec<String>,
    pub indicators_changed: bool,
    pub old_headers_hash: Option<String>,
    pub new_headers_hash: Option<String>,
    pub headers_changed: bool,
    pub old_body_hash: Option<String>,
    pub new_body_hash: Option<String>,
    pub body_changed: bool,
    pub arbitrary_method_delta: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub base_id: String,
    pub compare_id: String,
    pub new_endpoints: Vec<DiffEntry>,
    pub removed_endpoints: Vec<DiffEntry>,
    pub changed_endpoints: Vec<DiffEntry>,
    pub method_behavior_changes: Vec<String>,
}

pub fn run_diff(base: &str, compare: &str, matches: &ArgMatches) -> Result<()> {
    let base_results = load_results(base)?;
    let compare_results = load_results(compare)?;

    let report = compute_diff(base, compare, &base_results, &compare_results);

    let format = matches
        .get_one::<String>("output-format")
        .map(|s| s.as_str())
        .unwrap_or("stdout");
    let output_base = matches.get_one::<String>("output").map(|s| s.as_str());

    render::render_diff(&report, format, output_base)?;
    Ok(())
}

pub fn display_diff(report: &DiffReport) -> Result<()> {
    render::render_diff(report, "stdout", None)
}

fn load_results(path: &str) -> Result<Vec<crate::models::ScanResult>> {
    if path.ends_with(".db") || path.ends_with(".sqlite") {
        sqlite::load_sqlite(path)
    } else {
        json::load_json(path)
    }
}

pub fn compute_diff(base_id: &str, compare_id: &str, base_results: &[crate::models::ScanResult], compare_results: &[crate::models::ScanResult]) -> DiffReport {
    let mut base_map: BTreeMap<String, &crate::models::ScanResult> = BTreeMap::new();
    let mut compare_map: BTreeMap<String, &crate::models::ScanResult> = BTreeMap::new();

    for result in base_results {
        let key = format!("{}:{}:{}", result.url, result.method, result.port);
        base_map.insert(key, result);
    }

    for result in compare_results {
        let key = format!("{}:{}:{}", result.url, result.method, result.port);
        compare_map.insert(key, result);
    }

    let mut new_endpoints = Vec::new();
    let mut removed_endpoints = Vec::new();
    let mut changed_endpoints = Vec::new();

    let all_keys: BTreeSet<String> = base_map.keys().chain(compare_map.keys()).cloned().collect();

    for key in all_keys {
        let old = base_map.get(&key).copied();
        let new = compare_map.get(&key).copied();

        match (old, new) {
            (None, Some(new_res)) => {
                new_endpoints.push(build_entry(&key, None, Some(new_res)));
            }
            (Some(old_res), None) => {
                removed_endpoints.push(build_entry(&key, Some(old_res), None));
            }
            (Some(old_res), Some(new_res)) => {
                let entry = build_entry(&key, Some(old_res), Some(new_res));
                if entry.status_changed || entry.indicators_changed || entry.headers_changed || entry.body_changed || entry.arbitrary_method_delta {
                    changed_endpoints.push(entry);
                }
            }
            _ => {}
        }
    }

    let method_behavior_changes = compare_method_sets(base_results, compare_results);

    DiffReport {
        base_id: base_id.to_string(),
        compare_id: compare_id.to_string(),
        new_endpoints,
        removed_endpoints,
        changed_endpoints,
        method_behavior_changes,
    }
}

pub fn compute_diff_inline(base_results: &[crate::models::ScanResult], compare_results: &[crate::models::ScanResult]) -> DiffReport {
    compute_diff("inline_old", "inline_new", base_results, compare_results)
}

pub fn load_results_for_path(path: &str) -> Result<Vec<crate::models::ScanResult>> {
    load_results(path)
}

fn build_entry(key: &str, old: Option<&crate::models::ScanResult>, new: Option<&crate::models::ScanResult>) -> DiffEntry {
    let (url, method, port) = if let Some(res) = new.or(old) {
        (res.url.clone(), res.method.clone(), res.port)
    } else {
        (String::new(), String::new(), 0)
    };

    let old_indicators = old.map(crate::output::collect_vuln_indicators).unwrap_or_default();
    let new_indicators = new.map(crate::output::collect_vuln_indicators).unwrap_or_default();

    let indicators_changed = old_indicators != new_indicators;

    let old_headers_hash = old.and_then(|r| r.headers.as_deref()).map(hash_string);
    let new_headers_hash = new.and_then(|r| r.headers.as_deref()).map(hash_string);
    let headers_changed = old_headers_hash != new_headers_hash;

    let old_body_hash = old.and_then(|r| r.response_body.as_deref()).map(hash_string);
    let new_body_hash = new.and_then(|r| r.response_body.as_deref()).map(hash_string);
    let body_changed = old_body_hash != new_body_hash;

    let old_status = old.map(|r| r.status);
    let new_status = new.map(|r| r.status);
    let status_changed = old_status != new_status;

    let arbitrary_method_delta = old
        .and_then(|r| r.arbitrary_method_used.clone())
        != new.and_then(|r| r.arbitrary_method_used.clone());

    DiffEntry {
        key: key.to_string(),
        url,
        method,
        port,
        old_status,
        new_status,
        status_changed,
        old_indicators,
        new_indicators,
        indicators_changed,
        old_headers_hash,
        new_headers_hash,
        headers_changed,
        old_body_hash,
        new_body_hash,
        body_changed,
        arbitrary_method_delta,
    }
}

fn compare_method_sets(base_results: &[crate::models::ScanResult], compare_results: &[crate::models::ScanResult]) -> Vec<String> {
    let mut base_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut compare_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for r in base_results {
        base_map.entry(format!("{}:{}", r.url, r.port)).or_default().insert(r.method.clone());
    }

    for r in compare_results {
        compare_map.entry(format!("{}:{}", r.url, r.port)).or_default().insert(r.method.clone());
    }

    let mut changes = Vec::new();
    let keys: BTreeSet<String> = base_map.keys().chain(compare_map.keys()).cloned().collect();
    for key in keys {
        let old = base_map.get(&key).cloned().unwrap_or_default();
        let new = compare_map.get(&key).cloned().unwrap_or_default();
        if old != new {
            changes.push(format!("{}: methods changed (old: {:?}, new: {:?})", key, old, new));
        }
    }

    changes
}

fn hash_string(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ScanResult;

    fn sample(url: &str, status: u16) -> ScanResult {
        ScanResult {
            url: url.to_string(),
            method: "GET".to_string(),
            arbitrary_method_used: None,
            arbitrary_method_accepted: None,
            method_confusion_suspected: None,
            status,
            port: 443,
            headers: None,
            error: None,
            body_preview: None,
            matched_patterns: None,
            extracted_links: None,
            security_headers: None,
            detected_errors: None,
            reflection_detected: None,
            http2_desync: None,
            host_injection: None,
            xff_bypass: None,
            csrf_result: None,
            ssrf_result: None,
            request_headers: None,
            response_body: None,
        }
    }

    #[test]
    fn detects_status_changes() {
        let old = vec![sample("https://example.com", 200)];
        let new = vec![sample("https://example.com", 404)];
        let report = compute_diff_inline(&old, &new);
        assert_eq!(report.changed_endpoints.len(), 1);
        assert!(report.changed_endpoints[0].status_changed);
    }

    #[test]
    fn test_diff_detects_status_change() {
        let base = vec![sample("https://target.example.com/api", 200)];
        let compare = vec![sample("https://target.example.com/api", 500)];
        let report = compute_diff_inline(&base, &compare);
        assert_eq!(report.changed_endpoints.len(), 1);
        assert!(report.changed_endpoints[0].status_changed);
        assert_eq!(report.changed_endpoints[0].old_status, Some(200));
        assert_eq!(report.changed_endpoints[0].new_status, Some(500));
    }

    #[test]
    fn test_diff_detects_new_endpoint() {
        let base: Vec<ScanResult> = vec![];
        let compare = vec![sample("https://new.example.com/login", 200)];
        let report = compute_diff_inline(&base, &compare);
        assert_eq!(report.new_endpoints.len(), 1);
        assert_eq!(report.new_endpoints[0].url, "https://new.example.com/login");
        assert!(report.removed_endpoints.is_empty());
    }

    #[test]
    fn test_diff_detects_removed_endpoint() {
        let base = vec![sample("https://old.example.com/admin", 403)];
        let compare: Vec<ScanResult> = vec![];
        let report = compute_diff_inline(&base, &compare);
        assert_eq!(report.removed_endpoints.len(), 1);
        assert_eq!(report.removed_endpoints[0].url, "https://old.example.com/admin");
        assert!(report.new_endpoints.is_empty());
    }
}
