use anyhow::{Context, Result};
use std::collections::HashMap;

use crate::models::ScanResult;

#[derive(Debug)]
pub struct DiffResult {
    pub new_endpoints: Vec<ScanResult>,
    pub removed_endpoints: Vec<ScanResult>,
    pub status_changes: Vec<(ScanResult, ScanResult)>,
}

pub fn run_diff(old_file: &str, new_file: &str) -> Result<()> {
    let old_results = load_previous_scan(old_file)?;
    let new_results = load_previous_scan(new_file)?;
    let diff = compute_diff(&old_results, &new_results);
    display_diff(&diff);
    Ok(())
}

pub fn load_previous_scan(filename: &str) -> Result<Vec<ScanResult>> {
    let content = std::fs::read_to_string(filename)
        .with_context(|| format!("Cannot read diff file: {}", filename))?;
    let results: Vec<ScanResult> = serde_json::from_str(&content)
        .context("Failed to parse previous scan results. File must be in JSON format.")?;
    Ok(results)
}

pub fn compute_diff(old_results: &[ScanResult], new_results: &[ScanResult]) -> DiffResult {
    let mut old_map: HashMap<String, &ScanResult> = HashMap::new();
    for result in old_results {
        let key = format!("{}:{}:{}", result.url, result.method, result.port);
        old_map.insert(key, result);
    }

    let mut new_map: HashMap<String, &ScanResult> = HashMap::new();
    for result in new_results {
        let key = format!("{}:{}:{}", result.url, result.method, result.port);
        new_map.insert(key, result);
    }

    let mut diff = DiffResult {
        new_endpoints: Vec::new(),
        removed_endpoints: Vec::new(),
        status_changes: Vec::new(),
    };

    for (key, new_result) in &new_map {
        if !old_map.contains_key(key) {
            diff.new_endpoints.push((*new_result).clone());
        }
    }

    for (key, old_result) in &old_map {
        if let Some(new_result) = new_map.get(key) {
            if old_result.status != new_result.status {
                diff.status_changes.push(((*old_result).clone(), (*new_result).clone()));
            }
        } else {
            diff.removed_endpoints.push((*old_result).clone());
        }
    }

    diff
}

pub fn display_diff(diff: &DiffResult) {
    println!("\n{}", "=".repeat(80));
    println!("TERMINUS SCAN DIFF RESULTS");
    println!("{}\n", "=".repeat(80));

    if !diff.new_endpoints.is_empty() {
        println!("NEW ENDPOINTS ({}):", diff.new_endpoints.len());
        for result in &diff.new_endpoints {
            println!("  [+] {}:{} {} → Status {}",
                result.url, result.port, result.method, result.status);
        }
        println!();
    }

    if !diff.removed_endpoints.is_empty() {
        println!("REMOVED ENDPOINTS ({}):", diff.removed_endpoints.len());
        for result in &diff.removed_endpoints {
            println!("  [-] {}:{} {} (was Status {})",
                result.url, result.port, result.method, result.status);
        }
        println!();
    }

    if !diff.status_changes.is_empty() {
        println!("STATUS CHANGES ({}):", diff.status_changes.len());
        for (old, new) in &diff.status_changes {
            println!("  [~] {}:{} {} → Status {} → {}",
                new.url, new.port, new.method, old.status, new.status);
        }
        println!();
    }

    if diff.new_endpoints.is_empty() && diff.removed_endpoints.is_empty() && diff.status_changes.is_empty() {
        println!("No differences found between scans.\n");
    }

    println!("{}\n", "=".repeat(80));
}
