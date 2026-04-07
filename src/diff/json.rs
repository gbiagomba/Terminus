use anyhow::{Context, Result};

use crate::models::ScanResult;

pub fn load_json(filename: &str) -> Result<Vec<ScanResult>> {
    let content = std::fs::read_to_string(filename)
        .with_context(|| format!("Cannot read diff file: {}", filename))?;
    let results: Vec<ScanResult> = serde_json::from_str(&content)
        .context("Failed to parse previous scan results. File must be in JSON format.")?;
    Ok(results)
}
