use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Stdout,
    Txt,
    Json,
    Html,
    Csv,
    Sqlite,
    All,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "stdout" => Ok(OutputFormat::Stdout),
            "txt" => Ok(OutputFormat::Txt),
            "json" => Ok(OutputFormat::Json),
            "html" => Ok(OutputFormat::Html),
            "csv" => Ok(OutputFormat::Csv),
            "sqlite" | "db" => Ok(OutputFormat::Sqlite),
            "all" => Ok(OutputFormat::All),
            _ => Err(format!("Invalid output format: {}", s)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanResult {
    pub url: String,
    pub method: String,
    pub arbitrary_method_used: Option<String>,
    pub arbitrary_method_accepted: Option<bool>,
    pub method_confusion_suspected: Option<bool>,
    pub status: u16,
    pub port: u16,
    pub headers: Option<String>,
    pub error: Option<String>,
    pub body_preview: Option<String>,
    pub matched_patterns: Option<Vec<String>>,
    pub extracted_links: Option<Vec<String>>,
    pub security_headers: Option<SecurityHeaders>,
    pub detected_errors: Option<Vec<String>>,
    pub reflection_detected: Option<bool>,
    pub http2_desync: Option<Http2DesyncResult>,
    pub host_injection: Option<HostInjectionResult>,
    pub xff_bypass: Option<XffBypassResult>,
    pub csrf_result: Option<CsrfResult>,
    pub ssrf_result: Option<SsrfResult>,
    pub request_headers: Option<String>,
    pub response_body: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Http2DesyncResult {
    pub desync_detected: bool,
    pub http1_status: u16,
    pub http2_status: u16,
    pub status_mismatch: bool,
    pub response_diff: Option<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityHeaders {
    pub missing: Vec<String>,
    pub present: Vec<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostInjectionResult {
    pub injection_suspected: bool,
    pub reflected_in_location: bool,
    pub reflected_in_vary: bool,
    pub reflected_in_set_cookie: bool,
    pub injected_host: String,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct XffBypassResult {
    pub bypass_suspected: bool,
    pub baseline_status: u16,
    pub xff_status: u16,
    pub status_changed: bool,
    pub response_diff: Option<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CsrfResult {
    pub csrf_suspected: bool,
    pub accepts_without_origin: bool,
    pub accepts_with_fake_origin: bool,
    pub missing_samesite: bool,
    pub missing_x_frame_options: bool,
    pub missing_csp: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SsrfResult {
    pub ssrf_suspected: bool,
    pub vulnerable_params: Vec<String>,
    pub tested_payloads: Vec<String>,
    pub response_indicators: Vec<String>,
    pub issues: Vec<String>,
}
