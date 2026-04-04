use crate::models::ScanResult;

#[derive(Debug, Clone)]
pub struct OutputRow {
    pub url: String,
    pub method: String,
    pub arbitrary_method_used: Option<String>,
    pub status: u16,
    pub port: u16,
    pub headers: Option<String>,
    pub error: Option<String>,
    #[allow(dead_code)]
    pub body_preview: Option<String>,
    pub request_headers: Option<String>,
    pub response_body: Option<String>,
    pub indicators: Vec<String>,
}

impl OutputRow {
    pub fn from_scan(result: &ScanResult, indicators: Vec<String>) -> Self {
        Self {
            url: result.url.clone(),
            method: result.method.clone(),
            arbitrary_method_used: result.arbitrary_method_used.clone(),
            status: result.status,
            port: result.port,
            headers: result.headers.clone(),
            error: result.error.clone(),
            body_preview: result.body_preview.clone(),
            request_headers: result.request_headers.clone(),
            response_body: result.response_body.clone(),
            indicators,
        }
    }
}
