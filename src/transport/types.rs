use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
    Http3,
}

#[derive(Debug, Clone)]
pub struct TerminusRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
    pub version: Option<HttpVersion>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TerminusResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub version: String,
    pub remote_addr: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub allow_insecure: bool,
    pub proxy: Option<String>,
    pub http_version: HttpVersion,
    pub timeout: Option<Duration>,
}
