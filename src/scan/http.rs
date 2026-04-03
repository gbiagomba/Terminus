use regex::Regex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use std::str::FromStr;

pub fn build_full_url(url: &str, port: u16) -> String {
    if url.contains("://") && url.split("://").nth(1).map_or(false, |host_part| host_part.contains(':')) {
        return url.to_string();
    }

    let is_https = url.starts_with("https://");
    let is_http = url.starts_with("http://");
    let is_standard_port = (is_https && port == 443) || (is_http && port == 80);

    if is_standard_port {
        url.to_string()
    } else {
        format!("{}:{}", url, port)
    }
}

pub fn build_reqwest_method(method: &str) -> Method {
    Method::from_bytes(method.as_bytes()).unwrap_or_else(|_| {
        let sanitized: String = method
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        Method::from_bytes(sanitized.as_bytes()).unwrap_or(Method::GET)
    })
}

pub fn flatten_headers(headers: &HeaderMap) -> String {
    headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k, v.to_str().unwrap_or("INVALID")))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn parse_header(header_str: &str) -> Option<(HeaderName, HeaderValue)> {
    let parts: Vec<&str> = header_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }

    let key = parts[0].trim();
    let value = parts[1].trim();

    match (HeaderName::from_str(key), HeaderValue::from_str(value)) {
        (Ok(name), Ok(val)) => Some((name, val)),
        _ => None,
    }
}

pub fn resolve_redirect_target(base_url: &str, redirect_target: &str) -> Option<String> {
    let trimmed = redirect_target.trim().trim_matches(|c| c == '"' || c == '\'' || c == '`');
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(parsed) = reqwest::Url::parse(trimmed) {
        return Some(parsed.to_string());
    }

    reqwest::Url::parse(base_url)
        .ok()
        .and_then(|base| base.join(trimmed).ok())
        .map(|url| url.to_string())
}

pub fn extract_js_redirect_target(body: &str) -> Option<String> {
    let patterns = [
        r#"(?is)(?:window|document|self|top)?\.?location(?:\.href)?\s*=\s*["'`]([^"'`]+)["'`]"#,
        r#"(?is)(?:window|document|self|top)?\.?location\.(?:assign|replace)\(\s*["'`]([^"'`]+)["'`]\s*\)"#,
        r#"(?is)window\.navigate\(\s*["'`]([^"'`]+)["'`]\s*\)"#,
    ];

    for pattern in patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if let Some(captures) = regex.captures(body) {
                if let Some(target) = captures.get(1) {
                    return Some(target.as_str().to_string());
                }
            }
        }
    }

    None
}

pub fn extract_redirect_target(
    base_url: &str,
    headers: &HeaderMap,
    response_body: Option<&str>,
) -> Option<String> {
    if let Some(location) = headers.get(reqwest::header::LOCATION) {
        if let Ok(location_str) = location.to_str() {
            if let Some(resolved) = resolve_redirect_target(base_url, location_str) {
                return Some(resolved);
            }
        }
    }

    response_body
        .and_then(extract_js_redirect_target)
        .and_then(|target| resolve_redirect_target(base_url, &target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_js_location_href_redirect() {
        let body = r#"<script>window.location.href = "/dashboard";</script>"#;
        let target = extract_js_redirect_target(body);
        assert_eq!(target.as_deref(), Some("/dashboard"));
    }

    #[test]
    fn extracts_js_location_replace_redirect() {
        let body = r#"<script>window.location.replace('https://example.com/login');</script>"#;
        let target = extract_js_redirect_target(body);
        assert_eq!(target.as_deref(), Some("https://example.com/login"));
    }

    #[test]
    fn resolves_relative_js_redirect_against_base_url() {
        let headers = HeaderMap::new();
        let redirect = extract_redirect_target(
            "https://example.com/app/index.html",
            &headers,
            Some(r#"<script>location.assign('../home');</script>"#),
        );

        assert_eq!(redirect.as_deref(), Some("https://example.com/home"));
    }

    #[test]
    fn prefers_location_header_over_js_redirect() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::LOCATION,
            HeaderValue::from_static("/http-redirect"),
        );

        let redirect = extract_redirect_target(
            "https://example.com/start",
            &headers,
            Some(r#"<script>window.location='/js-redirect';</script>"#),
        );

        assert_eq!(redirect.as_deref(), Some("https://example.com/http-redirect"));
    }
}
