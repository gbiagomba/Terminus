use regex::Regex;
use std::str::FromStr;
use url::Url;
use http::header::{HeaderName, HeaderValue};

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

pub fn normalize_method(method: &str) -> String {
    let trimmed = method.trim();
    if trimmed.is_empty() {
        return "GET".to_string();
    }

    trimmed.to_uppercase()
}

pub fn flatten_headers(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k, v))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn parse_header(header_str: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = header_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }

    let key = parts[0].trim();
    let value = parts[1].trim();

    match (HeaderName::from_str(key), HeaderValue::from_str(value)) {
        (Ok(_), Ok(_)) => Some((key.to_string(), value.to_string())),
        _ => None,
    }
}

pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub fn upsert_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    let mut replaced = false;
    for (key, val) in headers.iter_mut() {
        if key.eq_ignore_ascii_case(name) {
            *val = value.to_string();
            replaced = true;
            break;
        }
    }

    if !replaced {
        headers.push((name.to_string(), value.to_string()));
    }
}

pub fn remove_header(headers: &mut Vec<(String, String)>, name: &str) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
}

pub fn resolve_redirect_target(base_url: &str, redirect_target: &str) -> Option<String> {
    let trimmed = redirect_target.trim().trim_matches(|c| c == '"' || c == '\'' || c == '`');
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(parsed) = Url::parse(trimmed) {
        return Some(parsed.to_string());
    }

    Url::parse(base_url)
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
    headers: &[(String, String)],
    response_body: Option<&str>,
) -> Option<String> {
    if let Some(location) = header_value(headers, "location") {
        if let Some(resolved) = resolve_redirect_target(base_url, location) {
            return Some(resolved);
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
        let headers = Vec::new();
        let redirect = extract_redirect_target(
            "https://example.com/app/index.html",
            &headers,
            Some(r#"<script>location.assign('../home');</script>"#),
        );

        assert_eq!(redirect.as_deref(), Some("https://example.com/home"));
    }

    #[test]
    fn prefers_location_header_over_js_redirect() {
        let headers = vec![("Location".to_string(), "/http-redirect".to_string())];

        let redirect = extract_redirect_target(
            "https://example.com/start",
            &headers,
            Some(r#"<script>window.location='/js-redirect';</script>"#),
        );

        assert_eq!(redirect.as_deref(), Some("https://example.com/http-redirect"));
    }
}
