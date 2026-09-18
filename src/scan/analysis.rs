use regex::Regex;
use std::collections::HashSet;

use crate::models::SecurityHeaders;
use crate::scan::http::header_value;

pub fn extract_links_from_body(body: &str) -> Vec<String> {
    let mut links = HashSet::new();

    let url_pattern = Regex::new(r#"https?://[^\s<>"{}|\\^`\[\]]+"#).unwrap();
    let href_pattern = Regex::new(r#"href=["']([^"']+)["']"#).unwrap();
    let src_pattern = Regex::new(r#"src=["']([^"']+)["']"#).unwrap();

    for capture in url_pattern.find_iter(body) {
        links.insert(capture.as_str().to_string());
    }

    for capture in href_pattern.captures_iter(body) {
        if let Some(url) = capture.get(1) {
            links.insert(url.as_str().to_string());
        }
    }

    for capture in src_pattern.captures_iter(body) {
        if let Some(url) = capture.get(1) {
            links.insert(url.as_str().to_string());
        }
    }

    links.into_iter().collect()
}

pub fn analyze_security_headers(headers: &[(String, String)]) -> SecurityHeaders {
    let mut missing = Vec::new();
    let mut present = Vec::new();
    let mut issues = Vec::new();

    let security_header_checks = vec![
        ("content-security-policy", "Content-Security-Policy"),
        ("strict-transport-security", "Strict-Transport-Security (HSTS)"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("x-xss-protection", "X-XSS-Protection"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
    ];

    for (header_name, display_name) in security_header_checks {
        if let Some(value) = header_value(headers, header_name) {
            present.push(display_name.to_string());

            match header_name {
                "content-security-policy" => {
                    if value.contains("'unsafe-inline'") || value.contains("'unsafe-eval'") {
                        issues.push(format!("CSP contains unsafe directives: {}", value));
                    }
                }
                "x-frame-options" => {
                    let lower = value.to_lowercase();
                    if !lower.contains("deny") && !lower.contains("sameorigin") {
                        issues.push(format!("Weak X-Frame-Options: {}", value));
                    }
                }
                "strict-transport-security" if !value.contains("max-age") => {
                    issues.push("HSTS missing max-age directive".to_string());
                }
                _ => {}
            }
        } else {
            missing.push(display_name.to_string());
        }
    }

    // A version token is two or more dot-separated numeric groups (e.g. 1.21.4)
    // or at least a major.minor pair. Compiled once and reused below.
    let version_pattern = Regex::new(r"\d+\.\d+").unwrap();

    // server / x-powered-by only "expose version information" when the value
    // actually carries a version token. A bare software name (e.g. `openresty`)
    // is a softer software-disclosure note, not a version leak.
    if let Some(value) = header_value(headers, "server") {
        if version_pattern.is_match(value) {
            issues.push("Server header exposes version information".to_string());
        } else {
            issues.push("Server software disclosed (no version)".to_string());
        }
    }

    if let Some(value) = header_value(headers, "x-powered-by") {
        if version_pattern.is_match(value) {
            issues.push("X-Powered-By header exposes technology stack".to_string());
        } else {
            issues.push("Technology stack disclosed (no version)".to_string());
        }
    }

    // x-aspnet-version is always a version string.
    if header_value(headers, "x-aspnet-version").is_some() {
        issues.push("X-AspNet-Version header exposes framework version".to_string());
    }

    if let Some(cors) = header_value(headers, "access-control-allow-origin") {
        if cors == "*" {
            issues.push("CORS allows all origins (*)".to_string());
        }
    }

    SecurityHeaders {
        missing,
        present,
        issues,
    }
}

pub fn detect_error_messages(body: &str) -> Vec<String> {
    let mut errors = Vec::new();

    let error_patterns = vec![
        (r"SQLException|SQL syntax|mysql_fetch|mysql_num_rows|mysql_query", "SQL Error"),
        (r"ORA-[0-9]+", "Oracle Error"),
        (r"com\\.mysql\\.jdbc\\.exceptions", "MySQL JDBC Exception"),
        (r"SQLSTATE\\[\\d+\\]", "SQLSTATE Error"),
        (r"Microsoft OLE DB Provider", "MS SQL Error"),
        (r"Unclosed quotation mark", "SQL Injection Error"),
        (r"System\\.Data\\.SqlClient", ".NET SQL Client Error"),
        (r"psql: FATAL", "PostgreSQL Error"),
        (r"Warning: mysql_", "MySQL Warning"),
        (r"java\\.sql\\.SQLException", "Java SQL Exception"),
        (r"com\\.mysql\\.jdbc\\.exceptions", "MySQL JDBC Exception"),
        (r"macromedia\\.jdbc\\.sqlserver", "SQL Server JDBC Exception"),
        (r"javax\\.servlet\\.ServletException", "Java Servlet Exception"),
        (r"Traceback \\(most recent call last\\)", "Python Traceback"),
        (r"Stack trace", "Stack Trace"),
        (r"Fatal error", "Fatal Error"),
        (r"Notice: Undefined variable", "PHP Notice"),
        (r"Warning: include\\(", "PHP Include Warning"),
        (r"Undefined index", "PHP Undefined Index"),
        (r"System\\.NullReferenceException", ".NET Null Reference"),
        (r"at java\\.", "Java Stack Trace"),
        (r"Microsoft VBScript runtime error", "VBScript Error"),
        (r"Application Error", "Application Error"),
        (r"Internal Server Error", "500 Error"),
    ];

    for (pattern, description) in error_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(body) {
                errors.push(description.to_string());
            }
        }
    }

    errors
}

pub fn check_reflection(body: &str, marker: &str) -> bool {
    if body.contains(marker) {
        return true;
    }

    let reflection_indicators = vec![
        r"document\\.write\\(",
        r"innerHTML\\s*=",
        r"outerHTML\\s*=",
        r"document\\.cookie",
        r"eval\\(",
        r"setTimeout\\(",
        r"setInterval\\(",
        r"onerror\\s*=",
        r"onload\\s*=",
        r"onclick\\s*=",
        r"onmouseover\\s*=",
        r"onfocus\\s*=",
        r"onblur\\s*=",
        r"onchange\\s*=",
    ];

    for pattern in &reflection_indicators {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(body) {
                return true;
            }
        }
    }

    if body.contains("?") && (body.contains("=") || body.contains("&")) {
        let param_pattern = Regex::new(r"[?&](\\w+)=([^&\\s<>]+)").unwrap();
        if param_pattern.is_match(body) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(name.to_string(), value.to_string())]
    }

    #[test]
    fn server_without_version_yields_soft_note() {
        let result = analyze_security_headers(&hdr("Server", "openresty"));
        assert!(result
            .issues
            .contains(&"Server software disclosed (no version)".to_string()));
        assert!(!result
            .issues
            .iter()
            .any(|i| i.contains("exposes version information")));
    }

    #[test]
    fn server_with_version_yields_version_information_issue() {
        let result = analyze_security_headers(&hdr("Server", "openresty/1.21.4"));
        assert!(result
            .issues
            .contains(&"Server header exposes version information".to_string()));
        assert!(!result
            .issues
            .iter()
            .any(|i| i.contains("no version")));
    }

    #[test]
    fn x_powered_by_without_version_yields_soft_note() {
        let result = analyze_security_headers(&hdr("X-Powered-By", "Express"));
        assert!(result
            .issues
            .contains(&"Technology stack disclosed (no version)".to_string()));
    }
}
