use anyhow::{Context, Result};
use clap::{Arg, ArgAction, Command};
use std::io::IsTerminal;
use regex::Regex;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use reqwest::blocking::ClientBuilder;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode, Version};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process;
use std::str::FromStr;

const HTTP_METHODS: &[&str] = &[
    "ACL", "ARBITRARY", "BASELINE-CONTROL", "BCOPY", "BDELETE", "BIND", "BMOVE", "BPROPFIND",
    "BPROPPATCH", "CHECKIN", "CHECKOUT", "CONNECT", "COPY", "DEBUG", "DELETE", "GET", "HEAD",
    "INDEX", "LABEL", "LINK", "LOCK", "MERGE", "MKACTIVITY", "MKCALENDAR", "MKCOL",
    "MKREDIRECTREF", "MKWORKSPACE", "MOVE", "NOTIFY", "OPTIONS", "ORDERPATCH", "PATCH", "POLL",
    "POST", "PROPFIND", "PROPPATCH", "PUT", "REBIND", "REPORT", "RPC_IN_DATA", "RPC_OUT_DATA",
    "SEARCH", "SUBSCRIBE", "TRACE", "TRACK", "UNBIND", "UNCHECKOUT", "UNLINK", "UNLOCK",
    "UNSUBSCRIBE", "UPDATE", "UPDATEREDIRECTREF", "VERSION-CONTROL", "X-MS-ENUMATTS"
];

#[derive(Debug, Clone, Copy)]
enum OutputFormat {
    Stdout,
    Txt,
    Json,
    Html,
    Csv,
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
            "all" => Ok(OutputFormat::All),
            _ => Err(format!("Invalid output format: {}", s)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ScanResult {
    url: String,
    method: String,
    status: u16,
    port: u16,
    headers: Option<String>,
    error: Option<String>,
    body_preview: Option<String>,
    matched_patterns: Option<Vec<String>>,
    extracted_links: Option<Vec<String>>,
    security_headers: Option<SecurityHeaders>,
    detected_errors: Option<Vec<String>>,
    reflection_detected: Option<bool>,
    http2_desync: Option<Http2DesyncResult>,
    host_injection: Option<HostInjectionResult>,
    xff_bypass: Option<XffBypassResult>,
    csrf_result: Option<CsrfResult>,
    ssrf_result: Option<SsrfResult>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Http2DesyncResult {
    desync_detected: bool,
    http1_status: u16,
    http2_status: u16,
    status_mismatch: bool,
    response_diff: Option<String>,
    issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SecurityHeaders {
    missing: Vec<String>,
    present: Vec<String>,
    issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct HostInjectionResult {
    injection_suspected: bool,
    reflected_in_location: bool,
    reflected_in_vary: bool,
    reflected_in_set_cookie: bool,
    injected_host: String,
    issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct XffBypassResult {
    bypass_suspected: bool,
    baseline_status: u16,
    xff_status: u16,
    status_changed: bool,
    response_diff: Option<String>,
    issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CsrfResult {
    csrf_suspected: bool,
    accepts_without_origin: bool,
    accepts_with_fake_origin: bool,
    missing_samesite: bool,
    missing_x_frame_options: bool,
    missing_csp: bool,
    issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SsrfResult {
    ssrf_suspected: bool,
    vulnerable_params: Vec<String>,
    tested_payloads: Vec<String>,
    response_indicators: Vec<String>,
    issues: Vec<String>,
}

#[derive(Debug)]
struct DiffResult {
    new_endpoints: Vec<ScanResult>,
    removed_endpoints: Vec<ScanResult>,
    status_changes: Vec<(ScanResult, ScanResult)>, // (old, new)
}

struct RateLimiter {
    requests_per_second: f64,
    last_request: std::time::Instant,
}

impl RateLimiter {
    fn new(rate_str: &str) -> Result<Self> {
        let parts: Vec<&str> = rate_str.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid rate format. Use format like '10/s' or '100/m'");
        }

        let count: f64 = parts[0].parse()
            .context("Invalid rate count")?;

        let requests_per_second = match parts[1] {
            "s" => count,
            "m" => count / 60.0,
            "h" => count / 3600.0,
            _ => anyhow::bail!("Invalid rate unit. Use 's' (seconds), 'm' (minutes), or 'h' (hours)"),
        };

        Ok(RateLimiter {
            requests_per_second,
            last_request: std::time::Instant::now(),
        })
    }

    fn wait(&mut self) {
        let interval = std::time::Duration::from_secs_f64(1.0 / self.requests_per_second);
        let elapsed = self.last_request.elapsed();

        if elapsed < interval {
            std::thread::sleep(interval - elapsed);
        }

        self.last_request = std::time::Instant::now();
    }
}

fn main() -> Result<()> {
    let matches = Command::new("Terminus")
        .version("2.8.0")
        .about("URL testing with HTTP/2 desync detection, security analysis, and passive vulnerability detection")
        .arg(Arg::new("url").short('u').long("url").value_name("URL").help("Specify a single URL/IP to check"))
        .arg(Arg::new("file").short('f').long("file").value_name("FILE").help("Input file (URLs, nmap XML/greppable, testssl JSON, nuclei/katana JSON)"))
        .arg(Arg::new("method").short('X').long("method").value_name("METHOD").help("Specify the HTTP method to use (default: GET). Use ALL to test all methods"))
        .arg(Arg::new("port").short('p').long("port").value_name("PORTS").help("Comma-separated ports to connect to (e.g., 80,443)").use_value_delimiter(true))
        .arg(Arg::new("ipv6").short('6').long("ipv6").help("Enable IPv6 scanning").action(ArgAction::SetTrue))
        .arg(Arg::new("insecure").short('k').long("insecure").help("Allow insecure SSL connections").action(ArgAction::SetTrue))
        .arg(Arg::new("verbose").short('v').long("verbose").help("Enable verbose output with response headers").action(ArgAction::SetTrue))
        .arg(Arg::new("follow").short('L').long("follow").help("Follow HTTP redirects").action(ArgAction::SetTrue))
        .arg(Arg::new("output").short('o').long("output").value_name("FILE").help("Output file base name (extension added based on format)"))
        .arg(Arg::new("output-format").long("output-format").value_name("FORMAT").help("Output format: stdout, txt, json, html, csv, all (default: stdout)"))
        .arg(Arg::new("filter").short('F').long("filter-code").value_name("STATUS_CODE").help("Filter results by HTTP status code"))
        .arg(Arg::new("proxy").short('x').long("proxy").value_name("PROXY").help("Specify proxy URL (e.g., http://127.0.0.1:8080 for Burp)"))
        .arg(Arg::new("header").short('H').long("header").value_name("HEADER").action(ArgAction::Append).help("Add custom header (format: 'Name: Value'). Can be specified multiple times"))
        .arg(Arg::new("header-file").long("header-file").value_name("FILE").help("Read headers from file (one per line, format: 'Name: Value')"))
        .arg(Arg::new("cookie").short('b').long("cookie").value_name("COOKIE").help("Add cookie string (format: 'name1=value1; name2=value2')"))
        .arg(Arg::new("cookie-file").short('c').long("cookie-file").value_name("FILE").help("Read cookies from file"))
        .arg(Arg::new("http-version").long("http-version").value_name("VERSION").help("Force HTTP version (1.0, 1.1, or 2)"))
        .arg(Arg::new("diff").long("diff").value_name("FILE").help("Compare results with previous scan (JSON file)"))
        .arg(Arg::new("grep-response").long("grep-response").value_name("PATTERN").help("Search for pattern in response body (regex supported)"))
        .arg(Arg::new("rate-limit").long("rate-limit").value_name("RATE").help("Rate limit requests (e.g., '10/s', '100/m')"))
        .arg(Arg::new("random-delay").long("random-delay").value_name("RANGE").help("Random delay between requests in seconds (e.g., '1-5')"))
        .arg(Arg::new("check-body").long("check-body").help("Analyze response body content").action(ArgAction::SetTrue))
        .arg(Arg::new("extract-links").long("extract-links").help("Extract and display links from response body").action(ArgAction::SetTrue))
        .arg(Arg::new("check-security-headers").long("check-security-headers").help("Analyze security headers (CSP, HSTS, X-Frame-Options, etc.)").action(ArgAction::SetTrue))
        .arg(Arg::new("detect-errors").long("detect-errors").help("Detect verbose error messages (SQL, stack traces, etc.)").action(ArgAction::SetTrue))
        .arg(Arg::new("detect-reflection").long("detect-reflection").help("Check if input is reflected in response (passive XSS detection)").action(ArgAction::SetTrue))
        .arg(Arg::new("http2-desync-check").long("http2-desync-check").help("Test HTTP/2 to HTTP/1.1 downgrade handling (detects potential request smuggling)").action(ArgAction::SetTrue))
        .arg(Arg::new("detect-host-injection").long("detect-host-injection").help("Passively detect Host header injection vulnerabilities by checking response headers").action(ArgAction::SetTrue))
        .arg(Arg::new("detect-xff-bypass").long("detect-xff-bypass").help("Detect X-Forwarded-For bypass by comparing baseline and XFF requests").action(ArgAction::SetTrue))
        .arg(Arg::new("detect-csrf").long("detect-csrf").help("Passively detect potential CSRF vulnerabilities and missing protections").action(ArgAction::SetTrue))
        .arg(Arg::new("detect-ssrf").long("detect-ssrf").help("Passively detect potential SSRF vulnerabilities in URL parameters").action(ArgAction::SetTrue))
        .arg(Arg::new("scan-level").long("scan-level").value_name("LEVEL").help("Scan preset level: quick (basic), standard (security headers+errors+reflection), full (all features), vuln (all vulnerability detection)"))
        .arg(Arg::new("threads").short('t').long("threads").value_name("NUM").default_value("10").help("Number of concurrent threads for scanning (default: 10)"))
        .get_matches();

    let verbose = matches.get_flag("verbose");
    let allow_insecure = matches.get_flag("insecure");
    let follow_redirects = matches.get_flag("follow");

    // Parse thread count
    let thread_count: usize = matches.get_one::<String>("threads")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    // Configure Rayon thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build_global()
        .context("Failed to initialize thread pool")?;

    // Process scan level presets
    let scan_level = matches.get_one::<String>("scan-level").map(|s| s.as_str());

    // Apply preset defaults, but allow individual flags to override
    let preset_check_body = matches!(scan_level, Some("full"));
    let preset_extract_links = matches!(scan_level, Some("full"));
    let preset_check_security_headers = matches!(scan_level, Some("standard") | Some("full") | Some("vuln"));
    let preset_detect_errors = matches!(scan_level, Some("standard") | Some("full") | Some("vuln"));
    let preset_detect_reflection = matches!(scan_level, Some("standard") | Some("full") | Some("vuln"));
    let preset_http2_desync_check = matches!(scan_level, Some("full") | Some("vuln"));
    let preset_detect_host_injection = matches!(scan_level, Some("full") | Some("vuln"));
    let preset_detect_xff_bypass = matches!(scan_level, Some("full") | Some("vuln"));
    let preset_detect_csrf = matches!(scan_level, Some("full") | Some("vuln"));
    let preset_detect_ssrf = matches!(scan_level, Some("full") | Some("vuln"));

    // Individual flags override presets
    let check_body = matches.get_flag("check-body") || preset_check_body;
    let extract_links = matches.get_flag("extract-links") || preset_extract_links;
    let check_security_headers = matches.get_flag("check-security-headers") || preset_check_security_headers;
    let detect_errors = matches.get_flag("detect-errors") || preset_detect_errors;
    let detect_reflection = matches.get_flag("detect-reflection") || preset_detect_reflection;
    let http2_desync_check = matches.get_flag("http2-desync-check") || preset_http2_desync_check;
    let detect_host_injection = matches.get_flag("detect-host-injection") || preset_detect_host_injection;
    let detect_xff_bypass = matches.get_flag("detect-xff-bypass") || preset_detect_xff_bypass;
    let detect_csrf = matches.get_flag("detect-csrf") || preset_detect_csrf;
    let detect_ssrf = matches.get_flag("detect-ssrf") || preset_detect_ssrf;

    // Parse rate limiting
    let rate_limiter_option = if let Some(rate_str) = matches.get_one::<String>("rate-limit") {
        Some(RateLimiter::new(rate_str)?)
    } else {
        None
    };

    // Parse random delay range
    let random_delay_range = if let Some(delay_str) = matches.get_one::<String>("random-delay") {
        let parts: Vec<&str> = delay_str.split('-').collect();
        if parts.len() != 2 {
            eprintln!("Invalid random-delay format. Use format like '1-5'");
            process::exit(1);
        }
        let min: u64 = parts[0].parse().context("Invalid delay minimum")?;
        let max: u64 = parts[1].parse().context("Invalid delay maximum")?;
        Some((min, max))
    } else {
        None
    };

    // Parse grep pattern for response body matching
    let grep_pattern = matches.get_one::<String>("grep-response")
        .map(|p| Regex::new(p))
        .transpose()
        .context("Invalid regex pattern")?;

    // Parse proxy if provided
    let mut client_builder = ClientBuilder::new()
        .danger_accept_invalid_certs(allow_insecure)
        .redirect(if follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        });

    if let Some(proxy_url) = matches.get_one::<String>("proxy") {
        let proxy = reqwest::Proxy::all(proxy_url)
            .context("Failed to configure proxy")?;
        client_builder = client_builder.proxy(proxy);
    }

    // Set HTTP version if specified
    if let Some(version_str) = matches.get_one::<String>("http-version") {
        let version = match version_str.as_str() {
            "1.0" => Version::HTTP_10,
            "1.1" => Version::HTTP_11,
            "2" | "2.0" => Version::HTTP_2,
            _ => {
                eprintln!("Invalid HTTP version: {}. Supported: 1.0, 1.1, 2", version_str);
                process::exit(1);
            }
        };
        // Note: reqwest will attempt to use the specified version but may fall back
        if version == Version::HTTP_2 {
            client_builder = client_builder.http2_prior_knowledge();
        }
    }

    let client = client_builder
        .build()
        .context("Failed to build HTTP client")?;

    // Determine output format
    let output_format = matches
        .get_one::<String>("output-format")
        .and_then(|f| OutputFormat::from_str(f).ok())
        .unwrap_or(OutputFormat::Stdout);

    let ipv6_enabled = matches.get_flag("ipv6");

    // Collect URLs from various sources
    let urls = if let Some(url) = matches.get_one::<String>("url") {
        vec![url.to_string()]
    } else if let Some(file) = matches.get_one::<String>("file") {
        parse_input_file(file, ipv6_enabled)?
    } else if !io::stdin().is_terminal() {
        // Read from stdin (pipe support)
        read_stdin(ipv6_enabled)?
    } else {
        eprintln!("You must provide a URL (-u), file (-f), or pipe input via stdin");
        process::exit(1);
    };

    let methods = if let Some(m) = matches.get_one::<String>("method") {
        if m.eq_ignore_ascii_case("ALL") {
            HTTP_METHODS.iter().map(|s| s.to_string()).collect()
        } else {
            vec![m.to_string()]
        }
    } else {
        vec!["GET".to_string()]
    };

    let ports: Vec<u16> = matches
        .get_many::<String>("port")
        .unwrap_or_default()
        .filter_map(|p| p.parse::<u16>().ok())
        .collect();

    let filter_code = matches
        .get_one::<String>("filter")
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|num| StatusCode::from_u16(num).ok());

    let output_base = matches.get_one::<String>("output").map(|s| s.as_str());

    // Use Arc/Mutex for thread-safe rate limiter and results collection
    let rate_limiter = Arc::new(Mutex::new(rate_limiter_option));
    let results = Arc::new(Mutex::new(Vec::new()));

    // Parse headers from command line and file
    let mut custom_headers = HeaderMap::new();

    // Add headers from -H flag
    if let Some(headers) = matches.get_many::<String>("header") {
        for header in headers {
            if let Some((key, value)) = parse_header(header) {
                custom_headers.insert(key, value);
            } else {
                eprintln!("Warning: Invalid header format: {}", header);
            }
        }
    }

    // Add headers from file
    if let Some(header_file) = matches.get_one::<String>("header-file") {
        match read_lines(header_file) {
            Ok(lines) => {
                for line in lines {
                    if let Some((key, value)) = parse_header(&line) {
                        custom_headers.insert(key, value);
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to read header file: {}", e);
            }
        }
    }

    // Parse cookies
    let mut cookie_string = String::new();

    // Add cookie from command line
    if let Some(cookie) = matches.get_one::<String>("cookie") {
        cookie_string = cookie.clone();
    }

    // Add cookies from file
    if let Some(cookie_file) = matches.get_one::<String>("cookie-file") {
        match read_lines(cookie_file) {
            Ok(lines) => {
                let file_cookies = lines.join("; ");
                if !cookie_string.is_empty() {
                    cookie_string.push_str("; ");
                }
                cookie_string.push_str(&file_cookies);
            }
            Err(e) => {
                eprintln!("Warning: Failed to read cookie file: {}", e);
            }
        }
    }

    // Add cookie to headers if present
    if !cookie_string.is_empty() {
        if let Ok(cookie_value) = HeaderValue::from_str(&cookie_string) {
            custom_headers.insert(reqwest::header::COOKIE, cookie_value);
        } else {
            eprintln!("Warning: Invalid cookie format");
        }
    }

    // Build scan tasks
    let mut scan_tasks = Vec::new();
    for url in &urls {
        // Check if URL already has a port specified
        let has_port = url.contains("://") && url.split("://").nth(1).map_or(false, |host_part| host_part.contains(':'));

        let test_ports = if has_port {
            // URL already has a port (from nmap/testssl/nuclei), use a dummy port since we won't append it
            vec![0]
        } else if !ports.is_empty() {
            // User specified ports via -p flag
            ports.clone()
        } else {
            // No ports specified and URL has no port - scan both 80 and 443 by default
            vec![80, 443]
        };

        for method in &methods {
            for port in &test_ports {
                scan_tasks.push((url.clone(), method.clone(), *port));
            }
        }
    }

    // Scan URLs in parallel
    scan_tasks.par_iter().for_each(|(url, method, port)| {
        let req_method = Method::from_str(method).unwrap_or(Method::GET);

        // Apply rate limiting if configured
        if let Ok(mut limiter_guard) = rate_limiter.lock() {
            if let Some(ref mut limiter) = *limiter_guard {
                limiter.wait();
            }
        }

        // Apply random delay if configured
        if let Some((min, max)) = random_delay_range {
            use rand::Rng;
            let delay = rand::rng().random_range(min..=max);
            std::thread::sleep(std::time::Duration::from_secs(delay));
        }

        // Only append port if URL doesn't already have one
        let full_url = if url.contains("://") && url.split("://").nth(1).map_or(false, |host_part| host_part.contains(':')) {
            // URL already has a port, use it as-is
            url.clone()
        } else {
            // No port in URL, append it
            format!("{}:{}", url, port)
        };

        match client.request(req_method.clone(), &full_url)
                    .headers(custom_headers.clone())
                    .send() {
                    Ok(resp) => {
                        let status = resp.status();
                        if let Some(filter) = filter_code {
                            if status != filter {
                                return;
                            }
                        }

                        let headers_str = if verbose {
                            Some(flatten_headers(resp.headers()))
                        } else {
                            None
                        };

                        // Store headers for security analysis
                        let response_headers = resp.headers().clone();

                        // Read response body if needed for analysis
                        let body_text = if check_body || extract_links || grep_pattern.is_some() || detect_errors || detect_reflection {
                            resp.text().ok()
                        } else {
                            None
                        };

                        // Extract body preview (first 200 chars) if check_body is enabled
                        let body_preview = if check_body {
                            body_text.as_ref().map(|b| {
                                let preview = b.chars().take(200).collect::<String>();
                                if b.len() > 200 {
                                    format!("{}...", preview)
                                } else {
                                    preview
                                }
                            })
                        } else {
                            None
                        };

                        // Search for patterns in response body
                        let matched_patterns = if let Some(ref pattern) = grep_pattern {
                            body_text.as_ref().and_then(|b| {
                                let matches: Vec<String> = pattern.find_iter(b)
                                    .map(|m| m.as_str().to_string())
                                    .collect();
                                if matches.is_empty() {
                                    None
                                } else {
                                    Some(matches)
                                }
                            })
                        } else {
                            None
                        };

                        // Extract links from response body
                        let extracted_links = if extract_links {
                            body_text.as_ref().map(|b| extract_links_from_body(b))
                        } else {
                            None
                        };

                        // Analyze security headers
                        let security_headers = if check_security_headers {
                            Some(analyze_security_headers(&response_headers))
                        } else {
                            None
                        };

                        // Detect error messages
                        let detected_errors = if detect_errors {
                            body_text.as_ref().and_then(|b| {
                                let errors = detect_error_messages(b);
                                if errors.is_empty() {
                                    None
                                } else {
                                    Some(errors)
                                }
                            })
                        } else {
                            None
                        };

                        // Check for input reflection (passive XSS detection)
                        let reflection_detected = if detect_reflection {
                            // Generate a unique marker for this request
                            let reflection_marker = format!("terminus_test_{}", rand::random::<u64>());
                            // For GET requests, we would check if URL parameters are reflected
                            // For now, we'll check if common reflection patterns exist
                            body_text.as_ref().map(|b| check_reflection(b, &reflection_marker))
                        } else {
                            None
                        };

                        // Only add result if there's a pattern match (when grep is enabled) or always if grep is not enabled
                        let should_add = if grep_pattern.is_some() {
                            matched_patterns.is_some()
                        } else {
                            true
                        };

                        // Perform HTTP/2 desync check if requested
                        let http2_desync = if http2_desync_check && full_url.starts_with("https") {
                            Some(perform_http2_desync_check(&client, &full_url, &req_method, &custom_headers, status.as_u16()))
                        } else {
                            None
                        };

                        // Perform host injection check if requested
                        let host_injection = if detect_host_injection {
                            Some(perform_host_injection_check(&client, &full_url, &req_method, &custom_headers))
                        } else {
                            None
                        };

                        // Perform X-Forwarded-For bypass check if requested
                        let xff_bypass = if detect_xff_bypass {
                            Some(perform_xff_bypass_check(&client, &full_url, &req_method, &custom_headers, status.as_u16()))
                        } else {
                            None
                        };

                        // Perform CSRF check if requested
                        let csrf_result = if detect_csrf {
                            Some(perform_csrf_check(&client, &full_url, &req_method, &custom_headers))
                        } else {
                            None
                        };

                        // Perform SSRF check if requested
                        let ssrf_result = if detect_ssrf {
                            Some(perform_ssrf_check(&client, &full_url, &req_method, &custom_headers))
                        } else {
                            None
                        };

                        if should_add {
                            if let Ok(mut results_guard) = results.lock() {
                                results_guard.push(ScanResult {
                                    url: url.clone(),
                                    method: method.clone(),
                                    status: status.as_u16(),
                                    port: *port,
                                    headers: headers_str,
                                    error: None,
                                    body_preview,
                                    matched_patterns,
                                    extracted_links,
                                    security_headers,
                                    detected_errors,
                                    reflection_detected,
                                    http2_desync,
                                    host_injection,
                                    xff_bypass,
                                    csrf_result,
                                    ssrf_result,
                                });
                            }
                        }
                    }
                    Err(e) => {
                        if let Ok(mut results_guard) = results.lock() {
                            results_guard.push(ScanResult {
                                url: url.clone(),
                                method: method.clone(),
                                status: 0,
                                port: *port,
                                headers: None,
                                error: Some(e.to_string()),
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
                            });
                        }
                    }
                }
    });

    // Extract results from Arc<Mutex>
    let final_results = results.lock().unwrap().clone();

    // Handle diff mode if requested
    if let Some(diff_file) = matches.get_one::<String>("diff") {
        let old_results = load_previous_scan(diff_file)?;
        let diff = compute_diff(&old_results, &final_results);
        display_diff(&diff);
    }

    // Output results in the specified format(s)
    output_results(&final_results, output_format, output_base, verbose)?;

    Ok(())
}

fn flatten_headers(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k, v.to_str().unwrap_or("INVALID")))
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_lines<P: AsRef<Path>>(filename: P) -> Result<Vec<String>> {
    let file = File::open(&filename).with_context(|| format!("Cannot open file: {}", filename.as_ref().display()))?;
    Ok(io::BufReader::new(file).lines().collect::<Result<_, _>>()?)
}

fn parse_header(header_str: &str) -> Option<(HeaderName, HeaderValue)> {
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

fn read_stdin(ipv6_enabled: bool) -> Result<Vec<String>> {
    let stdin = io::stdin();
    let mut urls = HashSet::new();

    for line in stdin.lock().lines() {
        let line = line?;
        let extracted = extract_targets_from_line(&line, ipv6_enabled);
        urls.extend(extracted);
    }

    Ok(urls.into_iter().collect())
}

fn parse_input_file(filename: &str, ipv6_enabled: bool) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(filename)
        .with_context(|| format!("Cannot read file: {}", filename))?;

    // Try to detect file format
    if content.trim_start().starts_with("<?xml") || content.contains("<nmaprun") {
        parse_nmap_xml(&content, ipv6_enabled)
    } else if content.trim_start().starts_with('{') || content.trim_start().starts_with('[') {
        parse_json_input(&content, ipv6_enabled)
    } else if content.contains("Host:") && content.contains("Ports:") {
        parse_nmap_greppable(&content, ipv6_enabled)
    } else {
        // Plain text file with URLs/IPs
        Ok(content.lines()
            .flat_map(|line| extract_targets_from_line(line, ipv6_enabled))
            .collect())
    }
}

fn extract_targets_from_line(line: &str, ipv6_enabled: bool) -> Vec<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return vec![];
    }

    let mut targets = Vec::new();

    // Try to parse as URL
    if line.starts_with("http://") || line.starts_with("https://") {
        targets.push(line.to_string());
        return targets;
    }

    // Try to parse as IPv4
    if let Ok(ipv4) = line.parse::<Ipv4Addr>() {
        targets.push(format!("http://{}", ipv4));
        return targets;
    }

    // Try to parse as IPv6 if enabled
    if ipv6_enabled {
        if let Ok(ipv6) = line.parse::<Ipv6Addr>() {
            targets.push(format!("http://[{}]", ipv6));
            return targets;
        }
    }

    // Try as hostname/domain
    if !line.contains('/') && !line.contains('\\') {
        targets.push(format!("http://{}", line));
    }

    targets
}

fn parse_nmap_xml(content: &str, ipv6_enabled: bool) -> Result<Vec<String>> {
    let mut urls = HashSet::new();

    // Simple regex-based parsing for nmap XML
    let host_regex = Regex::new(r#"<address\s+addr="([^"]+)"\s+addrtype="(ipv4|ipv6)""#)?;
    let port_regex = Regex::new(r#"<port\s+protocol="tcp"\s+portid="(\d+)"><state\s+state="open""#)?;

    let mut current_hosts = Vec::new();
    let mut in_host = false;

    for line in content.lines() {
        if line.contains("<host") {
            in_host = true;
            current_hosts.clear();
        }

        if in_host {
            if let Some(caps) = host_regex.captures(line) {
                let addr = caps.get(1).map(|m| m.as_str()).unwrap();
                let addr_type = caps.get(2).map(|m| m.as_str()).unwrap();

                if addr_type == "ipv4" || (addr_type == "ipv6" && ipv6_enabled) {
                    current_hosts.push(addr.to_string());
                }
            }

            if let Some(caps) = port_regex.captures(line) {
                let port = caps.get(1).map(|m| m.as_str()).unwrap();
                for host in &current_hosts {
                    let url = if host.contains(':') {
                        format!("http://[{}]:{}", host, port)
                    } else {
                        format!("http://{}:{}", host, port)
                    };
                    urls.insert(url);
                }
            }
        }

        if line.contains("</host>") {
            in_host = false;
        }
    }

    Ok(urls.into_iter().collect())
}

fn parse_nmap_greppable(content: &str, ipv6_enabled: bool) -> Result<Vec<String>> {
    let mut urls = HashSet::new();

    for line in content.lines() {
        if !line.starts_with("Host:") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let host = parts[1];

        // Check if IPv6 and if it's enabled
        if host.contains(':') && !ipv6_enabled {
            continue;
        }

        // Find ports section
        if let Some(ports_idx) = parts.iter().position(|&x| x == "Ports:") {
            if ports_idx + 1 < parts.len() {
                let ports_str = parts[ports_idx + 1];
                for port_entry in ports_str.split(',') {
                    let port_parts: Vec<&str> = port_entry.split('/').collect();
                    if port_parts.len() >= 2 {
                        let port = port_parts[0];
                        let state = port_parts[1];

                        if state == "open" {
                            let url = if host.contains(':') {
                                format!("http://[{}]:{}", host, port)
                            } else {
                                format!("http://{}:{}", host, port)
                            };
                            urls.insert(url);
                        }
                    }
                }
            }
        }
    }

    Ok(urls.into_iter().collect())
}

fn parse_json_input(content: &str, ipv6_enabled: bool) -> Result<Vec<String>> {
    let mut urls = HashSet::new();

    // Try to parse as JSON
    if let Ok(json) = serde_json::from_str::<JsonValue>(content) {
        // Handle testssl.sh JSON format
        if json.get("scanResult").is_some() {
            if let Some(scan_results) = json.get("scanResult").and_then(|v| v.as_array()) {
                for result in scan_results {
                    if let Some(ip) = result.get("ip").and_then(|v| v.as_str()) {
                        if let Some(port) = result.get("port").and_then(|v| v.as_str()) {
                            let url = if ip.contains(':') && ipv6_enabled {
                                format!("https://[{}]:{}", ip, port)
                            } else if !ip.contains(':') {
                                format!("https://{}:{}", ip, port)
                            } else {
                                continue;
                            };
                            urls.insert(url);
                        }
                    }
                }
            }
        }
        // Handle ProjectDiscovery JSON (nuclei/katana)
        else if json.get("host").is_some() || json.get("url").is_some() || json.get("endpoint").is_some() {
            // Nuclei/Katana single result
            extract_pd_urls(&json, &mut urls, ipv6_enabled);
        } else if let Some(array) = json.as_array() {
            // Array of results
            for item in array {
                extract_pd_urls(item, &mut urls, ipv6_enabled);
            }
        }
    }

    Ok(urls.into_iter().collect())
}

fn extract_pd_urls(json: &JsonValue, urls: &mut HashSet<String>, ipv6_enabled: bool) {
    // Try various fields that ProjectDiscovery tools use
    let possible_fields = ["url", "endpoint", "host", "target", "matched-at"];

    for field in &possible_fields {
        if let Some(value) = json.get(field).and_then(|v| v.as_str()) {
            if value.starts_with("http://") || value.starts_with("https://") {
                urls.insert(value.to_string());
            } else {
                // Try to extract host/IP
                let extracted = extract_targets_from_line(value, ipv6_enabled);
                urls.extend(extracted);
            }
        }
    }
}

fn output_results(results: &[ScanResult], format: OutputFormat, output_base: Option<&str>, verbose: bool) -> Result<()> {
    match format {
        OutputFormat::Stdout => output_stdout(results, verbose),
        OutputFormat::Txt => output_txt(results, output_base, verbose)?,
        OutputFormat::Json => output_json(results, output_base)?,
        OutputFormat::Html => output_html(results, output_base)?,
        OutputFormat::Csv => output_csv(results, output_base, verbose)?,
        OutputFormat::All => {
            output_stdout(results, verbose);
            output_txt(results, output_base, verbose)?;
            output_json(results, output_base)?;
            output_html(results, output_base)?;
            output_csv(results, output_base, verbose)?;
        }
    }
    Ok(())
}

fn collect_vuln_indicators(result: &ScanResult) -> Vec<String> {
    let mut indicators = Vec::new();

    // HTTP/2 Desync
    if let Some(ref desync) = result.http2_desync {
        if desync.desync_detected {
            indicators.push("[HTTP/2 Desync Detected]".to_string());
        }
    }

    // Host Injection
    if let Some(ref host_inj) = result.host_injection {
        if host_inj.injection_suspected {
            indicators.push("[Host Injection Suspected]".to_string());
        }
    }

    // XFF Bypass
    if let Some(ref xff) = result.xff_bypass {
        if xff.bypass_suspected {
            indicators.push("[XFF Bypass Suspected]".to_string());
        }
    }

    // CSRF
    if let Some(ref csrf) = result.csrf_result {
        if csrf.csrf_suspected {
            indicators.push("[CSRF Suspected]".to_string());
        }
    }

    // SSRF
    if let Some(ref ssrf) = result.ssrf_result {
        if ssrf.ssrf_suspected {
            indicators.push("[SSRF Suspected]".to_string());
        }
    }

    // Reflection
    if let Some(true) = result.reflection_detected {
        indicators.push("[Reflection Detected]".to_string());
    }

    // Security Headers Issues
    if let Some(ref sec_headers) = result.security_headers {
        if !sec_headers.issues.is_empty() {
            indicators.push(format!("[Security Issues: {}]", sec_headers.issues.len()));
        }
    }

    // Detected Errors
    if let Some(ref errors) = result.detected_errors {
        if !errors.is_empty() {
            indicators.push(format!("[Error Messages: {}]", errors.len()));
        }
    }

    indicators
}

fn output_stdout(results: &[ScanResult], verbose: bool) {
    for result in results {
        if let Some(error) = &result.error {
            eprintln!("Error on {}:{} using {}: {}", result.url, result.port, result.method, error);
        } else {
            let vuln_indicators = collect_vuln_indicators(result);
            let indicators_str = if !vuln_indicators.is_empty() {
                format!(" {}", vuln_indicators.join(" "))
            } else {
                String::new()
            };

            if verbose {
                if let Some(headers) = &result.headers {
                    println!("URL: {}, Method: {}, Status: {}, Port: {}, Headers: {}{}",
                        result.url, result.method, result.status, result.port, headers, indicators_str);
                } else {
                    println!("URL: {}, Method: {}, Status: {}, Port: {}{}",
                        result.url, result.method, result.status, result.port, indicators_str);
                }
            } else {
                println!("{} [{}:{}]{}",
                    result.url, result.method, result.status, indicators_str);
            }
        }
    }
}

fn output_txt(results: &[ScanResult], output_base: Option<&str>, verbose: bool) -> Result<()> {
    let filename = format!("{}.txt", output_base.unwrap_or("terminus_results"));
    let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(&filename)?;

    for result in results {
        if let Some(error) = &result.error {
            writeln!(file, "Error on {}:{} using {}: {}", result.url, result.port, result.method, error)?;
        } else {
            let vuln_indicators = collect_vuln_indicators(result);
            let indicators_str = if !vuln_indicators.is_empty() {
                format!(" {}", vuln_indicators.join(" "))
            } else {
                String::new()
            };

            if verbose {
                if let Some(headers) = &result.headers {
                    writeln!(file, "URL: {}, Method: {}, Status: {}, Port: {}, Headers: {}{}",
                        result.url, result.method, result.status, result.port, headers, indicators_str)?;
                } else {
                    writeln!(file, "URL: {}, Method: {}, Status: {}, Port: {}{}",
                        result.url, result.method, result.status, result.port, indicators_str)?;
                }
            } else {
                writeln!(file, "URL: {}, Method: {}, Status: {}, Port: {}{}",
                    result.url, result.method, result.status, result.port, indicators_str)?;
            }
        }
    }

    eprintln!("Results written to {}", filename);
    Ok(())
}

fn output_json(results: &[ScanResult], output_base: Option<&str>) -> Result<()> {
    let filename = format!("{}.json", output_base.unwrap_or("terminus_results"));
    let json = serde_json::to_string_pretty(results)?;
    std::fs::write(&filename, json)?;
    eprintln!("Results written to {}", filename);
    Ok(())
}

fn output_html(results: &[ScanResult], output_base: Option<&str>) -> Result<()> {
    let filename = format!("{}.html", output_base.unwrap_or("terminus_results"));

    // Calculate vulnerability statistics
    let total_results = results.len();
    let mut vuln_counts = std::collections::HashMap::new();
    vuln_counts.insert("http2_desync", 0);
    vuln_counts.insert("host_injection", 0);
    vuln_counts.insert("xff_bypass", 0);
    vuln_counts.insert("csrf", 0);
    vuln_counts.insert("ssrf", 0);
    vuln_counts.insert("reflection", 0);
    vuln_counts.insert("security_issues", 0);
    vuln_counts.insert("error_messages", 0);

    for result in results {
        if let Some(ref desync) = result.http2_desync {
            if desync.desync_detected {
                *vuln_counts.get_mut("http2_desync").unwrap() += 1;
            }
        }
        if let Some(ref host_inj) = result.host_injection {
            if host_inj.injection_suspected {
                *vuln_counts.get_mut("host_injection").unwrap() += 1;
            }
        }
        if let Some(ref xff) = result.xff_bypass {
            if xff.bypass_suspected {
                *vuln_counts.get_mut("xff_bypass").unwrap() += 1;
            }
        }
        if let Some(ref csrf) = result.csrf_result {
            if csrf.csrf_suspected {
                *vuln_counts.get_mut("csrf").unwrap() += 1;
            }
        }
        if let Some(ref ssrf) = result.ssrf_result {
            if ssrf.ssrf_suspected {
                *vuln_counts.get_mut("ssrf").unwrap() += 1;
            }
        }
        if let Some(true) = result.reflection_detected {
            *vuln_counts.get_mut("reflection").unwrap() += 1;
        }
        if let Some(ref sec_headers) = result.security_headers {
            if !sec_headers.issues.is_empty() {
                *vuln_counts.get_mut("security_issues").unwrap() += 1;
            }
        }
        if let Some(ref errors) = result.detected_errors {
            if !errors.is_empty() {
                *vuln_counts.get_mut("error_messages").unwrap() += 1;
            }
        }
    }

    let mut html = String::from("<!DOCTYPE html>\n<html>\n<head>\n<meta charset='UTF-8'>\n<title>Terminus Scan Results</title>\n");

    // Enhanced CSS styling
    html.push_str("<style>\n");
    html.push_str("body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5;}\n");
    html.push_str("h1{color:#2c3e50;}\n");
    html.push_str(".summary{background:#fff;padding:20px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,0.1);}\n");
    html.push_str(".summary h2{margin-top:0;color:#2c3e50;}\n");
    html.push_str(".stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-top:15px;}\n");
    html.push_str(".stat-card{background:#f8f9fa;padding:15px;border-radius:6px;border-left:4px solid #4CAF50;}\n");
    html.push_str(".stat-card.vuln{border-left-color:#e74c3c;}\n");
    html.push_str(".stat-label{font-size:12px;color:#7f8c8d;text-transform:uppercase;}\n");
    html.push_str(".stat-value{font-size:24px;font-weight:bold;color:#2c3e50;margin-top:5px;}\n");
    html.push_str(".filters{background:#fff;padding:15px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,0.1);}\n");
    html.push_str(".filter-group{display:inline-block;margin-right:15px;margin-bottom:10px;}\n");
    html.push_str(".filter-group label{margin-left:5px;}\n");
    html.push_str("table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 2px 4px rgba(0,0,0,0.1);}\n");
    html.push_str("th,td{border:1px solid #ddd;padding:12px;text-align:left;}\n");
    html.push_str("th{background-color:#4CAF50;color:white;position:sticky;top:0;}\n");
    html.push_str("tr:nth-child(even){background-color:#f8f9fa;}\n");
    html.push_str("tr:hover{background-color:#e8f5e9;}\n");
    html.push_str(".error{color:#e74c3c;font-weight:bold;}\n");
    html.push_str(".vuln-badge{display:inline-block;background:#e74c3c;color:white;padding:4px 8px;border-radius:4px;font-size:11px;margin:2px;}\n");
    html.push_str(".vuln-badge.security{background:#f39c12;}\n");
    html.push_str(".hidden{display:none;}\n");
    html.push_str("</style>\n");

    // JavaScript for filtering
    html.push_str("<script>\n");
    html.push_str("function filterTable() {\n");
    html.push_str("  const filters = {\n");
    html.push_str("    http2: document.getElementById('filter-http2').checked,\n");
    html.push_str("    host: document.getElementById('filter-host').checked,\n");
    html.push_str("    xff: document.getElementById('filter-xff').checked,\n");
    html.push_str("    csrf: document.getElementById('filter-csrf').checked,\n");
    html.push_str("    ssrf: document.getElementById('filter-ssrf').checked,\n");
    html.push_str("    reflection: document.getElementById('filter-reflection').checked,\n");
    html.push_str("    security: document.getElementById('filter-security').checked,\n");
    html.push_str("    errors: document.getElementById('filter-errors').checked,\n");
    html.push_str("    clean: document.getElementById('filter-clean').checked\n");
    html.push_str("  };\n");
    html.push_str("  const anyFilterActive = Object.values(filters).some(v => v);\n");
    html.push_str("  const rows = document.querySelectorAll('.data-row');\n");
    html.push_str("  rows.forEach(row => {\n");
    html.push_str("    if (!anyFilterActive) { row.classList.remove('hidden'); return; }\n");
    html.push_str("    const vulns = row.dataset.vulns.split(',').filter(v => v);\n");
    html.push_str("    const hasClean = vulns.length === 0;\n");
    html.push_str("    const shouldShow = (filters.http2 && vulns.includes('http2')) ||\n");
    html.push_str("      (filters.host && vulns.includes('host')) ||\n");
    html.push_str("      (filters.xff && vulns.includes('xff')) ||\n");
    html.push_str("      (filters.csrf && vulns.includes('csrf')) ||\n");
    html.push_str("      (filters.ssrf && vulns.includes('ssrf')) ||\n");
    html.push_str("      (filters.reflection && vulns.includes('reflection')) ||\n");
    html.push_str("      (filters.security && vulns.includes('security')) ||\n");
    html.push_str("      (filters.errors && vulns.includes('errors')) ||\n");
    html.push_str("      (filters.clean && hasClean);\n");
    html.push_str("    if (shouldShow) { row.classList.remove('hidden'); }\n");
    html.push_str("    else { row.classList.add('hidden'); }\n");
    html.push_str("  });\n");
    html.push_str("}\n");
    html.push_str("</script>\n");

    html.push_str("</head>\n<body>\n");

    // Title
    html.push_str("<h1>Terminus Scan Results</h1>\n");

    // Summary section
    html.push_str("<div class='summary'>\n");
    html.push_str("<h2>Scan Summary</h2>\n");
    html.push_str("<div class='stat-grid'>\n");
    html.push_str(&format!("<div class='stat-card'><div class='stat-label'>Total Endpoints</div><div class='stat-value'>{}</div></div>\n", total_results));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>HTTP/2 Desync</div><div class='stat-value'>{}</div></div>\n", vuln_counts["http2_desync"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>Host Injection</div><div class='stat-value'>{}</div></div>\n", vuln_counts["host_injection"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>XFF Bypass</div><div class='stat-value'>{}</div></div>\n", vuln_counts["xff_bypass"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>CSRF</div><div class='stat-value'>{}</div></div>\n", vuln_counts["csrf"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>SSRF</div><div class='stat-value'>{}</div></div>\n", vuln_counts["ssrf"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>Reflection</div><div class='stat-value'>{}</div></div>\n", vuln_counts["reflection"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>Security Issues</div><div class='stat-value'>{}</div></div>\n", vuln_counts["security_issues"]));
    html.push_str(&format!("<div class='stat-card vuln'><div class='stat-label'>Error Messages</div><div class='stat-value'>{}</div></div>\n", vuln_counts["error_messages"]));
    html.push_str("</div>\n</div>\n");

    // Filters section
    html.push_str("<div class='filters'>\n");
    html.push_str("<strong>Filter by Vulnerability:</strong><br>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-http2' onchange='filterTable()'><label for='filter-http2'>HTTP/2 Desync</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-host' onchange='filterTable()'><label for='filter-host'>Host Injection</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-xff' onchange='filterTable()'><label for='filter-xff'>XFF Bypass</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-csrf' onchange='filterTable()'><label for='filter-csrf'>CSRF</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-ssrf' onchange='filterTable()'><label for='filter-ssrf'>SSRF</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-reflection' onchange='filterTable()'><label for='filter-reflection'>Reflection</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-security' onchange='filterTable()'><label for='filter-security'>Security Issues</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-errors' onchange='filterTable()'><label for='filter-errors'>Error Messages</label></div>\n");
    html.push_str("<div class='filter-group'><input type='checkbox' id='filter-clean' onchange='filterTable()'><label for='filter-clean'>Clean (No Issues)</label></div>\n");
    html.push_str("</div>\n");

    // Results table
    html.push_str("<table>\n");
    html.push_str("<tr><th>URL</th><th>Method</th><th>Status</th><th>Port</th><th>Vulnerabilities</th><th>Error</th></tr>\n");

    for result in results {
        let mut vuln_tags: Vec<String> = Vec::new();
        let mut data_vulns = Vec::new();

        // Build vulnerability badges and data attributes
        if let Some(ref desync) = result.http2_desync {
            if desync.desync_detected {
                vuln_tags.push("<span class='vuln-badge'>HTTP/2 Desync</span>".to_string());
                data_vulns.push("http2");
            }
        }
        if let Some(ref host_inj) = result.host_injection {
            if host_inj.injection_suspected {
                vuln_tags.push("<span class='vuln-badge'>Host Injection</span>".to_string());
                data_vulns.push("host");
            }
        }
        if let Some(ref xff) = result.xff_bypass {
            if xff.bypass_suspected {
                vuln_tags.push("<span class='vuln-badge'>XFF Bypass</span>".to_string());
                data_vulns.push("xff");
            }
        }
        if let Some(ref csrf) = result.csrf_result {
            if csrf.csrf_suspected {
                vuln_tags.push("<span class='vuln-badge'>CSRF</span>".to_string());
                data_vulns.push("csrf");
            }
        }
        if let Some(ref ssrf) = result.ssrf_result {
            if ssrf.ssrf_suspected {
                vuln_tags.push("<span class='vuln-badge'>SSRF</span>".to_string());
                data_vulns.push("ssrf");
            }
        }
        if let Some(true) = result.reflection_detected {
            vuln_tags.push("<span class='vuln-badge'>Reflection</span>".to_string());
            data_vulns.push("reflection");
        }
        if let Some(ref sec_headers) = result.security_headers {
            if !sec_headers.issues.is_empty() {
                vuln_tags.push(format!("<span class='vuln-badge security'>Security Issues: {}</span>", sec_headers.issues.len()));
                data_vulns.push("security");
            }
        }
        if let Some(ref errors) = result.detected_errors {
            if !errors.is_empty() {
                vuln_tags.push(format!("<span class='vuln-badge security'>Error Messages: {}</span>", errors.len()));
                data_vulns.push("errors");
            }
        }

        let vuln_display = if vuln_tags.is_empty() {
            "<span style='color:#27ae60;'>✓ Clean</span>".to_string()
        } else {
            vuln_tags.join(" ")
        };

        let data_vulns_str = data_vulns.join(",");

        html.push_str(&format!("<tr class='data-row' data-vulns='{}'>", data_vulns_str));
        html.push_str(&format!("<td>{}</td>", html_escape(&result.url)));
        html.push_str(&format!("<td>{}</td>", html_escape(&result.method)));
        html.push_str(&format!("<td>{}</td>", result.status));
        html.push_str(&format!("<td>{}</td>", result.port));
        html.push_str(&format!("<td>{}</td>", vuln_display));
        html.push_str(&format!("<td class='error'>{}</td>", html_escape(result.error.as_deref().unwrap_or(""))));
        html.push_str("</tr>\n");
    }

    html.push_str("</table>\n</body>\n</html>");
    std::fs::write(&filename, html)?;
    eprintln!("Results written to {}", filename);
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn output_csv(results: &[ScanResult], output_base: Option<&str>, verbose: bool) -> Result<()> {
    let filename = format!("{}.csv", output_base.unwrap_or("terminus_results"));
    let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(&filename)?;

    // Write CSV header
    if verbose {
        writeln!(file, "URL,Method,Status,Port,Headers,Vulnerabilities,Error")?;
    } else {
        writeln!(file, "URL,Method,Status,Port,Vulnerabilities,Error")?;
    }

    // Write CSV rows
    for result in results {
        let url = csv_escape(&result.url);
        let method = csv_escape(&result.method);
        let status = result.status.to_string();
        let port = result.port.to_string();
        let error = csv_escape(result.error.as_deref().unwrap_or(""));

        let vuln_indicators = collect_vuln_indicators(result);
        let vulnerabilities = csv_escape(&vuln_indicators.join("; "));

        if verbose {
            let headers = csv_escape(result.headers.as_deref().unwrap_or(""));
            writeln!(file, "{},{},{},{},{},{},{}", url, method, status, port, headers, vulnerabilities, error)?;
        } else {
            writeln!(file, "{},{},{},{},{},{}", url, method, status, port, vulnerabilities, error)?;
        }
    }

    eprintln!("Results written to {}", filename);
    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn load_previous_scan(filename: &str) -> Result<Vec<ScanResult>> {
    let content = std::fs::read_to_string(filename)
        .with_context(|| format!("Cannot read diff file: {}", filename))?;
    let results: Vec<ScanResult> = serde_json::from_str(&content)
        .context("Failed to parse previous scan results. File must be in JSON format.")?;
    Ok(results)
}

fn compute_diff(old_results: &[ScanResult], new_results: &[ScanResult]) -> DiffResult {
    use std::collections::HashMap;

    // Create lookup maps using url+method+port as key
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

    // Find new endpoints
    for (key, new_result) in &new_map {
        if !old_map.contains_key(key) {
            diff.new_endpoints.push((*new_result).clone());
        }
    }

    // Find removed endpoints and status changes
    for (key, old_result) in &old_map {
        if let Some(new_result) = new_map.get(key) {
            // Endpoint exists in both - check for status changes
            if old_result.status != new_result.status {
                diff.status_changes.push(((*old_result).clone(), (*new_result).clone()));
            }
        } else {
            // Endpoint was removed
            diff.removed_endpoints.push((*old_result).clone());
        }
    }

    diff
}

fn display_diff(diff: &DiffResult) {
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

fn extract_links_from_body(body: &str) -> Vec<String> {
    let mut links = HashSet::new();

    // Regex patterns for different types of links
    let url_pattern = Regex::new(r#"https?://[^\s<>"{}|\\^`\[\]]+"#).unwrap();
    let href_pattern = Regex::new(r#"href=["']([^"']+)["']"#).unwrap();
    let src_pattern = Regex::new(r#"src=["']([^"']+)["']"#).unwrap();

    // Extract full URLs
    for capture in url_pattern.find_iter(body) {
        links.insert(capture.as_str().to_string());
    }

    // Extract href attributes
    for capture in href_pattern.captures_iter(body) {
        if let Some(url) = capture.get(1) {
            links.insert(url.as_str().to_string());
        }
    }

    // Extract src attributes
    for capture in src_pattern.captures_iter(body) {
        if let Some(url) = capture.get(1) {
            links.insert(url.as_str().to_string());
        }
    }

    links.into_iter().collect()
}

fn analyze_security_headers(headers: &HeaderMap) -> SecurityHeaders {
    let mut missing = Vec::new();
    let mut present = Vec::new();
    let mut issues = Vec::new();

    // Critical security headers to check
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
        if let Some(value) = headers.get(header_name) {
            present.push(display_name.to_string());

            // Check for weak or problematic configurations
            if let Ok(val_str) = value.to_str() {
                match header_name {
                    "content-security-policy" => {
                        if val_str.contains("'unsafe-inline'") || val_str.contains("'unsafe-eval'") {
                            issues.push(format!("CSP contains unsafe directives: {}", val_str));
                        }
                    }
                    "x-frame-options" => {
                        if !val_str.to_lowercase().contains("deny") && !val_str.to_lowercase().contains("sameorigin") {
                            issues.push(format!("Weak X-Frame-Options: {}", val_str));
                        }
                    }
                    "strict-transport-security" => {
                        if !val_str.contains("max-age") {
                            issues.push("HSTS missing max-age directive".to_string());
                        }
                    }
                    _ => {}
                }
            }
        } else {
            missing.push(display_name.to_string());
        }
    }

    // Check for problematic headers that should not be present
    let problematic_headers = vec![
        ("server", "Server header exposes version information"),
        ("x-powered-by", "X-Powered-By header exposes technology stack"),
        ("x-aspnet-version", "X-AspNet-Version header exposes framework version"),
    ];

    for (header_name, issue_desc) in problematic_headers {
        if headers.get(header_name).is_some() {
            issues.push(issue_desc.to_string());
        }
    }

    // Check CORS configuration
    if let Some(cors) = headers.get("access-control-allow-origin") {
        if let Ok(val_str) = cors.to_str() {
            if val_str == "*" {
                issues.push("CORS allows all origins (*)".to_string());
            }
        }
    }

    SecurityHeaders {
        missing,
        present,
        issues,
    }
}

fn detect_error_messages(body: &str) -> Vec<String> {
    let mut detected_errors = Vec::new();

    // SQL error patterns
    let sql_patterns = vec![
        r"SQL syntax.*?MySQL",
        r"Warning.*?\Wmysqli?_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"Unknown column '[^']+' in 'field list'",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc\.exceptions",
        r"ORA-[0-9]{5}",
        r"Oracle error",
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"macromedia\.jdbc\.sqlserver",
    ];

    for pattern in sql_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(body) {
                detected_errors.push(format!("SQL Error Pattern: {}", pattern));
                break; // Only report once per category
            }
        }
    }

    // Stack trace patterns
    let stack_trace_patterns = vec![
        r"at\s+[\w\.$]+\([^)]+\.java:\d+\)",  // Java
        r"Traceback \(most recent call last\):",  // Python
        r"Stack trace:.*?at\s+",  // .NET
        r"#\d+\s+/[\w/]+\.php\(\d+\)",  // PHP
        r"Error\s+in\s+/[\w/]+\s+on\s+line\s+\d+",  // Generic
    ];

    for pattern in stack_trace_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(body) {
                detected_errors.push("Stack trace detected".to_string());
                break;
            }
        }
    }

    // Debug/Development mode indicators
    let debug_patterns = vec![
        r"<title>.*?Exception.*?</title>",
        r"<b>Fatal error</b>:",
        r"<b>Warning</b>:",
        r"<b>Parse error</b>:",
        r"Undefined variable:",
        r"Undefined index:",
        r"Notice: Undefined",
        r"Debug mode|DEBUG_MODE",
        r"SQLSTATE\[\w+\]",
        r"PDOException",
    ];

    for pattern in debug_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(body) {
                detected_errors.push("Debug/error information exposed".to_string());
                break;
            }
        }
    }

    // Path disclosure
    let path_patterns = vec![
        r"[A-Za-z]:\\[\w\\]+",  // Windows paths
        r"/home/[\w/]+",  // Unix home paths
        r"/var/www/[\w/]+",  // Common web paths
        r"/usr/[\w/]+",  // Unix system paths
    ];

    for pattern in path_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(body) {
                detected_errors.push("File path disclosure detected".to_string());
                break;
            }
        }
    }

    detected_errors
}

fn check_reflection(body: &str, _marker: &str) -> bool {
    // Passive reflection detection - look for common indicators that user input might be reflected
    // We don't actually inject anything, just check if the response shows signs of reflection

    // Look for common reflection patterns in forms and inputs
    let reflection_indicators = vec![
        r#"<input[^>]+value=["'][^"']*\{[^}]*\}[^"']*["']"#,  // Templating in input values
        r#"<input[^>]+value=["'][^"']*\$[^"']*["']"#,  // Variables in input values
        r#"<script[^>]*>[^<]*document\.write\([^)]*\)"#,  // document.write with parameters
        r#"<script[^>]*>[^<]*innerHTML\s*="#,  // innerHTML assignment
        r#"<script[^>]*>[^<]*eval\("#,  // eval usage (potential XSS vector)
        r#"<[^>]+\son\w+\s*=\s*["'][^"']*["']"#,  // Inline event handlers
    ];

    for pattern in &reflection_indicators {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(body) {
                return true; // Potential reflection/XSS vector found
            }
        }
    }

    // Check for URL parameters reflected in response (basic check)
    // Look for query string patterns that might indicate reflected parameters
    if body.contains("?") && (body.contains("=") || body.contains("&")) {
        // This is a very basic check - in a real implementation, you'd want to
        // track the actual request parameters and see if they appear in the response
        let param_pattern = Regex::new(r"[?&](\w+)=([^&\s<>]+)").unwrap();
        if param_pattern.is_match(body) {
            return true;
        }
    }

    false
}

fn perform_http2_desync_check(
    _client: &reqwest::blocking::Client,
    url: &str,
    method: &Method,
    headers: &HeaderMap,
    http1_status: u16,
) -> Http2DesyncResult {
    let mut issues = Vec::new();
    let mut desync_detected = false;
    let http2_status;
    let mut status_mismatch = false;
    let mut response_diff = None;

    // Create separate clients for HTTP/1.1 and HTTP/2
    let http1_client = match ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            issues.push(format!("Failed to create HTTP/1.1 client: {}", e));
            return Http2DesyncResult {
                desync_detected: false,
                http1_status,
                http2_status: 0,
                status_mismatch: false,
                response_diff: Some("Unable to perform desync check".to_string()),
                issues,
            };
        }
    };

    let http2_client = match ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .http2_prior_knowledge()
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            issues.push(format!("Failed to create HTTP/2 client: {}", e));
            return Http2DesyncResult {
                desync_detected: false,
                http1_status,
                http2_status: 0,
                status_mismatch: false,
                response_diff: Some("Unable to perform desync check".to_string()),
                issues,
            };
        }
    };

    // Make HTTP/1.1 request
    let http1_response = match http1_client
        .request(method.clone(), url)
        .headers(headers.clone())
        .send()
    {
        Ok(resp) => resp,
        Err(e) => {
            issues.push(format!("HTTP/1.1 request failed: {}", e));
            return Http2DesyncResult {
                desync_detected: false,
                http1_status,
                http2_status: 0,
                status_mismatch: false,
                response_diff: Some("HTTP/1.1 request failed".to_string()),
                issues,
            };
        }
    };

    let http1_final_status = http1_response.status().as_u16();
    let http1_body = http1_response.text().unwrap_or_default();

    // Make HTTP/2 request
    let http2_response = match http2_client
        .request(method.clone(), url)
        .headers(headers.clone())
        .send()
    {
        Ok(resp) => resp,
        Err(e) => {
            issues.push(format!("HTTP/2 request failed: {}", e));
            // If HTTP/2 fails completely, it might indicate the server doesn't support HTTP/2
            // or there's a configuration issue
            return Http2DesyncResult {
                desync_detected: false,
                http1_status: http1_final_status,
                http2_status: 0,
                status_mismatch: false,
                response_diff: Some("HTTP/2 not supported or request failed".to_string()),
                issues,
            };
        }
    };

    http2_status = http2_response.status().as_u16();
    let http2_body = http2_response.text().unwrap_or_default();

    // Compare status codes
    if http1_final_status != http2_status {
        status_mismatch = true;
        desync_detected = true;
        issues.push(format!(
            "Status code mismatch: HTTP/1.1 returned {} but HTTP/2 returned {}",
            http1_final_status, http2_status
        ));
    }

    // Compare response body lengths for significant differences
    let body_length_diff = (http1_body.len() as i64 - http2_body.len() as i64).abs();
    if body_length_diff > 100 {
        desync_detected = true;
        issues.push(format!(
            "Significant response body length difference: HTTP/1.1={} bytes, HTTP/2={} bytes (diff={})",
            http1_body.len(),
            http2_body.len(),
            body_length_diff
        ));
        response_diff = Some(format!(
            "Body length: HTTP/1.1={}, HTTP/2={}",
            http1_body.len(),
            http2_body.len()
        ));
    }

    // Check for common desync indicators in responses
    let desync_patterns = vec![
        "Transfer-Encoding",
        "Content-Length",
        "chunked",
    ];

    for pattern in &desync_patterns {
        let http1_has = http1_body.contains(pattern) || http1_body.to_lowercase().contains(&pattern.to_lowercase());
        let http2_has = http2_body.contains(pattern) || http2_body.to_lowercase().contains(&pattern.to_lowercase());

        if http1_has != http2_has {
            desync_detected = true;
            issues.push(format!(
                "Encoding discrepancy detected: '{}' present in {} but not in {}",
                pattern,
                if http1_has { "HTTP/1.1" } else { "HTTP/2" },
                if http1_has { "HTTP/2" } else { "HTTP/1.1" }
            ));
        }
    }

    // If no issues found
    if issues.is_empty() && !desync_detected {
        issues.push("No HTTP/2 desync issues detected".to_string());
    }

    Http2DesyncResult {
        desync_detected,
        http1_status: http1_final_status,
        http2_status,
        status_mismatch,
        response_diff,
        issues,
    }
}
fn perform_host_injection_check(
    client: &reqwest::blocking::Client,
    url: &str,
    method: &Method,
    headers: &HeaderMap,
) -> HostInjectionResult {
    let mut issues = Vec::new();
    let mut injection_suspected = false;
    let mut reflected_in_location = false;
    let mut reflected_in_vary = false;
    let mut reflected_in_set_cookie = false;
    let injected_host = "evil.terminus.local";

    // Create a modified header map with injected Host header
    let mut modified_headers = headers.clone();
    if let Ok(host_value) = HeaderValue::from_str(injected_host) {
        modified_headers.insert(reqwest::header::HOST, host_value);
    } else {
        issues.push("Failed to create injected host header".to_string());
        return HostInjectionResult {
            injection_suspected: false,
            reflected_in_location: false,
            reflected_in_vary: false,
            reflected_in_set_cookie: false,
            injected_host: injected_host.to_string(),
            issues,
        };
    }

    // Make request with injected Host header
    let response = match client
        .request(method.clone(), url)
        .headers(modified_headers)
        .send()
    {
        Ok(resp) => resp,
        Err(e) => {
            issues.push(format!("Request with injected host failed: {}", e));
            return HostInjectionResult {
                injection_suspected: false,
                reflected_in_location: false,
                reflected_in_vary: false,
                reflected_in_set_cookie: false,
                injected_host: injected_host.to_string(),
                issues,
            };
        }
    };

    let response_headers = response.headers();

    // Check Location header
    if let Some(location) = response_headers.get("location") {
        if let Ok(location_str) = location.to_str() {
            if location_str.contains(injected_host) {
                reflected_in_location = true;
                injection_suspected = true;
                issues.push(format!(
                    "[Host Injection Suspected] Injected host '{}' reflected in Location header: {}",
                    injected_host, location_str
                ));
            }
        }
    }

    // Check Vary header
    if let Some(vary) = response_headers.get("vary") {
        if let Ok(vary_str) = vary.to_str() {
            if vary_str.contains(injected_host) {
                reflected_in_vary = true;
                injection_suspected = true;
                issues.push(format!(
                    "[Host Injection Suspected] Injected host '{}' reflected in Vary header: {}",
                    injected_host, vary_str
                ));
            }
        }
    }

    // Check Set-Cookie header
    if let Some(set_cookie) = response_headers.get("set-cookie") {
        if let Ok(cookie_str) = set_cookie.to_str() {
            if cookie_str.contains(injected_host) {
                reflected_in_set_cookie = true;
                injection_suspected = true;
                issues.push(format!(
                    "[Host Injection Suspected] Injected host '{}' reflected in Set-Cookie header: {}",
                    injected_host, cookie_str
                ));
            }
        }
    }

    // Also check response body for host reflection
    if let Ok(body) = response.text() {
        if body.contains(injected_host) {
            injection_suspected = true;
            issues.push(format!(
                "[Host Injection Suspected] Injected host '{}' reflected in response body",
                injected_host
            ));
        }
    }

    if !injection_suspected {
        issues.push("No host header injection detected".to_string());
    }

    HostInjectionResult {
        injection_suspected,
        reflected_in_location,
        reflected_in_vary,
        reflected_in_set_cookie,
        injected_host: injected_host.to_string(),
        issues,
    }
}

fn perform_xff_bypass_check(
    client: &reqwest::blocking::Client,
    url: &str,
    method: &Method,
    headers: &HeaderMap,
    baseline_status: u16,
) -> XffBypassResult {
    let mut issues = Vec::new();
    let mut bypass_suspected = false;
    let mut status_changed = false;
    let xff_value = "127.0.0.1";

    // Create modified headers with X-Forwarded-For
    let mut modified_headers = headers.clone();
    if let Ok(xff_header) = HeaderValue::from_str(xff_value) {
        modified_headers.insert(HeaderName::from_static("x-forwarded-for"), xff_header);
    } else {
        issues.push("Failed to create X-Forwarded-For header".to_string());
        return XffBypassResult {
            bypass_suspected: false,
            baseline_status,
            xff_status: baseline_status,
            status_changed: false,
            response_diff: None,
            issues,
        };
    }

    // Make request with X-Forwarded-For header
    let response = match client
        .request(method.clone(), url)
        .headers(modified_headers)
        .send()
    {
        Ok(resp) => resp,
        Err(e) => {
            issues.push(format!("Request with X-Forwarded-For failed: {}", e));
            return XffBypassResult {
                bypass_suspected: false,
                baseline_status,
                xff_status: baseline_status,
                status_changed: false,
                response_diff: None,
                issues,
            };
        }
    };

    let xff_status = response.status().as_u16();

    // Compare status codes
    if baseline_status != xff_status {
        status_changed = true;
        bypass_suspected = true;
        issues.push(format!(
            "[XFF Bypass?] Status changed from {} to {} with X-Forwarded-For: {}",
            baseline_status, xff_status, xff_value
        ));
    }

    // Check for suspicious status changes that indicate bypass
    if (baseline_status == 403 || baseline_status == 401) && (xff_status == 200 || xff_status == 301 || xff_status == 302) {
        bypass_suspected = true;
        issues.push(format!(
            "[XFF Bypass Suspected] Access control bypass: {} -> {} with XFF",
            baseline_status, xff_status
        ));
    }

    if !bypass_suspected {
        issues.push("No X-Forwarded-For bypass detected".to_string());
    }

    XffBypassResult {
        bypass_suspected,
        baseline_status,
        xff_status,
        status_changed,
        response_diff: if status_changed {
            Some(format!("Status: {} -> {}", baseline_status, xff_status))
        } else {
            None
        },
        issues,
    }
}

fn perform_csrf_check(
    client: &reqwest::blocking::Client,
    url: &str,
    method: &Method,
    headers: &HeaderMap,
) -> CsrfResult {
    let mut issues = Vec::new();
    let mut csrf_suspected = false;
    let mut accepts_without_origin = false;
    let mut accepts_with_fake_origin = false;
    let mut missing_samesite = true;
    let mut missing_x_frame_options = true;
    let mut missing_csp = true;

    // Only check for state-changing methods
    let state_changing = matches!(
        method.as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE" | "CONNECT" | "TRACE"
    );

    if !state_changing {
        issues.push("CSRF check skipped: not a state-changing method".to_string());
        return CsrfResult {
            csrf_suspected: false,
            accepts_without_origin: false,
            accepts_with_fake_origin: false,
            missing_samesite: true,
            missing_x_frame_options: true,
            missing_csp: true,
            issues,
        };
    }

    // Test 1: Request without Origin/Referer headers
    let mut headers_no_origin = headers.clone();
    headers_no_origin.remove("origin");
    headers_no_origin.remove("referer");

    let response_no_origin = match client
        .request(method.clone(), url)
        .headers(headers_no_origin)
        .send()
    {
        Ok(resp) => resp,
        Err(e) => {
            issues.push(format!("Request without Origin/Referer failed: {}", e));
            return CsrfResult {
                csrf_suspected: false,
                accepts_without_origin: false,
                accepts_with_fake_origin: false,
                missing_samesite: true,
                missing_x_frame_options: true,
                missing_csp: true,
                issues,
            };
        }
    };

    let status_no_origin = response_no_origin.status().as_u16();
    let headers_response_no_origin = response_no_origin.headers().clone();

    // Check if server accepts request without origin
    if status_no_origin == 200 || status_no_origin == 201 || status_no_origin == 204 {
        accepts_without_origin = true;
        csrf_suspected = true;
        issues.push(format!(
            "[CSRF Suspected] Server accepts {} request without Origin/Referer (status: {})",
            method, status_no_origin
        ));
    }

    // Test 2: Request with fake Origin header
    let mut headers_fake_origin = headers.clone();
    headers_fake_origin.remove("referer");
    if let Ok(fake_origin) = HeaderValue::from_str("http://evil.terminus.local") {
        headers_fake_origin.insert(reqwest::header::ORIGIN, fake_origin);
    }

    if let Ok(response_fake_origin) = client
        .request(method.clone(), url)
        .headers(headers_fake_origin)
        .send()
    {
        let status_fake_origin = response_fake_origin.status().as_u16();
        if status_fake_origin == 200 || status_fake_origin == 201 || status_fake_origin == 204 {
            accepts_with_fake_origin = true;
            csrf_suspected = true;
            issues.push(format!(
                "[CSRF Suspected] Server accepts {} request with fake Origin header (status: {})",
                method, status_fake_origin
            ));
        }
    }

    // Check for CSRF protections in response headers
    if let Some(set_cookie) = headers_response_no_origin.get("set-cookie") {
        if let Ok(cookie_str) = set_cookie.to_str() {
            if cookie_str.to_lowercase().contains("samesite=") {
                missing_samesite = false;
            } else {
                issues.push("[CSRF Missing Headers: SameSite]".to_string());
            }
        }
    }

    if headers_response_no_origin.get("x-frame-options").is_some() {
        missing_x_frame_options = false;
    } else {
        issues.push("[CSRF Missing Headers: X-Frame-Options]".to_string());
    }

    if headers_response_no_origin.get("content-security-policy").is_some() {
        missing_csp = false;
    } else {
        issues.push("[CSRF Missing Headers: CSP]".to_string());
    }

    if !csrf_suspected && !missing_samesite && !missing_x_frame_options && !missing_csp {
        issues.push("No CSRF vulnerabilities detected".to_string());
    }

    CsrfResult {
        csrf_suspected,
        accepts_without_origin,
        accepts_with_fake_origin,
        missing_samesite,
        missing_x_frame_options,
        missing_csp,
        issues,
    }
}

fn perform_ssrf_check(
    client: &reqwest::blocking::Client,
    url: &str,
    method: &Method,
    headers: &HeaderMap,
) -> SsrfResult {
    let mut issues = Vec::new();
    let mut ssrf_suspected = false;
    let mut vulnerable_params = Vec::new();
    let tested_payloads = vec![
        "http://127.0.0.1".to_string(),
        "http://[::1]".to_string(),
        "http://169.254.169.254/latest/meta-data/".to_string(),
        "http://evil.terminus.local".to_string(),
    ];
    let mut response_indicators = Vec::new();

    // Check if URL has parameters that might be vulnerable
    let ssrf_params = vec!["url", "uri", "dest", "destination", "next", "redirect", "image", "file", "path", "load", "fetch"];
    
    // Parse URL to check for suspicious parameters
    if let Ok(parsed_url) = reqwest::Url::parse(url) {
        if let Some(query) = parsed_url.query() {
            for ssrf_param in &ssrf_params {
                if query.to_lowercase().contains(&format!("{}=", ssrf_param)) {
                    vulnerable_params.push(ssrf_param.to_string());
                }
            }
        }
    }

    // If no suspicious parameters found, skip detailed testing
    if vulnerable_params.is_empty() {
        issues.push("No URL parameters found that typically indicate SSRF risk".to_string());
        return SsrfResult {
            ssrf_suspected: false,
            vulnerable_params,
            tested_payloads: Vec::new(),
            response_indicators,
            issues,
        };
    }

    // For passive detection, we check if the endpoint behavior suggests SSRF vulnerability
    // We make a baseline request and look for indicators
    let baseline_response = match client
        .request(method.clone(), url)
        .headers(headers.clone())
        .send()
    {
        Ok(resp) => resp,
        Err(e) => {
            issues.push(format!("Baseline SSRF check request failed: {}", e));
            return SsrfResult {
                ssrf_suspected: false,
                vulnerable_params,
                tested_payloads: Vec::new(),
                response_indicators,
                issues,
            };
        }
    };

    // Check response for SSRF indicators
    if let Ok(body) = baseline_response.text() {
        let ssrf_indicators = vec![
            ("EC2", "AWS metadata service indicator"),
            ("metadata", "Metadata service indicator"),
            ("internal", "Internal network indicator"),
            ("localhost", "Localhost access indicator"),
            ("169.254.169.254", "AWS metadata IP"),
            ("connection refused", "Connection attempt indicator"),
            ("timeout", "Timeout indicator"),
        ];

        for (indicator, description) in ssrf_indicators {
            if body.to_lowercase().contains(&indicator.to_lowercase()) {
                ssrf_suspected = true;
                response_indicators.push(indicator.to_string());
                issues.push(format!(
                    "[SSRF Suspected] {} found in response: '{}'",
                    description, indicator
                ));
            }
        }
    }

    if ssrf_suspected {
        issues.push(format!(
            "[SSRF Suspected] Vulnerable parameters detected: {}. Response contains SSRF indicators.",
            vulnerable_params.join(", ")
        ));
    } else if !vulnerable_params.is_empty() {
        issues.push(format!(
            "Potentially vulnerable parameters found ({}), but no SSRF indicators detected in response",
            vulnerable_params.join(", ")
        ));
    }

    SsrfResult {
        ssrf_suspected,
        vulnerable_params,
        tested_payloads,
        response_indicators,
        issues,
    }
}
