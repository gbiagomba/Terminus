use anyhow::{Context, Result};
use clap::ArgMatches;
use http::StatusCode;
use rand::RngExt;
use regex::Regex;
use reqwest;
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::io;
use std::process;
use std::sync::Arc;
use std::time::Duration;
use std::str::FromStr;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{sleep, Instant};

use crate::models::{OutputFormat, ScanResult};
use crate::output::{collect_vuln_indicators, output_results};
use crate::scan::analysis::{analyze_security_headers, check_reflection, detect_error_messages, extract_links_from_body};
use crate::scan::exploits::{
    perform_csrf_check, perform_host_injection_check, perform_http2_desync_check,
    perform_open_redirect_check, perform_sqli_check, perform_ssrf_check,
    perform_xff_bypass_check, perform_xss_check,
};
use crate::scan::exploits::payloads::{load_payloads_from_file, OPEN_REDIRECT_PAYLOADS, SQLI_PAYLOADS, XSS_PAYLOADS};
use crate::scan::http::{
    build_full_url, extract_redirect_target, flatten_headers, normalize_method, parse_header,
};
use crate::scan::input::{parse_input_file, read_lines, read_stdin};
use crate::scan::{ARBITRARY_HTTP_METHODS, HTTP_METHODS};
use crate::transport::{
    Http12Transport, Http3Transport, HttpTransport, HttpVersion, TerminusRequest, TransportConfig,
};

struct RateLimiter {
    requests_per_second: f64,
    last_request: Instant,
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
            last_request: Instant::now(),
        })
    }

    async fn wait(&mut self) {
        let interval = Duration::from_secs_f64(1.0 / self.requests_per_second);
        let elapsed = self.last_request.elapsed();

        if elapsed < interval {
            sleep(interval - elapsed).await;
        }

        self.last_request = Instant::now();
    }
}

fn build_request(url: &str, method: &str, headers: &[(String, String)]) -> TerminusRequest {
    TerminusRequest {
        url: url.to_string(),
        method: method.to_string(),
        headers: headers.to_vec(),
        body: None,
        timeout: None,
        version: None,
    }
}

pub async fn run_scan(matches: &ArgMatches) -> Result<()> {
    let verbose = matches.get_flag("verbose");
    let allow_insecure = matches.get_flag("insecure");
    let follow_redirects = matches.get_flag("follow");

    let thread_count: usize = matches.get_one::<String>("threads")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let scan_level = matches.get_one::<String>("scan-level").map(|s| s.as_str());

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

    // Parse --exploit unified flag
    let exploit_modules: HashSet<String> = matches
        .get_one::<String>("exploit")
        .map(|val| {
            val.split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // Also enable individual flags from --exploit modules
    let detect_csrf = detect_csrf || exploit_modules.contains("csrf");
    let detect_ssrf = detect_ssrf || exploit_modules.contains("ssrf");
    let detect_xss = exploit_modules.contains("xss");
    let detect_sqli = exploit_modules.contains("sqli");
    let detect_open_redirect = exploit_modules.contains("open_redirect");

    // Build payload lists (prefer user-supplied file, fall back to canned)
    let custom_payloads_file = matches.get_one::<String>("payloads");

    let xss_payloads: Vec<String> = if let Some(file) = custom_payloads_file {
        let loaded = load_payloads_from_file(file);
        if loaded.is_empty() {
            XSS_PAYLOADS.iter().map(|s| s.to_string()).collect()
        } else {
            loaded
        }
    } else {
        XSS_PAYLOADS.iter().map(|s| s.to_string()).collect()
    };

    let sqli_payloads: Vec<String> = if let Some(file) = custom_payloads_file {
        let loaded = load_payloads_from_file(file);
        if loaded.is_empty() {
            SQLI_PAYLOADS.iter().map(|s| s.to_string()).collect()
        } else {
            loaded
        }
    } else {
        SQLI_PAYLOADS.iter().map(|s| s.to_string()).collect()
    };

    let open_redirect_payloads: Vec<String> = if let Some(file) = custom_payloads_file {
        let loaded = load_payloads_from_file(file);
        if loaded.is_empty() {
            OPEN_REDIRECT_PAYLOADS.iter().map(|s| s.to_string()).collect()
        } else {
            loaded
        }
    } else {
        OPEN_REDIRECT_PAYLOADS.iter().map(|s| s.to_string()).collect()
    };

    let rate_limiter_option = if let Some(rate_str) = matches.get_one::<String>("rate-limit") {
        Some(RateLimiter::new(rate_str)?)
    } else {
        None
    };

    let random_delay_range = if let Some(delay_str) = matches.get_one::<String>("random-delay") {
        let parts: Vec<&str> = delay_str.split('-').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid random delay range. Use format like '1-5'");
        }
        let min: u64 = parts[0].parse().context("Invalid delay minimum")?;
        let max: u64 = parts[1].parse().context("Invalid delay maximum")?;
        Some((min, max))
    } else {
        None
    };

    let grep_pattern = matches.get_one::<String>("grep-response")
        .map(|p| Regex::new(p))
        .transpose()
        .context("Invalid regex pattern")?;

    let http_version = if let Some(version_str) = matches.get_one::<String>("http-version") {
        match version_str.as_str() {
            "1.0" => HttpVersion::Http10,
            "1.1" => HttpVersion::Http11,
            "2" | "2.0" => HttpVersion::Http2,
            "3" | "3.0" => HttpVersion::Http3,
            _ => {
                eprintln!("Invalid HTTP version: {}. Supported: 1.0, 1.1, 2, 3", version_str);
                process::exit(1);
            }
        }
    } else {
        HttpVersion::Http11
    };

    let proxy_url = matches.get_one::<String>("proxy").map(|s| s.to_string());

    let transport_config = TransportConfig {
        allow_insecure,
        proxy: proxy_url.clone(),
        http_version,
        timeout: None,
    };

    let transport: Arc<dyn HttpTransport> = match http_version {
        HttpVersion::Http3 => Arc::new(Http3Transport::new(transport_config)?),
        _ => Arc::new(Http12Transport::new(transport_config)?),
    };

    let output_format = matches
        .get_one::<String>("output-format")
        .and_then(|f| OutputFormat::from_str(f).ok())
        .unwrap_or(OutputFormat::Stdout);

    let ipv6_enabled = matches.get_flag("ipv6");

    let urls = if let Some(url) = matches.get_one::<String>("url") {
        vec![url.to_string()]
    } else if let Some(file) = matches.get_one::<String>("file") {
        parse_input_file(file, ipv6_enabled)?
    } else if !io::stdin().is_terminal() {
        read_stdin(ipv6_enabled)?
    } else {
        eprintln!("You must provide a URL (-u), file (-f), or pipe input via stdin");
        process::exit(1);
    };

    let fuzz_methods_enabled = matches.get_flag("fuzz-methods");
    let mut methods_set: HashSet<String> = HashSet::new();
    let mut arbitrary_methods: HashSet<String> = HashSet::new();

    let standard_methods: HashSet<String> = HTTP_METHODS.iter().map(|m| m.to_string()).collect();

    if let Some(m) = matches.get_one::<String>("method") {
        if m.eq_ignore_ascii_case("ALL") {
            for method in HTTP_METHODS {
                methods_set.insert(method.to_string());
            }
        } else {
            let method_upper = normalize_method(m);
            methods_set.insert(method_upper.clone());
            if !standard_methods.contains(&method_upper) {
                arbitrary_methods.insert(method_upper);
            }
        }
    } else {
        methods_set.insert("GET".to_string());
    }

    if fuzz_methods_enabled {
        for method in ARBITRARY_HTTP_METHODS {
            methods_set.insert(method.to_string());
            arbitrary_methods.insert(method.to_string());
        }
    }

    if let Some(custom_methods) = matches.get_many::<String>("custom-method") {
        for method in custom_methods {
            let method_upper = normalize_method(method);
            methods_set.insert(method_upper.clone());
            arbitrary_methods.insert(method_upper);
        }
    }

    if let Some(custom_methods_file) = matches.get_one::<String>("custom-methods-file") {
        match read_lines(custom_methods_file) {
            Ok(lines) => {
                for line in lines {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let method_upper = normalize_method(trimmed);
                    methods_set.insert(method_upper.clone());
                    arbitrary_methods.insert(method_upper);
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to read custom methods file: {}", e);
            }
        }
    }

    let mut methods: Vec<String> = methods_set.into_iter().collect();
    methods.sort();

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

    let rate_limiter = Arc::new(Mutex::new(rate_limiter_option));
    let results = Arc::new(Mutex::new(Vec::new()));

    let mut custom_headers: Vec<(String, String)> = Vec::new();

    if let Some(headers) = matches.get_many::<String>("header") {
        for header in headers {
            if let Some((key, value)) = parse_header(header) {
                custom_headers.push((key, value));
            } else {
                eprintln!("Warning: Invalid header format: {}", header);
            }
        }
    }

    if let Some(header_file) = matches.get_one::<String>("header-file") {
        match read_lines(header_file) {
            Ok(lines) => {
                for line in lines {
                    if let Some((key, value)) = parse_header(&line) {
                        custom_headers.push((key, value));
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to read header file: {}", e);
            }
        }
    }

    let mut cookie_string = String::new();

    if let Some(cookie) = matches.get_one::<String>("cookie") {
        cookie_string = cookie.clone();
    }

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

    if !cookie_string.is_empty() {
        custom_headers.push(("Cookie".to_string(), cookie_string));
    }

    let mut scan_targets = Vec::new();
    for url in &urls {
        let has_port = url.contains("://") && url.split("://").nth(1).map_or(false, |host_part| host_part.contains(':'));
        let is_https = url.starts_with("https://");
        let is_http = url.starts_with("http://");

        let test_ports = if has_port {
            vec![0]
        } else if !ports.is_empty() {
            ports.clone()
        } else if is_https {
            vec![443]
        } else if is_http {
            vec![80]
        } else {
            vec![80, 443]
        };

        for port in &test_ports {
            let full_url = build_full_url(url, *port);
            scan_targets.push((url.clone(), *port, full_url));
        }
    }

    let mut baseline_statuses: HashMap<String, u16> = HashMap::new();
    if !arbitrary_methods.is_empty() {
        let mut seen = HashSet::new();
        for (_, _port, full_url) in &scan_targets {
            if !seen.insert(full_url.clone()) {
                continue;
            }
            let mut limiter_guard = rate_limiter.lock().await;
            if let Some(ref mut limiter) = *limiter_guard {
                limiter.wait().await;
            }

            if let Some((min, max)) = random_delay_range {
                let delay = rand::rng().random_range(min..=max);
                sleep(Duration::from_secs(delay)).await;
            }

            let request = build_request(full_url, "GET", &custom_headers);
            let status = transport.send(request).await.map(|resp| resp.status).unwrap_or(0);

            baseline_statuses.insert(full_url.clone(), status);
        }
    }

    let baseline_statuses = Arc::new(baseline_statuses);
    let arbitrary_methods = Arc::new(arbitrary_methods);

    let mut scan_tasks = Vec::new();
    for (url, port, full_url) in &scan_targets {
        for method in &methods {
            scan_tasks.push((url.clone(), method.clone(), *port, full_url.clone()));
        }
    }

    let semaphore = Arc::new(Semaphore::new(thread_count));

    let mut handles = Vec::new();
    for (url, method, port, full_url) in scan_tasks {
        let permit = semaphore.clone().acquire_owned().await?;
        let rate_limiter = Arc::clone(&rate_limiter);
        let results = Arc::clone(&results);
        let custom_headers = custom_headers.clone();
        let arbitrary_methods = Arc::clone(&arbitrary_methods);
        let baseline_statuses = Arc::clone(&baseline_statuses);
        let transport = Arc::clone(&transport);
        let grep_pattern = grep_pattern.clone();
        let random_delay_range = random_delay_range;
        let proxy_url = proxy_url.clone();
        let xss_payloads = xss_payloads.clone();
        let sqli_payloads = sqli_payloads.clone();
        let open_redirect_payloads = open_redirect_payloads.clone();

        let handle = tokio::spawn(async move {
            let _permit = permit;
            let request_headers_str = flatten_headers(&custom_headers);

            let mut limiter_guard = rate_limiter.lock().await;
            if let Some(ref mut limiter) = *limiter_guard {
                limiter.wait().await;
            }

            if let Some((min, max)) = random_delay_range {
                let delay = rand::rng().random_range(min..=max);
                sleep(Duration::from_secs(delay)).await;
            }

            let is_arbitrary_method = arbitrary_methods.contains(&method);
            let arbitrary_method_used = if is_arbitrary_method {
                Some(method.clone())
            } else {
                None
            };

            let request = build_request(&full_url, &method, &custom_headers);

            match transport.send(request).await {
                Ok(resp) => {
                    let status = resp.status;
                    if let Some(filter) = filter_code {
                        if status != filter.as_u16() {
                            return;
                        }
                    }

                    let mut arbitrary_method_accepted = None;
                    let mut method_confusion_suspected = None;

                    if is_arbitrary_method {
                        if status >= 200 && status < 400 {
                            arbitrary_method_accepted = Some(true);
                        } else {
                            arbitrary_method_accepted = Some(false);
                        }

                        if let Some(baseline) = baseline_statuses.get(&full_url) {
                            if *baseline != 0 && *baseline != status {
                                method_confusion_suspected = Some(true);
                            } else {
                                method_confusion_suspected = Some(false);
                            }
                        }
                    }

                    let headers_str = if verbose {
                        Some(flatten_headers(&resp.headers))
                    } else {
                        None
                    };

                    let body_text = if resp.body.is_empty() {
                        None
                    } else {
                        Some(String::from_utf8_lossy(&resp.body).to_string())
                    };
                    let response_body = body_text.clone();

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

                    let extracted_links = if extract_links {
                        body_text.as_ref().map(|b| extract_links_from_body(b))
                    } else {
                        None
                    };

                    let security_headers = if check_security_headers {
                        Some(analyze_security_headers(&resp.headers))
                    } else {
                        None
                    };

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

                    let reflection_detected = if detect_reflection {
                        let reflection_marker = format!("terminus_test_{}", rand::random::<u64>());
                        body_text.as_ref().map(|b| check_reflection(b, &reflection_marker))
                    } else {
                        None
                    };

                    let should_add = if grep_pattern.is_some() {
                        matched_patterns.is_some()
                    } else {
                        true
                    };

                    let http2_desync = if http2_desync_check && full_url.starts_with("https") {
                        let proxy_url_opt = proxy_url.as_deref();
                        Some(perform_http2_desync_check(
                            allow_insecure,
                            &full_url,
                            &method,
                            &custom_headers,
                            status,
                            proxy_url_opt,
                        ).await)
                    } else {
                        None
                    };

                    let host_injection = if detect_host_injection {
                        Some(perform_host_injection_check(
                            transport.as_ref(),
                            &full_url,
                            &method,
                            &custom_headers,
                        ).await)
                    } else {
                        None
                    };

                    let xff_bypass = if detect_xff_bypass {
                        Some(perform_xff_bypass_check(
                            transport.as_ref(),
                            &full_url,
                            &method,
                            &custom_headers,
                            status,
                        ).await)
                    } else {
                        None
                    };

                    let csrf_result = if detect_csrf {
                        Some(perform_csrf_check(
                            transport.as_ref(),
                            &full_url,
                            &method,
                            &custom_headers,
                        ).await)
                    } else {
                        None
                    };

                    let ssrf_result = if detect_ssrf {
                        Some(perform_ssrf_check(
                            transport.as_ref(),
                            &full_url,
                            &method,
                            &custom_headers,
                        ).await)
                    } else {
                        None
                    };

                    // Build a shared reqwest client for exploit checks
                    let exploit_client = reqwest::Client::builder()
                        .danger_accept_invalid_certs(allow_insecure)
                        .redirect(reqwest::redirect::Policy::none())
                        .build()
                        .unwrap_or_default();

                    let xss_confirmed = if detect_xss {
                        perform_xss_check(&full_url, &exploit_client, &xss_payloads).await
                    } else {
                        Vec::new()
                    };

                    let sqli_confirmed = if detect_sqli {
                        perform_sqli_check(&full_url, &exploit_client, &sqli_payloads).await
                    } else {
                        Vec::new()
                    };

                    let open_redirect_confirmed = if detect_open_redirect {
                        perform_open_redirect_check(&full_url, &exploit_client, &open_redirect_payloads).await
                    } else {
                        Vec::new()
                    };

                    // Log findings to stderr for now (future: integrate into ScanResult)
                    if !xss_confirmed.is_empty() {
                        eprintln!("[XSS] {} confirmed payloads at {}: {:?}", xss_confirmed.len(), full_url, xss_confirmed);
                    }
                    if !sqli_confirmed.is_empty() {
                        eprintln!("[SQLi] {} confirmed payloads at {}: {:?}", sqli_confirmed.len(), full_url, sqli_confirmed);
                    }
                    if !open_redirect_confirmed.is_empty() {
                        eprintln!("[OpenRedirect] {} confirmed payloads at {}: {:?}", open_redirect_confirmed.len(), full_url, open_redirect_confirmed);
                    }

                    if should_add {
                        if verbose && matches!(output_format, OutputFormat::Stdout | OutputFormat::All) {
                            let temp_result = ScanResult {
                                url: url.clone(),
                                method: method.clone(),
                                arbitrary_method_used: arbitrary_method_used.clone(),
                                arbitrary_method_accepted,
                                method_confusion_suspected,
                                status,
                                port,
                                headers: headers_str.clone(),
                                error: None,
                                body_preview: body_preview.clone(),
                                matched_patterns: matched_patterns.clone(),
                                extracted_links: extracted_links.clone(),
                                security_headers: security_headers.clone(),
                                detected_errors: detected_errors.clone(),
                                reflection_detected,
                                http2_desync: http2_desync.clone(),
                                host_injection: host_injection.clone(),
                                xff_bypass: xff_bypass.clone(),
                                csrf_result: csrf_result.clone(),
                                ssrf_result: ssrf_result.clone(),
                                request_headers: Some(request_headers_str.clone()),
                                response_body: response_body.clone(),
                            };

                            let vuln_indicators = collect_vuln_indicators(&temp_result);
                            let indicators_str = if !vuln_indicators.is_empty() {
                                format!(" {}", vuln_indicators.join(" "))
                            } else {
                                String::new()
                            };

                            if let Some(ref headers) = headers_str {
                                println!("URL: {}, Method: {}, Status: {}, Port: {}, Headers: {}{}",
                                    url, method, status, port, headers, indicators_str);
                            } else {
                                println!("URL: {}, Method: {}, Status: {}, Port: {}{}",
                                    url, method, status, port, indicators_str);
                            }
                        }

                        let mut results_guard = results.lock().await;
                        results_guard.push(ScanResult {
                            url: url.clone(),
                            method: method.clone(),
                            arbitrary_method_used: arbitrary_method_used.clone(),
                            arbitrary_method_accepted,
                            method_confusion_suspected,
                            status,
                            port,
                            headers: headers_str.clone(),
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
                            request_headers: Some(request_headers_str.clone()),
                            response_body,
                        });
                    }

                    if follow_redirects {
                        let mut redirect_url = extract_redirect_target(
                            &full_url,
                            &resp.headers,
                            body_text.as_deref(),
                        );
                        let mut redirect_count = 0;
                        let max_redirects = 10;

                        while redirect_count < max_redirects {
                            let Some(next_url) = redirect_url.take() else {
                                break;
                            };

                            let request = build_request(&next_url, &method, &custom_headers);

                            match transport.send(request).await {
                                Ok(redirect_resp) => {
                                    let redirect_status = redirect_resp.status;
                                    let redirect_headers_str = if verbose {
                                        Some(flatten_headers(&redirect_resp.headers))
                                    } else {
                                        None
                                    };
                                    let redirect_body = if redirect_resp.body.is_empty() {
                                        None
                                    } else {
                                        Some(String::from_utf8_lossy(&redirect_resp.body).to_string())
                                    };

                                    let mut results_guard = results.lock().await;
                                    results_guard.push(ScanResult {
                                        url: next_url.clone(),
                                        method: method.clone(),
                                        arbitrary_method_used: arbitrary_method_used.clone(),
                                        arbitrary_method_accepted,
                                        method_confusion_suspected,
                                        status: redirect_status,
                                        port,
                                        headers: redirect_headers_str,
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
                                        request_headers: Some(request_headers_str.clone()),
                                        response_body: redirect_body.clone(),
                                    });

                                    redirect_url = extract_redirect_target(
                                        &next_url,
                                        &redirect_resp.headers,
                                        redirect_body.as_deref(),
                                    );
                                    redirect_count += 1;
                                }
                                Err(_) => {
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if verbose && matches!(output_format, OutputFormat::Stdout | OutputFormat::All) {
                        eprintln!("Error on {}:{} using {}: {}", url, port, method, e);
                    }

                    let mut results_guard = results.lock().await;
                    results_guard.push(ScanResult {
                        url: url.clone(),
                        method: method.clone(),
                        arbitrary_method_used: arbitrary_method_used.clone(),
                        arbitrary_method_accepted: None,
                        method_confusion_suspected: None,
                        status: 0,
                        port,
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
                        request_headers: Some(request_headers_str.clone()),
                        response_body: None,
                    });
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let final_results = results.lock().await.clone();

    if let Some(diff_file) = matches.get_one::<String>("diff") {
        let old_results = crate::diff::load_results_for_path(diff_file)?;
        let diff = crate::diff::compute_diff_inline(&old_results, &final_results);
        crate::diff::display_diff(&diff)?;
    }

    output_results(&final_results, output_format, output_base, verbose)?;

    Ok(())
}
