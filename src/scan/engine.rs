use anyhow::{Context, Result};
use clap::ArgMatches;
use rayon::prelude::*;
use regex::Regex;
use reqwest::blocking::ClientBuilder;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{StatusCode, Version};
use std::collections::HashSet;
use std::io::IsTerminal;
use std::io;
use std::str::FromStr;
use std::process;
use std::sync::{Arc, Mutex};

use crate::models::{OutputFormat, ScanResult};
use crate::output::{collect_vuln_indicators, output_results};
use crate::scan::analysis::{analyze_security_headers, check_reflection, detect_error_messages, extract_links_from_body};
use crate::scan::exploits::{
    perform_csrf_check, perform_host_injection_check, perform_http2_desync_check,
    perform_ssrf_check, perform_xff_bypass_check,
};
use crate::scan::http::{
    build_full_url, build_reqwest_method, extract_redirect_target, flatten_headers, parse_header,
};
use crate::scan::input::{parse_input_file, read_lines, read_stdin};
use crate::scan::{ARBITRARY_HTTP_METHODS, HTTP_METHODS};

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

pub fn run_scan(matches: &ArgMatches) -> Result<()> {
    let verbose = matches.get_flag("verbose");
    let allow_insecure = matches.get_flag("insecure");
    let follow_redirects = matches.get_flag("follow");

    let thread_count: usize = matches.get_one::<String>("threads")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build_global()
        .context("Failed to initialize thread pool")?;

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

    let mut client_builder = ClientBuilder::new()
        .danger_accept_invalid_certs(allow_insecure)
        .redirect(reqwest::redirect::Policy::none());

    if let Some(proxy_url) = matches.get_one::<String>("proxy") {
        let proxy = reqwest::Proxy::all(proxy_url)
            .context("Failed to configure proxy")?;
        client_builder = client_builder.proxy(proxy);
    }

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
        if version == Version::HTTP_2 {
            client_builder = client_builder.http2_prior_knowledge();
        }
    }

    let client = client_builder
        .build()
        .context("Failed to build HTTP client")?;

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
            methods_set.insert(m.to_uppercase());
            if !standard_methods.contains(&m.to_uppercase()) {
                arbitrary_methods.insert(m.to_uppercase());
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
            let method_upper = method.to_uppercase();
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
                    let method_upper = trimmed.to_uppercase();
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

    let mut custom_headers = HeaderMap::new();

    if let Some(headers) = matches.get_many::<String>("header") {
        for header in headers {
            if let Some((key, value)) = parse_header(header) {
                custom_headers.insert(key, value);
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
                        custom_headers.insert(key, value);
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
        if let Ok(cookie_value) = HeaderValue::from_str(&cookie_string) {
            custom_headers.insert(reqwest::header::COOKIE, cookie_value);
        } else {
            eprintln!("Warning: Invalid cookie format");
        }
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

    let mut baseline_statuses = std::collections::HashMap::new();
    if !arbitrary_methods.is_empty() {
        let mut seen = HashSet::new();
        for (_, _port, full_url) in &scan_targets {
            if !seen.insert(full_url.clone()) {
                continue;
            }
            if let Ok(mut limiter_guard) = rate_limiter.lock() {
                if let Some(ref mut limiter) = *limiter_guard {
                    limiter.wait();
                }
            }

            if let Some((min, max)) = random_delay_range {
                use rand::RngExt;
                let delay = rand::rng().random_range(min..=max);
                std::thread::sleep(std::time::Duration::from_secs(delay));
            }

            let baseline_method = build_reqwest_method("GET");
            let status = client.request(baseline_method, full_url)
                .headers(custom_headers.clone())
                .send()
                .map(|resp| resp.status().as_u16())
                .ok();

            if let Some(code) = status {
                baseline_statuses.insert(full_url.clone(), code);
            } else {
                baseline_statuses.insert(full_url.clone(), 0);
            }
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

    scan_tasks.par_iter().for_each(|(url, method, port, full_url)| {
        let req_method = build_reqwest_method(method);
        let is_arbitrary_method = arbitrary_methods.contains(method);
        let arbitrary_method_used = if is_arbitrary_method {
            Some(method.clone())
        } else {
            None
        };

        if let Ok(mut limiter_guard) = rate_limiter.lock() {
            if let Some(ref mut limiter) = *limiter_guard {
                limiter.wait();
            }
        }

        if let Some((min, max)) = random_delay_range {
            use rand::RngExt;
            let delay = rand::rng().random_range(min..=max);
            std::thread::sleep(std::time::Duration::from_secs(delay));
        }

        let request_headers_str = flatten_headers(&custom_headers);

        match client.request(req_method.clone(), full_url)
                    .headers(custom_headers.clone())
                    .send() {
                    Ok(resp) => {
                        let status = resp.status();
                        if let Some(filter) = filter_code {
                            if status != filter {
                                return;
                            }
                        }

                        let mut arbitrary_method_accepted = None;
                        let mut method_confusion_suspected = None;

                        if is_arbitrary_method {
                            if status.is_success() || status.is_redirection() {
                                arbitrary_method_accepted = Some(true);
                            } else {
                                arbitrary_method_accepted = Some(false);
                            }

                            if let Some(baseline) = baseline_statuses.get(full_url) {
                                if *baseline != 0 && *baseline != status.as_u16() {
                                    method_confusion_suspected = Some(true);
                                } else {
                                    method_confusion_suspected = Some(false);
                                }
                            }
                        }

                        let headers_str = if verbose {
                            Some(flatten_headers(resp.headers()))
                        } else {
                            None
                        };

                        let response_headers = resp.headers().clone();
                        let body_text = resp.text().ok();
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
                            Some(analyze_security_headers(&response_headers))
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
                            let proxy_url_opt = matches.get_one::<String>("proxy").map(|s| s.as_str());
                            Some(perform_http2_desync_check(&client, full_url, &req_method, &custom_headers, status.as_u16(), proxy_url_opt))
                        } else {
                            None
                        };

                        let host_injection = if detect_host_injection {
                            Some(perform_host_injection_check(&client, full_url, &req_method, &custom_headers))
                        } else {
                            None
                        };

                        let xff_bypass = if detect_xff_bypass {
                            Some(perform_xff_bypass_check(&client, full_url, &req_method, &custom_headers, status.as_u16()))
                        } else {
                            None
                        };

                        let csrf_result = if detect_csrf {
                            Some(perform_csrf_check(&client, full_url, &req_method, &custom_headers))
                        } else {
                            None
                        };

                        let ssrf_result = if detect_ssrf {
                            Some(perform_ssrf_check(&client, full_url, &req_method, &custom_headers))
                        } else {
                            None
                        };

                        if should_add {
                            if verbose && matches!(output_format, OutputFormat::Stdout | OutputFormat::All) {
                                let temp_result = ScanResult {
                                    url: url.clone(),
                                    method: method.clone(),
                                    arbitrary_method_used: arbitrary_method_used.clone(),
                                    arbitrary_method_accepted,
                                    method_confusion_suspected,
                                    status: status.as_u16(),
                                    port: *port,
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
                                        url, method, status.as_u16(), port, headers, indicators_str);
                                } else {
                                    println!("URL: {}, Method: {}, Status: {}, Port: {}{}",
                                        url, method, status.as_u16(), port, indicators_str);
                                }
                            }

                            if let Ok(mut results_guard) = results.lock() {
                                results_guard.push(ScanResult {
                                    url: url.clone(),
                                    method: method.clone(),
                                    arbitrary_method_used: arbitrary_method_used.clone(),
                                    arbitrary_method_accepted,
                                    method_confusion_suspected,
                                    status: status.as_u16(),
                                    port: *port,
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
                        }

                        if follow_redirects {
                            let mut redirect_url = extract_redirect_target(
                                full_url,
                                &response_headers,
                                body_text.as_deref(),
                            );
                            let mut redirect_count = 0;
                            let max_redirects = 10;

                            while redirect_count < max_redirects {
                                let Some(next_url) = redirect_url.take() else {
                                    break;
                                };

                                match client.request(req_method.clone(), &next_url)
                                    .headers(custom_headers.clone())
                                    .send() {
                                    Ok(redirect_resp) => {
                                        let redirect_status = redirect_resp.status();
                                        let redirect_headers = redirect_resp.headers().clone();
                                        let redirect_headers_str = if verbose {
                                            Some(flatten_headers(&redirect_headers))
                                        } else {
                                            None
                                        };
                                        let redirect_body = redirect_resp.text().ok();

                                        if let Ok(mut results_guard) = results.lock() {
                                            results_guard.push(ScanResult {
                                                url: next_url.clone(),
                                                method: method.clone(),
                                                arbitrary_method_used: arbitrary_method_used.clone(),
                                                arbitrary_method_accepted,
                                                method_confusion_suspected,
                                                status: redirect_status.as_u16(),
                                                port: *port,
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
                                        }

                                        redirect_url = extract_redirect_target(
                                            &next_url,
                                            &redirect_headers,
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

                        if let Ok(mut results_guard) = results.lock() {
                            results_guard.push(ScanResult {
                                url: url.clone(),
                                method: method.clone(),
                                arbitrary_method_used: arbitrary_method_used.clone(),
                                arbitrary_method_accepted: None,
                                method_confusion_suspected: None,
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
                                request_headers: Some(request_headers_str.clone()),
                                response_body: None,
                            });
                        }
                    }
                }
    });

    let final_results = results.lock().unwrap().clone();

    if let Some(diff_file) = matches.get_one::<String>("diff") {
        let old_results = crate::diff::load_previous_scan(diff_file)?;
        let diff = crate::diff::compute_diff(&old_results, &final_results);
        crate::diff::display_diff(&diff);
    }

    output_results(&final_results, output_format, output_base, verbose)?;

    Ok(())
}
