use anyhow::{Context, Result};
use atty::Stream;
use clap::{Arg, ArgAction, Command};
use regex::Regex;
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
            "all" => Ok(OutputFormat::All),
            _ => Err(format!("Invalid output format: {}", s)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanResult {
    url: String,
    method: String,
    status: u16,
    port: u16,
    headers: Option<String>,
    error: Option<String>,
}

fn main() -> Result<()> {
    let matches = Command::new("Terminus")
        .version("2.4.0")
        .about("URL testing with support for multiple input formats (nmap, testssl, ProjectDiscovery), IPv4/IPv6, and various output formats")
        .arg(Arg::new("url").short('u').long("url").value_name("URL").help("Specify a single URL/IP to check"))
        .arg(Arg::new("file").short('f').long("file").value_name("FILE").help("Input file (URLs, nmap XML/greppable, testssl JSON, nuclei/katana JSON)"))
        .arg(Arg::new("method").short('X').long("method").value_name("METHOD").help("Specify the HTTP method to use (default: GET). Use ALL to test all methods"))
        .arg(Arg::new("port").short('p').long("port").value_name("PORTS").help("Comma-separated ports to connect to (e.g., 80,443)").use_value_delimiter(true))
        .arg(Arg::new("ipv6").short('6').long("ipv6").help("Enable IPv6 scanning").action(ArgAction::SetTrue))
        .arg(Arg::new("insecure").short('k').long("insecure").help("Allow insecure SSL connections").action(ArgAction::SetTrue))
        .arg(Arg::new("verbose").short('v').long("verbose").help("Enable verbose output with response headers").action(ArgAction::SetTrue))
        .arg(Arg::new("follow").short('L').long("follow").help("Follow HTTP redirects").action(ArgAction::SetTrue))
        .arg(Arg::new("output").short('o').long("output").value_name("FILE").help("Output file base name (extension added based on format)"))
        .arg(Arg::new("output-format").long("output-format").value_name("FORMAT").help("Output format: stdout, txt, json, html, all (default: stdout)"))
        .arg(Arg::new("filter").short('F').long("filter-code").value_name("STATUS_CODE").help("Filter results by HTTP status code"))
        .arg(Arg::new("proxy").short('x').long("proxy").value_name("PROXY").help("Specify proxy URL (e.g., http://127.0.0.1:8080 for Burp)"))
        .arg(Arg::new("header").short('H').long("header").value_name("HEADER").action(ArgAction::Append).help("Add custom header (format: 'Name: Value'). Can be specified multiple times"))
        .arg(Arg::new("header-file").long("header-file").value_name("FILE").help("Read headers from file (one per line, format: 'Name: Value')"))
        .arg(Arg::new("cookie").short('b').long("cookie").value_name("COOKIE").help("Add cookie string (format: 'name1=value1; name2=value2')"))
        .arg(Arg::new("cookie-file").short('c').long("cookie-file").value_name("FILE").help("Read cookies from file"))
        .arg(Arg::new("http-version").long("http-version").value_name("VERSION").help("Force HTTP version (1.0, 1.1, or 2)"))
        .get_matches();

    let verbose = matches.get_flag("verbose");
    let allow_insecure = matches.get_flag("insecure");
    let follow_redirects = matches.get_flag("follow");

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
    } else if !atty::is(Stream::Stdin) {
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

    let mut results: Vec<ScanResult> = Vec::new();

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

    // Scan URLs
    for url in &urls {
        let default_port = if url.starts_with("https") { 443 } else { 80 };
        let test_ports = if ports.is_empty() { vec![default_port] } else { ports.clone() };

        for method in &methods {
            let req_method = Method::from_str(method).unwrap_or(Method::GET);
            for port in &test_ports {
                let full_url = format!("{}:{}", url, port);
                match client.request(req_method.clone(), &full_url)
                    .headers(custom_headers.clone())
                    .send() {
                    Ok(resp) => {
                        let status = resp.status();
                        if let Some(filter) = filter_code {
                            if status != filter {
                                continue;
                            }
                        }

                        let headers_str = if verbose {
                            Some(flatten_headers(resp.headers()))
                        } else {
                            None
                        };

                        results.push(ScanResult {
                            url: url.clone(),
                            method: method.clone(),
                            status: status.as_u16(),
                            port: *port,
                            headers: headers_str,
                            error: None,
                        });
                    }
                    Err(e) => {
                        results.push(ScanResult {
                            url: url.clone(),
                            method: method.clone(),
                            status: 0,
                            port: *port,
                            headers: None,
                            error: Some(e.to_string()),
                        });
                    }
                }
            }
        }
    }

    // Output results in the specified format(s)
    output_results(&results, output_format, output_base, verbose)?;

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
        OutputFormat::All => {
            output_stdout(results, verbose);
            output_txt(results, output_base, verbose)?;
            output_json(results, output_base)?;
            output_html(results, output_base)?;
        }
    }
    Ok(())
}

fn output_stdout(results: &[ScanResult], verbose: bool) {
    for result in results {
        if let Some(error) = &result.error {
            eprintln!("Error on {}:{} using {}: {}", result.url, result.port, result.method, error);
        } else {
            if verbose {
                if let Some(headers) = &result.headers {
                    println!("URL: {}, Method: {}, Status: {}, Port: {}, Headers: {}",
                        result.url, result.method, result.status, result.port, headers);
                } else {
                    println!("URL: {}, Method: {}, Status: {}, Port: {}",
                        result.url, result.method, result.status, result.port);
                }
            } else {
                println!("URL: {}, Method: {}, Status: {}, Port: {}",
                    result.url, result.method, result.status, result.port);
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
            if verbose {
                if let Some(headers) = &result.headers {
                    writeln!(file, "URL: {}, Method: {}, Status: {}, Port: {}, Headers: {}",
                        result.url, result.method, result.status, result.port, headers)?;
                } else {
                    writeln!(file, "URL: {}, Method: {}, Status: {}, Port: {}",
                        result.url, result.method, result.status, result.port)?;
                }
            } else {
                writeln!(file, "URL: {}, Method: {}, Status: {}, Port: {}",
                    result.url, result.method, result.status, result.port)?;
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

    let mut html = String::from("<!DOCTYPE html>\n<html>\n<head>\n<title>Terminus Scan Results</title>\n");
    html.push_str("<style>body{font-family:Arial,sans-serif;margin:20px;}table{border-collapse:collapse;width:100%;}");
    html.push_str("th,td{border:1px solid #ddd;padding:8px;text-align:left;}th{background-color:#4CAF50;color:white;}");
    html.push_str("tr:nth-child(even){background-color:#f2f2f2;}.error{color:red;}</style>\n</head>\n<body>\n");
    html.push_str("<h1>Terminus Scan Results</h1>\n<table>\n");
    html.push_str("<tr><th>URL</th><th>Method</th><th>Status</th><th>Port</th><th>Headers</th><th>Error</th></tr>\n");

    for result in results {
        html.push_str("<tr>");
        html.push_str(&format!("<td>{}</td>", result.url));
        html.push_str(&format!("<td>{}</td>", result.method));
        html.push_str(&format!("<td>{}</td>", result.status));
        html.push_str(&format!("<td>{}</td>", result.port));
        html.push_str(&format!("<td>{}</td>", result.headers.as_deref().unwrap_or("")));
        html.push_str(&format!("<td class='error'>{}</td>", result.error.as_deref().unwrap_or("")));
        html.push_str("</tr>\n");
    }

    html.push_str("</table>\n</body>\n</html>");
    std::fs::write(&filename, html)?;
    eprintln!("Results written to {}", filename);
    Ok(())
}