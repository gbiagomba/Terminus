use anyhow::{Context, Result};
use clap::{Arg, ArgAction, Command};
use reqwest::blocking::ClientBuilder;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode, Version};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
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

fn main() -> Result<()> {
    let matches = Command::new("Terminus")
        .version("2.3.0")
        .about("URL testing with multiple methods, ports, verbose logging, redirects, proxy, cookies, headers, and HTTP version support")
        .arg(Arg::new("url").short('u').long("url").value_name("URL").help("Specify a single URL to check"))
        .arg(Arg::new("file").short('f').long("file").value_name("FILE").help("Specify a file containing a list of URLs to check"))
        .arg(Arg::new("method").short('X').long("method").value_name("METHOD").help("Specify the HTTP method to use (default: GET). Use ALL to test all methods"))
        .arg(Arg::new("port").short('p').long("port").value_name("PORTS").help("Comma-separated ports to connect to (e.g., 80,443)").use_value_delimiter(true))
        .arg(Arg::new("insecure").short('k').long("insecure").help("Allow insecure SSL connections").action(ArgAction::SetTrue))
        .arg(Arg::new("verbose").short('v').long("verbose").help("Enable verbose output with response headers").action(ArgAction::SetTrue))
        .arg(Arg::new("follow").short('L').long("follow").help("Follow HTTP redirects").action(ArgAction::SetTrue))
        .arg(Arg::new("output").short('o').long("output").value_name("FILE").help("Write results to file"))
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

    let urls = if let Some(url) = matches.get_one::<String>("url") {
        vec![url.to_string()]
    } else if let Some(file) = matches.get_one::<String>("file") {
        read_lines(file)?
    } else {
        eprintln!("You must provide a URL (-u) or file (-f)");
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

    let mut output_file = if let Some(path) = matches.get_one::<String>("output") {
        Some(OpenOptions::new().append(true).create(true).open(path)?)
    } else {
        None
    };

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

                        let basic = format!("URL: {}, Method: {}, Status: {}, Port: {}", url, method, status, port);
                        if verbose {
                            let headers = flatten_headers(resp.headers());
                            let log = format!("{}, Headers: {}", basic, headers);
                            println!("{}", log);
                            if let Some(file) = output_file.as_mut() {
                                writeln!(file, "{}", log)?;
                            }
                        } else {
                            println!("{}", basic);
                            if let Some(file) = output_file.as_mut() {
                                writeln!(file, "{}", basic)?;
                            }
                        }
                    }
                    Err(e) => {
                        let err_msg = format!("Error on {}:{} using {}: {}", url, port, method, e);
                        eprintln!("{}", err_msg);
                        if let Some(file) = output_file.as_mut() {
                            writeln!(file, "{}", err_msg)?;
                        }
                    }
                }
            }
        }
    }

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