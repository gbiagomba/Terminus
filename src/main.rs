use anyhow::{Context, Result};
use clap::{Arg, ArgAction, Command};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::{Method, StatusCode};
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
    "UNSUBSCRIBE", "UPDATE", "UPDATEREDIRECTREF", "VERSION-CONTROL", "X-MS-ENUMATTS",
];

fn main() -> Result<()> {
    let matches = Command::new("Terminus")
        .version("2.1.0")
        .about("URL testing with multiple methods, ports, verbose logging, and redirects")
        .arg(Arg::new("url").short('u').long("url").value_name("URL").help("Specify a single URL to check"))
        .arg(Arg::new("file").short('f').long("file").value_name("FILE").help("Specify a file containing a list of URLs to check"))
        .arg(Arg::new("method").short('X').long("method").value_name("METHOD").help("Specify the HTTP method to use (default: GET). Use ALL to test all methods"))
        .arg(Arg::new("port").short('p').long("port").value_name("PORTS").help("Comma-separated ports to connect to (e.g., 80,443)").use_value_delimiter(true))
        .arg(Arg::new("insecure").short('k').long("insecure").help("Allow insecure SSL connections").action(ArgAction::SetTrue))
        .arg(Arg::new("verbose").short('v').long("verbose").help("Enable verbose output with response headers").action(ArgAction::SetTrue))
        .arg(Arg::new("follow").short('L').long("follow").help("Follow HTTP redirects").action(ArgAction::SetTrue))
        .arg(Arg::new("output").short('o').long("output").value_name("FILE").help("Write results to file"))
        .arg(Arg::new("filter").short('F').long("filter-code").value_name("STATUS_CODE").help("Filter results by HTTP status code"))
        .get_matches();

    let verbose = matches.get_flag("verbose");
    let allow_insecure = matches.get_flag("insecure");
    let follow_redirects = matches.get_flag("follow");

    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(allow_insecure)
        .redirect(if follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
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

    for url in &urls {
        let default_port = if url.starts_with("https") { 443 } else { 80 };
        let test_ports = if ports.is_empty() { vec![default_port] } else { ports.clone() };

        for method in &methods {
            let req_method = Method::from_str(method).unwrap_or(Method::GET);
            for port in &test_ports {
                let full_url = format!("{}:{}", url, port);
                match client.request(req_method.clone(), &full_url).send() {
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