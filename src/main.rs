use anyhow::{Context, Result};
use clap::{Arg, Command};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::{Method, StatusCode};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process;
use std::str::FromStr;

const HTTP_METHODS: &[&str] = &[
    "ACL", "BASELINE-CONTROL", "BCOPY", "BDELETE", "BMOVE", "BPROPFIND", "BPROPPATCH", 
    "CHECKIN", "CHECKOUT", "CONNECT", "COPY", "DEBUG", "DELETE", "GET", "HEAD", 
    "INDEX", "LABEL", "LOCK", "MERGE", "MKACTIVITY", "MKCOL", "MKWORKSPACE", 
    "MOVE", "NOTIFY", "OPTIONS", "ORDERPATCH", "PATCH", "POLL", "POST", 
    "PROPFIND", "PROPPATCH", "PUT", "REPORT", "RPC_IN_DATA", "RPC_OUT_DATA", 
    "SEARCH", "SUBSCRIBE", "TRACE", "UNCHECKOUT", "UNLOCK", "UNSUBSCRIBE", 
    "UPDATE", "VERSION-CONTROL", "X-MS-ENUMATTS"
];

fn main() -> Result<()> {
    println!("Starting program...");

    let matches = Command::new("Terminus")
        .version("1.0")
        .about("URL testing with multiple methods, ports, verbose logging, and redirects")
        .arg(Arg::new("url")
            .short('u')
            .long("url")
            .value_name("URL")
            .help("Specify a single URL to check"))
        .arg(Arg::new("file")
            .short('f')
            .long("file")
            .value_name("FILE")
            .help("Specify a file containing a list of URLs to check"))
        .arg(Arg::new("method")
            .short('X')
            .long("method")
            .value_name("METHOD")
            .help("Specify the HTTP method to use (default: GET). Use 'ALL' to test all methods"))
        .arg(Arg::new("port")
            .short('p')
            .long("port")
            .value_name("PORTS")
            .help("Specify comma-separated ports to connect to (e.g., 80,443)")
            .use_value_delimiter(true))
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .help("Increase verbosity to see details of requests and responses")
            .action(clap::ArgAction::SetTrue))  // Set the action to a boolean flag
        .arg(Arg::new("follow")
            .short('L')
            .long("follow")
            .help("Follow HTTP redirects")
            .action(clap::ArgAction::SetTrue))  // Set the action to a boolean flag
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .value_name("FILE")
            .help("Specify an output file to write results"))
        .arg(Arg::new("filter")
            .short('F')
            .long("filter-code")
            .value_name("STATUS_CODE")
            .help("Filter results by HTTP status code"))
        .get_matches();

    println!("Parsed arguments.");

    let verbose = matches.get_flag("verbose");
    let follow_redirects = matches.get_flag("follow");

    println!("Verbose: {}", verbose);
    println!("Follow Redirects: {}", follow_redirects);

    let client = build_client(follow_redirects);
    println!("HTTP client built.");

    let urls = if let Some(url) = matches.get_one::<String>("url") {
        println!("Using URL: {}", url);
        vec![url.to_string()]
    } else if let Some(file) = matches.get_one::<String>("file") {
        println!("Using file: {}", file);
        read_lines(file)?
    } else {
        println!("You must provide a URL (-u) or a file (-f) to check.");
        process::exit(1);
    };

    println!("URLs: {:?}", urls);

    let method_input = matches.get_one::<String>("method").map(String::as_str).unwrap_or("GET");
    let methods_to_use: Vec<String> = if method_input == "ALL" {
        HTTP_METHODS.iter().map(|&s| s.to_string()).collect()
    } else {
        vec![method_input.to_string()]
    };

    println!("Methods to be used: {:?}", methods_to_use);

    let ports: Vec<u16> = matches
        .get_many::<String>("port")
        .unwrap_or_default()
        .map(|p| p.parse::<u16>().unwrap())
        .collect();

    println!("Ports: {:?}", ports);

    let filter_code = matches
        .get_one::<String>("filter")
        .map(|code| {
            code.parse::<u16>()
                .ok()
                .and_then(|code_num| StatusCode::from_u16(code_num).ok())
        })
        .flatten();

    // Open output file in append mode if it exists, otherwise create a new one.
    let mut output_file = if let Some(output) = matches.get_one::<String>("output") {
        Some(OpenOptions::new().append(true).create(true).open(output).with_context(|| format!("Failed to create or open output file: {}", output))?)
    } else {
        None
    };

    for url in &urls {
        let scheme = if url.starts_with("https") { 443 } else { 80 };

        let ports_to_use = if ports.is_empty() {
            vec![scheme]
        } else {
            ports.clone()
        };

        for method in &methods_to_use {
            for port in &ports_to_use {
                let full_url = format!("{}:{}", url, port);
                println!("Testing URL: {} with Method: {} on Port: {}", full_url, method, port);

                let req_method = Method::from_str(method).unwrap_or(Method::GET);
                println!("Request method: {}", req_method);

                match client.request(req_method.clone(), &full_url).send() {
                    Ok(resp) => {
                        let status = resp.status();
                        if let Some(filter) = filter_code {
                            if status != filter {
                                continue;
                            }
                        }

                        let basic_result = format!("URL: {}, Method: {}, Status: {}, Port: {}", url, method, status, port);

                        if verbose {
                            let headers = headers_to_string(resp.headers());
                            println!("{}\nHeaders:\n{}", basic_result, headers);

                            if let Some(file) = output_file.as_mut() {
                                writeln!(file, "{}\nHeaders:\n{}", basic_result, headers).unwrap();
                            }
                        } else {
                            println!("{}", basic_result);

                            if let Some(file) = output_file.as_mut() {
                                writeln!(file, "{}", basic_result).unwrap();
                            }
                        }
                    }
                    Err(e) => {
                        println!(
                            "Error occurred while testing URL {} with method {} on port {}: {}",
                            full_url, method, port, e
                        );
                        if let Some(file) = output_file.as_mut() {
                            writeln!(
                                file,
                                "Error occurred while testing URL {}: {}",
                                full_url, e
                            )
                            .unwrap();
                        }
                    }
                }
            }
        }
    }

    println!("Program completed.");

    Ok(())
}

fn build_client(follow_redirects: bool) -> Client {
    let mut builder = ClientBuilder::new();
    if follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::limited(10));
    }
    builder.build().unwrap()
}

fn headers_to_string(headers: &reqwest::header::HeaderMap) -> String {
    headers.iter()
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("[invalid UTF-8]")))
        .collect::<Vec<_>>()
        .join("\n")
}

fn read_lines<P: AsRef<Path>>(filename: P) -> Result<Vec<String>> {
    let file = File::open(filename.as_ref()).with_context(|| format!("Failed to open file: {}", filename.as_ref().display()))?;
    Ok(io::BufReader::new(file).lines().collect::<Result<Vec<_>, _>>()?)
}