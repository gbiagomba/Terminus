use anyhow::{Context, Result, anyhow};
use clap::{Arg, Command, value_parser};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::{Method, StatusCode, header::HeaderMap};
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process;
use std::str::FromStr;
use std::time::Duration;
use rayon::prelude::*;

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
    let matches = Command::new("Terminus")
        .version("1.0")
        .about("Checks if URLs can be accessed without authentication using various HTTP methods.")
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
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .value_name("FILE")
            .help("Specify the output file for the results"))
        .arg(Arg::new("port")
            .short('p')
            .long("port")
            .value_name("PORTS")
            .help("Specify comma-separated ports to connect to (e.g., 80,443)")
            .use_value_delimiter(true)
            .value_parser(value_parser!(u16)))
        .arg(Arg::new("method")
            .short('X')
            .long("method")
            .value_name("METHOD")
            .help("Specify the HTTP method to use (default: GET). Use 'ALL' to test all methods or a specific HTTP method"))
        .arg(Arg::new("filter-code")
            .short('F')
            .long("filter-code")
            .value_name("STATUS_CODE")
            .help("Filter results by HTTP status code"))
        .arg(Arg::new("max-time")
            .short('m')
            .long("max-time")
            .value_name("SECONDS")
            .help("Maximum time, in seconds, that you allow the request to take"))
        .arg(Arg::new("concurrent")
            .short('c')
            .long("concurrent")
            .help("Enable concurrent scanning of URLs"))
        .arg(Arg::new("follow")
            .short('L')
            .long("follow")
            .help("Follow HTTP redirects"))
        .get_matches();

    let client = build_client(matches.contains_id("follow"), matches.get_one::<String>("max-time").and_then(|t| t.parse::<u64>().ok()));
    let default_output_file = "output.txt".to_string();
    let output_file = matches.get_one::<String>("output").unwrap_or(&default_output_file);
    let filter_code = matches.get_one::<String>("filter-code").and_then(|code| code.parse::<u16>().ok().and_then(|code| StatusCode::from_u16(code).ok()));
    let concurrent = matches.contains_id("concurrent");

    let ports: Vec<u16> = matches.get_many::<u16>("port").unwrap_or_default().copied().collect();
    let method_input = matches.get_one::<String>("method").map(String::as_str).unwrap_or("GET");

    let methods_to_use = if method_input == "ALL" {
        HTTP_METHODS.to_vec()
    } else {
        vec![method_input]
    };

    let urls = if let Some(url) = matches.get_one::<String>("url") {
        vec![url.to_string()]
    } else if let Some(file) = matches.get_one::<String>("file") {
        read_lines(file)?
    } else {
        eprintln!("You must provide a URL (-u) or a file (-f) to check.");
        process::exit(1);
    };

    if concurrent {
        urls.par_iter().for_each(|url| {
            for port in &ports {
                for method in &methods_to_use {
                    if let Err(e) = process_url(&client, url, method, Some(*port), output_file, filter_code) {
                        eprintln!("Error processing URL {}: {}", url, e);
                    }
                }
            }
        });
    } else {
        for url in urls {
            for port in &ports {
                for method in &methods_to_use {
                    process_url(&client, &url, method, Some(*port), output_file, filter_code)?;
                }
            }
        }
    }

    Ok(())
}

fn build_client(follow_redirects: bool, max_time: Option<u64>) -> Client {
    let mut builder = ClientBuilder::new();
    if follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::limited(10));
    }
    if let Some(seconds) = max_time {
        builder = builder.timeout(Duration::from_secs(seconds));
    }
    builder.build().unwrap()
}

fn process_url(client: &Client, url: &str, method: &str, port: Option<u16>, output_file: &str, filter_code: Option<StatusCode>) -> Result<()> {
    let full_url = if let Some(p) = port {
        format!("{}:{}", url, p)
    } else {
        url.to_string()
    };

    let req_method = Method::from_str(method)?;
    let response = client.request(req_method, &full_url).send()?;
    if filter_code.is_some() && filter_code != Some(response.status()) {
        return Ok(());
    }

    let status = response.status();
    let headers = response.headers();
    let output = format!("URL: {}, Method: {}, Status: {}, Headers: {:?}", url, method, status, headers_to_string(headers));

    let mut file = File::create(output_file)?;
    writeln!(file, "{}", output)?;
    Ok(())
}

fn headers_to_string(headers: &HeaderMap) -> String {
    headers.iter().map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or(""))).collect::<Vec<_>>().join(", ")
}

fn read_lines<P: AsRef<Path>>(filename: P) -> Result<Vec<String>> {
    let file = File::open(filename.as_ref()).with_context(|| format!("Failed to open file: {}", filename.as_ref().display()))?;
    io::BufReader::new(file).lines().collect::<Result<Vec<_>, _>>().map_err(|e| anyhow!(e))
}