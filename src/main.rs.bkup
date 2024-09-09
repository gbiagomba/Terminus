use anyhow::{Context, Result};
use clap::{Arg, Command};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::Method;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process;

// Constants for HTTP methods
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
            .value_name("PORT")
            .help("Specify a port to connect to"))
        .arg(Arg::new("method")
            .short('X')
            .long("method")
            .value_name("METHOD")
            .help("Specify the HTTP method to use (default: GET). Use 'ALL' to test all methods"))
        .arg(Arg::new("follow")
            .short('L')
            .long("follow")
            .help("Follow HTTP redirects"))
        .get_matches();

    let client = build_client(matches.contains_id("follow"));
    let default_output_file = "output.txt".to_string();
    let output_file = matches.get_one::<String>("output").unwrap_or(&default_output_file);
    let port = matches.get_one::<String>("port").and_then(|p| p.parse::<u16>().ok());
    let default_method = "GET".to_string();
    let method = matches.get_one::<String>("method").unwrap_or(&default_method);

    if let Some(url) = matches.get_one::<String>("url") {
        process_url(&client, url, method, port, output_file)?;
    } else if let Some(file) = matches.get_one::<String>("file") {
        process_file(&client, file, method, port, output_file)?;
    } else {
        eprintln!("You must provide a URL (-u) or a file (-f) to check.");
        process::exit(1);
    }

    Ok(())
}

fn build_client(follow_redirects: bool) -> Client {
    ClientBuilder::new()
        .redirect(if follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .build()
        .unwrap()
}

fn process_url(client: &Client, url: &str, method: &str, port: Option<u16>, output_file: &str) -> Result<()> {
    if method == "ALL" {
        for &http_method in HTTP_METHODS {
            check_url(client, url, http_method, port, output_file)?;
        }
    } else {
        check_url(client, url, method, port, output_file)?;
    }
    Ok(())
}

fn process_file(client: &Client, file_path: &str, method: &str, port: Option<u16>, output_file: &str) -> Result<()> {
    let lines = read_lines(file_path).with_context(|| format!("Failed to read file: {}", file_path))?;
    for line in lines {
        let url = line?;
        process_url(client, &url, method, port, output_file)?;
    }
    Ok(())
}

fn check_url(client: &Client, url: &str, method: &str, port: Option<u16>, output_file: &str) -> Result<()> {
    let full_url = if let Some(p) = port {
        format!("{}:{}", url, p)
    } else {
        url.to_string()
    };

    let req_method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    let response = client.request(req_method.clone(), &full_url).send()?;
    let status = response.status();
    let mut file = File::create(output_file)?;
    writeln!(file, "URL: {}, Method: {}, Status: {}", full_url, method, status)?;
    Ok(())
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path> {
    File::open(filename).map(|file| io::BufReader::new(file).lines())
}