use clap::{Arg, App};
use reqwest::blocking::Client;
use reqwest::Method;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::process;
use std::fs;
use std::env;

const HTTP_METHODS: &[&str] = &[
    "ACL", "BASELINE-CONTROL", "BCOPY", "BDELETE", "BMOVE", "BPROPFIND", "BPROPPATCH", 
    "CHECKIN", "CHECKOUT", "CONNECT", "COPY", "DEBUG", "DELETE", "GET", "HEAD", 
    "INDEX", "LABEL", "LOCK", "MERGE", "MKACTIVITY", "MKCOL", "MKWORKSPACE", 
    "MOVE", "NOTIFY", "OPTIONS", "ORDERPATCH", "PATCH", "POLL", "POST", 
    "PROPFIND", "PROPPATCH", "PUT", "REPORT", "RPC_IN_DATA", "RPC_OUT_DATA", 
    "SEARCH", "SUBSCRIBE", "TRACE", "UNCHECKOUT", "UNLOCK", "UNSUBSCRIBE", 
    "UPDATE", "VERSION-CONTROL", "X-MS-ENUMATTS"
];

// Function to check a single URL with a specified HTTP method and port
fn check_url(client: &Client, url: &str, method: &str, port: Option<u16>) -> Result<(), reqwest::Error> {
    let full_url = if let Some(p) = port {
        format!("{}:{}", url, p)
    } else {
        url.to_string()
    };

    let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);

    let response = client.request(method, &full_url).send()?;
    let status = response.status();
    println!("URL: {}, Method: {}, Status: {}", full_url, method, status);
    Ok(())
}

// Function to read URLs from a file and check each one with a specified method and port
fn check_urls_from_file(client: &Client, file_path: &str, method: &str, port: Option<u16>) {
    if let Ok(lines) = read_lines(file_path) {
        for line in lines {
            if let Ok(url) = line {
                if let Err(e) = check_url(&client, &url, method, port) {
                    eprintln!("Failed to check {}: {}", url, e);
                }
            }
        }
    } else {
        eprintln!("Could not read file: {}", file_path);
        process::exit(1);
    }
}

// Helper function to read lines from a file
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path> {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn main() {
    let matches = App::new("Terminus")
        .version("1.0")
        .about("Checks if URLs can be accessed without authentication using various HTTP methods.")
        .arg(Arg::with_name("url")
            .short("u")
            .long("url")
            .value_name("URL")
            .help("Specify a single URL to check")
            .takes_value(true))
        .arg(Arg::with_name("file")
            .short("f")
            .long("file")
            .value_name("FILE")
            .help("Specify a file containing a list of URLs to check")
            .takes_value(true))
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .value_name("DIR")
            .help("Specify the output directory for the results")
            .takes_value(true))
        .arg(Arg::with_name("port")
            .short("p")
            .long("port")
            .value_name("PORT")
            .help("Specify a port to connect to")
            .takes_value(true))
        .arg(Arg::with_name("method")
            .short("X")
            .long("method")
            .value_name("METHOD")
            .help("Specify an HTTP method to use (e.g., GET, POST, PUT) or 'ALL' to test all methods")
            .takes_value(true))
        .get_matches();

    let client = Client::new();
    
    // Determine output directory, default to ./terminus_results if not specified
    let output_dir = matches.value_of("output").unwrap_or("terminus_results");
    fs::create_dir_all(output_dir).expect("Failed to create output directory");

    // Port option
    let port = matches.value_of("port").and_then(|p| p.parse::<u16>().ok());

    // HTTP method option, default to GET
    let method = matches.value_of("method").unwrap_or("GET");

    if let Some(url) = matches.value_of("url") {
        if method == "ALL" {
            // If method is "ALL", test with every method in HTTP_METHODS
            for &http_method in HTTP_METHODS {
                if let Err(e) = check_url(&client, url, http_method, port) {
                    eprintln!("Error checking URL {} with method {}: {}", url, http_method, e);
                }
            }
        } else {
            // Check a single URL with the specified method
            if let Err(e) = check_url(&client, url, method, port) {
                eprintln!("Error checking URL: {}", e);
            }
        }
    } else if let Some(file) = matches.value_of("file") {
        if method == "ALL" {
            for &http_method in HTTP_METHODS {
                check_urls_from_file(&client, file, http_method, port);
            }
        } else {
            // Check URLs from a file with the specified method
            check_urls_from_file(&client, file, method, port);
        }
    } else {
        eprintln!("You must provide a URL (-u) or a file (-f) to check.");
        process::exit(1);
    }
}