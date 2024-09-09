use clap::{Arg, Command};
use reqwest::blocking::Client;
use reqwest::Method;
use std::fs;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::process;

const HTTP_METHODS: &[&str] = &[
    "ACL", "BASELINE-CONTROL", "BCOPY", "BDELETE", "BMOVE", "BPROPFIND", "BPROPPATCH", 
    "CHECKIN", "CHECKOUT", "CONNECT", "COPY", "DEBUG", "DELETE", "GET", "HEAD", 
    "INDEX", "LABEL", "LOCK", "MERGE", "MKACTIVITY", "MKCOL", "MKWORKSPACE", 
    "MOVE", "NOTIFY", "OPTIONS", "ORDERPATCH", "PATCH", "POLL", "POST", 
    "PROPFIND", "PROPPATCH", "PUT", "REPORT", "RPC_IN_DATA", "RPC_OUT_DATA", 
    "SEARCH", "SUBSCRIBE", "TRACE", "UNCHECKOUT", "UNLOCK", "UNSUBSCRIBE", 
    "UPDATE", "VERSION-CONTROL", "X-MS-ENUMATTS"
];

fn main() {
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
            .value_name("DIR")
            .help("Specify the output directory for the results"))
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
        .get_matches();

    let client = Client::new();
    let default_output_dir = String::from("./terminus_results");
    let output_dir = matches.get_one::<String>("output").unwrap_or(&default_output_dir);
    fs::create_dir_all(output_dir).expect("Failed to create output directory");
    let port = matches.get_one::<String>("port").and_then(|p| p.parse::<u16>().ok());
    let default_method = String::from("GET");
    let method = matches.get_one::<String>("method").unwrap_or(&default_method);

    if let Some(url) = matches.get_one::<String>("url") {
        process_url(&client, url, method, port, output_dir);
    } else if let Some(file) = matches.get_one::<String>("file") {
        process_file(&client, file, method, port, output_dir);
    } else {
        eprintln!("You must provide a URL (-u) or a file (-f) to check.");
        process::exit(1);
    }
}

fn process_url(client: &Client, url: &str, method: &str, port: Option<u16>, output_dir: &str) {
    if method == "ALL" {
        for &http_method in HTTP_METHODS {
            check_url(&client, url, http_method, port, output_dir);
        }
    } else {
        check_url(&client, url, method, port, output_dir);
    }
}

fn process_file(client: &Client, file_path: &str, method: &str, port: Option<u16>, output_dir: &str) {
    if let Ok(lines) = read_lines(file_path) {
        for line in lines {
            if let Ok(url) = line {
                process_url(client, &url, method, port, output_dir);
            }
        }
    } else {
        eprintln!("Could not read file: {}", file_path);
        process::exit(1);
    }
}

fn check_url(client: &Client, url: &str, method: &str, port: Option<u16>, output_dir: &str) -> Result<(), reqwest::Error> {
    let full_url = if let Some(p) = port {
        format!("{}:{}", url, p)
    } else {
        url.to_string()
    };

    let req_method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    let response = client.request(req_method.clone(), &full_url).send()?;
    let status = response.status();
    println!("URL: {}, Method: {}, Status: {}, Output dir: {}", full_url, method, status, output_dir);
    Ok(())
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path> {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}