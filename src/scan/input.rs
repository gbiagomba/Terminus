use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value as JsonValue;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub fn read_lines<P: AsRef<Path>>(filename: P) -> Result<Vec<String>> {
    let file = File::open(&filename).with_context(|| format!("Cannot open file: {}", filename.as_ref().display()))?;
    Ok(io::BufReader::new(file).lines().collect::<Result<_, _>>()?)
}

pub fn read_stdin(ipv6_enabled: bool) -> Result<Vec<String>> {
    let stdin = io::stdin();
    let mut urls = HashSet::new();

    for line in stdin.lock().lines() {
        let line = line?;
        let extracted = extract_targets_from_line(&line, ipv6_enabled);
        urls.extend(extracted);
    }

    Ok(urls.into_iter().collect())
}

pub fn parse_input_file(filename: &str, ipv6_enabled: bool) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(filename)
        .with_context(|| format!("Cannot read file: {}", filename))?;

    if content.trim_start().starts_with("<?xml") || content.contains("<nmaprun") {
        parse_nmap_xml(&content, ipv6_enabled)
    } else if content.trim_start().starts_with('{') || content.trim_start().starts_with('[') {
        parse_json_input(&content, ipv6_enabled)
    } else if content.contains("Host:") && content.contains("Ports:") {
        parse_nmap_greppable(&content, ipv6_enabled)
    } else {
        Ok(content.lines()
            .flat_map(|line| extract_targets_from_line(line, ipv6_enabled))
            .collect())
    }
}

pub fn extract_targets_from_line(line: &str, ipv6_enabled: bool) -> Vec<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return vec![];
    }

    let mut targets = Vec::new();

    if line.starts_with("http://") || line.starts_with("https://") {
        targets.push(line.to_string());
        return targets;
    }

    if let Ok(ipv4) = line.parse::<Ipv4Addr>() {
        targets.push(format!("http://{}", ipv4));
        return targets;
    }

    if ipv6_enabled {
        if let Ok(ipv6) = line.parse::<Ipv6Addr>() {
            targets.push(format!("http://[{}]", ipv6));
            return targets;
        }
    }

    if !line.contains('/') && !line.contains('\\') {
        targets.push(format!("http://{}", line));
    }

    targets
}

fn parse_nmap_xml(content: &str, ipv6_enabled: bool) -> Result<Vec<String>> {
    let mut urls = HashSet::new();

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

        if host.contains(':') && !ipv6_enabled {
            continue;
        }

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

    if let Ok(json) = serde_json::from_str::<JsonValue>(content) {
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
        else if json.get("host").is_some() || json.get("url").is_some() || json.get("endpoint").is_some() {
            extract_pd_urls(&json, &mut urls, ipv6_enabled);
        } else if let Some(array) = json.as_array() {
            for item in array {
                extract_pd_urls(item, &mut urls, ipv6_enabled);
            }
        }
    }

    Ok(urls.into_iter().collect())
}

fn extract_pd_urls(json: &JsonValue, urls: &mut HashSet<String>, ipv6_enabled: bool) {
    let possible_fields = ["url", "endpoint", "host", "target", "matched-at"];

    for field in &possible_fields {
        if let Some(value) = json.get(field).and_then(|v| v.as_str()) {
            if value.starts_with("http://") || value.starts_with("https://") {
                urls.insert(value.to_string());
            } else {
                let extracted = extract_targets_from_line(value, ipv6_enabled);
                urls.extend(extracted);
            }
        }
    }
}
