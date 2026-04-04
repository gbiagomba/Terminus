use anyhow::{Context, Result};
use clap::ArgMatches;
use rand::RngExt;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::str::FromStr;
use tokio::sync::Semaphore;
use tokio::time::Duration;

use crate::models::OutputFormat;
use crate::storage::sqlite::output_enum_sqlite;
use crate::transport::{Http12Transport, HttpTransport, HttpVersion, TerminusRequest, TransportConfig};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnumResult {
    pub target: String,
    pub url: String,
    pub status: u16,
    pub length: usize,
    pub wildcard: bool,
}

pub async fn run(matches: &ArgMatches) -> Result<()> {
    let domain = matches.get_one::<String>("domain")
        .context("domain is required")?;
    let wordlist = matches.get_one::<String>("wordlist")
        .context("wordlist is required")?;
    let scheme = matches.get_one::<String>("scheme").map(|s| s.as_str()).unwrap_or("https");
    let threads: usize = matches.get_one::<String>("threads")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let output_format = matches
        .get_one::<String>("output-format")
        .and_then(|f| OutputFormat::from_str(f).ok())
        .unwrap_or(OutputFormat::Stdout);
    let output_base = matches.get_one::<String>("output").map(|s| s.as_str());
    let filter_status: Option<Vec<u16>> = matches.get_one::<String>("filter-status")
        .map(|s| s.split(',').filter_map(|v| v.trim().parse().ok()).collect());
    let filter_length_min = matches.get_one::<String>("filter-length-min")
        .and_then(|s| s.parse::<usize>().ok());
    let filter_length_max = matches.get_one::<String>("filter-length-max")
        .and_then(|s| s.parse::<usize>().ok());

    let wildcard_enabled = !matches.get_flag("no-wildcard");

    let transport = Http12Transport::new(TransportConfig {
        allow_insecure: matches.get_flag("insecure"),
        proxy: matches.get_one::<String>("proxy").cloned(),
        http_version: HttpVersion::Http11,
        timeout: None,
    })?;
    let transport: Arc<dyn HttpTransport> = Arc::new(transport);

    let wildcard_probe = if wildcard_enabled {
        let rand_label = format!("terminus-{}", rand::rng().random_range(10000..99999));
        let host = format!("{}.{}", rand_label, domain);
        let url = format!("{}://{}", scheme, host);
        let (status, length) = probe(&transport, &url).await.unwrap_or((0, 0));
        Some((status, length))
    } else {
        None
    };

    let file = File::open(wordlist).context("Failed to open wordlist")?;
    let reader = BufReader::new(file);
    let mut candidates = Vec::new();
    for line in reader.lines() {
        let word = line.unwrap_or_default();
        let trimmed = word.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let host = format!("{}.{}", trimmed, domain);
        let url = format!("{}://{}", scheme, host);
        candidates.push((host, url));
    }

    let semaphore = Arc::new(Semaphore::new(threads));
    let mut handles = Vec::new();
    let results = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    for (host, url) in candidates {
        let transport = Arc::clone(&transport);
        let semaphore = Arc::clone(&semaphore);
        let results = Arc::clone(&results);
        let filter_status = filter_status.clone();
        let wildcard_probe = wildcard_probe.clone();
        let permit = semaphore.acquire_owned().await?;

        let handle = tokio::spawn(async move {
            let _permit = permit;
            let (status, length) = match probe(&transport, &url).await {
                Ok(val) => val,
                Err(_) => return,
            };

            let wildcard = wildcard_probe
                .map(|(ws, wl)| ws == status && wl == length)
                .unwrap_or(false);

            if wildcard {
                return;
            }

            if let Some(ref statuses) = filter_status {
                if !statuses.contains(&status) {
                    return;
                }
            }

            if let Some(min) = filter_length_min {
                if length < min {
                    return;
                }
            }

            if let Some(max) = filter_length_max {
                if length > max {
                    return;
                }
            }

            let mut guard = results.lock().await;
            guard.push(EnumResult {
                target: host,
                url,
                status,
                length,
                wildcard: false,
            });
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let final_results = results.lock().await.clone();

    output_results(&final_results, output_format, output_base)?;

    Ok(())
}

async fn probe(transport: &Arc<dyn HttpTransport>, url: &str) -> Result<(u16, usize)> {
    let request = TerminusRequest {
        url: url.to_string(),
        method: "GET".to_string(),
        headers: Vec::new(),
        body: None,
        timeout: Some(Duration::from_secs(10)),
        version: None,
    };
    let response = transport.send(request).await?;
    Ok((response.status, response.body.len()))
}

fn output_results(results: &[EnumResult], format: OutputFormat, output_base: Option<&str>) -> Result<()> {
    match format {
        OutputFormat::Stdout => {
            for row in results {
                println!("{} [{}]", row.url, row.status);
            }
        }
        OutputFormat::Json => {
            let filename = format!("{}.json", output_base.unwrap_or("terminus_enum"));
            let json = serde_json::to_string_pretty(results)?;
            std::fs::write(&filename, json)?;
            eprintln!("Results written to {}", filename);
        }
        OutputFormat::Csv => {
            let filename = format!("{}.csv", output_base.unwrap_or("terminus_enum"));
            let mut file = std::fs::File::create(&filename)?;
            writeln!(file, "target,url,status,length,wildcard")?;
            for row in results {
                writeln!(file, "{},{},{},{},{}", row.target, row.url, row.status, row.length, row.wildcard)?;
            }
            eprintln!("Results written to {}", filename);
        }
        OutputFormat::Sqlite => {
            output_enum_sqlite(results, output_base)?;
        }
        OutputFormat::All => {
            output_results(results, OutputFormat::Stdout, output_base)?;
            output_results(results, OutputFormat::Json, output_base)?;
            output_results(results, OutputFormat::Csv, output_base)?;
            output_results(results, OutputFormat::Sqlite, output_base)?;
        }
        OutputFormat::Txt => {
            let filename = format!("{}.txt", output_base.unwrap_or("terminus_enum"));
            let mut file = std::fs::File::create(&filename)?;
            for row in results {
                writeln!(file, "{} [{}]", row.url, row.status)?;
            }
            eprintln!("Results written to {}", filename);
        }
        OutputFormat::Html => {
            let filename = format!("{}.html", output_base.unwrap_or("terminus_enum"));
            let mut html = String::from("<html><body><table><tr><th>URL</th><th>Status</th><th>Length</th></tr>");
            for row in results {
                html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td></tr>", row.url, row.status, row.length));
            }
            html.push_str("</table></body></html>");
            std::fs::write(&filename, html)?;
            eprintln!("Results written to {}", filename);
        }
    }
    Ok(())
}
