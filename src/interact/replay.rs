use anyhow::Result;

/// Replay an HTTP request and return a short summary of the response.
///
/// `headers` is a newline-delimited string of "Name: Value" pairs.
pub async fn replay_request(url: &str, method: &str, headers: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let method_obj = reqwest::Method::from_bytes(method.as_bytes())
        .unwrap_or(reqwest::Method::GET);

    let mut request_builder = client.request(method_obj, url);

    for line in headers.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(idx) = line.find(':') {
            let name = line[..idx].trim();
            let value = line[idx + 1..].trim();
            request_builder = request_builder.header(name, value);
        }
    }

    let response = request_builder.send().await?;
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    let snippet: String = body.chars().take(300).collect();

    Ok(format!("HTTP {} | Body snippet: {}...", status, snippet))
}
