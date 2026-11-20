//! Parse a pasted `curl ...` command line into a request config.
//!
//! Ported from the sibling tool Inquisitor. Lets an operator paste a `curl`
//! invocation (for example copied from a browser's "Copy as cURL") and have
//! Terminus populate the target URL, method, headers, cookies, and body from it.
//! Explicit Terminus flags always take precedence over the parsed curl values;
//! the parser only fills the gaps (merge logic lives in `engine::run_scan`).

use anyhow::{anyhow, Result};

use crate::scan::http::parse_header;

/// A request parsed from a pasted `curl ...` command line.
///
/// Curl-semantics caveats (documented for the operator):
/// - `curl -A` sets the User-Agent; it maps to a `User-Agent` header here.
/// - `curl -u` is HTTP basic-auth `user:pass`, not a URL; it is ignored (its
///   value is consumed so it cannot be mistaken for the endpoint).
/// - `-d/--data/--data-binary/--data-raw/--data-ascii` all map to the body.
/// - A pasted-curl proxy (`-x`) is intentionally dropped; use Terminus's own
///   `--proxy`.
#[derive(Debug, Default, Clone)]
pub struct CurlRequest {
    pub url: Option<String>,
    pub method: Option<String>,
    pub data: Option<String>,
    pub headers: Vec<(String, String)>,
    pub cookie: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub insecure: bool,
}

/// Parse a pasted `curl ...` command line into a [`CurlRequest`]. Tokenizes with
/// shlex so quoted bodies/headers survive. Unrecognized flags are skipped so a
/// realistic pasted line does not abort the parse.
pub fn parse_curl(line: &str) -> Result<CurlRequest> {
    let tokens =
        shlex::split(line).ok_or_else(|| anyhow!("--from-curl: could not tokenize the curl command"))?;
    let mut req = CurlRequest::default();
    let mut it = tokens.into_iter().peekable();
    // Drop a leading "curl" if present.
    if it.peek().map(|s| s.as_str()) == Some("curl") {
        it.next();
    }
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "-X" | "--request" => req.method = it.next(),
            "-H" | "--header" => {
                if let Some(h) = it.next() {
                    if let Some(pair) = parse_header(&h) {
                        req.headers.push(pair);
                    }
                }
            }
            "-d" | "--data" | "--data-binary" | "--data-raw" | "--data-ascii" => {
                req.data = it.next();
            }
            "-b" | "--cookie" => req.cookie = it.next(),
            "-e" | "--referer" => req.referer = it.next(),
            // curl -A is the User-Agent.
            "-A" | "--user-agent" => req.user_agent = it.next(),
            "-k" | "--insecure" => req.insecure = true,
            // curl --url is an explicit endpoint.
            "--url" => req.url = it.next(),
            // Value-taking flags whose VALUE must be consumed so it is not
            // mistaken for the URL. `curl -x <proxy>` in particular would
            // otherwise leave its host as the first bare token and shadow the
            // real endpoint. A pasted-curl proxy is NOT applied; use `--proxy`.
            "-x" | "--proxy" | "--connect-timeout" | "--max-time" | "-m" | "-o" | "--output"
            | "-w" | "--write-out" | "-T" | "--upload-file" | "-c" | "--cookie-jar"
            | "--retry" | "--proxy-user" | "-U" | "--resolve" | "--cacert" | "-E" | "--cert"
            | "--key"
            // curl -u is basic-auth user:pass, not a URL.
            | "-u" | "--user" => {
                it.next();
            }
            // Accept-and-ignore common no-ops.
            "-i" | "--include" | "-s" | "--silent" | "-v" | "--verbose" | "--path-as-is"
            | "--compressed" | "-#" | "--progress-bar" | "-L" | "--location" | "-g"
            | "--globoff" => {}
            other if other.starts_with('-') => {
                // Unknown flag: skip it (and do not consume a following value,
                // since we cannot know its arity).
            }
            other => {
                // The first bare token that looks like a URL (has a scheme) is
                // the endpoint. Requiring a scheme prevents a proxy host, a
                // basic-auth string, or a stray flag value from being adopted as
                // the URL and silently shadowing the real endpoint.
                if req.url.is_none() && other.contains("://") {
                    req.url = Some(other.to_string());
                }
            }
        }
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::parse_curl;

    #[test]
    fn proxy_flag_value_does_not_shadow_the_url() {
        // `curl -x <proxy>`: the proxy host must not be adopted as the endpoint.
        let req =
            parse_curl("curl -x 127.0.0.1 -X POST https://api.example.com/assist -d '{}'").unwrap();
        assert_eq!(req.url.as_deref(), Some("https://api.example.com/assist"));
        assert_eq!(req.method.as_deref(), Some("POST"));
    }

    #[test]
    fn output_flag_value_does_not_shadow_the_url() {
        let req = parse_curl("curl -o out.txt https://a.example/b").unwrap();
        assert_eq!(req.url.as_deref(), Some("https://a.example/b"));
    }

    #[test]
    fn explicit_url_flag_sets_endpoint() {
        let req = parse_curl("curl --url https://a.example/x -H 'X: y'").unwrap();
        assert_eq!(req.url.as_deref(), Some("https://a.example/x"));
    }

    #[test]
    fn bare_non_url_token_is_not_adopted_as_url() {
        // No scheme'd token: url stays None so -u/positional can supply it.
        let req = parse_curl("curl -x 127.0.0.1 -k").unwrap();
        assert_eq!(req.url, None);
    }

    #[test]
    fn scheme_url_is_captured_and_headers_parse() {
        let req = parse_curl("curl -k -H 'Authorization: Bearer abc' https://h.example/p").unwrap();
        assert_eq!(req.url.as_deref(), Some("https://h.example/p"));
        assert!(req.insecure);
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer abc"));
    }

    #[test]
    fn data_body_is_captured() {
        let req =
            parse_curl("curl -X PUT -b 'sid=1' -A 'tscan/1' -d 'a=1&b=2' https://h.example/api")
                .unwrap();
        assert_eq!(req.data.as_deref(), Some("a=1&b=2"));
        assert_eq!(req.method.as_deref(), Some("PUT"));
        assert_eq!(req.cookie.as_deref(), Some("sid=1"));
        assert_eq!(req.user_agent.as_deref(), Some("tscan/1"));
        assert_eq!(req.url.as_deref(), Some("https://h.example/api"));
    }
}
