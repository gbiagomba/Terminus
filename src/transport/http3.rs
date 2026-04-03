use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Client;
use std::time::Duration;

use crate::transport::traits::HttpTransport;
use crate::transport::types::{HttpVersion, TerminusRequest, TerminusResponse, TransportConfig};

#[derive(Clone)]
pub struct Http3Transport {
    client: Client,
    default_timeout: Option<Duration>,
}

impl Http3Transport {
    pub fn new(config: TransportConfig) -> Result<Self> {
        if config.proxy.is_some() {
            anyhow::bail!("HTTP/3 transport does not support proxies");
        }

        if config.http_version != HttpVersion::Http3 {
            anyhow::bail!("HTTP/3 transport requires http-version=3");
        }

        let builder = Client::builder()
            .danger_accept_invalid_certs(config.allow_insecure)
            .redirect(reqwest::redirect::Policy::none())
            .http3_prior_knowledge();

        let client = builder.build().context("Failed to build HTTP/3 client")?;

        Ok(Self {
            client,
            default_timeout: config.timeout,
        })
    }

    fn build_headers(headers: &[(String, String)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                map.append(name, value);
            }
        }
        map
    }
}

#[async_trait::async_trait]
impl HttpTransport for Http3Transport {
    async fn send(&self, request: TerminusRequest) -> Result<TerminusResponse> {
        if !request.url.to_lowercase().starts_with("https://") {
            anyhow::bail!("HTTP/3 requests require https URLs");
        }

        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .unwrap_or_else(|_| {
                let sanitized: String = request
                    .method
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                    .collect();
                reqwest::Method::from_bytes(sanitized.as_bytes()).unwrap_or(reqwest::Method::GET)
            });

        let mut builder = self
            .client
            .request(method, &request.url)
            .headers(Self::build_headers(&request.headers));

        if let Some(body) = request.body {
            builder = builder.body(body);
        }

        let timeout = request.timeout.or(self.default_timeout);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }

        let response = builder.send().await.context("HTTP/3 request failed")?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    v.to_str().unwrap_or("INVALID").to_string(),
                )
            })
            .collect::<Vec<_>>();

        let body = response.bytes().await.context("Failed to read response body")?;

        Ok(TerminusResponse {
            status,
            headers,
            body: body.to_vec(),
            version: "HTTP/3".to_string(),
            remote_addr: None,
        })
    }
}
