use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Version};
use std::time::Duration;

use crate::transport::traits::HttpTransport;
use crate::transport::types::{HttpVersion, TerminusRequest, TerminusResponse, TransportConfig};

#[derive(Clone)]
pub struct Http12Transport {
    client: Client,
    default_version: HttpVersion,
    default_timeout: Option<Duration>,
}

impl Http12Transport {
    pub fn new(config: TransportConfig) -> Result<Self> {
        let mut builder = Client::builder()
            .danger_accept_invalid_certs(config.allow_insecure)
            .redirect(reqwest::redirect::Policy::none());

        if let Some(proxy_url) = &config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .context("Failed to configure proxy")?;
            builder = builder.proxy(proxy);
        }

        match config.http_version {
            HttpVersion::Http2 => {
                builder = builder.http2_prior_knowledge();
            }
            HttpVersion::Http10 | HttpVersion::Http11 => {
                builder = builder.http1_only();
            }
            HttpVersion::Http3 => {
                anyhow::bail!("HTTP/3 requested on HTTP/1.1/2 transport");
            }
        }

        let client = builder.build().context("Failed to build HTTP client")?;

        Ok(Self {
            client,
            default_version: config.http_version,
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

    fn map_version(version: HttpVersion) -> Result<Version> {
        match version {
            HttpVersion::Http10 => Ok(Version::HTTP_10),
            HttpVersion::Http11 => Ok(Version::HTTP_11),
            HttpVersion::Http2 => Ok(Version::HTTP_2),
            HttpVersion::Http3 => anyhow::bail!("HTTP/3 is not supported by HTTP/1.1/2 transport"),
        }
    }
}

#[async_trait::async_trait]
impl HttpTransport for Http12Transport {
    async fn send(&self, request: TerminusRequest) -> Result<TerminusResponse> {
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

        let version = request.version.unwrap_or(self.default_version);
        builder = builder.version(Self::map_version(version)?);

        let response = builder.send().await.context("Request failed")?;
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
        let version = response.version();
        let version_str = match version {
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_2 => "HTTP/2",
            Version::HTTP_3 => "HTTP/3",
            _ => "UNKNOWN",
        };
        let body = response.bytes().await.context("Failed to read response body")?;

        Ok(TerminusResponse {
            status,
            headers,
            body: body.to_vec(),
            version: version_str.to_string(),
            remote_addr: None,
        })
    }
}
