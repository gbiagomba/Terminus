//! Raw TCP+TLS HTTP/1.1 transport.
//!
//! Writes exact bytes over the wire, bypassing reqwest (which normalizes CRLF and
//! rejects malformed request lines). This is required for request-smuggling and
//! desync probes where every byte of the request must be under caller control.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Maximum number of response bytes to buffer, to avoid unbounded memory use.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Raw byte-exact HTTP/1.1 client.
pub struct RawHttp1Transport {
    allow_insecure: bool,
}

/// Result of a single raw exchange.
pub struct RawExchange {
    /// Wall-clock time from just before write to end of read loop. The primary
    /// desync signal: a hung/timed-out response often indicates a successful
    /// smuggle.
    pub elapsed: Duration,
    /// Raw response bytes read from the socket (capped at [`MAX_RESPONSE_BYTES`]).
    pub response_bytes: Vec<u8>,
    /// True if the read loop hit the timeout before the connection closed.
    pub timed_out: bool,
    /// True if the peer closed the connection (read returned 0 bytes).
    pub connection_closed: bool,
}

impl RawHttp1Transport {
    /// Create a new transport. When `allow_insecure` is true, TLS certificate
    /// verification is disabled (mirrors reqwest's `danger_accept_invalid_certs`).
    pub fn new(allow_insecure: bool) -> Self {
        Self { allow_insecure }
    }

    /// Open a fresh connection, write `raw_bytes` verbatim, then read the response
    /// until the connection closes or `timeout` elapses.
    ///
    /// Captures wall-clock elapsed time (the desync signal). A timeout is a valid
    /// result, not an error: it returns `Ok` with `timed_out = true`. Only
    /// connect/TLS/DNS failures produce `Err`.
    pub async fn send_raw(
        &self,
        host: &str,
        port: u16,
        tls: bool,
        raw_bytes: &[u8],
        timeout: Duration,
    ) -> Result<RawExchange> {
        // Connect (subject to the timeout budget). A connect failure is a real error.
        let tcp = tokio::time::timeout(timeout, TcpStream::connect((host, port)))
            .await
            .with_context(|| format!("Timed out connecting to {host}:{port}"))?
            .with_context(|| format!("Failed to connect to {host}:{port}"))?;
        tcp.set_nodelay(true).ok();

        if tls {
            let connector = self.tls_connector()?;
            let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .with_context(|| format!("Invalid TLS server name: {host}"))?;
            let stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
                .await
                .with_context(|| format!("Timed out during TLS handshake with {host}"))?
                .with_context(|| format!("TLS handshake failed with {host}"))?;
            Self::exchange(stream, raw_bytes, timeout).await
        } else {
            Self::exchange(tcp, raw_bytes, timeout).await
        }
    }

    /// Write the request, then read the response with a timeout. Generic over any
    /// async stream (plain TCP or TLS-wrapped).
    async fn exchange<S>(mut stream: S, raw_bytes: &[u8], timeout: Duration) -> Result<RawExchange>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let start = Instant::now();

        // Bound the write/flush by the same timeout budget so a stalled peer socket
        // buffer cannot block past the deadline. A write timeout is treated as a valid
        // signal (peer not draining), not a hard error.
        let write_result = tokio::time::timeout(timeout, async {
            stream.write_all(raw_bytes).await?;
            stream.flush().await
        })
        .await;
        match write_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e).context("Failed to write raw request bytes"),
            Err(_) => {
                return Ok(RawExchange {
                    elapsed: start.elapsed(),
                    response_bytes: Vec::new(),
                    timed_out: true,
                    connection_closed: false,
                });
            }
        }

        let mut response_bytes: Vec<u8> = Vec::new();
        let mut connection_closed = false;
        let mut timed_out = false;
        let mut buf = [0u8; 8192];

        loop {
            let remaining = match timeout.checked_sub(start.elapsed()) {
                Some(r) if !r.is_zero() => r,
                _ => {
                    timed_out = true;
                    break;
                }
            };

            match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    connection_closed = true;
                    break;
                }
                Ok(Ok(n)) => {
                    let room = MAX_RESPONSE_BYTES.saturating_sub(response_bytes.len());
                    if room == 0 {
                        break;
                    }
                    let take = n.min(room);
                    response_bytes.extend_from_slice(&buf[..take]);
                    if response_bytes.len() >= MAX_RESPONSE_BYTES {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    // A peer that closes abruptly after sending its response can
                    // surface as ECONNRESET/EPIPE/UnexpectedEof rather than a
                    // clean 0-byte read (common on macOS/BSD). Treat these as a
                    // normal connection close, not a transport error, so any
                    // bytes already buffered are still returned to the caller.
                    use std::io::ErrorKind;
                    match e.kind() {
                        ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                        | ErrorKind::UnexpectedEof => {
                            connection_closed = true;
                            break;
                        }
                        _ => {
                            return Err(
                                anyhow::Error::new(e).context("Error reading raw response")
                            );
                        }
                    }
                }
                Err(_) => {
                    timed_out = true;
                    break;
                }
            }
        }

        // On timeout, report the full timeout duration as elapsed (the signal).
        let elapsed = if timed_out { timeout } else { start.elapsed() };

        Ok(RawExchange {
            elapsed,
            response_bytes,
            timed_out,
            connection_closed,
        })
    }

    /// Build a rustls `TlsConnector`. Uses webpki-roots for verification, unless
    /// `allow_insecure` is set, in which case a no-op verifier is installed.
    fn tls_connector(&self) -> Result<TlsConnector> {
        let config = if self.allow_insecure {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(danger::NoVerification::new()))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };

        Ok(TlsConnector::from(Arc::new(config)))
    }
}

/// Assemble a request with literal `\r\n` line endings so callers control every
/// byte. The output is NOT normalized or validated: whatever is passed in is
/// emitted verbatim, which is exactly what smuggling/desync probes need.
///
/// Layout:
/// - request line: `"{method} {path} HTTP/1.1\r\n"`
/// - each header:  `"{k}: {v}\r\n"` in the order given
/// - blank line:   `"\r\n"`
/// - optional body
pub fn build_raw_request(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");

    // Always emit a Host header first (still verbatim; caller may override by
    // passing their own Host in `headers`).
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(b"\r\n");

    for (k, v) in headers {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);

    out
}

/// Dangerous TLS certificate verifier that accepts any certificate. Only used
/// when `allow_insecure` is explicitly enabled.
mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    pub struct NoVerification {
        provider: CryptoProvider,
    }

    impl NoVerification {
        pub fn new() -> Self {
            Self {
                provider: rustls::crypto::aws_lc_rs::default_provider(),
            }
        }
    }

    impl ServerCertVerifier for NoVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn build_raw_request_exact_bytes() {
        let bytes = build_raw_request("GET", "/", "example.com", &[], b"");
        let s = String::from_utf8(bytes).unwrap();

        assert!(s.starts_with("GET / HTTP/1.1\r\n"), "request line: {s:?}");
        assert!(s.contains("Host: example.com\r\n"), "host header: {s:?}");
        assert!(s.ends_with("\r\n\r\n"), "empty-body header terminator: {s:?}");
    }

    #[test]
    fn build_raw_request_preserves_header_order() {
        let headers = vec![
            ("X-First".to_string(), "1".to_string()),
            ("X-Second".to_string(), "2".to_string()),
            ("X-Third".to_string(), "3".to_string()),
        ];
        let bytes = build_raw_request("POST", "/submit", "h.test", &headers, b"data");
        let s = String::from_utf8(bytes).unwrap();

        let first = s.find("X-First").unwrap();
        let second = s.find("X-Second").unwrap();
        let third = s.find("X-Third").unwrap();
        assert!(first < second && second < third, "order not preserved: {s:?}");

        // Body is emitted verbatim after the blank line.
        assert!(s.ends_with("\r\n\r\ndata"), "body appended: {s:?}");
    }

    #[tokio::test]
    async fn send_raw_reads_response_then_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                .await
                .unwrap();
            sock.flush().await.unwrap();
            // Brief linger so the client reliably reads the payload before the
            // socket drops (avoids a racy ECONNRESET on macOS/BSD), then close.
            tokio::time::sleep(Duration::from_millis(100)).await;
            // Dropping sock closes the connection.
        });

        let transport = RawHttp1Transport::new(false);
        let req = build_raw_request("GET", "/", "127.0.0.1", &[], b"");
        let exchange = transport
            .send_raw(
                &addr.ip().to_string(),
                addr.port(),
                false,
                &req,
                Duration::from_secs(5),
            )
            .await
            .unwrap();

        server.await.unwrap();

        assert!(!exchange.timed_out, "should not time out");
        assert!(exchange.connection_closed, "peer should have closed");
        let body = String::from_utf8_lossy(&exchange.response_bytes);
        assert!(body.contains("200 OK"), "response was: {body:?}");
    }

    #[tokio::test]
    async fn send_raw_times_out_on_silent_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.unwrap();
            // Never respond; hold the connection open for a while.
            tokio::time::sleep(Duration::from_secs(3)).await;
        });

        let transport = RawHttp1Transport::new(false);
        let req = build_raw_request("GET", "/", "127.0.0.1", &[], b"");
        let start = Instant::now();
        let exchange = transport
            .send_raw(
                &addr.ip().to_string(),
                addr.port(),
                false,
                &req,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        let wall = start.elapsed();

        assert!(exchange.timed_out, "should have timed out");
        assert!(
            exchange.elapsed >= Duration::from_millis(950),
            "elapsed too short: {:?}",
            exchange.elapsed
        );
        assert!(
            wall >= Duration::from_millis(950),
            "wall clock too short: {wall:?}"
        );

        server.abort();
    }
}
