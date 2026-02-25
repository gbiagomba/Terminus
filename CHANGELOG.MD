# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [2.12.0] - 2026-02-23

### Added
- **Arbitrary HTTP Method Fuzzing**:
  - New flags: `--fuzz-methods`, `--custom-method`, `--custom-methods-file`
  - Predefined arbitrary methods: `BILBAO`, `FOOBAR`, `CATS`, `TERMINUS`, `PUZZLE`, `HELLO`
  - Baseline GET comparison for method confusion detection
  - New indicators: `[Arbitrary Method Accepted]`, `[Method Confusion Suspected]`
- **Interactive SQLite Mode**:
  - `--db-interactive <SQLITE_FILE>` REPL for safe database exploration
  - Commands: `help`, `list urls`, `list methods`, `find status <CODE>`, `find exploit <TYPE>`,
    `show scan <ID>`, `show raw <ID>`, `--more`, `exit`
  - Parameterized queries and 20-row pagination
  - Friendly error for non-Terminus databases
- **SQLite Schema Extension**:
  - Added `arbitrary_method_used` column to `scan_results`

### Changed
- **Version**: Bumped from 2.11.0 to 2.12.0
- **Outputs**: CSV and HTML include `arbitrary_method_used` where applicable

### Examples
```bash
# Fuzz arbitrary methods
terminus -u https://example.com --fuzz-methods -k

# Add custom methods
terminus -u https://example.com --fuzz-methods --custom-method BOUNCE --custom-method SPLAT -k

# SQLite interactive shell
terminus --db-interactive scan_results.db
```

## [2.8.0] - 2025-10-13

### Added
- **Advanced Passive Vulnerability Detection**: Four new passive security detection features
  - `--detect-host-injection`: Detects Host header injection vulnerabilities (CWE-444)
    - Sends requests with malicious Host header (`evil.terminus.local`)
    - Checks for reflection in Location, Vary, and Set-Cookie headers
    - Checks for reflection in response body
    - Marks findings as `[Host Injection Suspected]`
    - **NOTE**: Passive detection only - no exploitation

  - `--detect-xff-bypass`: Detects X-Forwarded-For IP-based access control bypasses
    - Adds `X-Forwarded-For: 127.0.0.1` header to requests
    - Compares baseline status code with XFF-modified request
    - Flags suspicious status changes (e.g., 403 → 200)
    - Marks findings as `[XFF Bypass?]` or `[XFF Bypass Suspected]`
    - Identifies potential IP whitelist bypass vulnerabilities

  - `--detect-csrf`: Passively detects CSRF vulnerabilities (CWE-352)
    - Only tests state-changing methods (POST, PUT, PATCH, DELETE, CONNECT, TRACE)
    - Test 1: Sends request without Origin and Referer headers
    - Test 2: Sends request with fake Origin (`http://evil.terminus.local`)
    - Checks for missing SameSite attribute on cookies
    - Checks for missing X-Frame-Options header
    - Checks for missing Content-Security-Policy header
    - Marks findings as `[CSRF Suspected]` or `[CSRF Missing Headers: ...]`

  - `--detect-ssrf`: Passively detects SSRF vulnerabilities (CWE-918)
    - Identifies suspicious URL parameters: url, uri, dest, destination, next, redirect, image, file, path, load, fetch
    - Checks response for SSRF indicators: EC2, metadata, internal, localhost, 169.254.169.254, connection refused, timeout
    - Marks findings as `[SSRF Suspected]` with vulnerable parameters
    - **NOTE**: Passive detection - looks for indicators, doesn't make external requests

### Changed
- Updated `ScanResult` struct to include four new optional fields:
  - `host_injection`: HostInjectionResult with injection details
  - `xff_bypass`: XffBypassResult with bypass detection results
  - `csrf_result`: CsrfResult with CSRF vulnerability details
  - `ssrf_result`: SsrfResult with SSRF detection findings
- Added four new result structs with detailed vulnerability information
- Enhanced tool description to emphasize advanced passive vulnerability detection
- Updated Cargo.toml version to 2.8.0
- Updated README with comprehensive examples for all new features
- Updated help text with clear descriptions of all new detection flags

### Security
- All new detection features are passive and defensive only
- No active exploitation or vulnerability testing
- Designed for ethical security assessment with proper authorization
- Host injection uses benign test host (`evil.terminus.local`)
- XFF bypass only compares status codes, no exploitation
- CSRF detection only checks for missing protections
- SSRF detection only looks for indicators in responses
- All features suitable for production environment scanning with rate limiting

### Examples
```bash
# Test for Host header injection
terminus -u https://example.com --detect-host-injection -k

# Detect XFF bypass on admin endpoints
terminus -f admin_endpoints.txt --detect-xff-bypass --rate-limit 5/s -k

# Check for CSRF vulnerabilities on state-changing endpoints
terminus -u https://api.example.com/update -X POST --detect-csrf -k

# Detect potential SSRF vulnerabilities
terminus -f api_endpoints.txt --detect-ssrf --check-body -k

# Comprehensive vulnerability assessment with all v2.8.0 features
terminus -f targets.txt \
  --detect-host-injection \
  --detect-xff-bypass \
  --detect-csrf \
  --detect-ssrf \
  --http2-desync-check \
  --check-security-headers \
  --detect-errors \
  --detect-reflection \
  --rate-limit 10/s \
  -k \
  --output-format all \
  -o comprehensive_vuln_scan

# Enterprise security workflow with AI analysis
terminus -f production_apps.txt \
  --detect-host-injection \
  --detect-xff-bypass \
  --detect-csrf \
  --detect-ssrf \
  --rate-limit 5/s \
  --random-delay 2-4 \
  -k \
  --output-format json \
  -o enterprise_scan

python terminus_ai_analyzer.py enterprise_scan.json \
  --provider anthropic \
  --persona security \
  -o security_findings.txt
```

## [2.7.0] - 2025-10-13

### Added
- **HTTP/2 Desync Detection**: Passive detection of HTTP/2 to HTTP/1.1 downgrade vulnerabilities (CWE-444)
  - `--http2-desync-check`: Compare HTTP/1.1 vs HTTP/2 responses to identify request smuggling vectors
  - Automatic status code comparison between HTTP versions
  - Response body length analysis for detecting significant differences
  - Detection of Transfer-Encoding and Content-Length discrepancies
  - Identifies potential HTTP request smuggling vulnerabilities in CDN/proxy configurations
  - **NOTE**: Only works with HTTPS URLs (HTTP/2 requires TLS)

### Changed
- Updated `ScanResult` struct to include new `http2_desync` field of type `Http2DesyncResult`
- Enhanced tool description to emphasize HTTP/2 desync detection capabilities
- Improved help text with clear description of HTTP/2 desync testing feature
- Updated Cargo.toml version to 2.7.0 and description to include HTTP/2 desync detection

### Security
- HTTP/2 desync detection is passive and defensive only
- No exploitation or active vulnerability testing
- Designed for authorized security assessment of HTTP/2 downgrade handling
- Identifies misconfigurations that could lead to HTTP request smuggling attacks
- Based on PortSwigger research on CDN/proxy HTTP/2 to HTTP/1.1 downgrade issues

### Examples
```bash
# Basic HTTP/2 desync check
terminus -u https://api.example.com --http2-desync-check -k

# Comprehensive HTTP/2 security assessment
terminus -f production_apis.txt \
  --http2-desync-check \
  --check-security-headers \
  --detect-errors \
  --rate-limit 10/s \
  --output-format json \
  -o http2_audit

# Test with custom headers through proxy
terminus -u https://target.com/api \
  --http2-desync-check \
  -H "X-Forwarded-For: 127.0.0.1" \
  -x http://127.0.0.1:8080 \
  -k \
  -v
```

## [2.6.0] - 2025-10-13

### Added
- **Passive Security Analysis**: Three new defensive security features for ethical assessment
  - `--check-security-headers`: Analyze HTTP security headers
    - Detects missing headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.
    - Identifies weak configurations (unsafe CSP directives, permissive CORS, etc.)
    - Flags information disclosure (Server, X-Powered-By headers)
  - `--detect-errors`: Detect verbose error messages and information disclosure
    - SQL error patterns (MySQL, PostgreSQL, Oracle, SQL Server)
    - Stack traces (Java, Python, .NET, PHP)
    - Debug/development mode indicators
    - File path disclosure (Windows/Unix paths)
  - `--detect-reflection`: Passive XSS vector detection
    - Identifies potential input reflection patterns
    - Detects unsafe JavaScript patterns (eval, innerHTML, document.write)
    - Checks for inline event handlers
    - **NOTE**: Passive detection only - no exploitation attempts

### Changed
- Updated `ScanResult` struct to include new security analysis fields:
  - `security_headers`: SecurityHeaders with missing/present/issues
  - `detected_errors`: Vec of detected error message types
  - `reflection_detected`: Boolean flag for potential XSS vectors
- Enhanced response body reading to support security analysis features
- Updated tool description to emphasize security analysis capabilities
- Improved help text with clear descriptions of passive security features

### Security
- All security features are passive and defensive only
- No exploitation or active vulnerability testing
- Designed for ethical security assessment with proper authorization
- Suitable for production environment scanning with rate limiting

### Examples
```bash
# Check security headers
terminus -f urls.txt --check-security-headers --output-format json -o audit

# Detect error messages and information disclosure
terminus -f api_endpoints.txt --detect-errors --detect-reflection

# Comprehensive security assessment
terminus -f targets.txt \
  --check-security-headers \
  --detect-errors \
  --detect-reflection \
  --rate-limit 10/s \
  --output-format all \
  -o security_assessment
```

## [2.5.0] - 2025-10-10

### Added
- **Smart Diffing**: Compare scan results to identify changes
  - `--diff` flag to compare with previous JSON scan
  - Displays new endpoints, removed endpoints, and status changes
  - Colored diff output with clear change indicators (+/-/~)
- **Response Pattern Matching**: Search for patterns in response bodies
  - `--grep-response` flag with regex support
  - Filters results to only show responses matching the pattern
  - Useful for finding sensitive data, error messages, or specific content
- **Rate Limiting & Throttling**: Control request rate for respectful scanning
  - `--rate-limit` flag (e.g., `10/s`, `100/m`, `50/h`)
  - `--random-delay` flag for random delays between requests (e.g., `1-5`)
  - Helps avoid overwhelming production systems or triggering rate limits
- **Response Body Analysis**: Analyze and extract information from responses
  - `--check-body` flag to include body preview in results (first 200 chars)
  - `--extract-links` flag to automatically extract URLs from response bodies
  - Extracts URLs from href, src attributes and plain text
- **AI-Powered Analysis Script**: Post-processing tool for scan results
  - `terminus_ai_analyzer.py` with support for 6 AI providers
  - Local providers: Ollama, LM Studio, vLLM
  - Cloud providers: OpenAI, Anthropic Claude, Google Gemini
  - Three analysis personas: Security Engineer (default), Developer, TPM
  - Customizable AI models and API endpoints

### Changed
- Updated `ScanResult` struct to include new fields:
  - `body_preview`: Optional preview of response body
  - `matched_patterns`: Patterns found in response body
  - `extracted_links`: URLs extracted from response
- Enhanced output formats (JSON, HTML, CSV) to include new body analysis fields
- Updated help text and documentation with all new features
- Improved scanning loop to support conditional body reading

### Dependencies
- Added `rand` 0.8 for random delay generation

### Examples
```bash
# Compare two scans
terminus -f targets.txt --diff previous_scan.json -o new_scan

# Find admin panels
terminus -f urls.txt --grep-response "admin|dashboard|config"

# Rate-limited production scan
terminus -f prod_urls.txt --rate-limit 10/s --random-delay 1-3

# Extract links from responses
terminus -u https://example.com --extract-links

# AI analysis of results
python terminus_ai_analyzer.py results.json --provider ollama --persona security
```

## [2.4.1] - 2025-10-10

### Added
- **CSV Output Format**: Export scan results to CSV format
  - Use `--output-format csv` to generate CSV files
  - Includes proper CSV escaping for special characters
  - Supports both verbose (with headers) and standard output
  - CSV format compatible with Excel, Google Sheets, and other spreadsheet applications

### Changed
- Updated help text to include CSV in output format options
- Enhanced documentation with CSV examples

## [2.4.0] - 2025-10-10

### Added
- **Input Format Support**: Parse multiple input formats automatically
  - Nmap XML output (`-oX`)
  - Nmap greppable output (`-oG`)
  - testssl.sh JSON output
  - ProjectDiscovery JSON outputs (nuclei, katana, etc.)
- **Stdin Pipe Support**: Read input from stdin for tool chaining
  - Example: `cat domains.txt | httpx | terminus`
- **IPv4/IPv6 Support**: Native support for both IP versions
  - IPv6 scanning enabled with `-6/--ipv6` flag
  - Automatic IP address detection and parsing
- **Multiple Output Formats**: Generate results in various formats
  - stdout (default), txt, json, html, or all simultaneously
  - `--output-format` flag to specify format(s)
  - `-o` flag sets base name (extension added automatically)
- **Enhanced URL Parsing**: Intelligent target extraction
  - Automatic detection of URLs, IPs, and hostnames
  - Support for piped input from security tools
  - Deduplication of targets across formats

### Changed
- Refactored input handling for better format detection
- Improved error handling and reporting
- Enhanced output file management with proper extensions
- Updated help text and documentation

### Dependencies
- Added `serde` 1.0 for JSON serialization
- Added `serde_json` 1.0 for JSON parsing
- Added `quick-xml` 0.36 for XML parsing
- Added `regex` 1.10 for pattern matching
- Added `atty` 0.2 for stdin detection

## [2.3.0] - 2025-10-10

### Added
- Proxy support flag (`-x/--proxy`) to route traffic through proxy tools like Burp Suite
- Custom header support via `-H/--header` flag (can be specified multiple times)
- Header file support via `--header-file` to read headers from a file
- Cookie support via `-b/--cookie` flag for inline cookie strings
- Cookie file support via `-c/--cookie-file` to read cookies from a file
- HTTP version control via `--http-version` flag to force HTTP/1.0, 1.1, or 2.0
- HTTP/2 support with `http2` feature enabled in reqwest
- Comprehensive examples in README for new features
- New Makefile targets: `test`, `check`, `fmt`, and `lint`

### Changed
- Updated Cargo.toml to version 2.3.0
- Enhanced reqwest dependency with `cookies` and `http2` features
- Updated Dockerfile to use debian:bookworm-slim with CA certificates
- Improved README with detailed usage examples for all new features
- Enhanced tool description in help text

### Security
- All new features follow secure coding practices
- Proxy connections properly validated
- Header and cookie parsing includes proper validation

## [2.2.0] - 2024-XX-XX

### Added
- Insecure flag (`-k/--insecure`) to deal with untrusted certificates
- Updated the build yaml file

## [2.1.0] - 2024-XX-XX

### Added
- Complete rewrite in Rust
- Filter response code functionality (`-F/--filter-code`)
- Verbose output option (`-v/--verbose`)
- Redirect following (`-L/--follow`)
- Logo using Adobe Firefly

### Fixed
- Various bug fixes and improvements

## [2.11.0] - 2026-01-28

### Added
- **SQLite Database Export**: New `--output-format sqlite` option for queryable database export
  - Export scan results to SQLite database for SQL-based analysis
  - Denormalized schema with 50+ columns covering all scan results and vulnerabilities
  - Automatic indexing on URL, status, scan_timestamp, and vulnerability flags for fast queries
  - Supports both `sqlite` and `db` format names
  - Full response bodies and headers preserved for deep analysis
  - Example: `sqlite3 results.db "SELECT url FROM scan_results WHERE csrf_suspected = 1;"`
  - Compatible with all existing scan features and security checks
  - Accessible via standard `sqlite3` CLI or any SQLite library
  - Included in `--output-format all` mode

### Fixed
- **HTML Port Display**: Fixed port column showing "0" for URLs with embedded ports
  - Port column now displays "N/A" when port is already part of the URL
  - Normal port scanning (via `-p` flag) continues to show actual port numbers (80, 443, etc.)
  - Improves clarity in HTML reports for mixed URL formats

- **HTML Table Overflow**: Fixed table layout issues with long URLs and content
  - Added CSS `max-width` constraints and `word-break` rules to prevent table overflow
  - URLs now truncate with ellipsis (`...`) and show full text on hover
  - Table uses fixed layout (`table-layout: fixed`) for consistent column widths
  - Improved mobile and small screen responsiveness
  - All table cells respect `max-width: 300px` with word wrapping

- **CSV Export Improvements**: Simplified CSV format for better spreadsheet compatibility
  - Removed full response bodies from CSV output (reduces file size by 90%+)
  - Improved CSV escaping to handle all control characters (`\r`, `\n`, `\t`, `\0`)
  - Better RFC 4180 compliance for Excel and Google Sheets
  - CSV headers updated to reflect removed "Response Body" column
  - Response bodies still available in JSON, HTML, and SQLite formats for detailed analysis

### Changed
- **Dependencies**:
  - Added `rusqlite = { version = "0.32", features = ["bundled"] }` for SQLite support
  - Added `chrono = "0.4"` for timestamp handling in database exports
- **Version**: Bumped from 2.10.2 to 2.11.0 (minor version per Semantic Versioning)
- **Output Formats**: Updated help text and documentation to include SQLite/DB format
- **CSV Strategy**: CSV export now optimized for spreadsheet use; use JSON/SQLite for full data

### Examples
```bash
# Export to SQLite database
terminus -f urls.txt --output-format sqlite -o scan_results

# Query the database
sqlite3 scan_results.db "SELECT url, status FROM scan_results WHERE status >= 400;"

# Find all vulnerable endpoints
sqlite3 scan_results.db "SELECT url FROM scan_results WHERE
  http2_desync_detected = 1 OR
  host_injection_suspected = 1 OR
  csrf_suspected = 1;"

# Export to all formats including SQLite
terminus -f targets.txt --output-format all -o comprehensive_scan

# Filter and export specific columns from database to CSV
sqlite3 -header -csv scan_results.db "SELECT url, status, port FROM scan_results;" > filtered.csv
```
