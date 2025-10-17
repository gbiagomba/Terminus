![alt tag](rsc/Firefly%20Create%20a%20minimalist%20yet%20powerful%20logo%20inspired%20by%20the%20Roman%20god%20Terminus,%20the%20protector%20of%20b%20(2).jpg)

# `terminus`
![GitHub](https://img.shields.io/github/license/Achiefs/fim) [![Tip Me via PayPal](https://img.shields.io/badge/PayPal-tip_me-green?logo=paypal)](paypal.me/gbiagomba)

`terminus` is a command-line tool designed to test the accessibility of URLs without authentication, using various HTTP methods. It's particularly useful for identifying unprotected paths to web servers that require authentication, helping to expose potential security vulnerabilities. The tool supports individual URLs or lists from files, custom HTTP methods, multiple ports, and concurrent execution.

## Table of Contents

- [Features](#features)
  - [Input Sources](#input-sources)
  - [Output Options](#output-options)
  - [HTTP Testing](#http-testing)
  - [Advanced Features](#advanced-features)
  - [Smart Analysis Features](#smart-analysis-features-v250)
  - [Passive Security Analysis](#passive-security-analysis-v260)
  - [HTTP/2 Desync Detection](#http2-desync-detection-v270)
  - [Advanced Passive Vulnerability Detection](#advanced-passive-vulnerability-detection-v280)
- [Installation](#installation)
  - [Using the Makefile](#using-the-makefile)
- [Usage](#usage)
  - [Examples](#examples)
    - [Basic Usage](#basic-usage)
    - [Input Format Examples](#input-format-examples)
    - [Piping Examples](#piping-examples)
    - [Output Format Examples](#output-format-examples)
    - [Advanced Examples](#advanced-examples)
    - [Smart Analysis Examples](#smart-analysis-examples-v250)
    - [Passive Security Analysis Examples](#passive-security-analysis-examples-v260)
    - [HTTP/2 Desync Detection Examples](#http2-desync-detection-examples-v270)
    - [Advanced Passive Vulnerability Detection Examples](#advanced-passive-vulnerability-detection-examples-v280)
- [AI-Powered Analysis](#ai-powered-analysis)
- [HTTP Methods Tested](#http-methods-tested)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Input Sources
- **Single URL/IP Testing**: Test URLs or IP addresses (IPv4/IPv6) with the `-u` flag
- **File Input**: Support for multiple input formats via `-f` flag:
  - Plain text files with URLs/domains/IPs
  - Nmap XML output (`-oX`)
  - Nmap greppable output (`-oG`)
  - testssl.sh JSON output
  - ProjectDiscovery JSON (nuclei, katana)
- **Stdin Pipe**: Chain tools together (e.g., `cat domains.txt | httpx | terminus`)
- **IPv4/IPv6 Support**: Native support for both IPv4 and IPv6 addresses with `-6` flag

### Output Options
- **Multiple Output Formats**: stdout, txt, json, html, csv, or all formats simultaneously
- **Output Format Control**: Use `--output-format` to specify desired format(s)
- **Custom Output Location**: Specify output file base name with `-o` flag
- **Vulnerability Indicators**: All output formats (stdout, txt, csv, html) display detected vulnerabilities with clear indicators
- **Enhanced HTML Reports**: Interactive HTML reports with:
  - Vulnerability summary dashboard with statistics
  - JavaScript-powered filtering by vulnerability type
  - Visual badges for detected issues (HTTP/2 Desync, Host Injection, XFF Bypass, CSRF, SSRF, Reflection, Security Issues, Error Messages)
  - Clean/Pass indicators for endpoints with no vulnerabilities
- **CSV Export**: Generate CSV files with vulnerability columns for easy data analysis and import into spreadsheets

### HTTP Testing
- **HTTP Methods**: Use any HTTP method with `-X` flag or `ALL` to test all predefined methods
- **Smart Port Scanning**:
  - Default: Scans ports 80 and 443 when no `-p` flag is specified
  - Custom Ports: Specify comma-separated ports like `80,443,8080` with `-p` flag
  - File-based: Automatically uses ports from nmap/testssl/nuclei scan outputs
  - URL-embedded: Respects ports already specified in URLs (e.g., `http://example.com:8080`)
- **HTTP Version Control**: Force HTTP/1.0, 1.1, or 2.0 using `--http-version`
- **Status Code Filtering**: Filter responses by status code using `-F`

### Advanced Features
- **Concurrent Scanning**: Multi-threaded scanning with configurable thread count using `-t/--threads` flag (default: 10 threads)
- **Proxy Support**: Route traffic through proxy tools like Burp Suite using `-x` flag
- **Custom Headers**: Add headers via `-H` flag (multiple allowed) or `--header-file`
- **Cookie Support**: Include cookies with `-b` flag or from file using `-c/--cookie-file`
- **TLS/SSL Options**: Allow insecure connections with `-k` flag
- **Redirect Handling**: Follow redirects with `-L` flag
- **Verbose Output**: View detailed response headers with `-v` flag
- **Scan Level Presets**: Predefined security scan configurations with `--scan-level` flag:
  - `quick`: Basic HTTP requests only (default behavior)
  - `standard`: Security headers, error detection, and reflection checks
  - `full`: All features including body analysis and link extraction
  - `vuln`: All vulnerability detection features (HTTP/2 desync, Host injection, XFF bypass, CSRF, SSRF)

### Smart Analysis Features (v2.5.0)
- **Smart Diffing**: Compare two scans and identify new/removed endpoints and status changes
- **Pattern Matching**: Search for specific patterns in response bodies using regex
- **Rate Limiting**: Control request rate for respectful scanning (e.g., `10/s`, `100/m`)
- **Random Delays**: Add random delays between requests to avoid detection
- **Body Analysis**: Analyze response body content with `--check-body`
- **Link Extraction**: Automatically extract URLs from response bodies with `--extract-links`

### Passive Security Analysis (v2.6.0)
- **Security Headers Analysis**: Detect missing or misconfigured security headers (CSP, HSTS, X-Frame-Options, etc.)
- **Error Message Detection**: Identify verbose error messages, SQL errors, stack traces, and path disclosure
- **Reflection Detection**: Passive detection of input reflection and potential XSS vectors (no exploitation)

### HTTP/2 Desync Detection (v2.7.0)
- **HTTP/2 Downgrade Testing**: Compare HTTP/1.1 vs HTTP/2 responses to detect desync vulnerabilities (CWE-444)
- **Request Smuggling Detection**: Identify potential HTTP request smuggling vectors from HTTP/2 to HTTP/1.1 translation
- **CDN/Proxy Analysis**: Test for misconfiguration in CDN and reverse proxy HTTP/2 downgrade handling
- **Status Code Comparison**: Detect discrepancies in status codes between HTTP versions
- **Response Body Analysis**: Compare response body lengths and content for HTTP version differences

### Advanced Passive Vulnerability Detection (v2.8.0)
- **Host Header Injection Detection**: Passively detect Host header injection vulnerabilities (CWE-444) by checking if malicious host values are reflected in Location, Vary, or Set-Cookie headers
- **X-Forwarded-For Bypass Detection**: Detect IP-based access control bypasses by comparing baseline requests with X-Forwarded-For header modifications
- **CSRF Vulnerability Detection**: Passively identify missing CSRF protections including Origin/Referer validation, SameSite cookies, X-Frame-Options, and CSP headers
- **SSRF Vulnerability Detection**: Detect potential Server-Side Request Forgery (CWE-918) vulnerabilities by identifying suspicious URL parameters and response indicators

### Performance & Usability Enhancements (v2.9.0)
- **Multi-threaded Scanning**: Concurrent request processing with configurable thread count (default: 10 threads) using Rayon for parallel execution
- **Smart Default Port Scanning**: Automatically scans ports 80 and 443 when no ports specified, while respecting ports from file inputs (nmap/testssl/nuclei)
- **Enhanced Vulnerability Reporting**: All output formats now display vulnerability indicators with clear, actionable information
- **Interactive HTML Reports**: Complete redesign with vulnerability summary dashboard, JavaScript filtering by vulnerability type, and visual badges
- **Improved CSV Export**: Added dedicated "Vulnerabilities" column for easy data analysis and reporting

---

## Installation

Ensure Rust is installed on your system:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone and build the repository:
```bash
git clone https://github.com/your_github/terminus.git
cd terminus
cargo build --release
```

Install the tool:
```bash
cargo install --path .
```

---

### Using the `Makefile`

- **Build** the project:
  ```bash
  make build
  ```

- **Run** the program with default settings:
  ```bash
  make run
  ```

- **Run** with a specific URL and test all HTTP methods:
  ```bash
  make run-url
  ```

- **Run** with a file of URLs and test all HTTP methods:
  ```bash
  make run-file
  ```

- **Install** the program globally:
  ```bash
  make install
  ```

- **Uninstall** the program:
  ```bash
  make uninstall
  ```

- **Clean** the project:
  ```bash
  make clean
  ```
  
---

## Usage

```plaintext
URL testing with support for multiple input formats (nmap, testssl, ProjectDiscovery), IPv4/IPv6, and various output formats

Usage: terminus [OPTIONS]

Options:
  -u, --url <URL>                  Specify a single URL/IP to check
  -f, --file <FILE>                Input file (URLs, nmap XML/greppable, testssl JSON, nuclei/katana JSON)
  -X, --method <METHOD>            Specify the HTTP method to use (default: GET). Use ALL to test all methods
  -p, --port <PORTS>               Comma-separated ports to connect to (e.g., 80,443)
  -6, --ipv6                       Enable IPv6 scanning
  -k, --insecure                   Allow insecure SSL connections
  -v, --verbose                    Enable verbose output with response headers
  -L, --follow                     Follow HTTP redirects
  -o, --output <FILE>              Output file base name (extension added based on format)
      --output-format <FORMAT>     Output format: stdout, txt, json, html, csv, all (default: stdout)
  -F, --filter-code <STATUS_CODE>  Filter results by HTTP status code
  -x, --proxy <PROXY>              Specify proxy URL (e.g., http://127.0.0.1:8080 for Burp)
  -H, --header <HEADER>            Add custom header (format: 'Name: Value'). Can be specified multiple times
      --header-file <FILE>         Read headers from file (one per line, format: 'Name: Value')
  -b, --cookie <COOKIE>            Add cookie string (format: 'name1=value1; name2=value2')
  -c, --cookie-file <FILE>         Read cookies from file
      --http-version <VERSION>     Force HTTP version (1.0, 1.1, or 2)
      --diff <FILE>                Compare results with previous scan (JSON file)
      --grep-response <PATTERN>    Search for pattern in response body (regex supported)
      --rate-limit <RATE>          Rate limit requests (e.g., '10/s', '100/m')
      --random-delay <RANGE>       Random delay between requests in seconds (e.g., '1-5')
      --check-body                 Analyze response body content
      --extract-links              Extract and display links from response body
      --check-security-headers     Analyze security headers (CSP, HSTS, X-Frame-Options, etc.)
      --detect-errors              Detect verbose error messages (SQL, stack traces, etc.)
      --detect-reflection          Check if input is reflected in response (passive XSS detection)
      --http2-desync-check         Test HTTP/2 to HTTP/1.1 downgrade handling (detects potential request smuggling)
      --detect-host-injection      Passively detect Host header injection vulnerabilities by checking response headers
      --detect-xff-bypass          Detect X-Forwarded-For bypass by comparing baseline and XFF requests
      --detect-csrf                Passively detect potential CSRF vulnerabilities and missing protections
      --detect-ssrf                Passively detect potential SSRF vulnerabilities in URL parameters
      --scan-level <LEVEL>         Scan preset level: quick (basic), standard (security headers+errors+reflection), full (all features), vuln (all vulnerability detection)
  -t, --threads <NUM>              Number of concurrent threads for scanning (default: 10)
  -h, --help                       Print help
  -V, --version                    Print version

```

### Examples

#### Basic Usage

**Test a single URL (scans both port 80 and 443 by default)**:
```bash
terminus -u http://example.com
```

**Test an IPv4 address (scans ports 80 and 443)**:
```bash
terminus -u 192.168.1.1
```

**Test an IPv6 address**:
```bash
terminus -u "2001:db8::1" -6
```

**Test with custom ports**:
```bash
terminus -u http://example.com -p 8080,8443
```

**Test multiple URLs from a file**:
```bash
terminus -f urls.txt -X ALL
```

**Test specific ports only**:
```bash
terminus -f urls.txt -p 80,443,8080 -X ALL
```

#### Input Format Examples

**Parse nmap XML output (uses ports from nmap scan)**:
```bash
nmap -p80,443,8080 -oX scan.xml target.com
terminus -f scan.xml
```

**Parse nmap greppable output (uses ports from nmap scan)**:
```bash
nmap -p80,443 -oG scan.gnmap target.com
terminus -f scan.gnmap
```

**Parse testssl.sh JSON output (uses ports from testssl scan)**:
```bash
testssl --json-pretty target.com > testssl.json
terminus -f testssl.json
```

**Parse ProjectDiscovery tool output (uses discovered URLs with ports)**:
```bash
echo "target.com" | katana -json -o katana.json
terminus -f katana.json
```

**Note**: When using file inputs, Terminus automatically uses the ports specified in the scan output. No `-p` flag needed!

#### Piping Examples

**Chain with other tools**:
```bash
cat domains.txt | httpx | terminus
```

**Complex pipeline with nuclei**:
```bash
cat domains.txt | httpx -silent | nuclei -t cves/ -json | terminus
```

**Chain with subfinder and httprobe**:
```bash
subfinder -d target.com -silent | httprobe | terminus --output-format json -o results
```

#### Output Format Examples

**Output to JSON**:
```bash
terminus -u http://example.com --output-format json -o scan_results
```

**Output to HTML**:
```bash
terminus -f urls.txt --output-format html -o scan_results
```

**Output to CSV**:
```bash
terminus -f urls.txt --output-format csv -o scan_results
```

**Output to all formats**:
```bash
terminus -f urls.txt --output-format all -o scan_results
```

#### Advanced Examples

**Test with proxy (Burp Suite)**:
```bash
terminus -u https://example.com -x http://127.0.0.1:8080 -k
```

**Test with custom headers**:
```bash
terminus -u https://example.com -H "Authorization: Bearer token123" -H "X-Custom: value"
```

**Test with cookies**:
```bash
terminus -u https://example.com -b "session=abc123; user=admin"
```

**Force HTTP/2**:
```bash
terminus -u https://example.com --http-version 2
```

**Complete pentest workflow**:
```bash
terminus -u https://api.example.com -X POST \
  -H "Content-Type: application/json" \
  -b "session=xyz789" \
  -x http://127.0.0.1:8080 \
  -k -v -L \
  --http-version 2 \
  --output-format all \
  -o pentest_results
```

**Scan Level Preset Examples**:
```bash
# Quick scan - basic requests only (fastest)
terminus -f urls.txt --scan-level quick

# Standard scan - security headers, errors, and reflection detection
terminus -f production_urls.txt --scan-level standard -o standard_scan

# Full scan - all features including body analysis
terminus -f targets.txt --scan-level full --rate-limit 10/s -o full_scan

# Vulnerability scan - all passive vulnerability detection
terminus -f api_endpoints.txt --scan-level vuln -k -o vuln_scan

# Override preset with individual flags
terminus -f urls.txt --scan-level standard --detect-host-injection -o custom_scan

# Combine preset with other flags
terminus -f targets.txt --scan-level vuln --rate-limit 5/s --random-delay 2-4 -o comprehensive_scan
```

**Concurrent Scanning with Threading**:
```bash
# Fast scan with 20 concurrent threads
terminus -f large_url_list.txt -t 20 -o fast_scan

# Balanced scanning with 10 threads (default)
terminus -f urls.txt --scan-level vuln -o balanced_scan

# Conservative scanning with 5 threads for production
terminus -f production_endpoints.txt -t 5 --rate-limit 10/s -o conservative_scan

# Maximum speed scan with 50 threads
terminus -f urls.txt -t 50 --output-format all -o speed_scan

# Thread control with vulnerability detection
terminus -f targets.txt \
  -t 15 \
  --scan-level vuln \
  --rate-limit 20/s \
  --output-format json \
  -o threaded_vuln_scan
```

#### Smart Analysis Examples (v2.5.0)

**Compare two scans to identify changes**:
```bash
# First scan
terminus -f targets.txt --output-format json -o scan1

# Second scan (after changes)
terminus -f targets.txt --output-format json -o scan2

# Compare scans
terminus -f targets.txt --diff scan1.json -o scan2
```

**Search for sensitive patterns in responses**:
```bash
# Find admin panels or config files
terminus -f urls.txt --grep-response "admin|backup|config|\.env"

# Find API keys or tokens
terminus -f api_endpoints.txt --grep-response "[Aa]pi[_-]?[Kk]ey|[Tt]oken|[Ss]ecret"

# Search for specific error messages
terminus -f urls.txt --grep-response "SQL syntax|mysql_fetch|ORA-[0-9]+"
```

**Rate-limited scanning for production environments**:
```bash
# 10 requests per second
terminus -f production_urls.txt --rate-limit 10/s

# 100 requests per minute
terminus -f large_list.txt --rate-limit 100/m

# Combine with random delays for stealth
terminus -f targets.txt --rate-limit 5/s --random-delay 1-3
```

**Analyze response bodies and extract links**:
```bash
# Check response body content
terminus -u https://example.com --check-body -v

# Extract all links from response
terminus -u https://example.com --extract-links

# Combine with grep for specific content
terminus -f urls.txt --check-body --grep-response "password|credential" -o findings
```

**Advanced reconnaissance workflow**:
```bash
# Scan with body analysis and link extraction
terminus -f targets.txt \
  --check-body \
  --extract-links \
  --grep-response "api|v[0-9]|admin" \
  --rate-limit 20/s \
  --output-format all \
  -o recon_results

# Compare with previous scan
terminus -f targets.txt \
  --diff recon_results.json \
  --check-body \
  -o new_scan
```

#### Passive Security Analysis Examples (v2.6.0)

**Analyze security headers**:
```bash
# Check for missing or misconfigured security headers
terminus -f production_urls.txt --check-security-headers -o security_audit

# Combine with JSON output for detailed analysis
terminus -u https://example.com --check-security-headers --output-format json -o headers_check
```

**Detect verbose error messages**:
```bash
# Scan for SQL errors, stack traces, and debug information
terminus -f urls.txt --detect-errors

# Find specific error types with grep
terminus -f api_endpoints.txt --detect-errors --grep-response "SQL|Exception|Traceback"

# Export error findings to CSV for reporting
terminus -f targets.txt --detect-errors --output-format csv -o error_findings
```

**Passive reflection detection (XSS indicators)**:
```bash
# Check for potential XSS vectors without exploitation
terminus -f forms_urls.txt --detect-reflection

# Combine with error detection for comprehensive analysis
terminus -u https://webapp.com/search --detect-reflection --detect-errors -v
```

**Comprehensive security audit workflow**:
```bash
# Full passive security assessment
terminus -f target_list.txt \
  --check-security-headers \
  --detect-errors \
  --detect-reflection \
  --check-body \
  --extract-links \
  --rate-limit 10/s \
  --output-format all \
  -o security_assessment

# Then analyze with AI for insights
python athena.py security_assessment.json \
  --provider ollama \
  --persona security \
  -o security_report.txt
```

**Enterprise security scanning**:
```bash
# Respectful production scanning with all security checks
terminus -f production_endpoints.txt \
  --check-security-headers \
  --detect-errors \
  --detect-reflection \
  --rate-limit 5/s \
  --random-delay 2-5 \
  -k \
  --output-format json \
  -o prod_security_scan

# Compare with baseline
terminus -f production_endpoints.txt \
  --check-security-headers \
  --detect-errors \
  --diff prod_security_scan.json \
  -o latest_scan
```

#### HTTP/2 Desync Detection Examples (v2.7.0)

**Test HTTP/2 to HTTP/1.1 downgrade handling**:
```bash
# Basic HTTP/2 desync check on a single target
terminus -u https://api.example.com --http2-desync-check -k

# Check multiple endpoints for desync vulnerabilities
terminus -f https_endpoints.txt --http2-desync-check --output-format json -o desync_scan
```

**Detect request smuggling vectors**:
```bash
# Test for HTTP/2 downgrade issues with specific HTTP methods
terminus -u https://target.com/api/endpoint \
  -X POST \
  --http2-desync-check \
  -k \
  --output-format json \
  -o smuggling_test

# Test multiple methods for desync vulnerabilities
terminus -u https://api.target.com \
  -X ALL \
  --http2-desync-check \
  --rate-limit 5/s \
  -k \
  -o method_desync_scan
```

**Combine with other security checks**:
```bash
# Comprehensive HTTP/2 security assessment
terminus -f production_apis.txt \
  --http2-desync-check \
  --check-security-headers \
  --detect-errors \
  --check-body \
  --rate-limit 10/s \
  --output-format all \
  -k \
  -o http2_security_audit

# Proxy through Burp Suite for manual analysis
terminus -u https://target.com/vulnerable/endpoint \
  --http2-desync-check \
  -x http://127.0.0.1:8080 \
  -k \
  -v \
  --output-format json \
  -o burp_desync_test
```

**Enterprise CDN/proxy testing**:
```bash
# Test CDN endpoints for HTTP/2 downgrade issues
terminus -f cdn_endpoints.txt \
  --http2-desync-check \
  --rate-limit 5/s \
  --random-delay 2-4 \
  -k \
  --output-format json \
  -o cdn_desync_scan

# Compare desync results over time
terminus -f api_endpoints.txt \
  --http2-desync-check \
  --diff previous_desync_scan.json \
  -k \
  -o latest_desync_scan

# Test with custom headers to bypass WAF/CDN
terminus -u https://target.com/api \
  --http2-desync-check \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "User-Agent: Mozilla/5.0" \
  -k \
  --output-format json \
  -o waf_bypass_desync_test
```

**Automated desync detection workflow**:
```bash
# Full HTTP/2 desync assessment pipeline
echo "target.com" | httpx -silent | \
terminus --http2-desync-check \
  --check-security-headers \
  --detect-errors \
  --rate-limit 10/s \
  -k \
  --output-format json \
  -o desync_findings

# Analyze findings with AI
python athena.py desync_findings.json \
  --provider ollama \
  --persona security \
  -o desync_analysis.txt
```

#### Advanced Passive Vulnerability Detection Examples (v2.8.0)

**Test for Host Header Injection**:
```bash
# Basic Host header injection detection
terminus -u https://example.com --detect-host-injection -k

# Test multiple endpoints for host injection
terminus -f endpoints.txt --detect-host-injection --output-format json -o host_injection_scan

# Combine with verbose output to see response headers
terminus -u https://target.com/api \
  --detect-host-injection \
  -v \
  -k \
  --output-format json \
  -o host_injection_detailed
```

**Detect X-Forwarded-For Bypasses**:
```bash
# Check for XFF bypass on protected endpoints
terminus -u https://admin.example.com --detect-xff-bypass -k

# Test multiple protected paths
terminus -f admin_endpoints.txt \
  --detect-xff-bypass \
  --rate-limit 5/s \
  --output-format json \
  -o xff_bypass_scan

# Test with different HTTP methods
terminus -u https://api.target.com/admin \
  -X ALL \
  --detect-xff-bypass \
  -k \
  --output-format json \
  -o xff_method_scan
```

**Detect CSRF Vulnerabilities**:
```bash
# Test for CSRF on state-changing endpoints
terminus -u https://example.com/api/update -X POST --detect-csrf -k

# Scan multiple POST/PUT/DELETE endpoints
terminus -f state_changing_endpoints.txt \
  -X POST \
  --detect-csrf \
  --output-format json \
  -o csrf_scan

# Comprehensive CSRF testing with all methods
terminus -f api_endpoints.txt \
  -X ALL \
  --detect-csrf \
  --rate-limit 10/s \
  -k \
  --output-format all \
  -o csrf_comprehensive_scan
```

**Detect SSRF Vulnerabilities**:
```bash
# Test endpoints with URL parameters for SSRF
terminus -u "https://example.com/proxy?url=http://internal" --detect-ssrf -k

# Scan endpoints that might be vulnerable to SSRF
terminus -f urls_with_params.txt \
  --detect-ssrf \
  --output-format json \
  -o ssrf_scan

# Test API endpoints for SSRF indicators
terminus -f api_endpoints.txt \
  --detect-ssrf \
  --check-body \
  --rate-limit 5/s \
  -k \
  --output-format json \
  -o ssrf_detailed_scan
```

**Comprehensive Vulnerability Assessment**:
```bash
# Full passive vulnerability scan with all v2.8.0 features
terminus -f target_list.txt \
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

# Then analyze with AI
python athena.py comprehensive_vuln_scan.json \
  --provider ollama \
  --persona security \
  -o vulnerability_analysis.txt
```

**Enterprise Security Testing Workflow**:
```bash
# Stage 1: Reconnaissance with all detection features
terminus -f production_apps.txt \
  --detect-host-injection \
  --detect-xff-bypass \
  --detect-csrf \
  --detect-ssrf \
  --http2-desync-check \
  --check-security-headers \
  --detect-errors \
  --check-body \
  --extract-links \
  --rate-limit 5/s \
  --random-delay 2-4 \
  -k \
  --output-format json \
  -o enterprise_scan_stage1

# Stage 2: Deep analysis of findings
python athena.py enterprise_scan_stage1.json \
  --provider anthropic \
  --persona security \
  -o security_findings.txt

# Stage 3: Compare with previous scan
terminus -f production_apps.txt \
  --detect-host-injection \
  --detect-xff-bypass \
  --detect-csrf \
  --detect-ssrf \
  --diff enterprise_scan_stage1.json \
  -k \
  -o enterprise_scan_stage2
```

**Targeted Testing Examples**:
```bash
# Test only for bypass techniques (XFF and Host Injection)
terminus -f protected_endpoints.txt \
  --detect-host-injection \
  --detect-xff-bypass \
  -k \
  --output-format json \
  -o bypass_techniques_scan

# Test only for injection vulnerabilities (CSRF and SSRF)
terminus -f api_endpoints.txt \
  -X POST \
  --detect-csrf \
  --detect-ssrf \
  --rate-limit 10/s \
  -k \
  --output-format json \
  -o injection_vulns_scan

# Proxy through Burp for manual review
terminus -u https://target.com/vulnerable/endpoint \
  --detect-host-injection \
  --detect-xff-bypass \
  --detect-csrf \
  --detect-ssrf \
  -x http://127.0.0.1:8080 \
  -k \
  -v \
  --output-format json \
  -o burp_manual_review
```

## AI-Powered Analysis

Terminus includes a companion Python script for AI-powered analysis of scan results using multiple AI providers.

### Features
- **Local AI Providers**: Ollama, LM Studio, vLLM
- **Cloud AI Providers**: OpenAI, Anthropic Claude, Google Gemini
- **Multiple Personas**:
  - Security Engineer (default): Focus on vulnerabilities and security hardening
  - Developer: Focus on bugs, code-level fixes, and API design
  - Technical Program Manager: Focus on business impact and project decisions

### Installation
```bash
pip install -r requirements.txt
```

### Usage Examples

**Analyze with Ollama (local)**:
```bash
python athena.py scan_results.json --provider ollama --persona security
```

**Analyze with specific model**:
```bash
python athena.py scan_results.json --provider ollama --model llama3 --persona developer
```

**Analyze with OpenAI**:
```bash
export OPENAI_API_KEY=sk-...
python athena.py scan_results.json --provider openai --persona tpm
```

**Analyze with Anthropic Claude**:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
python athena.py scan_results.json --provider anthropic --persona security
```

**Save analysis to file**:
```bash
python athena.py scan_results.json \
  --provider ollama \
  --persona security \
  --output analysis_report.txt
```

**Custom local AI server**:
```bash
python athena.py scan_results.json \
  --provider lmstudio \
  --base-url http://localhost:1234 \
  --persona developer
```

---

## HTTP Methods Tested

When using the `-X ALL` flag, the following HTTP methods are tested:

```
ACL, BASELINE-CONTROL, BCOPY, BDELETE, BMOVE, BPROPFIND, BPROPPATCH,
CHECKIN, CHECKOUT, CONNECT, COPY, DEBUG, DELETE, GET, HEAD,
INDEX, LABEL, LOCK, MERGE, MKACTIVITY, MKCOL, MKWORKSPACE,
MOVE, NOTIFY, OPTIONS, ORDERPATCH, PATCH, POLL, POST,
PROPFIND, PROPPATCH, PUT, REPORT, RPC_IN_DATA, RPC_OUT_DATA,
SEARCH, SUBSCRIBE, TRACE, UNCHECKOUT, UNLOCK, UNSUBSCRIBE,
UPDATE, VERSION-CONTROL, X-MS-ENUMATTS
```

---

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

---

## License

GPL-3.0 License. For more details, see the [LICENSE](LICENSE) file.