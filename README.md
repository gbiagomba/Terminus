![alt tag](rsc/Firefly%20Create%20a%20minimalist%20yet%20powerful%20logo%20inspired%20by%20the%20Roman%20god%20Terminus,%20the%20protector%20of%20b%20(2).jpg)

# `terminus`
![GitHub](https://img.shields.io/github/license/Achiefs/fim) [![Tip Me via PayPal](https://img.shields.io/badge/PayPal-tip_me-green?logo=paypal)](paypal.me/gbiagomba)

`terminus` is a command-line tool designed to test the accessibility of URLs without authentication, using various HTTP methods. It's particularly useful for identifying unprotected paths to web servers that require authentication, helping to expose potential security vulnerabilities. The tool supports individual URLs or lists from files, custom HTTP methods, multiple ports, and concurrent execution.

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
- **CSV Export**: Generate CSV files for easy data analysis and import into spreadsheets

### HTTP Testing
- **HTTP Methods**: Use any HTTP method with `-X` flag or `ALL` to test all predefined methods
- **Multiple Ports**: Specify comma-separated ports like `80,443` with `-p` flag
- **HTTP Version Control**: Force HTTP/1.0, 1.1, or 2.0 using `--http-version`
- **Status Code Filtering**: Filter responses by status code using `-F`

### Advanced Features
- **Proxy Support**: Route traffic through proxy tools like Burp Suite using `-x` flag
- **Custom Headers**: Add headers via `-H` flag (multiple allowed) or `--header-file`
- **Cookie Support**: Include cookies with `-b` flag or from file using `-c/--cookie-file`
- **TLS/SSL Options**: Allow insecure connections with `-k` flag
- **Redirect Handling**: Follow redirects with `-L` flag
- **Verbose Output**: View detailed response headers with `-v` flag

### Smart Analysis Features (v2.5.0)
- **Smart Diffing**: Compare two scans and identify new/removed endpoints and status changes
- **Pattern Matching**: Search for specific patterns in response bodies using regex
- **Rate Limiting**: Control request rate for respectful scanning (e.g., `10/s`, `100/m`)
- **Random Delays**: Add random delays between requests to avoid detection
- **Body Analysis**: Analyze response body content with `--check-body`
- **Link Extraction**: Automatically extract URLs from response bodies with `--extract-links`

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
  -h, --help                       Print help
  -V, --version                    Print version

```

### Examples

#### Basic Usage

**Test a single URL**:
```bash
terminus -u http://example.com
```

**Test an IPv4 address**:
```bash
terminus -u 192.168.1.1
```

**Test an IPv6 address**:
```bash
terminus -u "2001:db8::1" -6
```

**Test multiple URLs from a file**:
```bash
terminus -f urls.txt -p 80,443 -X ALL
```

#### Input Format Examples

**Parse nmap XML output**:
```bash
nmap -p80,443 -oX scan.xml target.com
terminus -f scan.xml
```

**Parse nmap greppable output**:
```bash
nmap -p80,443 -oG scan.gnmap target.com
terminus -f scan.gnmap
```

**Parse testssl.sh JSON output**:
```bash
testssl --json-pretty target.com > testssl.json
terminus -f testssl.json
```

**Parse ProjectDiscovery tool output**:
```bash
echo "target.com" | katana -json -o katana.json
terminus -f katana.json
```

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
python terminus_ai_analyzer.py scan_results.json --provider ollama --persona security
```

**Analyze with specific model**:
```bash
python terminus_ai_analyzer.py scan_results.json --provider ollama --model llama3 --persona developer
```

**Analyze with OpenAI**:
```bash
export OPENAI_API_KEY=sk-...
python terminus_ai_analyzer.py scan_results.json --provider openai --persona tpm
```

**Analyze with Anthropic Claude**:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
python terminus_ai_analyzer.py scan_results.json --provider anthropic --persona security
```

**Save analysis to file**:
```bash
python terminus_ai_analyzer.py scan_results.json \
  --provider ollama \
  --persona security \
  --output analysis_report.txt
```

**Custom local AI server**:
```bash
python terminus_ai_analyzer.py scan_results.json \
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