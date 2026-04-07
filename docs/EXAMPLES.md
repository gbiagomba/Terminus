# Terminus — Full Workflow Examples

A comprehensive cookbook for common `terminus` use cases. For a feature overview and quick-start commands, see the main [README](../README.md).

---

## Table of Contents

- [Basic Usage](#basic-usage)
- [Input Format Examples](#input-format-examples)
- [Piping Examples](#piping-examples)
- [Output Format Examples](#output-format-examples)
- [Scan Level Presets](#scan-level-presets)
- [Method Fuzzing](#method-fuzzing)
- [Concurrent Scanning](#concurrent-scanning)
- [Smart Analysis](#smart-analysis)
- [Passive Security Analysis](#passive-security-analysis)
- [HTTP/2 Desync Detection](#http2-desync-detection)
- [Advanced Passive Vulnerability Detection](#advanced-passive-vulnerability-detection)
- [Active Exploit Modules](#active-exploit-modules)
- [Enumeration](#enumeration)
- [Diff](#diff)
- [Interactive SQLite (REPL & TUI)](#interactive-sqlite-repl--tui)
- [AI Analysis](#ai-analysis)
- [Enterprise Workflows](#enterprise-workflows)

---

## Basic Usage

```bash
# Single URL — scans ports 80 and 443 by default
terminus scan -u http://example.com

# IPv4 address
terminus scan -u 192.168.1.1

# IPv6 address
terminus scan -u "2001:db8::1" -6

# Custom ports
terminus scan -u http://example.com -p 8080,8443

# Multiple URLs from file, all HTTP methods
terminus scan -f urls.txt -X ALL

# Specific ports with file input
terminus scan -f urls.txt -p 80,443,8080 -X ALL
```

---

## Input Format Examples

```bash
# nmap XML — ports extracted from scan output automatically
nmap -p80,443,8080 -oX scan.xml target.com
terminus scan -f scan.xml

# nmap greppable output
nmap -p80,443 -oG scan.gnmap target.com
terminus scan -f scan.gnmap

# testssl.sh JSON
testssl --json-pretty target.com > testssl.json
terminus scan -f testssl.json

# ProjectDiscovery (katana/nuclei)
echo "target.com" | katana -json -o katana.json
terminus scan -f katana.json
```

> When using file inputs, Terminus automatically reads ports from the scan output — no `-p` flag needed.

---

## Piping Examples

```bash
# Pipe httpx output directly
cat domains.txt | httpx | terminus

# Pipeline with nuclei CVE templates
cat domains.txt | httpx -silent | nuclei -t cves/ -json | terminus

# Full recon pipeline with JSON output
subfinder -d target.com -silent | httprobe | terminus --output-format json -o results
```

---

## Output Format Examples

```bash
# JSON
terminus scan -u http://example.com --output-format json -o scan_results

# HTML
terminus scan -f urls.txt --output-format html -o scan_results

# CSV
terminus scan -f urls.txt --output-format csv -o scan_results

# SQLite database
terminus scan -f urls.txt --output-format sqlite -o scan_results

# All formats at once (.txt, .json, .html, .csv, .db)
terminus scan -f urls.txt --output-format all -o scan_results
```

### Querying the SQLite database

```bash
# Filter by status code
sqlite3 scan_results.db "SELECT url, status, port FROM scan_results WHERE status >= 400;"

# Find all endpoints with vulnerabilities
sqlite3 scan_results.db "SELECT url, method FROM scan_results WHERE
  http2_desync_detected = 1 OR
  host_injection_suspected = 1 OR
  csrf_suspected = 1 OR
  ssrf_suspected = 1;"

# Export filtered columns to CSV
sqlite3 -header -csv scan_results.db "SELECT url, status, port FROM scan_results;" > filtered.csv

# Interactive query shell (TUI)
terminus interact --db scan_results.db
```

---

## Scan Level Presets

```bash
# quick — basic requests only (fastest)
terminus scan -f urls.txt --scan-level quick

# standard — security headers + error detection + reflection checks
terminus scan -f production_urls.txt --scan-level standard -o standard_scan

# full — all features including body analysis and link extraction
terminus scan -f targets.txt --scan-level full --rate-limit 10/s -o full_scan

# vuln — all passive vulnerability detection
terminus scan -f api_endpoints.txt --scan-level vuln -k -o vuln_scan

# Mix preset with individual flags
terminus scan -f urls.txt --scan-level standard --detect-host-injection -o custom_scan
```

---

## Method Fuzzing

```bash
# Fuzz with built-in arbitrary methods
terminus scan -u https://example.com --fuzz-methods -k

# Add custom arbitrary methods
terminus scan -u https://example.com --fuzz-methods \
  --custom-method BOUNCE --custom-method SPLAT -k

# Load methods from file
terminus scan -u https://example.com --fuzz-methods --custom-methods-file methods.txt -k

# Test all predefined methods
terminus scan -f urls.txt -X ALL -k
```

---

## Concurrent Scanning

```bash
# 20 concurrent tasks — fast scan
terminus scan -f large_url_list.txt -t 20 -o fast_scan

# 5 threads — conservative for production
terminus scan -f production_endpoints.txt -t 5 --rate-limit 10/s -o conservative_scan

# Threaded vuln scan with rate limiting
terminus scan -f targets.txt \
  -t 15 \
  --scan-level vuln \
  --rate-limit 20/s \
  --output-format json \
  -o threaded_vuln_scan
```

---

## Smart Analysis

### Diffing scans

```bash
# Capture baseline
terminus scan -f targets.txt --output-format json -o scan1

# After changes, compare
terminus diff --base scan1.json --compare scan2.json

# Or inline during scan
terminus scan -f targets.txt --diff scan1.json -o scan2
```

### Pattern matching in response bodies

```bash
# Find admin panels, config files
terminus scan -f urls.txt --grep-response "admin|backup|config|\.env"

# Find API key leaks
terminus scan -f api_endpoints.txt --grep-response "[Aa]pi[_-]?[Kk]ey|[Tt]oken|[Ss]ecret"

# Find SQL error strings
terminus scan -f urls.txt --grep-response "SQL syntax|mysql_fetch|ORA-[0-9]+"
```

### Rate limiting

```bash
# 10 requests per second
terminus scan -f production_urls.txt --rate-limit 10/s

# 100 requests per minute
terminus scan -f large_list.txt --rate-limit 100/m

# Add random delays for stealth
terminus scan -f targets.txt --rate-limit 5/s --random-delay 1-3
```

### Body analysis and link extraction

```bash
# Analyze body content
terminus scan -u https://example.com --check-body -v

# Extract all links from responses
terminus scan -u https://example.com --extract-links

# Combine with pattern search
terminus scan -f urls.txt --check-body --grep-response "password|credential" -o findings
```

---

## Passive Security Analysis

```bash
# Missing/misconfigured security headers
terminus scan -f production_urls.txt --check-security-headers -o security_audit

# Verbose error messages (SQL errors, stack traces, debug output)
terminus scan -f urls.txt --detect-errors

# Passive reflection detection (potential XSS indicators)
terminus scan -f forms_urls.txt --detect-reflection

# Combined passive assessment
terminus scan -f target_list.txt \
  --check-security-headers \
  --detect-errors \
  --detect-reflection \
  --check-body \
  --extract-links \
  --rate-limit 10/s \
  --output-format all \
  -o security_assessment
```

---

## HTTP/2 Desync Detection

```bash
# Basic desync check
terminus scan -u https://api.example.com --http2-desync-check -k

# With POST method
terminus scan -u https://target.com/api/endpoint \
  -X POST \
  --http2-desync-check \
  -k \
  --output-format json \
  -o smuggling_test

# All methods
terminus scan -u https://api.target.com \
  -X ALL \
  --http2-desync-check \
  --rate-limit 5/s \
  -k \
  -o method_desync_scan

# Proxy through Burp Suite
terminus scan -u https://target.com/vulnerable/endpoint \
  --http2-desync-check \
  -x http://127.0.0.1:8080 \
  -k -v \
  --output-format json \
  -o burp_desync_test

# CDN endpoint testing
terminus scan -f cdn_endpoints.txt \
  --http2-desync-check \
  --rate-limit 5/s \
  --random-delay 2-4 \
  -k \
  --output-format json \
  -o cdn_desync_scan
```

---

## Advanced Passive Vulnerability Detection

### Host Header Injection

```bash
terminus scan -u https://example.com --detect-host-injection -k

terminus scan -f endpoints.txt --detect-host-injection \
  --output-format json -o host_injection_scan
```

### X-Forwarded-For Bypass

```bash
terminus scan -u https://admin.example.com --detect-xff-bypass -k

terminus scan -f admin_endpoints.txt \
  --detect-xff-bypass \
  --rate-limit 5/s \
  --output-format json \
  -o xff_bypass_scan
```

### CSRF Vulnerabilities

```bash
terminus scan -u https://example.com/api/update -X POST --detect-csrf -k

terminus scan -f state_changing_endpoints.txt \
  -X POST \
  --detect-csrf \
  --output-format json \
  -o csrf_scan
```

### SSRF Vulnerabilities

```bash
terminus scan -u "https://example.com/proxy?url=http://internal" --detect-ssrf -k

terminus scan -f urls_with_params.txt \
  --detect-ssrf \
  --output-format json \
  -o ssrf_scan
```

### Full Passive Vuln Sweep

```bash
terminus scan -f target_list.txt \
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
```

---

## Active Exploit Modules

Run active exploit modules with `--exploit`. Multiple modules can be comma-separated.

```bash
# XSS payload injection (query params)
terminus scan -u https://target.com --exploit xss -k

# SQL injection
terminus scan -u https://target.com --exploit sqli -k

# Open redirect
terminus scan -u https://target.com --exploit open_redirect -k

# Multiple modules at once
terminus scan -u https://target.com --exploit xss,sqli,open_redirect -k

# All injection/CSRF/SSRF modules
terminus scan -u https://target.com --exploit csrf,ssrf,header,smuggling -k

# Custom payloads from file
terminus scan -u https://target.com \
  --exploit xss,sqli \
  --payloads payloads.txt \
  -k \
  --output-format json \
  -o exploit_results
```

---

## Enumeration

```bash
# Subdomain enumeration
terminus enum subdomains -d example.com -w words.txt

# Path enumeration
terminus enum paths -u https://example.com -w common.txt

# With output formats
terminus enum paths -u https://example.com -w wordlist.txt \
  --output-format json -o path_enum

# Disable wildcard suppression
terminus enum subdomains -d example.com -w words.txt --no-wildcard

# Filter by status code
terminus enum paths -u https://example.com -w words.txt -F 200
```

---

## Diff

```bash
# Compare two JSON scans
terminus diff --base scan1.json --compare scan2.json

# Auto-detect SQLite inputs
terminus diff --base scan1.db --compare scan2.db

# Output diff to HTML
terminus diff --base scan1.json --compare scan2.json \
  --output-format html -o diff_report
```

---

## Interactive SQLite (REPL & TUI)

### TUI mode (default)

```bash
terminus interact --db scan_results.db
```

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate rows |
| `Enter` | Inspect full row details |
| `r` | Replay selected request |
| `/` | Enter search mode (filter by URL or method) |
| `:open <id>` | Open scan by ID |
| `:replay <id>` | Replay scan by ID |
| `:filter status <code>` | Filter by HTTP status code |
| `?` | Keyboard help |
| `q` / `Esc` | Quit |

### REPL mode (`--no-tui`)

```bash
terminus interact --db scan_results.db --no-tui

terminus> list urls
terminus> list methods
terminus> find status 403
terminus> find exploit csrf
terminus> show scan 42
terminus> show raw 42
terminus> --more
terminus> exit
```

---

## AI Analysis

### Built-in `ai` subcommand

```bash
# Prioritize findings with OpenAI
terminus ai prioritize --db scan.db --provider openai --model gpt-4o

# Use Ollama (local, no key required)
terminus ai prioritize --db scan.db --provider ollama

# Use Groq
terminus ai prioritize --db scan.db --provider groq --model llama-3.1-8b-instant

# Strict JSON parsing (for programmatic output)
terminus ai prioritize --db scan.db --provider groq \
  --model llama-3.1-8b-instant --strict-json

# List available models
terminus ai prioritize --provider openai --list-models
terminus ai prioritize --provider ollama --list-models
terminus ai prioritize --provider openai --list-models --list-models-format json
terminus ai prioritize --provider openai --list-models --list-models-format csv -o models
```

### Companion Python script (`athena.py`)

The optional `athena.py` script analyzes JSON scan output as a post-processing step.

```bash
pip install -r requirements.txt

# Local Ollama
python athena.py scan_results.json --provider ollama --persona security

# OpenAI
export OPENAI_API_KEY=sk-...
python athena.py scan_results.json --provider openai --persona tpm

# Anthropic Claude
export ANTHROPIC_API_KEY=sk-ant-...
python athena.py scan_results.json --provider anthropic --persona security

# Save to file
python athena.py scan_results.json \
  --provider ollama \
  --persona security \
  --output analysis_report.txt

# Custom local AI server (LM Studio, vLLM)
python athena.py scan_results.json \
  --provider lmstudio \
  --base-url http://localhost:1234 \
  --persona developer
```

---

## Enterprise Workflows

### Full passive assessment + AI triage

```bash
# Stage 1: Comprehensive passive scan
terminus scan -f production_apps.txt \
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

# Stage 2: AI prioritization of findings
terminus ai prioritize --db enterprise_scan_stage1.db \
  --provider anthropic --model claude-opus-4-6

# Stage 3: Compare with previous baseline
terminus diff --base previous_scan.json --compare enterprise_scan_stage1.json \
  --output-format html -o delta_report
```

### Pentest workflow with Burp Suite

```bash
terminus scan -u https://api.example.com -X POST \
  -H "Content-Type: application/json" \
  -b "session=xyz789" \
  -x http://127.0.0.1:8080 \
  -k -v -L \
  --http-version 2 \
  --output-format all \
  -o pentest_results
```

### Bypass technique testing

```bash
# Test bypass techniques
terminus scan -f protected_endpoints.txt \
  --detect-host-injection \
  --detect-xff-bypass \
  -k \
  --output-format json \
  -o bypass_techniques_scan

# Proxy through Burp for manual review
terminus scan -u https://target.com/vulnerable/endpoint \
  --detect-host-injection \
  --detect-xff-bypass \
  --detect-csrf \
  --detect-ssrf \
  -x http://127.0.0.1:8080 \
  -k -v \
  --output-format json \
  -o burp_manual_review
```
