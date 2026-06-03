![alt tag](rsc/Firefly%20Create%20a%20minimalist%20yet%20powerful%20logo%20inspired%20by%20the%20Roman%20god%20Terminus,%20the%20protector%20of%20b%20(2).jpg)

# `terminus`
![GitHub](https://img.shields.io/github/license/Achiefs/fim) [![Tip Me via PayPal](https://img.shields.io/badge/PayPal-tip_me-green?logo=paypal)](paypal.me/gbiagomba)

`terminus` is a command-line HTTP security scanner that tests URL accessibility across methods, detects passive and active vulnerabilities, enumerates subdomains and paths, diffs scan results, and reasons over findings with built-in AI. Built in Rust with async/HTTP/3 transport.

---

## Quick Start

```bash
# Install
cargo install --git https://github.com/gbiagomba/terminus.git

# Scan a single target
terminus scan -u https://example.com

# Full vuln scan with all output formats
terminus scan -f targets.txt --scan-level vuln --output-format all -o results

# AI triage of findings
terminus ai prioritize --db results.db --provider ollama
```

---

## Installation

Requires Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**Option 1 — cargo install from GitHub** (recommended):
```bash
cargo install --git https://github.com/gbiagomba/terminus.git
```

**Option 2 — clone and build**:
```bash
git clone https://github.com/gbiagomba/terminus.git
cd terminus
cargo build --release
cargo install --path .
```

**HTTP/3 note**: reqwest HTTP/3 requires `RUSTFLAGS="--cfg reqwest_unstable"`. This repo sets it in `.cargo/config.toml`. If you build outside the repo, export it manually:
```bash
export RUSTFLAGS="--cfg reqwest_unstable"
```

### Makefile targets

| Target | Description |
|--------|-------------|
| `make build` | Compile the project |
| `make run` | Run with default settings |
| `make run-url` | Run against a specific URL, all methods |
| `make run-file` | Run against a file of URLs, all methods |
| `make install` | Install globally |
| `make uninstall` | Remove global install |
| `make clean` | Remove build artifacts |

---

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `scan` | Primary HTTP scanning engine |
| `enum` | Subdomain and path enumeration |
| `diff` | Compare two scan outputs |
| `interact` | Interactive SQLite review (TUI + REPL) |
| `ai` | AI decision-support over SQLite evidence |
| `help` | Manual-style help (`terminus help scan`, etc.) |

---

## Features

### Input & Output

**Input sources**:
- `-u <URL>` — single URL or IP (IPv4/IPv6 with `-6`)
- `-f <FILE>` — plain text, nmap XML/greppable, testssl.sh JSON, nuclei/katana JSON
- stdin pipe — `cat domains.txt | httpx | terminus`

**Output formats** (`--output-format`):
- `stdout`, `txt`, `json`, `html`, `csv`, `sqlite` / `db`, `all`
- Use `-o <base>` to set the output file name (extension added automatically)

**HTML reports**: vulnerability summary dashboard, JS-powered filtering by type, visual badges per finding.

**SQLite**: 50+ column denormalized schema, automatic indexes, schema versioning, queryable with standard SQL or via `terminus interact`.

---

### Scanning

- **HTTP methods**: `-X <METHOD>` or `-X ALL` to test all predefined methods
- **Ports**: `-p 80,443,8080` (defaults to 80 + 443; file inputs use embedded ports automatically)
- **Protocol version**: `--http-version 1.0|1.1|2|3`
- **Concurrency**: `-t <N>` async tasks (default: 10)
- **Proxy**: `-x http://127.0.0.1:8080` (Burp Suite, etc.)
- **TLS**: `-k` to allow insecure connections
- **Headers**: `-H "Name: Value"` (repeatable) or `--header-file`
- **Cookies**: `-b "name=val"` or `-c/--cookie-file`
- **Redirects**: `-L` follows HTTP `Location` and JavaScript-triggered redirects (`window.location`, `location.href`, `location.assign()`, `location.replace()`, meta refresh)
- **Rate limiting**: `--rate-limit 10/s` or `100/m`; `--random-delay 1-5` for random gaps
- **Verbose**: `-v` shows full response headers

**Scan level presets** (`--scan-level`):

| Level | What it enables |
|-------|----------------|
| `quick` | Basic HTTP requests only (fastest) |
| `standard` | Security headers + error detection + reflection |
| `full` | All features including body analysis and link extraction |
| `vuln` | All passive vulnerability detection |

---

### Passive Analysis

- **Security headers**: detect missing/misconfigured CSP, HSTS, X-Frame-Options, etc. (`--check-security-headers`)
- **Error messages**: SQL errors, stack traces, path disclosure (`--detect-errors`)
- **Reflection**: passive input-reflection / XSS indicator detection (`--detect-reflection`)
- **Body analysis**: `--check-body`, `--extract-links`, `--grep-response <regex>`

---

### Active Exploits

Use `--exploit <module[,module]>` to run active exploit modules. Combine with `--payloads <file>` for custom payload lists (falls back to built-in payloads when omitted).

| Module | What it tests |
|--------|--------------|
| `xss` | Injects payloads into query params, checks for reflection |
| `sqli` | Injects payloads, looks for DB error strings |
| `open_redirect` | Injects redirect payloads, inspects `Location` header |
| `csrf` | Active CSRF protection checks |
| `ssrf` | SSRF indicator detection via URL parameters |
| `header` | Header injection payloads |
| `smuggling` | HTTP request smuggling probes |

```bash
terminus scan -u https://target.com --exploit xss,sqli,open_redirect -k
terminus scan -u https://target.com --exploit xss --payloads payloads.txt -k
```

---

### Enumeration

```bash
terminus enum subdomains -d example.com -w words.txt
terminus enum paths -u https://example.com -w common.txt
```

- Wildcard suppression on by default (`--no-wildcard` to disable)
- Filters: `-F <status>` (status code), content-length
- Output formats: stdout, txt, json, html, csv, sqlite, all

---

### Diff

Compare two scans (JSON or SQLite, auto-detected):

```bash
terminus diff --base scan1.json --compare scan2.json --output-format html -o delta
```

Detects: new/removed endpoints, status changes, indicator deltas, header/body fingerprint changes, method-acceptance deltas.

---

### Interact

Launch the TUI (default) or REPL against a SQLite scan database:

```bash
terminus interact --db results.db          # TUI
terminus interact --db results.db --no-tui # REPL
```

**TUI keybindings**:

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate rows |
| `Enter` | Inspect full row details |
| `r` | Replay selected request |
| `/` | Search (filter by URL or method) |
| `:open <id>` | Open scan by ID |
| `:replay <id>` | Replay scan by ID |
| `:filter status <code>` | Filter by HTTP status code |
| `?` | Keyboard help |
| `q` / `Esc` | Quit |

**REPL commands**: `list urls`, `list methods`, `find status <CODE>`, `find exploit <TYPE>`, `show scan <ID>`, `show raw <ID>`, `--more` (pagination), `exit`.

---

### AI Analysis

Built-in Rust AI pipeline (`terminus ai`) reasons over SQLite evidence using any of seven LLM providers:

| Provider | Notes |
|----------|-------|
| `openai` | Requires `OPENAI_API_KEY` |
| `openai-compatible` | Custom base URL via `OPENAI_BASE_URL` |
| `anthropic` | Requires `ANTHROPIC_API_KEY` |
| `gemini` | Requires `GEMINI_API_KEY` |
| `cohere` | Requires `COHERE_API_KEY` |
| `groq` | `https://api.groq.com/openai/v1`, requires `GROQ_API_KEY` |
| `ollama` | `http://localhost:11434/v1`, no key required |

```bash
terminus ai prioritize --db scan.db --provider openai --model gpt-4o
terminus ai prioritize --provider ollama --list-models
terminus ai prioritize --db scan.db --provider groq --model llama-3.1-8b-instant --strict-json
```

**Optional companion**: `athena.py` is a standalone Python script for post-processing JSON scan output (see [docs/EXAMPLES.md](docs/EXAMPLES.md#ai-analysis) for usage).

---

## Examples

Full cookbook in **[docs/EXAMPLES.md](docs/EXAMPLES.md)**. Quick references:

```bash
# Scan with proxy through Burp Suite
terminus scan -u https://example.com -x http://127.0.0.1:8080 -k -v

# Passive vulnerability sweep
terminus scan -f targets.txt \
  --detect-host-injection --detect-xff-bypass \
  --detect-csrf --detect-ssrf --http2-desync-check \
  --rate-limit 10/s -k --output-format all -o vuln_sweep

# Active exploit scan with custom payloads
terminus scan -u https://target.com --exploit xss,sqli --payloads payloads.txt -k

# Subdomains + paths enumeration
terminus enum subdomains -d target.com -w subdomains.txt
terminus enum paths -u https://target.com -w common.txt

# Compare two scans
terminus diff --base scan1.json --compare scan2.json

# AI triage
terminus ai prioritize --db results.db --provider ollama

# Pipe from subfinder → httpx → terminus
subfinder -d target.com -silent | httprobe | terminus --output-format json -o results
```

---

## HTTP Methods Tested

When using `-X ALL`, the following methods are tested:

```
ACL, BASELINE-CONTROL, BCOPY, BDELETE, BMOVE, BPROPFIND, BPROPPATCH,
CHECKIN, CHECKOUT, CONNECT, COPY, DEBUG, DELETE, GET, HEAD,
INDEX, LABEL, LOCK, MERGE, MKACTIVITY, MKCOL, MKWORKSPACE,
MOVE, NOTIFY, OPTIONS, ORDERPATCH, PATCH, POLL, POST,
PROPFIND, PROPPATCH, PUT, REPORT, RPC_IN_DATA, RPC_OUT_DATA,
SEARCH, SUBSCRIBE, TRACE, UNCHECKOUT, UNLOCK, UNSUBSCRIBE,
UPDATE, VERSION-CONTROL, X-MS-ENUMATTS
```

When using `--fuzz-methods`, arbitrary methods are also tested (e.g., `BILBAO`, `FOOBAR`, `CATS`, `TERMINUS`, `PUZZLE`, `HELLO`). Extend with `--custom-method` or `--custom-methods-file`.

Indicators:
- `[Arbitrary Method Accepted]` — non-standard method returned 2xx/3xx
- `[Method Confusion Suspected]` — response status differs from baseline GET

---

## Contributing

Contributions welcome — open a PR or file an issue.

---

## License

GPL-3.0. See [LICENSE](LICENSE).
