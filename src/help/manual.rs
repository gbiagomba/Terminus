pub fn render(topic: Option<&str>) -> String {
    match topic.unwrap_or("") {
        "scan" => scan_manual(),
        "enum" => enum_manual(),
        "diff" => diff_manual(),
        "interact" => interact_manual(),
        "ai" => ai_manual(),
        _ => overview_manual(),
    }
}

fn overview_manual() -> String {
    r#"TERMINUS MANUAL

SYNOPSIS
  terminus <subcommand> [options]

SUBCOMMANDS
  scan        HTTP scanning and exploit checks
  enum        Subdomain/path enumeration
  diff        Deterministic scan diffing
  interact    SQLite review mode
  help        Manual-style help
  ai          AI decision support

EXAMPLES
  terminus scan -u https://example.com
  terminus enum subdomains -d example.com -w words.txt
  terminus enum paths -u https://example.com -w common.txt
  terminus diff --base old.json --compare new.json
  terminus interact --db scan.db
  terminus ai prioritize --db scan.db --provider openai --model gpt-4o

NOTES
  Use `terminus help <subcommand>` for focused documentation.
"#.to_string()
}

fn scan_manual() -> String {
    r#"SCAN MANUAL

SYNOPSIS
  terminus scan -u <URL> [options]
  terminus scan -f <FILE> [options]

KEY OPTIONS
  -X, --method <METHOD>        HTTP method or ALL
  -p, --port <PORTS>           Comma-separated ports
  -H, --header <HEADER>        Custom header (repeatable)
  -b, --cookie <COOKIE>        Cookie string
  -x, --proxy <PROXY>          Proxy URL
  -k, --insecure               Allow insecure TLS
  -L, --follow                 Follow HTTP, JS, and meta refresh redirects
  --http-version <1.0|1.1|2|3> Force HTTP version
  --output-format <FORMAT>     stdout, txt, json, html, csv, sqlite, all

WORKFLOWS
  - Start with `--scan-level standard` for passive checks.
  - Use `--fuzz-methods` or `-X ALL` to detect method confusion.
  - For HTTP/3, use `--http-version 3` and HTTPS targets only.
"#.to_string()
}

fn enum_manual() -> String {
    r#"ENUM MANUAL

SYNOPSIS
  terminus enum subdomains -d <DOMAIN> -w <WORDLIST>
  terminus enum paths -u <URL> -w <WORDLIST>

SUBDOMAINS OPTIONS
  -d, --domain <DOMAIN>        Base domain
  -w, --wordlist <FILE>        Wordlist
  --scheme <http|https>        Scheme (default: https)
  --no-wildcard                Disable wildcard suppression

PATHS OPTIONS
  -u, --url <URL>              Base URL
  -w, --wordlist <FILE>        Wordlist
  --extensions <ext1,ext2>     Optional extensions
  --recursive                  One-level recursion

OUTPUT
  --output-format stdout|txt|json|html|csv|sqlite|all
  -o, --output <BASE>
"#.to_string()
}

fn diff_manual() -> String {
    r#"DIFF MANUAL

SYNOPSIS
  terminus diff --base <FILE> --compare <FILE> [options]

INPUTS
  JSON-to-JSON
  SQLite-to-SQLite
  JSON-to-SQLite (auto-detected by extension)

OUTPUT
  --output-format stdout|json|csv|html|sqlite
  -o, --output <BASE>

NOTES
  Diffing includes endpoint adds/removals, status changes, vulnerability deltas,
  header/body fingerprint changes, and arbitrary method deltas when available.
"#.to_string()
}

fn interact_manual() -> String {
    r#"INTERACT MANUAL

SYNOPSIS
  terminus interact --db <SQLITE_FILE>

DESCRIPTION
  Interactive SQLite review for scan results. Uses safe, parameterized queries
  with pagination. Intended for read-only analysis and replay workflows.
"#.to_string()
}

fn ai_manual() -> String {
    r#"AI MANUAL

SYNOPSIS
  terminus ai <mode> [options]

DESCRIPTION
  AI decision support over structured evidence. Modes include prioritize,
  cluster, diff, validate, and campaign. AI is evidence-driven; raw data is
  minimized and validated with deterministic extraction and correlation.

EXAMPLE
  terminus ai prioritize --db scan.db --provider openai --model gpt-4o
  terminus ai prioritize --db scan.db --provider groq --model llama-3.1-8b-instant
  terminus ai prioritize --db scan.db --provider ollama --model llama3
  terminus ai prioritize --db scan.db --provider groq --model llama-3.1-8b-instant --strict-json
  terminus ai prioritize --provider openai --list-models
  terminus ai prioritize --provider openai --list-models --list-models-format json
  terminus ai prioritize --provider openai --list-models --list-models-format csv -o models
"#.to_string()
}
