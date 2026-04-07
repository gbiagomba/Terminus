use clap::{Arg, ArgAction, Command};

pub fn build_cli() -> Command {
    Command::new("Terminus")
        .disable_version_flag(true)
        .disable_help_subcommand(true)
        .about("URL testing with HTTP/2 desync detection, security analysis, passive vulnerability detection, and concurrent scanning")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(scan_subcommand())
        .subcommand(diff_subcommand())
        .subcommand(interact_subcommand())
        .subcommand(help_subcommand())
        .subcommand(enum_subcommand())
        .subcommand(ai_subcommand())
}

fn scan_subcommand() -> Command {
    Command::new("scan")
        .about("Primary HTTP scanning engine with optional exploit checks")
        .arg(Arg::new("url").short('u').long("url").value_name("URL").help("Specify a single URL/IP to check"))
        .arg(Arg::new("file").short('f').long("file").value_name("FILE").help("Input file (URLs, nmap XML/greppable, testssl JSON, nuclei/katana JSON)"))
        .arg(Arg::new("method").short('X').long("method").value_name("METHOD").help("Specify the HTTP method to use (default: GET). Use ALL to test all methods"))
        .arg(Arg::new("fuzz-methods").long("fuzz-methods").help("Enable arbitrary HTTP method fuzzing").action(ArgAction::SetTrue))
        .arg(Arg::new("custom-method").long("custom-method").value_name("METHOD").action(ArgAction::Append).help("Add one or more arbitrary HTTP methods for fuzzing (can be specified multiple times)"))
        .arg(Arg::new("custom-methods-file").long("custom-methods-file").value_name("FILE").help("Load arbitrary HTTP methods from a file (one per line)"))
        .arg(Arg::new("port").short('p').long("port").value_name("PORTS").help("Comma-separated ports to connect to (e.g., 80,443)").use_value_delimiter(true))
        .arg(Arg::new("ipv6").short('6').long("ipv6").help("Enable IPv6 scanning").action(ArgAction::SetTrue))
        .arg(Arg::new("insecure").short('k').long("insecure").help("Allow insecure SSL connections").action(ArgAction::SetTrue))
        .arg(Arg::new("verbose").short('v').long("verbose").help("Enable verbose output with response headers").action(ArgAction::SetTrue))
        .arg(Arg::new("follow").short('L').long("follow").help("Follow HTTP redirects, including common JavaScript-triggered redirects").action(ArgAction::SetTrue))
        .arg(Arg::new("output").short('o').long("output").value_name("FILE").help("Output file base name (extension added based on format)"))
        .arg(Arg::new("output-format").long("output-format").value_name("FORMAT").help("Output format: stdout, txt, json, html, csv, sqlite/db, all (default: stdout)"))
        .arg(Arg::new("filter").short('F').long("filter-code").value_name("STATUS_CODE").help("Filter results by HTTP status code"))
        .arg(Arg::new("proxy").short('x').long("proxy").value_name("PROXY").help("Specify proxy URL (e.g., http://127.0.0.1:8080 for Burp)"))
        .arg(Arg::new("header").short('H').long("header").value_name("HEADER").action(ArgAction::Append).help("Add custom header (format: 'Name: Value'). Can be specified multiple times"))
        .arg(Arg::new("header-file").long("header-file").value_name("FILE").help("Read headers from file (one per line, format: 'Name: Value')"))
        .arg(Arg::new("cookie").short('b').long("cookie").value_name("COOKIE").help("Add cookie string (format: 'name1=value1; name2=value2')"))
        .arg(Arg::new("cookie-file").short('c').long("cookie-file").value_name("FILE").help("Read cookies from file"))
        .arg(Arg::new("http-version").long("http-version").value_name("VERSION").help("Force HTTP version (1.0, 1.1, 2, or 3)"))
        .arg(Arg::new("diff").long("diff").value_name("FILE").help("Compare results with previous scan (JSON file)"))
        .arg(Arg::new("grep-response").long("grep-response").value_name("PATTERN").help("Search for pattern in response body (regex supported)"))
        .arg(Arg::new("rate-limit").long("rate-limit").value_name("RATE").help("Rate limit requests (e.g., '10/s', '100/m')"))
        .arg(Arg::new("random-delay").long("random-delay").value_name("RANGE").help("Random delay between requests in seconds (e.g., '1-5')"))
        .arg(Arg::new("check-body").long("check-body").help("Analyze response body content").action(ArgAction::SetTrue))
        .arg(Arg::new("extract-links").long("extract-links").help("Extract and display links from response body").action(ArgAction::SetTrue))
        .arg(Arg::new("check-security-headers").long("check-security-headers").help("Analyze security headers (CSP, HSTS, X-Frame-Options, etc.)").action(ArgAction::SetTrue))
        .arg(Arg::new("detect-errors").long("detect-errors").help("Detect verbose error messages (SQL, stack traces, etc.)").action(ArgAction::SetTrue))
        .arg(Arg::new("detect-reflection").long("detect-reflection").help("Check if input is reflected in response (passive XSS detection)").action(ArgAction::SetTrue))
        .arg(Arg::new("http2-desync-check").long("http2-desync-check").help("Test HTTP/2 to HTTP/1.1 downgrade handling (detects potential request smuggling)").action(ArgAction::SetTrue))
        .arg(Arg::new("detect-host-injection").long("detect-host-injection").help("Passively detect Host header injection vulnerabilities by checking response headers").action(ArgAction::SetTrue))
        .arg(Arg::new("detect-xff-bypass").long("detect-xff-bypass").help("Detect X-Forwarded-For bypass by comparing baseline and XFF requests").action(ArgAction::SetTrue))
        .arg(Arg::new("detect-csrf").long("detect-csrf").help("Passively detect potential CSRF vulnerabilities and missing protections").action(ArgAction::SetTrue))
        .arg(Arg::new("detect-ssrf").long("detect-ssrf").help("Passively detect potential SSRF vulnerabilities in URL parameters").action(ArgAction::SetTrue))
        .arg(Arg::new("scan-level").long("scan-level").value_name("LEVEL").help("Scan preset level: quick (basic), standard (security headers+errors+reflection), full (all features), vuln (all vulnerability detection)"))
        .arg(Arg::new("threads").short('t').long("threads").value_name("NUM").default_value("10").help("Number of concurrent threads for scanning"))
        .arg(Arg::new("exploit").long("exploit").value_name("MODULES").help("Comma-separated exploit modules to run: header,csrf,ssrf,open_redirect,smuggling,xss,sqli"))
        .arg(Arg::new("payloads").long("payloads").value_name("FILE").help("Path to file with custom payloads (one per line)"))
}

fn diff_subcommand() -> Command {
    Command::new("diff")
        .about("Compare two scan outputs (JSON)")
        .arg(Arg::new("base").long("base").value_name("FILE").required(true).help("Base scan JSON file"))
        .arg(Arg::new("compare").long("compare").value_name("FILE").required(true).help("Comparison scan JSON file"))
        .arg(Arg::new("output").short('o').long("output").value_name("FILE").help("Output file base name"))
        .arg(Arg::new("output-format").long("output-format").value_name("FORMAT").help("Output format: stdout, json, html, csv, sqlite"))
}

fn interact_subcommand() -> Command {
    Command::new("interact")
        .about("Interactive SQLite review mode")
        .arg(Arg::new("db").long("db").value_name("SQLITE_FILE").required(true).help("Terminus SQLite database file"))
        .arg(Arg::new("no-tui").long("no-tui").help("Disable TUI and use classic REPL mode").action(ArgAction::SetTrue))
}

fn help_subcommand() -> Command {
    Command::new("help")
        .about("Manual-style help (overview)")
        .arg(Arg::new("topic").value_name("SUBCOMMAND").help("Help topic (scan, enum, diff, interact, ai)"))
}

fn enum_subcommand() -> Command {
    Command::new("enum")
        .about("Enumeration subcommands (subdomains/paths)")
        .subcommand(enum_subdomains())
        .subcommand(enum_paths())
}

fn ai_subcommand() -> Command {
    Command::new("ai")
        .about("AI decision-support commands")
        .subcommand(ai_mode("prioritize"))
        .subcommand(ai_mode("cluster"))
        .subcommand(ai_mode("diff"))
        .subcommand(ai_mode("validate"))
        .subcommand(ai_mode("campaign"))
}

fn ai_mode(name: &'static str) -> Command {
    Command::new(name)
        .about("AI mode")
        .arg(Arg::new("db").long("db").value_name("SQLITE_FILE").required_unless_present("list-models").help("Terminus SQLite database file"))
        .arg(Arg::new("provider").long("provider").value_name("PROVIDER").help("openai, openai-compatible, anthropic, gemini, cohere, groq, ollama"))
        .arg(Arg::new("model").long("model").value_name("MODEL").help("LLM model name"))
        .arg(Arg::new("base-url").long("base-url").value_name("URL").help("Override provider base URL (OpenAI compatible)"))
        .arg(Arg::new("max-findings").long("max-findings").value_name("NUM").help("Maximum findings to return"))
        .arg(Arg::new("confidence-threshold").long("confidence-threshold").value_name("NUM").help("Minimum confidence threshold"))
        .arg(Arg::new("include-raw").long("include-raw").action(ArgAction::SetTrue).help("Include raw snippets in reasoning task"))
        .arg(Arg::new("strict-json").long("strict-json").action(ArgAction::SetTrue).help("Reject partial AI output that does not match the ReasoningResult schema"))
        .arg(Arg::new("list-models").long("list-models").action(ArgAction::SetTrue).help("List available models for the selected provider and exit"))
        .arg(Arg::new("list-models-format").long("list-models-format").value_name("FORMAT").help("List models output format: stdout, json, csv (default: stdout)"))
        .arg(Arg::new("output").short('o').long("output").value_name("FILE").help("Output file base name (used with --list-models-format json/csv)"))
}

fn enum_subdomains() -> Command {
    Command::new("subdomains")
        .about("Subdomain enumeration")
        .arg(Arg::new("domain").short('d').long("domain").value_name("DOMAIN").required(true).help("Base domain"))
        .arg(Arg::new("wordlist").short('w').long("wordlist").value_name("FILE").required(true).help("Wordlist file"))
        .arg(Arg::new("scheme").long("scheme").value_name("SCHEME").help("http or https (default: https)"))
        .arg(Arg::new("no-wildcard").long("no-wildcard").action(ArgAction::SetTrue).help("Disable wildcard suppression"))
        .arg(Arg::new("threads").short('t').long("threads").value_name("NUM").default_value("20").help("Concurrency level"))
        .arg(Arg::new("filter-status").long("filter-status").value_name("CODES").help("Comma-separated status filter (e.g., 200,301)"))
        .arg(Arg::new("filter-length-min").long("filter-length-min").value_name("NUM").help("Minimum response length"))
        .arg(Arg::new("filter-length-max").long("filter-length-max").value_name("NUM").help("Maximum response length"))
        .arg(Arg::new("output").short('o').long("output").value_name("FILE").help("Output file base name"))
        .arg(Arg::new("output-format").long("output-format").value_name("FORMAT").help("Output format: stdout, txt, json, html, csv, sqlite, all"))
        .arg(Arg::new("proxy").short('x').long("proxy").value_name("PROXY").help("Proxy URL"))
        .arg(Arg::new("insecure").short('k').long("insecure").help("Allow insecure SSL connections").action(ArgAction::SetTrue))
}

fn enum_paths() -> Command {
    Command::new("paths")
        .about("Path enumeration")
        .arg(Arg::new("url").short('u').long("url").value_name("URL").required(true).help("Base URL"))
        .arg(Arg::new("wordlist").short('w').long("wordlist").value_name("FILE").required(true).help("Wordlist file"))
        .arg(Arg::new("extensions").long("extensions").value_name("LIST").help("Comma-separated extensions (e.g., php,asp)"))
        .arg(Arg::new("recursive").long("recursive").action(ArgAction::SetTrue).help("Enable one-level recursion"))
        .arg(Arg::new("no-wildcard").long("no-wildcard").action(ArgAction::SetTrue).help("Disable wildcard suppression"))
        .arg(Arg::new("threads").short('t').long("threads").value_name("NUM").default_value("20").help("Concurrency level"))
        .arg(Arg::new("filter-status").long("filter-status").value_name("CODES").help("Comma-separated status filter (e.g., 200,301)"))
        .arg(Arg::new("filter-length-min").long("filter-length-min").value_name("NUM").help("Minimum response length"))
        .arg(Arg::new("filter-length-max").long("filter-length-max").value_name("NUM").help("Maximum response length"))
        .arg(Arg::new("output").short('o').long("output").value_name("FILE").help("Output file base name"))
        .arg(Arg::new("output-format").long("output-format").value_name("FORMAT").help("Output format: stdout, txt, json, html, csv, sqlite, all"))
        .arg(Arg::new("proxy").short('x').long("proxy").value_name("PROXY").help("Proxy URL"))
        .arg(Arg::new("insecure").short('k').long("insecure").help("Allow insecure SSL connections").action(ArgAction::SetTrue))
}
