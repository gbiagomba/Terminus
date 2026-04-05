You are extending an existing Rust CLI security tool called `Terminus`.

Terminus is evolving into a structured HTTP reconnaissance, exploit validation, persistence, and AI-assisted decision-support platform.

The tool already supports or is planned to support:
- URL input via `-u`
- file/stdin input via `-f`
- multiple output formats including stdout, txt, json, html, csv, sqlite
- multiple HTTP methods and ports
- arbitrary HTTP method fuzzing
- proxy support
- custom headers and cookies
- insecure TLS via `-k`
- redirect following via `-L`
- response grep / regex matching
- body analysis
- link extraction
- scan diffing
- exploit modules such as header, csrf, ssrf, open-redirect, smuggling, xss, sqli
- SQLite persistence
- interactive SQLite/TUI review
- AI reasoning and prioritization

Your task is to redesign and extend Terminus into a modular subcommand-driven architecture.

============================================================
TOP-LEVEL GOAL
============================================================

Refactor Terminus so that it is organized around these subcommands:

- scan
- enum
- diff
- help
- interact
- ai

IMPORTANT:
- Do NOT create a separate `vuln` subcommand.
- All vulnerability/exploit scanning logic must live under `scan`.
- The `scan` subcommand is the primary operational engine and should support both normal HTTP scanning and optional exploit modules.

============================================================
SUBCOMMANDS
============================================================

1. `scan`
--------------------------------
This is the main request engine and must absorb all existing scanning and exploit functionality.

It must support:
- URL / file / stdin input
- multiple methods and ports
- arbitrary method fuzzing
- custom headers / cookies
- proxy support
- insecure TLS
- redirect following
- HTTP version control
- output formats (stdout, txt, json, html, csv, sqlite)
- body analysis
- regex response grep
- link extraction
- rate limiting / random delays
- scan-level presets
- JavaScript redirect following if already planned
  - include meta refresh and common timer-based redirects (e.g., `setTimeout(...)`)
  - include bracketed `location["href"]` assignments
- exploit modules

Exploit modules under `scan`:
- header
- csrf
- ssrf
- open-redirect
- smuggling
- xss
- sqli

Example usage:
- `terminus scan -u https://example.com`
- `terminus scan -f targets.txt -X ALL -p 80,443`
- `terminus scan -f urls.txt --exploit header,csrf,ssrf`
- `terminus scan -u https://api.example.com --exploit xss,sqli --payloads payloads.txt`

Required `scan` implementation details:
- Existing scanning logic moves here
- Existing exploit logic also moves here
- Exploit execution must be opt-in via flags
- Support canned payloads and user-supplied payloads
- Allow payload injection across:
  - standard request fields
  - common non-standard request fields
  - verb override headers
  - forwarding headers
  - other applicable request fields

Suggested files:
- `src/scan/mod.rs`
- `src/scan/engine.rs`
- `src/scan/input.rs`
- `src/scan/output.rs`
- `src/scan/http.rs`
- `src/scan/results.rs`
- `src/scan/exploits/mod.rs`
- `src/scan/exploits/header.rs`
- `src/scan/exploits/csrf.rs`
- `src/scan/exploits/ssrf.rs`
- `src/scan/exploits/open_redirect.rs`
- `src/scan/exploits/smuggling.rs`
- `src/scan/exploits/xss.rs`
- `src/scan/exploits/sqli.rs`
- `src/scan/exploits/payloads.rs`

2. `enum`
--------------------------------
Add a Gobuster-like enumeration subcommand in Rust.

Purpose:
- subdomain enumeration
- URL path / directory enumeration

Submodes:
- `terminus enum subdomains`
- `terminus enum paths`

Examples:
- `terminus enum subdomains -d example.com -w subdomains.txt`
- `terminus enum paths -u https://example.com -w raft-small-words.txt`

Requirements:
- wordlist-driven
- file/stdin targets
- support extensions
- support recursion toggle
- wildcard detection / suppression
- filter by status / content length
- configurable concurrency/threads
- output to stdout/json/csv/sqlite

Guardrails:
- do NOT build a full crawler
- do NOT turn this into ffuf + gobuster + feroxbuster simultaneously
- keep it focused and practical

Suggested files:
- `src/enum/mod.rs`
- `src/enum/subdomains.rs`
- `src/enum/paths.rs`
- `src/enum/wordlist.rs`

3. `diff`
--------------------------------
Add a pure-Rust diff subcommand.

IMPORTANT:
This is not the AI diff.
This is deterministic Rust-based comparison logic.

Purpose:
Compare two scan outputs and identify:
- new endpoints
- removed endpoints
- status changes
- method behavior changes
- exploit finding changes
- body / header fingerprint changes
- newly reachable unauthenticated paths
- arbitrary method deltas
- enumeration result changes if applicable

Supported comparisons:
- JSON-to-JSON
- SQLite-to-SQLite
- JSON-to-SQLite if feasible

Output:
- stdout
- json
- csv
- html
- sqlite if useful

Suggested files:
- `src/diff/mod.rs`
- `src/diff/json.rs`
- `src/diff/sqlite.rs`
- `src/diff/render.rs`

4. `help`
--------------------------------
Add a manual-style subcommand similar to Unix/Linux `man`.

Purpose:
Provide richer documentation than Clap help.

Examples:
- `terminus help`
- `terminus help scan`
- `terminus help enum`
- `terminus help diff`
- `terminus help interact`
- `terminus help ai`

Content should include:
- synopsis
- use cases
- workflow guidance
- flag explanations
- examples
- caveats
- false-positive notes
- output format explanations
- SQLite/interact explanation
- AI explanation

Suggested files:
- `src/help/mod.rs`
- `src/help/manual.rs`

5. `interact`
--------------------------------
Move the interactive SQLite functionality into this subcommand.

Purpose:
Provide a terminal UI / session-based workflow where the user can:
- see requests/results in a table
- search / filter / sort
- inspect requests and responses
- replay a selected request to the target
- compare baseline and variant requests
- add operator feedback / tagging

Requirements:
- SQLite-backed
- read-only by default
- optional replay mode
- table view
- pagination
- keyboard navigation if practical
- safe parameterized queries only
- avoid arbitrary SQL execution

Potential UI stack:
- ratatui/tui-rs + crossterm
or another mature terminal UI crate

Potential internal commands:
- `/search text`
- `:open 42`
- `:replay 42`
- `:filter status 200`
- `:filter exploit xss`
- `:tag 42 confirmed`
- `:quit`

Suggested files:
- `src/interact/mod.rs`
- `src/interact/app.rs`
- `src/interact/ui.rs`
- `src/interact/db.rs`
- `src/interact/replay.rs`

6. `ai`
--------------------------------
This subcommand is the AI reasoning / decision-support system.

IMPORTANT:
This is NOT an AI summary feature.
Do NOT build a generic chatbot.
Do NOT just dump scan logs into an LLM and ask for prose.

The AI layer must be evidence-driven and help answer:
- What matters most?
- Which findings are likely real?
- Which findings are likely noise?
- What should the operator validate next?
- What is the minimum next request to reduce uncertainty?

Use a 3-stage pipeline:
1. Deterministic extraction
2. Rule-based correlation
3. AI reasoning

AI modes:
- prioritize
- cluster
- diff
- validate
- campaign

Examples:
- `terminus ai prioritize --db scan.db --provider ollama --model qwen2.5-coder`
- `terminus ai diff --db old.db --compare new.db --provider openai --model gpt-4.1`
- `terminus ai validate --db scan.db --finding 42 --provider openai-compatible --base-url http://localhost:1234`
- `terminus ai prioritize --provider openai --list-models`
- `terminus ai prioritize --db scan.db --provider groq --model llama-3.1-8b-instant --strict-json`

============================================================
AI IMPLEMENTATION REQUIREMENTS
============================================================

Use the `rig` crate as the AI integration layer.

The tool must support both:
- local LLM providers
- cloud LLM providers

Examples of local support:
- Ollama
- LM Studio / OpenAI-compatible local server
- vLLM / OpenAI-compatible endpoint

Examples of cloud support:
- OpenAI
- Anthropic
- Gemini
- Cohere
(Groq via OpenAI-compatible endpoint)
(if Rig supports them cleanly in current version)

Design the AI layer so Rig is used behind an abstraction.

Define a trait like:
```rust
pub trait ReasoningEngine {
    fn run(&self, task: ReasoningTask) -> Result<ReasoningResult>;
}
```

Implement:
		RigReasoningEngine
		provider-specific wrappers/configs as needed

Do NOT tightly couple Terminus to Rig-specific types across the whole codebase.
Keep Rig isolated in the AI module.

Suggested AI files:
		src/ai/mod.rs
		src/ai/types.rs
		src/ai/provider.rs
		src/ai/rig_engine.rs
		src/ai/prompts.rs
		src/ai/prioritize.rs
		src/ai/cluster.rs
		src/ai/diff.rs
		src/ai/validate.rs
		src/ai/campaign.rs

============================================================
AI DATA FLOW

Create these major internal structs:
		EvidenceRecord
		HypothesisRecord
		ReasoningTask
		ReasoningResult
		ReasonedFinding
		RecommendedRequest

Example:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub scan_id: String,
    pub url: String,
    pub host: String,
    pub scheme: String,
    pub port: u16,
    pub method: String,
    pub exploit_family: Option<String>,
    pub payload_location: Option<String>,
    pub payload_value: Option<String>,
    pub baseline_status: Option<u16>,
    pub variant_status: u16,
    pub baseline_headers_hash: Option<String>,
    pub variant_headers_hash: Option<String>,
    pub baseline_body_hash: Option<String>,
    pub variant_body_hash: Option<String>,
    pub baseline_content_length: Option<usize>,
    pub variant_content_length: Option<usize>,
    pub body_markers: Vec<String>,
    pub reflected_markers: Vec<String>,
    pub environment_markers: Vec<String>,
    pub auth_markers: Vec<String>,
    pub redirect_location: Option<String>,
    pub confidence_seed: f32,
    pub timestamp: String,
}
```

And:
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct ReasoningTask {
    pub mode: String,
    pub objective: String,
    pub evidence: Vec<EvidenceRecord>,
    pub hypotheses: Vec<HypothesisRecord>,
    pub max_findings: usize,
    pub confidence_threshold: f32,
    pub include_raw_snippets: bool,
}
```

The AI layer must operate on structured evidence, not unbounded raw response text.
Each AI mode should have distinct objective shaping so `prioritize`, `cluster`, `diff`, `validate`,
and `campaign` are not treated identically.

============================================================
HTTP/3 SUPPORT

Add real HTTP/3 support.

Important:
Terminus currently documents that HTTP/3 is not supported because the current blocking reqwest architecture does not support QUIC/HTTP/3 and would require an async rewrite. Preserve that reality in comments and architecture, but implement the rewrite needed to support HTTP/3 properly. (github.com)

Requirements:
		introduce a transport abstraction layer
		move core request execution to async Tokio
		support:
		HTTP/1.0
		HTTP/1.1
		HTTP/2
		HTTP/3
		do not fake HTTP/3 support
		degrade gracefully if HTTP/3 is unavailable in the environment

Define:
		src/transport/mod.rs
		src/transport/traits.rs
		src/transport/http12.rs
		src/transport/http3.rs

Transport trait:
```rust
#[async_trait::async_trait]
pub trait HttpTransport {
    async fn send(&self, request: TerminusRequest) -> Result<TerminusResponse>;
}
```

Normalized request/response model:
```rust
pub struct TerminusRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Option<u64>,
}

pub struct TerminusResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub version: String,
    pub remote_addr: Option<String>,
}
```

============================================================
SQLITE

Preserve and extend SQLite support.

Existing or planned SQLite support already includes:
		denormalized schema
		indexed scan results
		full request/response persistence
		arbitrary method tracking
		vulnerability flags
		interactive review mode

Preserve compatibility with that design.

Extend schema to support:
		scan_results
		evidence_records
		hypotheses
		ai_assessments
		operator_feedback
		enumeration_results
		diff_results

Add schema versioning and migrations.

============================================================
OUTPUT LAYER

All subcommands should integrate with a common output/rendering system.

Support:
		stdout
		txt
		json
		html
		csv
		sqlite
		all

Preserve semantics:
		stdout = operator-first
		csv/json = analysis-friendly
		html = richer reporting
		sqlite = persistent structured workspace

============================================================
INTER-SUBCOMMAND CHAINING

Design chaining compatibility:
		enum results can feed scan
		scan results can feed AI
		scan results can feed diff
		diff results can feed AI
		interact reads SQLite outputs from scan/diff/enum/ai

============================================================
TESTING

Add tests for:
		subcommand dispatch
		scan + exploit module integration
		enum wildcard suppression
		diff correctness
		SQLite migrations
		interact command parsing
		AI JSON validation
		Rig provider abstraction
		local/cloud provider configuration
		HTTP/3 fallback / degradation behavior

============================================================
MODULE LAYOUT

Create a clean layout such as:
		src/main.rs
		src/cli.rs
		src/config.rs
		src/error.rs
		src/models.rs
		src/output/
		src/storage/
		src/transport/
		src/scan/
		src/enum/
		src/diff/
		src/help/
		src/interact/
		src/ai/

============================================================
NON-GOALS

Do not:
		create a separate vuln subcommand
		turn Terminus into a browser
		build a full crawler
		add desktop GUI frameworks
		create a generic chatbot
		tightly couple the whole project to Rig internals
		fake HTTP/3 support

============================================================
DELIVERABLES

Generate:
	1.	updated CLI/subcommand architecture
	2.	refactored scan subcommand with exploit modules embedded
	3.	enum subcommand implementation
	4.	diff subcommand implementation
	5.	help/manual subcommand implementation
	6.	interact subcommand implementation
	7.	ai subcommand using Rig
	8.	provider abstractions for local and cloud LLMs
	9.	async transport layer with HTTP/3 support
	10.	SQLite migrations/schema changes
	11.	shared output/rendering layer
	12.	tests
	13.	README snippets if useful

Build a disciplined, modular, operator-grade Rust CLI security platform.

## Updated final Terminus architecture diagram
```text
                                   ┌──────────────────────────────┐
                                   │          terminus            │
                                   │        CLI / main.rs         │
                                   └──────────────┬───────────────┘
                                                  │
                                                  ▼
                                    ┌───────────────────────────┐
                                    │      cli.rs / config      │
                                    │  subcommand + flag parse  │
                                    └───────┬───────┬──────────┘
                                            │       │
          ┌─────────────────────────────────┼───────┼─────────────────────────────────┐
          │                                 │       │                                 │
          ▼                                 ▼       ▼                                 ▼
 ┌─────────────────┐               ┌─────────────────┐                       ┌─────────────────┐
 │      scan       │               │      enum       │                       │      diff       │
 │ requests +      │               │ subdomains/paths│                       │ pure Rust diff  │
 │ exploit modules │               │                 │                       │                 │
 └────────┬────────┘               └────────┬────────┘                       └────────┬────────┘
          │                                 │                                         │
          └───────────────────────┬─────────┴───────────────────────────────┬─────────┘
                                  │                                         │
                                  ▼                                         ▼
                    ┌─────────────────────────────────────────────────────────────────┐
                    │                   shared models / results                       │
                    │ requests, responses, findings, evidence, enum results, diffs   │
                    └──────────────────────────────┬──────────────────────────────────┘
                                                   │
                                                   ▼
                                  ┌────────────────────────────────┐
                                  │       transport abstraction    │
                                  │  HTTP/1.0 / 1.1 / 2 / 3        │
                                  │  async core, CLI-friendly UX   │
                                  └──────────────┬─────────────────┘
                                                 │
                  ┌──────────────────────────────┼──────────────────────────────┐
                  │                              │                              │
                  ▼                              ▼                              ▼
       ┌────────────────────┐         ┌────────────────────┐         ┌────────────────────┐
       │  transport/http12  │         │  transport/http3   │         │ tls/proxy/retries/ │
       │ reqwest-based      │         │ QUIC-capable stack │         │ timeout/version     │
       └────────────────────┘         └────────────────────┘         └────────────────────┘

                                                   │
                                                   ▼
                                  ┌────────────────────────────────┐
                                  │        output/render layer     │
                                  │ stdout/txt/json/html/csv/sqlite│
                                  └──────────────┬─────────────────┘
                                                 │
                                                 ▼
                                  ┌────────────────────────────────┐
                                  │         storage / SQLite       │
                                  │ scans, evidence, diffs, enum,  │
                                  │ AI assessments, feedback       │
                                  └──────────────┬────────────┬────┘
                                                 │            │
                                                 ▼            ▼
                                     ┌────────────────┐  ┌────────────────┐
                                     │    interact    │  │       ai       │
                                     │ TUI / replay / │  │ Rig-backed     │
                                     │ inspect/search │  │ decision layer │
                                     └────────────────┘  └────────────────┘
```
