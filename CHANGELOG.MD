# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

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