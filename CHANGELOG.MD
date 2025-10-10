# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

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