![alt tag](rsc/Firefly%20Create%20a%20minimalist%20yet%20powerful%20logo%20inspired%20by%20the%20Roman%20god%20Terminus,%20the%20protector%20of%20b%20(2).jpg)

# `terminus`
![GitHub](https://img.shields.io/github/license/Achiefs/fim) [![Tip Me via PayPal](https://img.shields.io/badge/PayPal-tip_me-green?logo=paypal)](paypal.me/gbiagomba)

`terminus` is a command-line tool designed to test the accessibility of URLs without authentication, using various HTTP methods. It's particularly useful for identifying unprotected paths to web servers that require authentication, helping to expose potential security vulnerabilities. The tool supports individual URLs or lists from files, custom HTTP methods, multiple ports, and concurrent execution.

---

## Features
- **Single URL Testing**: Test a specific URL with the `-u` flag.
- **File Input**: Test multiple URLs from a file using the `-f` flag.
- **HTTP Methods**: Use any HTTP method with the `-X` flag or `ALL` to test all predefined methods.
- **Multiple Ports**: Specify one or more ports using `-p`, accepting comma-separated values like `80,443`.
- **Custom Output**: Specify an output directory for results with the `-o` flag.
- **Status Code Filtering**: Filter responses by status code using `-F`.
- **Proxy Support**: Route traffic through proxy tools like Burp Suite using the `-x` flag.
- **Custom Headers**: Add custom headers via `-H` flag (multiple allowed) or from file using `--header-file`.
- **Cookie Support**: Include cookies with the `-b` flag or from file using `-c/--cookie-file`.
- **HTTP Version Control**: Force HTTP/1.0, HTTP/1.1, or HTTP/2 using `--http-version`.
- **TLS/SSL Options**: Allow insecure connections with `-k` flag.
- **Redirect Handling**: Follow redirects with the `-L` flag.
- **Verbose Output**: View detailed response headers with the `-v` flag.

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
URL testing with multiple methods, ports, verbose logging, redirects, proxy, cookies, headers, and HTTP version support

Usage: terminus [OPTIONS]

Options:
  -u, --url <URL>                  Specify a single URL to check
  -f, --file <FILE>                Specify a file containing a list of URLs to check
  -X, --method <METHOD>            Specify the HTTP method to use (default: GET). Use ALL to test all methods
  -p, --port <PORTS>               Comma-separated ports to connect to (e.g., 80,443)
  -k, --insecure                   Allow insecure SSL connections
  -v, --verbose                    Enable verbose output with response headers
  -L, --follow                     Follow HTTP redirects
  -o, --output <FILE>              Write results to file
  -F, --filter-code <STATUS_CODE>  Filter results by HTTP status code
  -x, --proxy <PROXY>              Specify proxy URL (e.g., http://127.0.0.1:8080 for Burp)
  -H, --header <HEADER>            Add custom header (format: 'Name: Value'). Can be specified multiple times
      --header-file <FILE>         Read headers from file (one per line, format: 'Name: Value')
  -b, --cookie <COOKIE>            Add cookie string (format: 'name1=value1; name2=value2')
  -c, --cookie-file <FILE>         Read cookies from file
      --http-version <VERSION>     Force HTTP version (1.0, 1.1, or 2)
  -h, --help                       Print help
  -V, --version                    Print version

```

### Examples

**Test a single URL with a specific method**:
```bash
terminus -u http://example.com -X POST
```

**Test multiple URLs from a file on multiple ports**:
```bash
terminus -f urls.txt -p 80,443 -X ALL
```

**Test with proxy (e.g., Burp Suite)**:
```bash
terminus -u https://example.com -x http://127.0.0.1:8080 -k
```

**Test with custom headers**:
```bash
terminus -u https://example.com -H "Authorization: Bearer token123" -H "X-Custom: value"
```

**Test with headers from file**:
```bash
terminus -u https://example.com --header-file headers.txt
```

**Test with cookies**:
```bash
terminus -u https://example.com -b "session=abc123; user=admin"
```

**Test with cookies from file**:
```bash
terminus -u https://example.com -c cookies.txt
```

**Force HTTP/2**:
```bash
terminus -u https://example.com --http-version 2
```

**Filter by status code and set a custom output directory**:
```bash
terminus -u http://example.com -X GET -F 404 -o ./custom_results
```

**Complex example with multiple features**:
```bash
terminus -u https://api.example.com -X POST \
  -H "Content-Type: application/json" \
  -b "session=xyz789" \
  -x http://127.0.0.1:8080 \
  -k -v -L \
  --http-version 2 \
  -o results.txt
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