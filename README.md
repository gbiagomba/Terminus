![alt tag](rsc/Firefly%20Create%20a%20minimalist%20yet%20powerful%20logo%20inspired%20by%20the%20Roman%20god%20Terminus,%20the%20protector%20of%20b%20(2).jpg)

# `terminus`

`terminus` is a command-line tool designed to test the accessibility of URLs without authentication, using various HTTP methods. It's particularly useful for identifying unprotected paths to web servers that require authentication, helping to expose potential security vulnerabilities. The tool supports individual URLs or lists from files, custom HTTP methods, multiple ports, and concurrent execution.

---

## Features
- **Single URL Testing**: Test a specific URL with the `-u` flag.
- **File Input**: Test multiple URLs from a file using the `-f` flag.
- **HTTP Methods**: Use any HTTP method with the `-X` flag or `ALL` to test all predefined methods.
- **Multiple Ports**: Specify one or more ports using `-p`, accepting comma-separated values like `80,443`.
- **Concurrent Execution**: Enable concurrent URL testing with the `-c` or `--concurrent` flag, enhancing performance.
- **Custom Output**: Specify an output directory for results with the `-o` flag.
- **Status Code Filtering**: Filter responses by status code using `-F`.
- **Timeout Configuration**: Set a maximum request duration with `-m`.

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

## Usage

```plaintext
Checks if URLs can be accessed without authentication using various HTTP methods.

Usage: terminus [OPTIONS]

Options:
  -u, --url <URL>                  Specify a single URL to check
  -f, --file <FILE>                Specify a file containing a list of URLs to check
  -o, --output <FILE>              Specify the output file for the results
  -p, --port <PORTS>               Specify comma-separated ports to connect to (e.g., 80,443)
  -X, --method <METHOD>            Specify the HTTP method to use (default: GET). Use 'ALL' to test all methods or a specific HTTP method
  -F, --filter-code <STATUS_CODE>  Filter results by HTTP status code
  -m, --max-time <SECONDS>         Maximum time, in seconds, that you allow the request to take
  -c, --concurrent <concurrent>    Enable concurrent scanning of URLs
  -L, --follow <follow>            Follow HTTP redirects
  -v, --verbose <verbose>          Increase verbosity to see details of requests and responses
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

**Concurrently test all methods for a URL**:
```bash
terminus -u http://example.com -X ALL -c
```

**Filter by status code and set a custom output directory**:
```bash
terminus -u http://example.com -X GET -F 404 -o ./custom_results
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

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

---

## License

GPL-3.0 License. For more details, see the [LICENSE](LICENSE) file.