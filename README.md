![alt tag](rsc/Firefly%20Create%20a%20minimalist%20yet%20powerful%20logo%20inspired%20by%20the%20Roman%20god%20Terminus,%20the%20protector%20of%20b%20(2).jpg)

# `terminus`

`terminus` is a command-line tool that checks if a list of URLs can be accessed by an unauthenticated user using various HTTP methods. It is useful for identifying potential security gaps in web applications where protected pages might be exposed without proper authentication. The tool supports testing individual URLs or multiple URLs from a file, specifying a custom port, and using any HTTP method. The results are saved in a workspace folder, including logs, status codes, and other useful data. The tool is written in Rust and is easy to install and use. It is licensed under the GPL-3.0 License and contributions are welcome!

---

## Features
- Accepts individual URLs via the `-u` flag or a file containing a list of URLs with the `-f` flag.
- Supports specifying a port using the `-p` flag.
- Allows the use of any HTTP method via the `-X` flag, including common methods like `GET`, `POST`, `PUT`, or less common methods like `COPY`, `LOCK`, etc.
- The `-X ALL` option will test all HTTP methods provided in the original shell script.
- Saves results in a workspace folder, including logs, status codes, and other useful data.

---

## Installation

### Prerequisites:
1. Install Rust by following instructions from the official Rust website: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install).

2. Clone the repository:
   ```bash
   git clone git@github.com:gbiagomba/Terminus.git
   cd terminus
   ```

3. Build the program:
   ```bash
   cargo build --release
   ```

4. Install the program globally:
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

```
terminus 1.0
Checks if URLs can be accessed without authentication using various HTTP methods.

USAGE:
    terminus [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -u, --url <URL>          Test a single URL
    -f, --file <FILE>        Test multiple URLs from a file
    -p, --port <PORT>        Specify the port to connect to (default: 80 for HTTP, 443 for HTTPS)
    -X, --method <METHOD>    Specify the HTTP method to use (default: GET). Use 'ALL' to test all methods.
    -o, --output <DIR>       Specify output directory (default: ./terminus_results)
```

### Example:

1. **Test a single URL with a specific HTTP method**:
   ```bash
   terminus -u http://example.com -X POST
   ```

2. **Test a single URL with a specific port and HTTP method**:
   ```bash
   terminus -u http://example.com -p 8080 -X PUT
   ```

3. **Test multiple URLs from a file**:
   ```bash
   terminus -f urls.txt
   ```

4. **Test all HTTP methods on a single URL**:
   ```bash
   terminus -u http://example.com -X ALL
   ```

5. **Test all HTTP methods on multiple URLs from a file**:
   ```bash
   terminus -f urls.txt -X ALL
   ```

6. **Specify a custom output directory**:
   ```bash
   terminus -f urls.txt -X ALL -o ./custom_results
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

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for more details.

---

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

---

## Credits

Originally developed by Gilles Biagomba.

