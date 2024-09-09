# Makefile for Terminus

# Default configuration
TARGET := terminus
BUILD_DIR := ./target/release
OUTPUT_DIR := ./terminus_results
CARGO := cargo

# Default build target
.PHONY: all
all: build

# Build the release version
.PHONY: build
build:
	$(CARGO) build --release

# Run the program with default arguments
.PHONY: run
run:
	$(BUILD_DIR)/$(TARGET) -u http://example.com -X GET -o $(OUTPUT_DIR)

# Run the program with specific arguments (example with a URL)
.PHONY: run-url
run-url:
	$(BUILD_DIR)/$(TARGET) -u http://example.com -X ALL

# Run the program with specific arguments (example with a file)
.PHONY: run-file
run-file:
	$(BUILD_DIR)/$(TARGET) -f urls.txt -X ALL

# Clean the build artifacts
.PHONY: clean
clean:
	$(CARGO) clean

# Install the binary globally
.PHONY: install
install:
	$(CARGO) install --path .

# Uninstall the globally installed binary
.PHONY: uninstall
uninstall:
	$(CARGO) uninstall $(TARGET)