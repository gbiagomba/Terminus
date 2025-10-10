# Use an official Rust image as the base image
FROM rust:latest AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Cargo.toml and Cargo.lock files first to leverage Docker cache
COPY Cargo.toml Cargo.lock ./

# Create a dummy file to initialize dependencies
RUN mkdir src
RUN echo "fn main() {}" > src/main.rs

# Build the dependencies only
RUN cargo build --release

# Now copy the actual source files
COPY . .

# Compile the full application
RUN cargo build --release

# Start a new stage from a smaller base image
FROM debian:bookworm-slim

# Install CA certificates for HTTPS support
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Set working directory in the new stage
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/terminus /app/

# Define the entry point for the container
ENTRYPOINT ["./terminus"]

# Add metadata
LABEL maintainer="Gilles Biagomba <gilles.infosec@gmail.com>"
LABEL version="2.3.0"
LABEL description="CLI tool to check URL accessibility with proxy, headers, cookies, and HTTP/1-2 support"