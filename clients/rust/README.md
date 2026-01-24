# Rust Quinn Test Client

Simple QUIC test client using the quinn library for testing interoperability with the Zig QUIC server implementation.

## Prerequisites

Install Rust toolchain from https://rustup.rs/ if not already installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Build

Run the build script:

```bash
./build.sh
```

Or build manually:

```bash
cargo build --release
```

## Usage

Run the compiled binary:

```bash
./target/release/test-client 127.0.0.1:4433
```

Or run with cargo:

```bash
cargo run --release -- 127.0.0.1:4433
```

For debug output, set RUST_LOG environment variable:

```bash
RUST_LOG=info cargo run --release -- 127.0.0.1:4433
```

## Testing with Server

Start the QUIC server in one terminal:

```bash
./zig-out/bin/quic-server --bind 127.0.0.1:4433 --insecure
```

In another terminal, build and run the client:

```bash
cd clients/rust
./build.sh
./target/release/test-client 127.0.0.1:4433
```

## Dependencies

- quinn 0.11 - QUIC implementation
- tokio - Async runtime
- rustls - TLS implementation
- anyhow - Error handling
- tracing - Logging

See `Cargo.toml` for full list.
