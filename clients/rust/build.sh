#!/usr/bin/env bash
# Build script for Rust quinn test client

set -e

echo "=== Building Rust QUIC test client ==="

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo "❌ Error: cargo not found. Please install Rust toolchain from https://rustup.rs/"
    exit 1
fi

echo "Building release binary..."
cargo build --release

echo ""
echo "✅ Build complete!"
echo ""
echo "Binary location: target/release/test-client"
echo ""
echo "To run the test client:"
echo "  ./target/release/test-client 127.0.0.1:4433"
echo ""
echo "Or with cargo:"
echo "  cargo run --release -- 127.0.0.1:4433"
