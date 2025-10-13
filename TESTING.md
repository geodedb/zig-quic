# QUIC Interoperability Testing

This document describes the interop testing setup for the Zig QUIC implementation.

## Quick Start

### Run Internal Zig Interop Test
```bash
./test_interop.sh
```

This tests Zig client <-> Zig server communication. It automatically:
- Builds the QUIC implementation
- Starts a Zig QUIC server on a random port
- Runs a Zig QUIC client to connect and send/receive data
- Verifies the echo response

**Expected output:** ✓ PASSED - Client received correct echo response

### Run quic-go Interop Tests
```bash
./test_quic_go_interop.sh
```

This tests cross-implementation interoperability:
1. **Test 1:** Zig Server <-> quic-go Client
2. **Test 2:** quic-go Server <-> Zig Client

**Prerequisites:** Install quic-go interop tools:
```bash
git clone https://github.com/marten-seemann/quic-go.git
cd quic-go/interop
go build -o quic-interop-server ./server
go build -o quic-interop-client ./client
sudo cp quic-interop-* /usr/local/bin/
```

## Test Details

### test_interop.sh
- **Purpose:** Verify internal Zig QUIC implementation works correctly
- **What it tests:**
  - End-to-end QUIC connection establishment
  - TLS 1.3 handshake
  - Application data exchange (echo test)
  - Proper connection termination
- **Runtime:** ~2-3 seconds
- **Logs:** `/tmp/quic_server_test.log` and `/tmp/quic_client_test.log`

### test_quic_go_interop.sh
- **Purpose:** Verify compatibility with other QUIC implementations
- **What it tests:**
  - Zig server can accept connections from quic-go clients
  - Zig client can connect to quic-go servers
  - Protocol compatibility (QUIC v1, TLS 1.3)
- **Runtime:** ~5-10 seconds
- **Logs:** `/tmp/zig_*_interop.log` and `/tmp/quicgo_*_interop.log`

## Integration with CI/CD

Add to your CI pipeline:

```yaml
# Example for GitHub Actions
- name: Run QUIC Interop Tests
  run: |
    ./test_interop.sh
    
# For quic-go interop (if quic-go tools are installed)
- name: Run quic-go Interop Tests
  run: |
    ./test_quic_go_interop.sh
  continue-on-error: true  # Optional, if you want to allow failures
```

## Current Test Status

### Internal Interop (Zig <-> Zig)
✅ **WORKING** - All tests pass consistently

### External Interop (Zig <-> quic-go)
Status depends on quic-go availability and compatibility.

## Troubleshooting

### Test fails with "Build failed"
```bash
# Manually build first
zig build -Doptimize=ReleaseFast
```

### Test fails with "Port already in use"
```bash
# Kill any running QUIC servers
killall -9 quic-server quic-client
```

### quic-go interop test fails
```bash
# Verify quic-go tools are installed
which quic-interop-server quic-interop-client

# Check logs for details
cat /tmp/zig_*_interop.log
cat /tmp/quicgo_*_interop.log
```

## Manual Testing

For manual debugging, you can run the server and client separately:

```bash
# Terminal 1: Start server
./zig-out/bin/quic-server 127.0.0.1:4433

# Terminal 2: Run client
./zig-out/bin/quic-client https://127.0.0.1:4433 "hello world"
```

## Docker Interop Tests

Docker-based interop tests using the QUIC Network Simulator are available but currently experiencing networking issues. These tests are in `examples/interop/` and can be run with:

```bash
./scripts/interop_full.sh
```

**Note:** Docker interop tests are currently non-functional due to network simulator packet forwarding issues. Use the standalone tests above instead.
