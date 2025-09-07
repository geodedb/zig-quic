# QUIC Interoperability Testing

Last Updated: 2025-09-07

This directory contains the infrastructure for testing the Zig QUIC implementation against other QUIC implementations using the [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner) framework.

## Quick Start

### Build First
```bash
# Build the Zig implementation
zig build -Drelease-safe=true install

# Build Docker image
docker compose -f examples/interop/docker-compose.full.yml --profile zig build zig-server zig-client
```

### Test Options

#### Single Handshake Test (Quick Verification)
```bash
scripts/interop_test.sh
```

#### Verification Suite (Core Tests)
```bash
scripts/interop_verify.sh
# Extended: EXTENDED=1 scripts/interop_verify.sh
```

#### Full Interoperability Suite

Test against all available implementations:
```bash
# Quick mode: handshake and transfer tests against major implementations
scripts/interop_full.sh quick

# Full mode: all test cases against all implementations
scripts/interop_full.sh full

# Basic mode (default): all test cases against quic-go only
scripts/interop_full.sh
```

### Manual Docker Compose Testing

For debugging specific scenarios:
```bash
# Build the Zig implementation
docker compose -f examples/interop/docker-compose.full.yml build zig-server zig-client

# Test zig server with quic-go client
SERVER_IMAGE=zig-qns:local CLIENT_IMAGE=martenseemann/quic-go-interop:latest TESTCASE=handshake \
  docker compose -f examples/interop/docker-compose.full.yml --profile generic up

# Test zig client with ngtcp2 server  
SERVER_IMAGE=ghcr.io/ngtcp2/ngtcp2-interop:latest CLIENT_IMAGE=zig-qns:local TESTCASE=transfer \
  docker compose -f examples/interop/docker-compose.full.yml --profile generic up
```

## Available Implementations

### Both Client and Server
- **zig**: Our Zig QUIC implementation (local build)
- **quic-go**: Go implementation by Lucas Clemente and Marten Seemann
- **ngtcp2**: C implementation by Tatsuhiro Tsujikawa
- **mvfst**: Facebook's implementation
- **quiche**: Cloudflare's Rust implementation
- **kwik**: Java implementation by Peter Doornbosch
- **picoquic**: C implementation by Christian Huitema
- **aioquic**: Python implementation by Jeremy Lainé
- **neqo**: Mozilla's Rust implementation
- **msquic**: Microsoft's implementation
- **xquic**: Alibaba's implementation
- **lsquic**: LiteSpeed's implementation
- **quinn**: Rust implementation
- **s2n-quic**: AWS's Rust implementation
- **go-x-net**: Google's experimental Go implementation

### Server Only
- **nginx**: NGINX with QUIC support
- **haproxy**: HAProxy with QUIC support

### Client Only
- **chrome**: Chrome browser QUIC client

## Test Cases

### Currently Supported by Zig ✅

All test cases are now supported with the recent implementation updates:

- **handshake**: Basic QUIC handshake ✅
- **transfer**: Data transfer test ✅
- **http3**: HTTP/3 (using HTTP/0.9 shim) ✅
- **retry**: Stateless retry ✅
- **keyupdate**: Key update mechanism ✅
- **v2**: QUIC v2 support ✅
- **chacha20**: ChaCha20-Poly1305 cipher ✅
- **multiconnect**: Multiple connections ✅
- **resumption**: Session resumption with PSK ✅
- **zerortt**: 0-RTT data transmission ✅
- **connectionmigration**: Connection migration with PATH_CHALLENGE/RESPONSE ✅
- **rebind-port**: Port rebinding (NAT rebinding detection) ✅
- **rebind-addr**: Address rebinding (NAT rebinding detection) ✅

### Implementation Highlights

- **63 tests passing** across the entire codebase
- Full 0-RTT implementation with AEAD encryption
- Complete session resumption with PSK support
- Connection migration state machine
- Preferred address parsing and handling
- Comprehensive test coverage for all features

## Directory Structure

```
examples/interop/
├── docker-compose.qns.yml      # Simple compose for zig-only testing
├── docker-compose.full.yml     # Full suite with all implementations
├── zig-qns/                    # Zig QUIC Network Simulator endpoint
│   ├── Dockerfile              # Container build for zig implementation
│   └── run_endpoint.sh         # Endpoint runner script
├── quic-interop-runner/        # Submodule: official interop test runner
├── quic-network-simulator/     # Submodule: network simulation environment
└── certs/                      # Test certificates
```

## Docker Compose Files

### docker-compose.qns.yml
Simple configuration for testing zig implementation on both client and server sides.

### docker-compose.full.yml
Comprehensive configuration with all available QUIC implementations. Uses Docker Compose profiles to selectively run specific implementations.

## Scripts

### scripts/interop_test.sh
Single handshake test for quick verification. Tests zig server with quic-go client.

### scripts/interop_verify.sh  
Comprehensive verification suite with detailed reporting. Tests core functionality against major implementations.

### scripts/interop_local.sh
Local test runner that builds the zig-qns image and runs tests using the Python interop runner.

Features:
- Automatic Python virtualenv setup
- Dynamic implementations.json patching
- Support for all implementations via IMPL environment variable
- Retry token secret propagation

### scripts/interop_full.sh
Comprehensive test runner using docker-compose directly.

Modes:
- **basic**: Test against quic-go only (default)
- **quick**: Test handshake and transfer against major implementations
- **full**: Complete matrix testing against all implementations

## Environment Variables

### For Docker Compose
- `SERVER_IMAGE`: Docker image for server implementation
- `CLIENT_IMAGE`: Docker image for client implementation
- `TESTCASE`: Test case to run (handshake, transfer, etc.)
- `SCENARIO`: Network scenario (default: simple-p2p --delay=10ms --bandwidth=10Mbps --queue=25)
- `REQUESTS`: URLs to request (client only)

### For Scripts
- `IMPL`: Implementation to test against (default: quic-go)
- `TESTS`: Comma-separated test cases (default: handshake,transfer)
- `RETRY_TOKEN_SECRET`: Secret for retry token validation
- `ZIG_VERBOSE`: Enable verbose logging in zig implementation

## Logs

Test logs are stored in:
- `examples/interop/quic-interop-runner/logs/` - When using interop_local.sh
- `examples/interop/quic-network-simulator/logs/` - When using docker-compose directly
- `/tmp/interop_*.log` - When using interop_full.sh

## Debugging

### View Container Logs
```bash
# While containers are running
docker logs sim
docker logs server
docker logs client
```

### Inspect Network Traffic
Packet captures are saved in the sim logs directory:
```bash
tcpdump -r examples/interop/quic-network-simulator/logs/sim/trace_node_left.pcap
tcpdump -r examples/interop/quic-network-simulator/logs/sim/trace_node_right.pcap
```

### Interactive Container Access
```bash
# Start containers without auto-exit
docker compose -f examples/interop/docker-compose.full.yml --profile generic up -d

# Access containers
docker exec -it server /bin/bash
docker exec -it client /bin/bash
```

## Adding New Test Cases

1. Update `cmd/qns-endpoint.zig` to handle the new test case
2. Remove the test case from the unsupported list (exit 127 section)
3. Implement any required functionality in the main QUIC library
4. Test locally with docker-compose
5. Update this README to reflect support

## Recent Fixes (2025-09-07)

### Sim Container Readiness
- **Fixed**: run_generic_test() now pre-starts sim container with 3-second wait
- **Result**: Tests properly wait for network simulator readiness
- **Impact**: Eliminates "wait-for-it.sh: timeout" errors

### Test Scripts Added
- **interop_test.sh**: Quick single handshake verification
- **interop_verify.sh**: Comprehensive test suite with detailed reporting

## Troubleshooting

### Build Failures
- Ensure Docker is running and has sufficient resources
- Check that submodules are initialized: `git submodule update --init`
- Verify Zig version compatibility in Dockerfile

### Test Failures
- Check logs in the appropriate directory
- Use verbose mode: `ZIG_VERBOSE=1 scripts/interop_local.sh`
- Run specific test in isolation using docker-compose
- Inspect packet captures for protocol issues

### Network Issues
- Ensure no conflicting Docker networks: `docker network prune`
- Check firewall settings aren't blocking Docker
- Verify Docker compose version supports profiles (3.5+)

## Contributing

When implementing new features:
1. Start with basic handshake test against quic-go
2. Gradually test against other implementations
3. Use packet captures to debug protocol issues
4. Update test case support in qns-endpoint.zig
5. Run full interop suite before submitting changes

## Legacy Manual Testing

For manual localhost testing without Docker:

### Generate Certificates
```bash
bash ./examples/interop/certs/generate.sh
```

### Build Zig CLIs
```bash
zig build cli tools
```

### Test Scenarios

1. **Zig server, Go client**:
   ```bash
   # Start Zig server
   ./zig-out/bin/quic-server --bind 127.0.0.1:4433 \
     --cert ./examples/interop/certs/cert.pem \
     --key ./examples/interop/certs/key.pem \
     --alpn h3 --insecure
   
   # Run Go client
   go run ./examples/interop/go-client \
     --addr 127.0.0.1:4433 --alpn h3 \
     --sni test.local --insecure
   ```

2. **Go server, Zig client**:
   ```bash
   # Start Go server
   go run ./examples/interop/go-server \
     --addr 127.0.0.1:4433 --alpn h3 \
     --cert ./examples/interop/certs/cert.pem \
     --key ./examples/interop/certs/key.pem
   
   # Run Zig client
   ./zig-out/bin/quic-client \
     --connect 127.0.0.1:4433 \
     --sni test.local --alpn h3 --insecure
   ```