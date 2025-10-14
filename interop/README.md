# QUIC Interoperability Testing

This directory contains the configuration for running the Zig QUIC implementation against the official [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner).

## Overview

The QUIC Interop Runner is the official testing framework used by the IETF QUIC working group to test interoperability between different QUIC implementations. It uses Docker containers and a network simulator to create controlled testing conditions.

## Directory Structure

```
interop/
├── Dockerfile              # Docker image for Zig QUIC endpoint
├── run_endpoint.sh         # Endpoint entrypoint script
├── implementations.json    # Configuration for quic-interop-runner
└── README.md              # This file
```

## Quick Start

### Basic Testing (Using Custom Script)

Run basic interop tests against quic-go:

```bash
./scripts/interop_full.sh basic
```

Run quick tests against major implementations:

```bash
./scripts/interop_full.sh quick
```

Run full test matrix:

```bash
./scripts/interop_full.sh full
```

### Official QUIC Interop Runner

Use the official quic-interop-runner:

```bash
./scripts/interop_full.sh runner
```

Or with the --official flag:

```bash
./scripts/interop_full.sh --official
```

## Test Modes

The interop test script supports several modes:

- **basic** - Test against quic-go only (handshake, transfer, retry, http3, keyupdate)
- **quick** - Test against quic-go, ngtcp2, and quiche
- **full** - Test against all available implementations in both directions
- **runner** - Use the official quic-interop-runner

## Supported Test Cases

According to `implementations.json`, the Zig QUIC implementation currently supports:

✅ **Supported:**
- handshake - Basic QUIC handshake
- transfer - Data transfer
- retry - Retry packet handling
- http3 - HTTP/3 over QUIC
- multiconnect - Multiple connections
- keyupdate - TLS key updates
- ipv6 - IPv6 support

❌ **Not Yet Supported:**
- resumption - TLS session resumption
- zerortt - 0-RTT data
- ecn - ECN marking
- amplificationlimit - Anti-amplification
- handshakeloss - Handshake with packet loss
- transferloss - Transfer with packet loss
- handshakecorruption - Handshake with corruption
- transfercorruption - Transfer with corruption
- v2 - QUIC v2
- blackhole - Blackhole detection
- chacha20 - ChaCha20 cipher

## Building the Docker Image

Build the Zig QUIC Docker image for interop testing:

```bash
docker build -f interop/Dockerfile -t zig-quic:interop .
```

## Manual Testing with Official Runner

1. Clone the official runner:

```bash
git clone https://github.com/quic-interop/quic-interop-runner.git interop/quic-interop-runner
cd interop/quic-interop-runner
```

2. Set up Python environment:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

3. Copy our implementations config:

```bash
cp ../implementations.json implementations.local.json
```

4. Run tests:

```bash
# Test Zig against itself
.venv/bin/python interop.py \
    --client zig \
    --server zig \
    --log-dir logs \
    --implementations implementations.local.json \
    --tests handshake,transfer

# Test Zig client against quic-go server
.venv/bin/python interop.py \
    --client zig \
    --server quic-go \
    --log-dir logs \
    --tests handshake,transfer

# Test quic-go client against Zig server
.venv/bin/python interop.py \
    --client quic-go \
    --server zig \
    --log-dir logs \
    --tests handshake,transfer
```

## Network Simulator

The tests run inside a network simulator that can introduce:
- Packet loss
- Packet corruption
- Latency
- Bandwidth limitations
- Network blackholes

This simulated network environment ensures tests are realistic and repeatable.

## Environment Variables

The endpoint script recognizes these environment variables:

- `ROLE` - "server" or "client"
- `TESTCASE` - Test case name (e.g., "handshake", "transfer")
- `REQUESTS` - URLs to request (for client)
- `CLIENT_PARAMS` - Additional client parameters
- `SSLKEYLOGFILE` - Path to SSL key log file (for Wireshark decryption)
- `QLOGDIR` - Directory for QLOG files

## Test Files

For download/transfer tests, the server automatically creates test files in `/www/`:

- 5KB file: /www/5000
- 10KB file: /www/10000
- 500KB file: /www/500000
- 1MB file: /www/1000000
- 5MB file: /www/5000000
- 10MB file: /www/10000000

## Debugging

Logs are available in:
- Server logs: `/logs/server.log`
- Client logs: `/logs/client.log`

Enable SSL key logging for Wireshark decryption:

```bash
export SSLKEYLOGFILE=/logs/keys.log
```

Enable QLOG for connection debugging:

```bash
export QLOGDIR=/logs/qlog
```

## Implementation Details

The Zig QUIC implementation:

1. Uses the `qns-endpoint` binary built from the main codebase
2. Supports both client and server roles
3. Implements the QUIC Network Simulator (QNS) protocol
4. Auto-detects standard TLS 1.3 ClientHello (see TLS fix in commit history)
5. Falls back to minimal "CH1" format for backward compatibility

## Continuous Integration

The interop tests can be integrated into CI/CD:

```yaml
# Example GitHub Actions workflow
- name: Run QUIC Interop Tests
  run: |
    ./scripts/interop_full.sh quick
```

## Troubleshooting

### Docker Network Conflicts

If you see "Pool overlaps with other one on this address space":

```bash
# Clean up conflicting networks
docker network prune -f
# Or set environment variable
export SKIP_QNS_NET_PRUNE=0
```

### Simulator Not Ready

If the client can't connect to the simulator:

- Check Docker logs: `docker logs <container_id>`
- Increase wait time in `run_endpoint.sh`
- Ensure the simulator container is running: `docker ps`

### Test Failures

Common causes:
1. TLS compatibility issues (check logs for "Failed to parse")
2. Network simulator issues (check sim container logs)
3. Timeout issues (increase timeouts in docker-compose.yml)

## Contributing

To add support for new test cases:

1. Update `implementations.json` to mark the test as supported
2. Implement the required functionality in the main codebase
3. Test locally with the official runner
4. Update this README

## References

- [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner)
- [QUIC Network Simulator](https://github.com/quic-interop/quic-network-simulator)
- [Interop Test Matrix](https://interop.seemann.io/)
- [QUIC Specifications](https://quicwg.org/)
