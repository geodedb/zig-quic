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

Replay the public run profile from `https://interop.seemann.io/?run=2026-02-16T09:04`
against this implementation:

```bash
./scripts/interop_runner_replay.sh \
  --run-url "https://interop.seemann.io/?run=2026-02-16T09:04" \
  --client zig,quic-go \
  --server zig,quic-go
```

Run the full matrix while requiring every pair to include `zig`:

```bash
./scripts/interop_runner_replay.sh \
  --run-url "https://interop.seemann.io/?run=2026-02-16T09:04" \
  --must-include zig
```

`scripts/interop_full.sh runner` and `make interop-runner` now delegate to this workflow.

## Test Modes

The interop test script supports several modes:

- **basic** - Test against quic-go only (handshake, transfer, retry, http3, keyupdate)
- **quick** - Test against quic-go, ngtcp2, and quiche
- **full** - Test against all available implementations in both directions
- **runner** - Use the official quic-interop-runner

## Test Case Support Signaling

The endpoint strictly follows current interop-runner behavior:

- Supported test cases are executed normally.
- Unsupported test cases exit with status code `127`.

This is implemented in both endpoint entry scripts:

- `interop/run_endpoint.sh`
- `examples/interop/zig-qns/run_endpoint.sh`

## Building the Docker Image

Build the qns-endpoint binary locally first:

```bash
zig build -Doptimize=ReleaseSafe cli
```

Then build the Docker image:

```bash
docker build -f interop/Dockerfile \
  --build-arg QNS_TAG=latest \
  --build-arg VCS_REF="$(git rev-parse --short HEAD || echo dev)" \
  --build-arg BUILD_DATE="$(date -u +%Y%m%d)" \
  -t zig-quic:interop .
```

Or simply use the Makefile target (builds binary and image):

```bash
make interop-build
```

## Manual Testing with Official Runner

Use the automation script instead of invoking runner internals directly:

```bash
# Quick bidirectional smoke against quic-go
scripts/interop_runner_replay.sh \
  --run-url "https://interop.seemann.io/?run=2026-02-16T09:04" \
  --client zig,quic-go \
  --server zig,quic-go

# Full current run profile with zig in every pair
scripts/interop_runner_replay.sh \
  --run-url "https://interop.seemann.io/?run=2026-02-16T09:04" \
  --must-include zig
```

To inspect what would run without executing it:

```bash
scripts/interop_runner_replay.sh --dry-run
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
- `SSLKEYLOGFILE` - Path to SSL key log file (for Wireshark decryption)
- `QLOGDIR` - Directory for QLOG files
- `INTEROP_CLIENT_START_DELAY` - Client startup delay in seconds (default: `5`)
- `WAIT_FOR_TARGET` - Optional `host:port` readiness check before starting client
- `INTEROP_DROP_PRIVS` - Set to `1` to run endpoint as `quic` user via `setpriv`
- `QNS_USE_MOUNTED_CERTS` - Set to `1` to force `/certs/{cert.pem,priv.key}` usage

By default the server uses bundled certs at `/quic/certs/{cert.pem,key.pem}` for
deterministic local and runner behavior. Mounted runner certs are opt-in via
`QNS_USE_MOUNTED_CERTS=1`.

## Test Files

In official interop runs, `/www` is mounted by the runner and already contains
the generated fixture files. The endpoint only creates tiny fallback files for
local compose runs when `/www` is empty.

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

### Docker Network/DNS Issues

If Docker builds fail with errors like "Could not connect to archive.ubuntu.com" or "Unable to fetch some archives":

**Quick Diagnosis:**
```bash
# Run the diagnostic script
./interop/fix-docker-network.sh
```

This script checks:
- Docker daemon status
- DNS resolution inside containers
- Ubuntu repository access
- Zig download site connectivity

**Solutions:**

1. **Already Applied in Dockerfile**: The Dockerfile includes:
   - Retry logic (3 attempts) for transient network failures
   - `--fix-missing` flag for apt-get

2. **Configure Docker Daemon DNS** (Recommended): Edit `/etc/docker/daemon.json`:
   ```json
   {
     "dns": ["8.8.8.8", "1.1.1.1"]
   }
   ```
   Then restart: `sudo systemctl restart docker`

3. **Use Host Network**: For builds (not recommended for tests):
   ```bash
   docker build --network=host -f interop/Dockerfile -t zig-quic:interop .
   ```

4. **Corporate Proxy**: If behind a proxy, add to `/etc/docker/daemon.json`:
   ```json
   {
     "dns": ["8.8.8.8", "1.1.1.1"],
     "proxies": {
       "http-proxy": "http://proxy.example.com:80",
       "https-proxy": "http://proxy.example.com:80"
     }
   }
   ```

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
