# QUIC Interoperability Testing

This directory contains interoperability tests for verifying the QUIC implementation works correctly with other established QUIC implementations.

## Tested Implementations

The following QUIC implementations are used for interoperability testing:

1. **quic-go** - Go implementation (Cloudflare/Google)
2. **aioquic** - Python implementation (Cloudflare)
3. **quinn** - Rust implementation (Mozilla)
4. **quiche** - Rust/C implementation (Cloudflare)

## Test Categories

### Handshake Interop
- Basic TLS 1.3 handshake completion
- Version negotiation
- ALPN negotiation
- Transport parameter exchange
- 0-RTT handshake

### Data Transfer Interop
- Unidirectional stream data
- Bidirectional stream data
- Large data transfers (>1MB)
- Multiple concurrent streams
- Flow control interaction

### Connection Management Interop
- Connection migration
- Connection closure
- Idle timeout
- Stateless reset

### Advanced Features Interop
- Key updates
- Path validation
- ECN marking
- DATAGRAM extension (RFC 9221)

## Running Interop Tests

**Note**: Interop tests require external QUIC implementations to be installed and accessible.

### Prerequisites

Install the reference implementations:

```bash
# quic-go (requires Go)
go install github.com/quic-go/quic-go/...@latest

# aioquic (requires Python)
pip install aioquic

# quinn (requires Rust)
cargo install quinn-cli

# quiche (build from source)
git clone --recursive https://github.com/cloudflare/quiche.git
cd quiche && cargo build --release
```

### Running Tests

```bash
# Run all interop tests
zig test tests/integration/interop/interop.zig

# Test against specific implementation
zig test tests/integration/interop/interop.zig --test-filter "quic-go"

# Run with verbose logging
zig test tests/integration/interop/interop.zig -- --summary all
```

## Test Infrastructure

### External Process Management
The interop tests spawn external QUIC client/server processes and coordinate communication between the Zig implementation and reference implementations.

### Test Scenarios
Each test follows this pattern:
1. Start reference implementation server
2. Connect Zig client to reference server (or vice versa)
3. Exchange data and verify correctness
4. Verify handshake, streams, and features
5. Clean up processes

### Timeout Handling
All interop tests have timeouts to prevent hanging on incompatibilities.

## Test Matrix

| Feature | quic-go | aioquic | quinn | quiche |
|---------|---------|---------|-------|--------|
| Basic Handshake | 📝 TODO | 📝 TODO | 📝 TODO | 📝 TODO |
| Version Negotiation | 📝 TODO | 📝 TODO | 📝 TODO | 📝 TODO |
| Data Transfer | 📝 TODO | 📝 TODO | 📝 TODO | 📝 TODO |
| Connection Migration | 📝 TODO | 📝 TODO | 📝 TODO | 📝 TODO |
| 0-RTT | 📝 TODO | 📝 TODO | 📝 TODO | 📝 TODO |
| Key Updates | 📝 TODO | 📝 TODO | 📝 TODO | 📝 TODO |

## Debugging Interop Issues

### Packet Capture
Enable packet capture to analyze wire-level communication:
```bash
tcpdump -i lo -w quic_interop.pcap 'udp port 4433'
```

### SSLKEYLOGFILE
Export TLS keys for Wireshark decryption:
```bash
export SSLKEYLOGFILE=/tmp/quic_keys.log
zig test tests/integration/interop/interop.zig
```

### Verbose Logging
Enable detailed logging in both implementations to diagnose issues.

## Known Interop Issues

Document any known interoperability issues here:

- **Issue**: TBD
- **Implementations**: TBD
- **Status**: TBD

## Contributing

When adding interop tests:
1. Test both client and server roles
2. Document test expectations clearly
3. Handle version differences gracefully
4. Include timeout mechanisms
5. Clean up processes on failure
