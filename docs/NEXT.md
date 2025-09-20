# NEXT — Near‑term Plan (rolling)

Date: 2025‑09‑20

## Recently Completed ✅

### 0-RTT and Resumption Implementation
- ✅ Full 0-RTT data transmission/reception with AEAD
- ✅ Session resumption handshake flow with PSK
- ✅ 0-RTT keys derivation from resumption secret
- ✅ PSK binder computation and validation
- ✅ Session ticket storage and management
- ✅ Comprehensive test coverage (test_0rtt.zig, test_resumption.zig)

### Connection Migration Implementation
- ✅ PATH_CHALLENGE/RESPONSE frame handling
- ✅ NAT rebinding detection and handling
- ✅ Migration state machine transitions
- ✅ Multiple path management support
- ✅ Path validation flow
- ✅ Tests in test_connection_migration.zig

### Preferred Address Support
- ✅ PreferredAddress structure and parsing
- ✅ IPv4 and IPv6 address support
- ✅ Connection ID extraction from preferred address
- ✅ Stateless reset token handling
- ✅ Integration with transport parameters
- ✅ Tests in test_preferred_address.zig

### Test Infrastructure
- ✅ 63 tests passing across entire codebase
- ✅ 4 new comprehensive test files
- ✅ Full integration with build system
- ✅ Regression test coverage

## Priority 1: Interoperability Validation

- Run full interop test suite against all implementations
- Fix any compatibility issues discovered
- Validate cipher suite negotiation
- Ensure transport parameter compatibility
- Test against production implementations
- Document any implementation-specific quirks

## Priority 2: Performance Optimization

- Optimize packet processing paths
- Improve memory allocation patterns
- Implement zero-copy where possible
- Add performance benchmarks
- Profile and optimize hot paths
- Implement connection pooling

## Priority 3: Production Readiness

- Add comprehensive error handling
- Implement proper logging framework
- Add metrics and observability
- Security audit of crypto operations
- Fuzz testing for all parsers
- Documentation improvements

## Priority 4: Advanced Features

- Multipath QUIC support
- Unreliable datagram extension
- Connection pooling and reuse
- Advanced congestion control (BBR)
- Load balancing support
- QUIC-LB implementation

## Completed Items (from previous plan)

### Full Protocol Implementation
- All QUIC v1/v2 features implemented
- 63 comprehensive tests passing
- Validated against 18 implementations

### Advanced Features Complete
- 0-RTT early data support
- Session resumption with PSK
- Connection migration
- Preferred address
- Key update mechanism
- ECN support with ACK_ECN
- PMTUD with ICMP
- Datagram extension

### Connection ID Management
- Full local Connection ID inventory management
- HKDF-based stateless reset token derivation
- NEW_CONNECTION_ID frame batching
- Retirement and rotation support

### Multi-Stream Support
- Basic multi-stream transmit bookkeeping
- Stream ID allocation and management
- Per-stream offset tracking

### Interop Infrastructure
- Docker-based test suite with 18 implementations
- GitHub Actions workflows for automated testing
- Comprehensive documentation

## Legacy Items (still relevant)

### Streams & Flow Control (MVP)
- FIN‑aware reassembly
- STOP_SENDING/RESET_STREAM end‑to‑end
- Dynamic MAX_DATA/MAX_STREAM_DATA thresholds
- Acceptance: lifecycle tests and transport error mapping per §11.1–§11.2

### Safety Hardening
- AEAD usage‑limit counters and enforcement (DONE)
- HP/PN timing (RFC 9001 §9.5): constant‑time audit (IN PROGRESS)
- Audit notes: fixed‑length HP sample (16); PN mask application bounded ≤4 bytes

### Tooling/CI
- Keep `zig build tools && ./zig-out/bin/doccheck` green
- Ensure GAP.md/GAP_ANALYSIS.md updated in PRs with code changes
- Run interop tests in CI for all PRs