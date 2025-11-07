# RFC Compliance Test Plan for QUIC Modular Architecture

## Overview

This document outlines the comprehensive RFC compliance testing strategy for all modular QUIC components. Each module has targeted unit tests that verify compliance with specific RFC sections.

## Testing Principles

1. **RFC-Aligned**: Each test references specific RFC sections
2. **Comprehensive Coverage**: Positive cases, negative cases, edge cases, and RFC compliance
3. **Isolated Testing**: Each module tested independently
4. **Deterministic**: No flaky tests, no timing dependencies
5. **Well-Documented**: Clear test names indicating what is being tested

## Test Organization

Tests are organized by module category under `tests/unit/`:

```
tests/unit/
├── connection/          # Connection module tests (RFC 9000, 9001, 9002)
│   ├── test_types.zig            ✓ COMPLETED
│   ├── test_crypto_buffer.zig    ✓ COMPLETED
│   ├── test_packet_number.zig    ✓ COMPLETED
│   ├── test_ack.zig               ✓ COMPLETED
│   ├── test_stream.zig            ✓ COMPLETED
│   ├── test_connection_id.zig     ✓ COMPLETED
│   ├── test_handshake.zig         □ TODO
│   ├── test_path.zig              □ TODO
│   ├── test_amplification.zig     □ TODO
│   ├── test_pmtud.zig             □ TODO
│   ├── test_limits.zig            □ TODO
│   ├── test_flow_control.zig      □ TODO
│   ├── test_error.zig             □ TODO
│   └── test_idle.zig              □ TODO
│
├── frame/              # Frame module tests (RFC 9000 §19, RFC 9221)
│   ├── test_types.zig            ✓ COMPLETED
│   ├── test_misc.zig             □ TODO
│   ├── test_crypto.zig           □ TODO
│   ├── test_stream.zig           □ TODO
│   ├── test_ack.zig              □ TODO
│   ├── test_path.zig             □ TODO
│   ├── test_connection_mgmt.zig  □ TODO
│   ├── test_flow_control.zig     □ TODO
│   └── test_datagram.zig         □ TODO
│
├── packet/             # Packet module tests (RFC 9000 §17, RFC 9001 §5)
│   ├── test_types.zig            □ TODO
│   ├── test_header.zig           □ TODO
│   └── test_packet.zig           □ TODO
│
├── version/            # Version negotiation tests (RFC 9000 §6, RFC 9369)
│   └── test_version.zig          □ TODO
│
├── recovery/           # Recovery module tests (RFC 9002)
│   ├── test_types.zig            □ TODO
│   ├── test_rtt.zig              □ TODO
│   ├── test_loss_detection.zig   □ TODO
│   ├── test_congestion.zig       □ TODO
│   └── test_recovery.zig         □ TODO
│
└── endpoint/           # Endpoint module tests (RFC 9000 §7-8)
    ├── test_types.zig            ✓ COMPLETED
    ├── test_timer.zig            □ TODO
    ├── test_lookup.zig           □ TODO
    ├── test_io.zig               □ TODO
    ├── test_client.zig           □ TODO
    ├── test_server.zig           □ TODO
    ├── test_incoming.zig         □ TODO
    └── test_pto.zig              □ TODO
```

## Completed Tests (7/40)

### Connection Modules
- ✓ `test_types.zig` - Role, SockAddr, Cid types (RFC 9000 §2-5)
- ✓ `test_crypto_buffer.zig` - Out-of-order CRYPTO frame reassembly (RFC 9000 §4.9.2)
- ✓ `test_packet_number.zig` - PN tracking, expansion, ACK generation (RFC 9000 §12.3, §13.2)
- ✓ `test_ack.zig` - ACK descriptor, ECN counters (RFC 9000 §19.3, RFC 3168)
- ✓ `test_stream.zig` - Stream RX/TX state, reassembly (RFC 9000 §2-4)
- ✓ `test_connection_id.zig` - CID management, stateless reset tokens (RFC 9000 §5, §10.3)

### Frame Modules
- ✓ `test_types.zig` - FrameType enum, AckRange, EcnCounts (RFC 9000 §19)

### Endpoint Modules
- ✓ `test_types.zig` - Timer, Key, EndpointRole types (RFC 9000 §5.1)

## Test Template Structure

Each test file follows this structure:

```zig
//! Unit tests for <module>/<file>.zig
//!
//! RFC References:
//! - RFC XXXX §Y.Z: Relevant section description
//! - RFC XXXX §A.B: Another relevant section
//!
//! Coverage:
//! - Positive cases: Normal operation scenarios
//! - Negative cases: Error conditions, invalid inputs
//! - Edge cases: Boundary values, wraparound, limits
//! - RFC compliance: Specific requirements from RFCs

const std = @import("std");
const testing = std.testing;

// Import module under test
const module = @import("relative/path/to/module.zig");

// =============================================================================
// Category 1: Basic Functionality Tests
// =============================================================================

test "RFC XXXX §Y.Z - Description of what is tested" {
    // Arrange
    // Act
    // Assert
}

// =============================================================================
// Category 2: Edge Cases and Boundaries
// =============================================================================

test "boundary: Description of boundary condition" {
    // ...
}

// =============================================================================
// Category 3: Negative Tests (Error Conditions)
// =============================================================================

test "negative: Description of error condition" {
    // ...
}

// =============================================================================
// Category 4: RFC Compliance Tests
// =============================================================================

test "RFC XXXX §Y.Z - Specific requirement verification" {
    // ...
}
```

## Module-Specific Test Requirements

### Connection Modules

#### handshake.zig (RFC 9001 §4, §8.2)
- [ ] TLS handshake state transitions
- [ ] ALPN negotiation
- [ ] Transport parameter encoding/decoding
- [ ] Key phase tracking
- [ ] Handshake completion detection

#### path.zig (RFC 9000 §9, §19.17-19.18)
- [ ] Path validation with CHALLENGE/RESPONSE
- [ ] Path migration detection
- [ ] Active path tracking
- [ ] Multi-path state management

#### amplification.zig (RFC 9000 §8.1)
- [ ] Anti-amplification limit tracking (3x)
- [ ] Limit enforcement before address validation
- [ ] Limit removal after validation
- [ ] Retry packet impact

#### pmtud.zig (RFC 9000 §14.2-14.4, RFC 8899)
- [ ] DPLPMTUD probe generation
- [ ] MTU discovery state machine
- [ ] Path MTU clamping
- [ ] Probe loss handling

#### limits.zig (RFC 9001 §6.6)
- [ ] AEAD usage limit tracking
- [ ] Key update trigger conditions
- [ ] Per-cipher suite limits
- [ ] Confidentiality/integrity limits

#### flow_control.zig (RFC 9000 §4)
- [ ] Window size tracking
- [ ] MAX_DATA/MAX_STREAM_DATA generation
- [ ] Blocked frame emission
- [ ] Window expansion logic

#### error.zig (RFC 9000 §10, §20)
- [ ] Error code validation
- [ ] CONNECTION_CLOSE frame generation
- [ ] Draining state timer
- [ ] Error propagation

#### idle.zig (RFC 9000 §10.1)
- [ ] Idle timeout negotiation
- [ ] Timer management
- [ ] Keepalive behavior
- [ ] Expiry detection

### Frame Modules (RFC 9000 §19)

#### misc.zig (§19.1-19.2, §19.7, §19.20)
- [ ] PADDING frame encoding/decoding
- [ ] PING frame encoding/decoding
- [ ] NEW_TOKEN frame encoding/decoding
- [ ] HANDSHAKE_DONE frame encoding/decoding

#### crypto.zig (§19.6)
- [ ] CRYPTO frame encoding with offset
- [ ] CRYPTO frame decoding
- [ ] Length validation
- [ ] Offset handling

#### stream.zig (§19.8)
- [ ] STREAM frame encoding with flags (OFF, LEN, FIN)
- [ ] Stream ID encoding
- [ ] Offset and length handling
- [ ] FIN bit semantics

#### ack.zig (§19.3)
- [ ] ACK frame encoding
- [ ] ACK range compression
- [ ] ECN count inclusion
- [ ] Largest acknowledged PN

#### path.zig (§19.17-19.18)
- [ ] PATH_CHALLENGE encoding/decoding
- [ ] PATH_RESPONSE encoding/decoding
- [ ] 8-byte data validation

#### connection_mgmt.zig (§19.4-19.5, §19.15-19.16, §19.19)
- [ ] RESET_STREAM encoding/decoding
- [ ] STOP_SENDING encoding/decoding
- [ ] NEW_CONNECTION_ID encoding/decoding
- [ ] RETIRE_CONNECTION_ID encoding/decoding
- [ ] Error code validation

#### flow_control.zig (§19.10-19.14)
- [ ] MAX_DATA encoding/decoding
- [ ] MAX_STREAM_DATA encoding/decoding
- [ ] MAX_STREAMS encoding/decoding
- [ ] *_BLOCKED frame encoding/decoding

#### datagram.zig (RFC 9221)
- [ ] DATAGRAM frame encoding/decoding
- [ ] Length field handling
- [ ] Unreliable delivery semantics

### Packet Modules

#### types.zig (RFC 9000 §17)
- [ ] PacketNumber type validation
- [ ] LongHeaderType enum
- [ ] Decoded* result structures
- [ ] QUIC version constants

#### header.zig (RFC 9000 §17.2-17.3)
- [ ] LongHeader structure validation
- [ ] ShortHeader structure validation
- [ ] Header protection readiness
- [ ] DCID/SCID handling

### Version Negotiation (RFC 9000 §6, RFC 9369)

#### version.zig
- [ ] Version parsing (v1: 0x00000001, v2: 0x6b3343cf)
- [ ] Version encoding
- [ ] VN packet encode/decode
- [ ] Downgrade protection
- [ ] Version selection algorithm

### Recovery Modules (RFC 9002)

#### types.zig (§2)
- [ ] CcState enum validation
- [ ] SentPacket structure
- [ ] PacketNumberSpace enum
- [ ] CUBIC constants

#### rtt.zig (§5, §6.2)
- [ ] RTT estimation (smoothed, rttvar)
- [ ] Initial RTT values
- [ ] RTT sample processing
- [ ] PTO calculation

#### loss_detection.zig (§6.1)
- [ ] Loss detection thresholds
- [ ] Packet/time threshold detection
- [ ] ACK-eliciting frame detection
- [ ] Loss event handling

#### congestion.zig (§7, Appendix B)
- [ ] NewReno congestion control
- [ ] CUBIC congestion control
- [ ] Slow start
- [ ] Congestion avoidance
- [ ] Fast recovery
- [ ] Pacing delay computation

### Endpoint Modules

#### timer.zig (RFC 9002 §6.2)
- [ ] Min-heap timer management
- [ ] Timer insertion/removal
- [ ] Next expiry calculation
- [ ] PTO timer handling

#### lookup.zig (RFC 9000 §5.1-5.2)
- [ ] Connection routing by CID
- [ ] Hash table operations
- [ ] CID collision handling
- [ ] Connection not found scenarios

#### io.zig (RFC 9000 §13.3, RFC 3168)
- [ ] UDP I/O operations
- [ ] ECN marking read/write
- [ ] Socket error handling
- [ ] Buffer management

#### client.zig (RFC 9000 §7)
- [ ] Client connection initiation
- [ ] Initial packet generation
- [ ] Address validation
- [ ] 0-RTT support

#### server.zig (RFC 9000 §7, §8.1)
- [ ] Server connection acceptance
- [ ] Address validation (Retry)
- [ ] Initial packet processing
- [ ] Connection establishment

#### incoming.zig (RFC 9000 §12-17)
- [ ] Incoming packet processing
- [ ] Packet type dispatch
- [ ] Decryption coordination
- [ ] Frame processing

#### pto.zig (RFC 9002 §6.2)
- [ ] PTO probe generation
- [ ] Probe packet construction
- [ ] Per-space probe selection
- [ ] ACK-eliciting content

## Running Tests

### Run All RFC Compliance Tests
```bash
zig build test
```

### Run Specific Module Tests
```bash
# Connection module tests
zig build test --test-filter test_crypto_buffer
zig build test --test-filter test_ack
zig build test --test-filter test_stream
zig build test --test-filter test_connection_id

# Frame module tests
zig build test --test-filter test_frame_types

# All connection tests
zig build test --test-filter connection
```

### Run Individual Test
```bash
zig test tests/unit/connection/test_crypto_buffer.zig
```

## Test Coverage Goals

- **Line Coverage**: ≥90% for all modules
- **Branch Coverage**: ≥85% for all modules
- **RFC Compliance**: 100% of MUST requirements tested
- **Edge Cases**: All boundary conditions covered

## Continuous Integration

All RFC compliance tests are run on:
- Every commit
- Every pull request
- Daily scheduled runs
- Before releases

## Documentation Requirements

Each test must include:
1. RFC section reference in test name
2. Clear description of what is being tested
3. Arrange-Act-Assert structure
4. Comments explaining non-obvious assertions

## Future Work

- [ ] Property-based testing with fuzzing
- [ ] Mutation testing for test quality
- [ ] Coverage reporting integration
- [ ] RFC requirement traceability matrix
- [ ] Automated test generation from RFC parsing

## References

- RFC 9000: QUIC Transport Protocol
- RFC 9001: Using TLS to Secure QUIC
- RFC 9002: QUIC Loss Detection and Congestion Control
- RFC 9221: QUIC Datagram Extension
- RFC 9369: QUIC Version 2
- RFC 3168: Explicit Congestion Notification
- RFC 8899: Packetization Layer Path MTU Discovery

## Completion Status

**Overall Progress**: 7/40 test files completed (17.5%)

### By Module Category
- Connection: 6/14 (42.9%)
- Frame: 1/9 (11.1%)
- Packet: 0/3 (0%)
- Version: 0/1 (0%)
- Recovery: 0/5 (0%)
- Endpoint: 1/8 (12.5%)

---

Last Updated: 2025-11-07
