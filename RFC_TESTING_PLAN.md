# RFC-Based Unit Testing Plan for QUIC Implementation

## Overview

This document outlines a comprehensive, phased approach to adding RFC-compliant unit tests for all 21 modules in the QUIC implementation. Each module will receive both **positive tests** (correct behavior) and **negative tests** (error handling, boundary conditions).

## Testing Philosophy

### RFC-Driven Testing
- Every test case must reference specific RFC section(s)
- Tests validate compliance with MUST, MUST NOT, SHOULD, and SHOULD NOT requirements
- Negative tests verify protocol violation detection and proper error handling

### Test Structure
Each module test file follows this pattern:
```zig
//! Unit tests for <module_name>
//!
//! RFC References: <list of relevant RFC sections>
//!
//! Coverage:
//! - Positive cases: <summary>
//! - Negative cases: <summary>
//! - Edge cases: <summary>
//! - RFC compliance: <summary>

const std = @import("std");
const testing = std.testing;
const module = @import("<module_path>");

// Positive test cases
test "RFC XXXX §Y.Z - <requirement description>" { ... }

// Negative test cases
test "RFC XXXX §Y.Z - rejects invalid <condition>" { ... }

// Edge cases
test "boundary: <edge condition>" { ... }
```

### Test Coverage Requirements

For each module, tests must cover:
1. **Positive Cases**: All documented functionality works correctly
2. **Negative Cases**: Invalid inputs/states are rejected appropriately
3. **Edge Cases**: Boundary conditions (0, max values, wraparound, etc.)
4. **RFC Compliance**: Explicit validation of MUST/MUST NOT requirements
5. **State Transitions**: For stateful modules, all valid and invalid transitions

## Module Inventory

### Connection Modules (12 modules, 747 lines)
1. `connection/types.zig` (68 lines) - RFC 9000 §2-5
2. `connection/crypto_buffer.zig` (165 lines) - RFC 9000 §4.9.2, RFC 9001 §4
3. `connection/packet_number.zig` (137 lines) - RFC 9000 §12.3, §13.2, Appendix A.3
4. `connection/ack.zig` (24 lines) - RFC 9000 §13.2, §19.3, RFC 3168
5. `connection/stream.zig` (85 lines) - RFC 9000 §2-4, §19.8
6. `connection/connection_id.zig` (47 lines) - RFC 9000 §5.1-5.3, §10.3, §19.15
7. `connection/handshake.zig` (29 lines) - RFC 9001 §4, §8.2
8. `connection/path.zig` (16 lines) - RFC 9000 §9, §19.17-19.18
9. `connection/amplification.zig` (46 lines) - RFC 9000 §8.1
10. `connection/pmtud.zig` (29 lines) - RFC 9000 §14.2-14.4, RFC 8899
11. `connection/limits.zig` (26 lines) - RFC 9001 §6.6
12. `connection/connection.zig` (56 lines) - Integration

### Endpoint Modules (9 modules, 497 lines)
13. `endpoint/types.zig` (94 lines) - RFC 9000 §5.1
14. `endpoint/timer.zig` (119 lines) - RFC 9002 §6.2
15. `endpoint/lookup.zig` (49 lines) - RFC 9000 §5.1-5.2
16. `endpoint/io.zig` (56 lines) - RFC 9000 §13.3, RFC 3168
17. `endpoint/client.zig` (23 lines) - RFC 9000 §7
18. `endpoint/server.zig` (25 lines) - RFC 9000 §7, §8.1
19. `endpoint/incoming.zig` (28 lines) - RFC 9000 §12-17
20. `endpoint/pto.zig` (34 lines) - RFC 9002 §6.2
21. `endpoint/endpoint.zig` (69 lines) - Integration

## Phased Testing Approach

### Phase 1: Foundation Types & Utilities (Week 1)
**Target**: 3 modules, ~185 lines
- `connection/types.zig` - Core types (Role, SockAddr, Cid, SendFn)
- `endpoint/types.zig` - Endpoint types (Timer, Key, helpers)
- `connection/packet_number.zig` - PN expansion, truncation, ACK windows

**Priority**: CRITICAL - These are dependencies for all other modules

**Estimated Tests**: ~25-30 test cases
- SockAddr operations (IPv4/IPv6, equality, construction)
- Connection ID operations (validation, comparison)
- Packet number expansion algorithm (RFC 9000 §12.3, Appendix A.3)
- PnWindow tracking and ACK range building

### Phase 2: Core Protocol Modules (Week 2)
**Target**: 3 modules, ~214 lines
- `connection/crypto_buffer.zig` - Out-of-order CRYPTO frame reassembly
- `connection/ack.zig` - ACK generation, ECN counters
- `endpoint/timer.zig` - Min-heap timer management

**Priority**: HIGH - Core protocol functionality

**Estimated Tests**: ~30-35 test cases
- CRYPTO buffer out-of-order reassembly edge cases
- ACK range generation and compression
- ECN counter overflow and validation
- Timer heap operations (insert, pop, cancel)
- Timer priority ordering

### Phase 3: Connection Management (Week 3)
**Target**: 3 modules, ~161 lines
- `connection/stream.zig` - Stream state machine (RFC 9000 §2-4)
- `connection/connection_id.zig` - CID management, stateless reset
- `connection/handshake.zig` - TLS state, ALPN, transport params

**Priority**: HIGH - Connection lifecycle management

**Estimated Tests**: ~35-40 test cases
- Stream state transitions (all valid and invalid paths)
- Stream flow control enforcement
- CID rotation and retirement
- Stateless reset token derivation (RFC 9000 §10.3)
- Transport parameter encoding/decoding

### Phase 4: Path & Limits (Week 4)
**Target**: 4 modules, ~117 lines
- `connection/path.zig` - Path validation state
- `connection/amplification.zig` - Anti-amplification tracking
- `connection/pmtud.zig` - PMTUD state
- `connection/limits.zig` - AEAD usage limits

**Priority**: MEDIUM - Advanced features

**Estimated Tests**: ~25-30 test cases
- Path validation challenge/response
- Anti-amplification limit enforcement (RFC 9000 §8.1)
- PMTUD probe sizing (RFC 8899, RFC 9000 §14.2-14.4)
- AEAD confidentiality limit calculation (RFC 9001 §6.6)

### Phase 5: Endpoint Infrastructure (Week 5)
**Target**: 2 modules, ~105 lines
- `endpoint/lookup.zig` - Connection routing by CID hash
- `endpoint/io.zig` - UDP I/O, ECN marking

**Priority**: MEDIUM - Endpoint infrastructure

**Estimated Tests**: ~20-25 test cases
- CID hash collision handling
- Connection lookup by DCID
- ECN marking and validation (RFC 3168)
- UDP send/receive operations

### Phase 6: Endpoint Operations (Week 6)
**Target**: 4 modules, ~110 lines
- `endpoint/client.zig` - Client establishment
- `endpoint/server.zig` - Server acceptance
- `endpoint/incoming.zig` - Packet processing
- `endpoint/pto.zig` - PTO probe generation

**Priority**: MEDIUM - Endpoint operations

**Estimated Tests**: ~25-30 test cases
- Client connection initiation
- Server address validation (RFC 9000 §8.1)
- Packet header parsing and validation
- PTO timer calculation and probe generation (RFC 9002 §6.2)

### Integration Modules (Post Phase 6)
**Target**: 2 modules, ~125 lines
- `connection/connection.zig` - Connection coordinator
- `endpoint/endpoint.zig` - Endpoint coordinator

**Priority**: LOW - Mainly re-exports, covered by integration tests

**Estimated Tests**: ~10-15 test cases (sanity checks)

## Test Organization

### Directory Structure
```
tests/
├── unit/
│   ├── connection/
│   │   ├── test_types.zig
│   │   ├── test_packet_number.zig
│   │   ├── test_crypto_buffer.zig
│   │   ├── test_ack.zig
│   │   ├── test_stream.zig
│   │   ├── test_connection_id.zig
│   │   ├── test_handshake.zig
│   │   ├── test_path.zig
│   │   ├── test_amplification.zig
│   │   ├── test_pmtud.zig
│   │   └── test_limits.zig
│   └── endpoint/
│       ├── test_types.zig
│       ├── test_timer.zig
│       ├── test_lookup.zig
│       ├── test_io.zig
│       ├── test_client.zig
│       ├── test_server.zig
│       ├── test_incoming.zig
│       └── test_pto.zig
└── integration/  (existing tests remain here)
```

## Phase 1 Detailed Test Plan

### Module: `connection/types.zig`

#### Test File: `tests/unit/connection/test_types.zig`

**RFC Coverage**: RFC 9000 §2-5 (Connection roles, addresses, identifiers)

**Test Cases**:

1. **Role Operations**
   - Positive: Role.Client and Role.Server basic usage

2. **SockAddr - IPv4 Construction** (RFC 9000 §5)
   - Positive: `ipv4(127,0,0,1,443)` creates valid address
   - Positive: Port is correctly stored in network byte order
   - Edge: `ipv4(0,0,0,0,0)` - all zeros valid
   - Edge: `ipv4(255,255,255,255,65535)` - all max values valid

3. **SockAddr - IPv6 Construction** (RFC 9000 §5)
   - Positive: `ipv6(...)` creates valid address
   - Positive: Port is correctly stored in network byte order
   - Edge: IPv6 loopback ::1
   - Edge: IPv6 any address ::

4. **SockAddr - Equality** (RFC 9000 §5)
   - Positive: Identical addresses are equal
   - Negative: Different ports make addresses unequal
   - Negative: Different IPs make addresses unequal
   - Negative: IPv4 vs IPv6 with same port unequal

5. **SockAddr - Family Detection**
   - Positive: IPv4 returns AF.INET
   - Positive: IPv6 returns AF.INET6

6. **Cid (Connection ID) Operations** (RFC 9000 §5.1)
   - Positive: Zero-length CID is valid (RFC 9000 §5.1)
   - Positive: Max 20-byte CID is valid (RFC 9000 §5.1)
   - Negative: 21+ byte CID rejected (RFC 9000 §5.1 MUST NOT exceed 20)
   - Edge: CID equality comparison
   - Edge: CID hashing for lookup tables

7. **SendFn Integration**
   - Positive: SendFn can be called with valid parameters
   - Negative: Invalid buffer/address handled gracefully

**Estimated**: ~15 test cases

---

### Module: `endpoint/types.zig`

#### Test File: `tests/unit/endpoint/test_types.zig`

**RFC Coverage**: RFC 9000 §5.1 (Connection lookup), RFC 9002 §6.2 (Timers)

**Test Cases**:

1. **Timer Structure** (RFC 9002 §6.2)
   - Positive: Timer creation with deadline
   - Positive: Timer comparison by deadline
   - Edge: Two timers with same deadline
   - Edge: Timer with deadline 0
   - Edge: Timer with max u64 deadline

2. **Key Type** (RFC 9000 §5.1)
   - Positive: Key from CID bytes (0-20 bytes)
   - Positive: Key equality comparison
   - Positive: Key hashing for HashMap
   - Edge: Zero-length CID key
   - Edge: Max 20-byte CID key

3. **EndpointRole**
   - Positive: Client vs Server role distinction

**Estimated**: ~10 test cases

---

### Module: `connection/packet_number.zig`

#### Test File: `tests/unit/connection/test_packet_number.zig`

**RFC Coverage**:
- RFC 9000 §12.3 (Packet Number Encoding/Decoding)
- RFC 9000 §13.2 (ACK Generation)
- RFC 9000 Appendix A.3 (Sample Packet Number Decoding Algorithm)

**Test Cases**:

1. **PnWindow - Basic Tracking** (RFC 9000 §13.2)
   - Positive: Track first packet (PN=0)
   - Positive: Track sequential packets (0,1,2,3...)
   - Positive: Track out-of-order packets
   - Edge: Track only packet at PN=0
   - Edge: Track packets at window boundary (255-256)

2. **PnWindow - Sliding Window** (RFC 9000 §13.2)
   - Positive: Window slides forward as max increases
   - Positive: Old packets outside window are dropped
   - Negative: PN=1000 then PN=0 - old packet ignored
   - Edge: Window at PN space wraparound (near 2^62-1)

3. **PnWindow - ACK Range Building** (RFC 9000 §19.3)
   - Positive: Single packet returns first_range=0
   - Positive: Contiguous packets (0,1,2) returns first_range=2
   - Positive: Gap creates additional AckRange entry
   - Positive: Multiple gaps create multiple ranges
   - Edge: 256 contiguous packets fill window
   - Edge: Alternating packets (0,2,4,6...) create max ranges
   - Negative: Empty window returns 0 ranges

4. **expandTruncatedPn** (RFC 9000 §12.3, Appendix A.3)
   - Positive: expected=0, trunc=0x12, len=1 → 0x12
   - Positive: expected=0x100, trunc=0xfe, len=1 → 0xfe
   - Positive: expected=0xa82f30ea, trunc=0x9b32, len=2 → 0xa82f9b32 (RFC Appendix A.3)
   - Edge: Truncation length 1, 2, 3, 4 bytes
   - Edge: Wraparound near 2^64-1
   - Edge: Window boundary cases (candidate ± pn_hwin)
   - Negative: expected > trunc by more than half window → higher candidate
   - Negative: expected < trunc by more than half window → lower candidate

5. **PnWindow - RFC Compliance** (RFC 9000 §13.2)
   - RFC 9000 §13.2: "An endpoint SHOULD acknowledge all packets within 256 packets of the largest acknowledged"
   - Test: Verify window size is exactly 256

**Estimated**: ~25 test cases

---

## Success Criteria

### Per-Phase Criteria
- [ ] All test cases documented in detail
- [ ] 100% of module public APIs have positive tests
- [ ] 100% of RFC MUST/MUST NOT requirements have validation tests
- [ ] All boundary conditions have edge case tests
- [ ] All error paths have negative tests
- [ ] Tests compile and pass
- [ ] Code coverage measured and documented

### Overall Success Criteria
- [ ] All 21 modules have comprehensive unit tests
- [ ] Test suite runs in <10 seconds (unit tests should be fast)
- [ ] Documentation includes RFC section mapping
- [ ] CI/CD integration for automatic test execution
- [ ] Test coverage >90% for all modules

## Metrics

### Phase 1 Target Metrics
- **Test Files Created**: 3
- **Test Cases Written**: 50
- **Lines of Test Code**: ~600-800 lines
- **RFC Sections Validated**: 10+
- **Code Coverage**: >90% for Phase 1 modules

### Full Project Target Metrics
- **Test Files Created**: 21
- **Test Cases Written**: 200-240
- **Lines of Test Code**: ~4,000-5,000 lines
- **RFC Sections Validated**: 60+
- **Code Coverage**: >90% overall

## Timeline

- **Phase 1**: Days 1-7 (Foundation modules)
- **Phase 2**: Days 8-14 (Core protocol)
- **Phase 3**: Days 15-21 (Connection management)
- **Phase 4**: Days 22-28 (Path & limits)
- **Phase 5**: Days 29-35 (Endpoint infrastructure)
- **Phase 6**: Days 36-42 (Endpoint operations)

**Total Duration**: 6 weeks

## Next Steps

1. ✅ Review and approve this plan
2. ⏳ Create test directory structure
3. ⏳ Implement Phase 1 tests
4. ⏳ Measure code coverage for Phase 1
5. ⏳ Iterate on phases 2-6
6. ⏳ Final integration and CI/CD setup

---

*Last Updated: 2025-11-07*
*Status: Plan Complete - Ready for Phase 1 Execution*
