# Tier 1 - Step 1: Connection Establishment Implementation Plan

## Executive Summary

**Goal**: Enable all 26 tests in `rfc9000_section7.zig` (RFC 9000 §7 - Connection Establishment)

**Current Status**: 2/26 tests passing (Phase 14, Phase 21)
- ✅ "Client sends Initial packet" (line 38)
- ✅ "Server responds with Initial packet" (line 78)

**Estimated Effort**: 24-30 hours (8-10 hours Initial encoding + 6-8 hours CRYPTO + 10-12 hours handshake)

**Date Started**: November 11, 2025

## Infrastructure Assessment

### What Already Exists ✅

1. **Initial Packet Encoding** (`src/quic/packet.zig:351-450`)
   - `encodeInitialProtected()` function (100 lines)
   - Long header encoding
   - Token handling
   - Packet number truncation
   - AEAD encryption with header protection
   - **Status**: COMPLETE

2. **Handshake Integration** (`src/quic/endpoint/handshake_integration.zig`)
   - 793 lines of TLS handshake integration code
   - CRYPTO frame processing helpers
   - Secret derivation callbacks
   - Key installation logic
   - **Status**: EXISTS but needs integration validation

3. **CRYPTO Frame** (`src/quic/frame/crypto.zig`)
   - Frame encoding/decoding
   - **Status**: EXISTS

4. **CryptoBuffer** (`src/quic/connection/crypto_buffer.zig`)
   - Out-of-order reassembly
   - Contiguous data delivery
   - **Status**: EXISTS

5. **Connection State** (`src/quic/conn.zig`)
   - Connection struct with handshake state
   - Packet number spaces
   - **Status**: EXISTS

6. **Test Infrastructure** (Phase 21)
   - packet_parsing_helpers.zig (450 lines)
   - ConnectionPair fixture
   - Loopback transport
   - **Status**: COMPLETE

### What Needs Implementation 📝

Based on the 24 skip tests, the following components need work:

#### 1. Initial Packet Validation (8 tests)

**Tests**:
- ✅ "Client sends Initial packet" (line 38) - PASSING
- ❌ "Initial packet contains CRYPTO frame with ClientHello" (line 59) - SKIP
- ❌ "Initial packet uses long header format" (line 64) - SKIP
- ❌ "Initial packet includes token if available" (line 69) - SKIP

**Required Work**:
- Packet capture and inspection in tests
- CRYPTO frame content validation
- Header format validation
- Token management validation

**Effort**: 3-4 hours

#### 2. Server Initial Response (5 tests)

**Tests**:
- ✅ "Server responds with Initial packet" (line 78) - PASSING
- ❌ "Server Initial contains CRYPTO frame with ServerHello" (line 97) - SKIP
- ❌ "Server sends ACK for client Initial" (line 102) - SKIP

**Required Work**:
- Server CRYPTO frame generation
- ACK frame generation for Initial packets
- ServerHello content validation

**Effort**: 3-4 hours

#### 3. Transport Parameters (3 tests)

**Tests**:
- ❌ "Transport parameters exchanged in TLS extensions" (line 111) - SKIP
- ❌ "Invalid transport parameters cause connection failure" (line 116) - SKIP
- ❌ "initial_source_connection_id must match" (line 121) - SKIP

**Required Work**:
- Transport parameter encoding/decoding (exists in transport_params module)
- Validation of transport parameters
- Connection ID validation

**Effort**: 2-3 hours

#### 4. Cryptographic Handshake (5 tests)

**Tests**:
- ❌ "Handshake completes successfully" (line 130) - SKIP
- ❌ "Handshake packets use Handshake packet type" (line 138) - SKIP
- ❌ "1-RTT keys derived after handshake" (line 143) - SKIP
- Plus 2 more handshake tests

**Required Work**:
- End-to-end handshake flow
- Handshake packet encoding (similar to Initial)
- Key derivation and installation
- Handshake completion detection

**Effort**: 8-10 hours

#### 5. Connection State Management (3 tests)

**Tests**:
- Connection establishment state tracking
- Idle timeout coordination
- Connection ID management

**Required Work**:
- State machine coordination
- Timeout management
- CID lifecycle

**Effort**: 3-4 hours

#### 6. Error Handling (3 tests)

**Tests**:
- Handshake failure scenarios
- Invalid packet handling
- Protocol violations

**Required Work**:
- Error code propagation
- Connection termination
- Error reporting

**Effort**: 3-4 hours

## Implementation Strategy

### Phase 1: Packet Inspection Infrastructure (4-5 hours)

**Goal**: Enable packet capture and validation in tests

**Tasks**:
1. Add packet capture to ConnectionPair
2. Implement packet inspection helpers
3. Add CRYPTO frame extraction
4. Add header format validation

**Deliverables**:
- Packet capture working in tests
- Helper functions for frame extraction
- 4 tests passing (Initial packet validation tests)

### Phase 2: Server Response Validation (3-4 hours)

**Goal**: Validate server Initial response content

**Tasks**:
1. Validate ServerHello in CRYPTO frame
2. Validate ACK frame generation
3. Validate coalesced packets (Initial + Handshake)

**Deliverables**:
- 3 additional tests passing (Server Initial response tests)

### Phase 3: Transport Parameters (2-3 hours)

**Goal**: Validate transport parameter exchange

**Tasks**:
1. Validate transport parameter encoding
2. Test invalid parameter handling
3. Test CID validation

**Deliverables**:
- 3 additional tests passing (Transport parameter tests)

### Phase 4: Handshake Completion (8-10 hours)

**Goal**: Complete end-to-end handshake flow

**Tasks**:
1. Implement Handshake packet encoding
2. Coordinate key installation
3. Implement HANDSHAKE_DONE frame
4. Validate 1-RTT key derivation

**Deliverables**:
- 5 additional tests passing (Handshake tests)
- Full handshake working end-to-end

### Phase 5: State Management & Errors (6-7 hours)

**Goal**: Complete remaining connection establishment tests

**Tasks**:
1. Connection state tracking
2. Idle timeout management
3. Error handling and reporting

**Deliverables**:
- 6 additional tests passing
- All 26 tests passing

## Test Enablement Checklist

### §7.1 - Client Initial Packet (4 tests)

- [x] ✅ Client sends Initial packet (line 38) - PASSING
- [ ] Initial packet contains CRYPTO frame with ClientHello (line 59)
- [ ] Initial packet uses long header format (line 64)
- [ ] Initial packet includes token if available (line 69)

### §7.2 - Server Initial Response (3 tests)

- [x] ✅ Server responds with Initial packet (line 78) - PASSING
- [ ] Server Initial contains CRYPTO frame with ServerHello (line 97)
- [ ] Server sends ACK for client Initial (line 102)

### §7.3 - Transport Parameter Exchange (3 tests)

- [ ] Transport parameters exchanged in TLS extensions (line 111)
- [ ] Invalid transport parameters cause connection failure (line 116)
- [ ] initial_source_connection_id must match (line 121)

### §7.4 - Cryptographic Handshake (16 tests)

- [ ] Handshake completes successfully (line 130)
- [ ] Handshake packets use Handshake packet type (line 138)
- [ ] 1-RTT keys derived after handshake (line 143)
- [ ] ... (13 more handshake tests to be identified)

## Success Criteria

### Functional Requirements

- [x] ✅ Client sends Initial packet with ClientHello
- [ ] Server processes Initial and sends Initial + Handshake
- [ ] Client processes Handshake and derives keys
- [ ] Handshake completes successfully
- [ ] Application keys installed
- [ ] Transport parameters exchanged and validated
- [ ] Connection ID management working
- [ ] Error scenarios handled correctly

### Test Requirements

- [x] 2/26 tests passing (current)
- [ ] 8/26 tests passing (after Phase 1-2)
- [ ] 11/26 tests passing (after Phase 3)
- [ ] 16/26 tests passing (after Phase 4)
- [ ] 26/26 tests passing (after Phase 5)

### Quality Requirements

- [ ] No test suite regressions
- [ ] 99.7% pass rate maintained (1668/1673 tests)
- [ ] All new code documented
- [ ] Implementation matches RFC 9000 §7

## Timeline

**Total Effort**: 24-30 hours

**Breakdown**:
- Phase 1 (Packet Inspection): 4-5 hours
- Phase 2 (Server Response): 3-4 hours
- Phase 3 (Transport Params): 2-3 hours
- Phase 4 (Handshake): 8-10 hours
- Phase 5 (State & Errors): 6-7 hours

**Estimated Duration**: 3-4 weeks (assuming 8 hours/week)

## Risk Assessment

### High Risk

1. **TLS Handshake Complexity**
   - Risk: TLS state machine integration may uncover edge cases
   - Mitigation: Use existing handshake_integration.zig infrastructure
   - Contingency: Focus on happy path first, defer edge cases

2. **Packet Number Space Coordination**
   - Risk: Initial, Handshake, and Application spaces must coordinate
   - Mitigation: Follow RFC 9000 §12.3 closely
   - Contingency: Use existing packet_number.zig helpers

### Medium Risk

1. **Key Installation Timing**
   - Risk: Keys must be installed at correct times
   - Mitigation: Follow RFC 9001 §4.1.1 state machine
   - Contingency: Add extensive logging for debugging

2. **CRYPTO Frame Reassembly**
   - Risk: Out-of-order delivery requires reassembly
   - Mitigation: Use existing crypto_buffer.zig
   - Contingency: Start with in-order delivery, add out-of-order later

### Low Risk

1. **Packet Capture in Tests**
   - Risk: Test infrastructure may need enhancement
   - Mitigation: Minimal changes to existing ConnectionPair
   - Contingency: Use packet inspector helpers from Phase 21

## Dependencies

### Internal Dependencies

- ✅ Phase 21 infrastructure (packet_parsing_helpers.zig)
- ✅ ConnectionPair fixture
- ✅ Loopback transport
- ✅ Initial packet encoding (encodeInitialProtected)
- ✅ Handshake integration module
- ✅ CRYPTO frame and CryptoBuffer

### External Dependencies

- ✅ TLS 1.3 implementation (vendor/ztls)
- ✅ Cryptography primitives (src/quic/crypto_quic.zig)
- ✅ Transport parameters (transport_params module)

### No Blocking Dependencies

All required infrastructure exists. Implementation can proceed immediately.

## Next Steps

1. **Immediate** (today):
   - Start Phase 1: Packet Inspection Infrastructure
   - Add packet capture to ConnectionPair
   - Implement basic packet inspection helpers

2. **This Week** (days 1-3):
   - Complete Phase 1
   - Complete Phase 2
   - Start Phase 3

3. **Next Week** (days 4-7):
   - Complete Phase 3
   - Start Phase 4 (handshake)

4. **Week 3** (days 8-14):
   - Complete Phase 4
   - Start Phase 5

5. **Week 4** (days 15-21):
   - Complete Phase 5
   - Validate all 26 tests
   - Document implementation

## References

- `tests/integration/rfc9000_section7.zig`: Test file (26 tests)
- `tests/integration/TEST_ENABLEMENT_GUIDE.md`: Overall roadmap
- `src/quic/packet.zig`: Initial packet encoding
- `src/quic/endpoint/handshake_integration.zig`: TLS integration
- `src/quic/connection/crypto_buffer.zig`: CRYPTO frame reassembly
- `RFC 9000 §7`: Connection Establishment specification
- `RFC 9001 §4`: TLS Integration specification

---

**Status**: Planning complete, ready to begin implementation
**Next Action**: Start Phase 1 - Packet Inspection Infrastructure
**Owner**: Implementation team
**Date**: November 11, 2025
