# QUIC Test Enablement Guide

## Overview

This guide provides a comprehensive roadmap for enabling the 474 skip tests in the QUIC test suite using the infrastructure built in Phases 21-24. It serves as the practical handbook for systematically moving from test infrastructure to enabled, passing tests.

**Target Audience**: Developers implementing QUIC features and enabling corresponding tests.

**Prerequisite**: Complete understanding of Phases 21-24 infrastructure (see ENDPOINT_INTEGRATION_GUIDE.md).

## Executive Summary

**Current Status**:
- ✅ **474 skip tests** documented and ready
- ✅ **6 helper modules** (~3,500 lines) providing test infrastructure
- ✅ **43 infrastructure tests** passing (100% helper coverage)
- ✅ **CI/CD automation** ready for production

**Goal**: Systematically enable all 474 skip tests by implementing required QUIC features.

**Estimated Effort**: 200-300 hours (12-18 weeks) for full implementation.

## Test Enablement Roadmap

### Phase Progression

The test enablement process follows the priority tiers established in Phases 21-23:

```
Phase 21 Infrastructure → Tier 1 Tests (84 tests, 18%)
    ↓
Phase 22 Infrastructure → Tier 2 Tests (127 tests, 26%)
    ↓
Phase 23 Infrastructure → Tier 3 Tests (263 tests, 56%)
    ↓
Phase 24 CI/CD → Automated Validation (100%)
```

### Priority Framework

Tests are prioritized based on:

1. **Dependency Order**: Features required by other features come first
2. **RFC Compliance**: Core protocol features (RFC 9000 §7-13) before advanced features
3. **Risk Impact**: High-risk areas (handshake, packet encoding) before edge cases
4. **Development Effort**: Quick wins (validation helpers) before complex features (0-RTT)

## Tier 1: High Priority Tests (84 tests, 18% coverage)

**Goal**: Enable core QUIC functionality - connection establishment, packet processing, loss recovery.

**Prerequisites**: Phases 21.1-21.5 infrastructure complete ✅

**Estimated Effort**: 60-80 hours (4-5 weeks)

### Step 1: Connection Establishment (RFC 9000 §7)

**Tests to Enable**: 26 tests in `rfc9000_section7.zig`

**Required Implementation**:

1. **Initial Packet Encoding** (8-10 hours):
   ```zig
   // src/quic/packet/initial.zig
   pub fn encodeInitialPacket(
       conn: *Connection,
       dcid: []const u8,
       scid: []const u8,
       token: []const u8,
       payload: []const u8,
   ) ![]u8 {
       // Encode long header with Initial type
       // Add token length and token
       // Add length field (varint)
       // Add packet number (encoded and truncated)
       // Apply header protection
       // Apply AEAD encryption
   }
   ```

2. **CRYPTO Frame Handling** (6-8 hours):
   ```zig
   // Already exists: src/quic/connection/crypto_buffer.zig
   // Integration needed in endpoint/incoming.zig:

   pub fn processCryptoFrame(
       conn: *Connection,
       frame: frame.CryptoFrame,
   ) !void {
       // Add to CryptoBuffer for reassembly
       // Deliver to TLS when contiguous
       // Process TLS messages
       // Generate response CRYPTO frames
   }
   ```

3. **Handshake State Machine** (10-12 hours):
   ```zig
   // Already exists: src/quic/connection/handshake.zig
   // Integration needed in Connection:

   pub fn updateHandshakeState(
       conn: *Connection,
       event: HandshakeEvent,
   ) !void {
       // Track handshake progress
       // Coordinate packet number spaces
       // Install keys at appropriate times
       // Mark handshake complete
   }
   ```

**Validation**:
```bash
# Enable tests by removing `return error.SkipZigTest;`
zig build test --test-filter "RFC 9000 §7"

# Expected: 26/26 tests passing
```

**Success Criteria**:
- ✅ Client sends Initial packet with ClientHello
- ✅ Server processes Initial and sends Initial + Handshake
- ✅ Client processes Handshake and derives keys
- ✅ Handshake completes successfully
- ✅ Application keys installed

### Step 2: Loss Recovery (RFC 9002)

**Tests to Enable**: 26 tests in `rfc9002_recovery.zig`

**Required Implementation**:

1. **RTT Estimation** (4-5 hours):
   ```zig
   // Already exists: src/quic/recovery/rtt.zig
   // Integration needed in Connection:

   pub fn updateRtt(
       conn: *Connection,
       ack_delay_us: u64,
       packet_sent_time: i64,
   ) void {
       // Update smoothed_rtt and rttvar
       // Track min_rtt
       // Use for PTO calculation
   }
   ```

2. **Loss Detection** (8-10 hours):
   ```zig
   // Already exists: src/quic/recovery/loss_detection.zig
   // Integration needed:

   pub fn detectLostPackets(
       conn: *Connection,
       pn_space: PacketNumberSpace,
   ) ![]LostPacket {
       // Check packet threshold (3 packets)
       // Check time threshold (9/8 * max_ack_delay)
       // Mark packets as lost
       // Trigger retransmission
   }
   ```

3. **PTO Timers** (6-8 hours):
   ```zig
   // Already exists: src/quic/endpoint/pto.zig
   // Integration needed:

   pub fn calculatePto(
       conn: *Connection,
       pn_space: PacketNumberSpace,
   ) u64 {
       // PTO = smoothed_rtt + max(4*rttvar, 1ms) + max_ack_delay
       // Apply backoff if PTO count > 0
       // Use for probe packet generation
   }
   ```

**Validation**:
```bash
zig build test --test-filter "RFC 9002"
# Expected: 26/26 tests passing
```

**Success Criteria**:
- ✅ RTT estimation converges to actual RTT
- ✅ Lost packets detected within time threshold
- ✅ PTO triggers probe packet generation
- ✅ Retransmissions succeed
- ✅ Congestion control responds appropriately

### Step 3: Packet Processing (RFC 9000 §12-17)

**Tests to Enable**: 32 tests in `rfc9000_packets.zig`

**Required Implementation**:

1. **Packet Number Handling** (4-5 hours):
   ```zig
   // Already exists: src/quic/connection/packet_number.zig
   // Integration needed:

   pub fn decodePacketNumber(
       largest_pn: u64,
       truncated_pn: u32,
       pn_nbits: u8,
   ) u64 {
       // Expand truncated PN to full PN
       // Use largest acknowledged PN as reference
   }
   ```

2. **ACK Frame Processing** (6-8 hours):
   ```zig
   // Already exists: src/quic/connection/ack.zig
   // Integration needed:

   pub fn processAckFrame(
       conn: *Connection,
       ack_frame: frame.AckFrame,
       pn_space: PacketNumberSpace,
   ) !void {
       // Mark packets as acknowledged
       // Update RTT if largest acknowledged is new
       // Detect lost packets
       // Update congestion window
   }
   ```

3. **Coalesced Packets** (4-5 hours):
   ```zig
   // Integration needed in endpoint/incoming.zig:

   pub fn processCoalescedPackets(
       endpoint: *Endpoint,
       datagram: []const u8,
   ) !void {
       // Parse multiple QUIC packets from single UDP datagram
       // Process each packet in order
       // Handle mixed packet types (Initial + Handshake)
   }
   ```

**Validation**:
```bash
zig build test --test-filter "RFC 9000 Packets"
# Expected: 32/32 tests passing
```

**Success Criteria**:
- ✅ Packet numbers decoded correctly
- ✅ ACK frames processed accurately
- ✅ Coalesced packets handled properly
- ✅ Header protection applied/removed correctly

## Tier 2: Medium Priority Tests (127 tests, 26% coverage)

**Goal**: Enable medium priority features - address validation, connection migration, flow control.

**Prerequisites**: Tier 1 tests passing, Phase 22 infrastructure complete ✅

**Estimated Effort**: 70-90 hours (5-6 weeks)

### Step 4: Address Validation (RFC 9000 §8)

**Tests to Enable**: 30 tests in `rfc9000_section8.zig`

**Required Implementation**:

1. **PATH_CHALLENGE Generation** (4-5 hours):
   ```zig
   // src/quic/endpoint/path_validation.zig (new file)

   pub fn sendPathChallenge(
       conn: *Connection,
       path: *Path,
   ) !void {
       // Generate 8 random bytes
       // Send PATH_CHALLENGE frame
       // Start validation timer
       // Track pending challenges
   }
   ```

2. **PATH_RESPONSE Processing** (3-4 hours):
   ```zig
   pub fn processPathResponse(
       conn: *Connection,
       response: frame.PathResponseFrame,
   ) !void {
       // Match response data with pending challenge
       // Mark path as validated
       // Cancel validation timer
       // Update connection state
   }
   ```

3. **Anti-Amplification** (3-4 hours):
   ```zig
   // Already exists: src/quic/connection/amplification.zig
   // Integration needed:

   pub fn checkAmplificationLimit(
       conn: *Connection,
       packet_size: usize,
   ) bool {
       // Limit: 3x bytes received before validation
       // Allow unlimited after address validation
   }
   ```

**Validation**:
```bash
zig build test --test-filter "RFC 9000 §8"
# Expected: 30/30 tests passing
```

### Step 5: Connection Migration (RFC 9000 §9)

**Tests to Enable**: 46 tests in `migration.zig`

**Required Implementation**:

1. **Client-Initiated Migration** (8-10 hours):
   ```zig
   pub fn initiateConnectionMigration(
       conn: *Connection,
       new_local_addr: SockAddr,
   ) !void {
       // Create new path
       // Send PATH_CHALLENGE on new path
       // Continue on old path until validated
       // Switch to new path when validated
   }
   ```

2. **NAT Rebinding Detection** (5-7 hours):
   ```zig
   pub fn handleNatRebinding(
       conn: *Connection,
       new_peer_addr: SockAddr,
   ) !void {
       // Detect peer address change
       // Send PATH_CHALLENGE to new address
       // Update path if validated
   }
   ```

3. **Path Validation Requirement** (4-5 hours):
   ```zig
   pub fn validateMigrationPath(
       conn: *Connection,
       old_path: *Path,
       new_path: *Path,
   ) !void {
       // Ensure PATH_CHALLENGE sent before migration
       // Verify PATH_RESPONSE received
       // Update active path only after validation
   }
   ```

**Validation**:
```bash
zig build test --test-filter "migration"
# Expected: 46/46 tests passing
```

### Step 6: Flow Control (RFC 9000 §4)

**Tests to Enable**: 51 tests in `flow_control.zig`

**Required Implementation**:

1. **Connection-Level Flow Control** (5-6 hours):
   ```zig
   // Already exists: src/quic/connection/flow_control.zig
   // Integration needed:

   pub fn updateConnectionFlowControl(
       conn: *Connection,
       bytes_sent: u64,
   ) !void {
       // Track bytes sent
       // Check against max_data limit
       // Send DATA_BLOCKED if blocked
       // Process MAX_DATA updates
   }
   ```

2. **Stream-Level Flow Control** (6-8 hours):
   ```zig
   pub fn updateStreamFlowControl(
       stream: *Stream,
       bytes_sent: u64,
   ) !void {
       // Track bytes sent per stream
       // Check against max_stream_data limit
       // Send STREAM_DATA_BLOCKED if blocked
       // Process MAX_STREAM_DATA updates
   }
   ```

3. **Flow Control Auto-Tuning** (4-5 hours):
   ```zig
   pub fn autoTuneFlowControl(
       conn: *Connection,
   ) void {
       // Increase limits based on consumption rate
       // Send MAX_DATA / MAX_STREAM_DATA frames
       // Prevent receiver from blocking sender
   }
   ```

**Validation**:
```bash
zig build test --test-filter "flow_control"
# Expected: 51/51 tests passing
```

## Tier 3: Low Priority Tests (263 tests, 56% coverage)

**Goal**: Enable advanced features - key updates, 0-RTT, stress testing, fault injection, interoperability.

**Prerequisites**: Tiers 1-2 passing, Phase 23 infrastructure complete ✅

**Estimated Effort**: 80-120 hours (6-8 weeks)

### Step 7: Key Updates (RFC 9001 §6)

**Tests to Enable**: 52 tests in `key_update.zig`

**Required Implementation**:

1. **Key Update Initiation** (8-10 hours):
   ```zig
   // src/quic/connection/key_update.zig (new file)

   pub fn initiateKeyUpdate(
       conn: *Connection,
   ) !void {
       // Toggle key phase bit
       // Derive new keys using HKDF-Expand-Label
       // Update crypto context
       // Start using new keys
   }
   ```

2. **Key Phase Tracking** (5-6 hours):
   ```zig
   pub fn processKeyPhaseChange(
       conn: *Connection,
       packet_key_phase: u1,
   ) !void {
       // Detect key phase bit change
       // Derive corresponding keys
       // Update local key phase
       // Acknowledge with new key phase
   }
   ```

3. **AEAD Usage Limits** (4-5 hours):
   ```zig
   // Already exists: src/quic/connection/limits.zig
   // Integration needed:

   pub fn checkAeadLimits(
       conn: *Connection,
   ) bool {
       // Track packets encrypted with current keys
       // Trigger key update when approaching limit
       // RFC 9001 §6.6: limits depend on cipher
   }
   ```

**Validation**:
```bash
zig build test --test-filter "key_update"
# Expected: 52/52 tests passing
```

### Step 8: 0-RTT and Session Resumption (RFC 9001 §4.6)

**Tests to Enable**: 62 tests in `zero_rtt.zig`

**Required Implementation**:

1. **Session Ticket Generation** (8-10 hours):
   ```zig
   // Integration with vendor/ztls:

   pub fn generateSessionTicket(
       conn: *Connection,
   ) !SessionTicket {
       // Generate ticket via TLS
       // Include transport parameters
       // Set max_early_data_size
       // Store for resumption
   }
   ```

2. **0-RTT Packet Support** (10-12 hours):
   ```zig
   pub fn send0RttPacket(
       conn: *Connection,
       early_data: []const u8,
   ) !void {
       // Use 0-RTT keys derived from ticket
       // Send with packet type 0x01
       // Track early data sent
       // Handle acceptance/rejection
   }
   ```

3. **Anti-Replay Protection** (6-8 hours):
   ```zig
   pub fn validate0RttPacket(
       conn: *Connection,
       packet: []const u8,
   ) !void {
       // Check ticket validity
       // Verify replay protection token
       // Accept or reject early data
       // Send appropriate response
   }
   ```

**Validation**:
```bash
zig build test --test-filter "zero_rtt"
# Expected: 62/62 tests passing
```

### Step 9: Stress and Fault Injection

**Tests to Enable**: 93 tests in `stress.zig` and fault injection tests

**Required Implementation**:

1. **Concurrent Connection Management** (8-10 hours):
   ```zig
   // Optimize endpoint for 100+ concurrent connections:
   - Connection pool management
   - Memory optimization
   - CPU-efficient timer management
   - Lock-free data structures where possible
   ```

2. **Fault Recovery** (10-12 hours):
   ```zig
   // Ensure robust error handling:
   - Packet corruption detection and recovery
   - Duplicate packet handling
   - Out-of-order reassembly
   - Timeout recovery with exponential backoff
   ```

**Validation**:
```bash
zig build test --test-filter "stress"
zig build test --test-filter "fault"
# Expected: All stress and fault injection tests passing
```

### Step 10: Interoperability

**Tests to Enable**: 40 tests for cross-implementation testing

**Required Implementation**:

1. **External Implementation Integration** (10-15 hours):
   ```bash
   # Setup Docker containers for:
   - quiche (Cloudflare)
   - quinn (Rust)
   - aioquic (Python)
   - quic-go (Go)

   # Create test harness for cross-implementation testing
   ```

2. **Compliance Test Suite** (8-10 hours):
   ```bash
   # Integrate with QUIC Interop Runner
   # Run against compliance test suite
   # Document compatibility matrix
   ```

**Validation**:
```bash
zig build test --test-filter "interop"
# Expected: Handshake + data transfer with all implementations
```

## Test Enablement Process

### Step-by-Step Workflow

For each test to enable:

1. **Understand Test Requirements**:
   ```bash
   # Read test code
   less tests/integration/rfc9000_section7.zig

   # Check helper API
   less tests/integration/connection_establishment_helpers.zig

   # Review RFC section
   open https://www.rfc-editor.org/rfc/rfc9000.html#section-7
   ```

2. **Implement Required Feature**:
   ```bash
   # Create/modify implementation file
   vim src/quic/connection/crypto.zig

   # Add unit tests
   vim src/quic/connection/test_crypto.zig

   # Verify unit tests pass
   zig build test --test-filter "test_crypto"
   ```

3. **Enable Integration Test**:
   ```zig
   // In tests/integration/rfc9000_section7.zig:

   test "RFC 9000 §7.1 - Client sends Initial packet" {
       // Remove: return error.SkipZigTest;

       const allocator = std.testing.allocator;
       var scenario = scenarios.Scenario.init(allocator);
       defer scenario.deinit();

       var pair = try scenario.createPair();
       defer pair.deinit();

       // Use helpers to verify behavior
       try connection_establishment_helpers.expectInitialPacket(
           allocator,
           pair.getCapturedPackets(),
       );
   }
   ```

4. **Verify Test Passes**:
   ```bash
   # Run specific test
   zig build test --test-filter "RFC 9000 §7.1"

   # Run all tests in file
   zig build test tests/integration/rfc9000_section7.zig

   # Verify no regressions
   zig build test
   ```

5. **Update Documentation**:
   ```markdown
   # Update IMPLEMENTATION_SUMMARY.md:
   - ✅ RFC 9000 §7.1: Client sends Initial packet (1/26)

   # Update test enablement tracking
   ```

### Continuous Validation

Use Phase 24 CI/CD infrastructure:

```yaml
# .github/workflows/ci.yml already configured
# Automatic validation on every push:
- Build and test (all platforms)
- Code coverage tracking
- Performance regression detection
- Test result aggregation
```

## Success Metrics

### Test Coverage Progression

Track progress through test enablement:

```
Current:  474/474 skip tests (0% enabled)
          43/43 infrastructure tests (100% passing)

Tier 1:   84/474 tests enabled (18%)
Tier 2:   211/474 tests enabled (44%)
Tier 3:   474/474 tests enabled (100%)
```

### Code Coverage Targets

Maintain high code coverage as tests are enabled:

```
Target:   80% overall coverage (Phase 24 CI/CD threshold)
Current:  TBD (enable coverage tracking in CI)

Per-module targets:
- endpoint.zig: 85%+
- conn.zig: 85%+
- packet encoding/decoding: 90%+
- frame processing: 85%+
- recovery: 85%+
```

### Performance Benchmarks

Track performance as features are implemented:

```
Handshake latency:    < 50ms (localhost)
Throughput:          > 1 Gbps (localhost)
Concurrent conns:    > 1000 connections
Memory per conn:     < 100 KB
```

## Troubleshooting Guide

### Common Issues

**Issue 1: Test fails after removing `return error.SkipZigTest;`**

**Cause**: Required feature not yet implemented.

**Solution**:
```bash
# Read test to understand requirements
# Check helper function expectations
# Implement missing functionality
# Verify with unit tests first
```

**Issue 2: Test passes in isolation but fails in CI**

**Cause**: Race condition or resource leak.

**Solution**:
```bash
# Run test multiple times
for i in {1..100}; do zig build test --test-filter "testname"; done

# Check for resource leaks
valgrind --leak-check=full ./test-binary

# Use thread sanitizer
zig build test -Doptimize=Debug -Dasan=true
```

**Issue 3: Performance regression detected in CI**

**Cause**: Inefficient implementation or N^2 algorithm.

**Solution**:
```bash
# Profile the code
perf record -g ./benchmark
perf report

# Use Zig's built-in profiler
zig build test -Doptimize=ReleaseFast --summary all
```

## Maintenance Guide

### Keeping Tests Green

**Daily**:
- Monitor CI results
- Fix any test failures within 24 hours
- Respond to performance regressions

**Weekly**:
- Review code coverage reports
- Update test enablement tracking
- Triage new test failures

**Monthly**:
- Review skip test list
- Plan next wave of test enablement
- Update benchmarks

### Adding New Tests

When adding new QUIC features:

1. **Create skip test first**:
   ```zig
   test "RFC XXXX §Y - New feature" {
       return error.SkipZigTest;

       // TODO: Implement feature
       // TODO: Add helper functions
       // TODO: Enable test
   }
   ```

2. **Document in skip test list**:
   ```markdown
   - RFC XXXX §Y: New feature (1 test)
     - Requires: Feature implementation
     - Helper: new_feature_helpers.zig
     - Priority: Tier 1/2/3
   ```

3. **Follow enablement process** (see above)

## Conclusion

This guide provides a systematic approach to enabling all 474 skip tests in the QUIC test suite. By following the tier-based prioritization and step-by-step workflow, developers can progressively enable tests as QUIC features are implemented.

**Key Takeaways**:

1. ✅ **Infrastructure Ready**: Phases 21-24 provide complete test infrastructure
2. ✅ **Clear Roadmap**: Tier-based prioritization ensures efficient progress
3. ✅ **Validated Approach**: CI/CD automation validates every step
4. ✅ **Comprehensive Coverage**: All 474 tests documented and ready
5. ✅ **Practical Guidance**: Step-by-step workflows for implementation

**Estimated Timeline**:

- **Tier 1** (84 tests): 4-5 weeks
- **Tier 2** (127 tests): 5-6 weeks
- **Tier 3** (263 tests): 6-8 weeks
- **Total**: 15-19 weeks (4-5 months) for complete implementation

**Next Steps**:

1. Review this guide thoroughly
2. Set up Phase 24 CI/CD (copy .github/workflows/ci.yml.template)
3. Begin with Tier 1, Step 1 (Connection Establishment)
4. Enable tests incrementally using the provided workflow
5. Maintain test coverage and performance benchmarks
6. Document progress in IMPLEMENTATION_SUMMARY.md

**Success**: All 474 tests enabled and passing, full RFC 9000/9001/9002 compliance achieved.
