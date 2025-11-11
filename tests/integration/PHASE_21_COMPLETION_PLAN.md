# Phase 21: Enable Remaining Tier 1 Tests - Implementation Plan

**Status**: IN PROGRESS
**Goal**: Enable 84 Tier 1 skip tests across connection establishment, loss recovery, and packet processing
**Estimated Effort**: 11-16 hours (revised from strategic analysis)

## Executive Summary

Phase 21 enables the 84 highest-priority integration tests that validate core QUIC functionality. Unlike Phases 19-20 which used component validation to achieve 70-80% effort reduction, Phase 21 requires actual end-to-end implementation because the skip tests verify system behavior, not component existence.

**Key Achievement from Phase 14**: Production Endpoint integration complete - real endpoints now created via `initWithTransport()`, ConnectionPair infrastructure in place, first integration test compiling and executing.

**Current Blocker**: TLS handshake not completing - server never accepts connection, test times out after 1900+ poll() calls.

## Test Breakdown

### Tier 1 Tests (84 total):
1. **Connection Establishment** (RFC 9000 §7): 26 tests - `rfc9000_section7.zig`
2. **Loss Recovery** (RFC 9002): 26 tests - `rfc9002_recovery.zig`
3. **Packet Processing** (RFC 9000 packets): 32 tests - `rfc9000_packets.zig`

**Target**: 84/84 Tier 1 tests enabled and passing
**Current**: 1/84 tests enabled (compiles, hangs at runtime)

## Current Status (Post-Phase 14)

### ✅ Infrastructure Complete (Phase 14)
1. **Real Endpoint Integration**:
   - `Endpoint.initWithTransport()` working
   - `LoopbackTransportAdapter` provides Transport interface
   - ConnectionPair creates real client/server endpoints

2. **Connection Creation**:
   - `endpoint.connectClient()` creates Connection object
   - Connection IDs generated (DCID, SCID)
   - Connection registered in lookup tables
   - Config applied (ALPN, congestion control, etc.)

3. **Initial Packet Sending**:
   - `endpoint.clientSendInitialProbe()` called
   - Initial packet constructed with CRYPTO frame
   - Packet sent via transport adapter

4. **Packet Exchange**:
   - `endpoint.poll()` drives I/O
   - Loopback transport queues packets
   - Both endpoints call recv() via poll()

### ❌ Blocking Issues (Preventing Handshake Completion)

**Issue #1: Server Not Processing Initial Packet**
- Symptoms: Server endpoint never adds connection to `accepted` list
- Root Cause: TBD - need to trace packet processing in server endpoint
- Impact: Connection establishment fails, test times out

**Issue #2: TLS Handshake Not Completing**
- Symptoms: `handshake_done_sent` and `handshake_done_seen` never become true
- Root Cause: TBD - need to verify TLS context, CRYPTO frame processing
- Impact: `waitForHandshake()` times out

**Issue #3: Packet Processing Loop**
- Symptoms: Test hangs, poll() called 1900+ times before abort
- Root Cause: Wait loop continues indefinitely because server never accepts
- Impact: Test framework kills test with signal 6 (SIGABRT)

## Analysis of Current Behavior

### Test Execution Flow:
```
1. ConnectionPair.init()
   ✅ Creates loopback transport
   ✅ Creates client endpoint (SideA)
   ✅ Creates server endpoint (SideB)

2. ConnectionPair.connect()
   ✅ Calls client.endpoint.connectClient("127.0.0.1:443")
      ✅ Creates Connection object
      ✅ Generates random CIDs (DCID, SCID)
      ✅ Registers connection in lookup tables

   ✅ Calls client.endpoint.clientSendInitialProbe(client_conn)
      ✅ Derives Initial secrets from DCID
      ✅ Sets up client transport parameters
      ✅ Generates ClientHello via TLS
      ✅ Builds CRYPTO frame with ClientHello
      ✅ Pads to 1200 bytes minimum
      ✅ Protects packet with Initial keys
      ✅ Sends via transport (loopback queue)
      ✅ Arms Initial PTO timer

   ✅ Calls exchangePackets()
      ✅ client.endpoint.poll(0)
         ✅ Processes timers
         ✅ Calls transport.poll()
         ✅ Calls transport.recv() in loop
            ⚠️ No packets received (queue empty or wrong queue?)
         ✅ Processes expired timers
         ✅ Prunes closed connections

      ✅ server.endpoint.poll(0)
         ✅ Processes timers
         ✅ Calls transport.poll()
         ✅ Calls transport.recv() in loop
            ⚠️ Should receive Initial packet from client
            ❌ Packet not being processed correctly
         ✅ Processes expired timers
         ✅ Prunes closed connections

   ❌ Wait loop (max 1000ms, increment 10ms per iteration)
      Expected: 100 iterations = 200 poll calls
      Actual: 900+ iterations = 1900+ poll calls
      ❌ server.endpoint.accepted.items.len == 0 (never increases)
      ❌ Timeout, returns error.ServerConnectionTimeout
```

### Loopback Transport Flow:
```
Client sends Initial packet:
   1. client.endpoint.clientSendInitialProbe()
   2. Calls send_fn (senderPaced or direct)
   3. Eventually calls transport.send(peer, data)
   4. LoopbackTransportAdapter.sendFn()
      - self.side == .SideA
      - Calls loopback.sendAtoB(data)
      - Adds packet to queue_a_to_b

Server should receive Initial packet:
   1. server.endpoint.poll(0)
   2. Calls transport.recv(buf)
   3. LoopbackTransportAdapter.recvFn()
      - self.side == .SideB
      - Calls loopback.recvAtB(buf)
      - Should read from queue_a_to_b
      - Returns RecvResult{ .n = len, .peer = client_addr }
   4. endpoint.recvFrom() returns result
   5. endpoint.processIncomingDatagram(peer, data, ecn)
      ❌ Something fails here - packet not processed correctly
```

## Root Cause Investigation Plan

### Step 1: Verify Packet Transport (30 min)
**Goal**: Confirm packets are actually being queued and dequeued

**Tasks**:
1. Add debug logging to `LoopbackTransport.sendAtoB()` and `recvAtB()`
2. Add debug logging to `LoopbackTransportAdapter.sendFn()` and `recvFn()`
3. Run test and verify:
   - Initial packet is sent to queue_a_to_b
   - Server recv pulls packet from queue_a_to_b
   - Packet data is correct (not corrupted)

**Expected Output**:
```
[Client] sendFn: sending 1200 bytes to 127.0.0.1:443
[Loopback] sendAtoB: queued 1200 bytes
[Server] recvFn: checking queue_a_to_b
[Loopback] recvAtB: dequeued 1200 bytes
[Server] recv result: n=1200, peer=127.0.0.1:4433
```

### Step 2: Verify Packet Processing (1 hour)
**Goal**: Confirm server endpoint processes Initial packet correctly

**Tasks**:
1. Add debug logging to `endpoint.processIncomingDatagram()`
2. Add debug logging to `endpoint/incoming.zig` packet processing
3. Verify:
   - Packet reaches processIncomingDatagram()
   - Packet type identified as Initial
   - DCID lookup succeeds or creates new connection
   - Packet decryption succeeds
   - CRYPTO frame extracted
   - TLS handshake processes ClientHello

**Expected Behavior**:
- Server should create new connection for Initial packet
- Connection added to `endpoint.conns` map
- Server should derive Initial secrets from client's DCID
- Server should decrypt Initial packet payload
- Server should extract CRYPTO frame with ClientHello
- Server should process ClientHello via TLS context
- Server should generate ServerHello + Certificate + Finished
- Server should send Handshake packet back to client

### Step 3: Verify Server Acceptance (30 min)
**Goal**: Confirm server adds connection to `accepted` list

**Tasks**:
1. Find where server should call `endpoint.accepted.append(conn)`
2. Verify this code path is reached
3. Add debug logging before/after append
4. Check if there's a condition preventing append

**Expected Code Path**:
```zig
// In endpoint/server.zig or endpoint/incoming.zig
fn handleInitialPacket(...) {
    // Create new connection
    const conn = try createServerConnection(...);

    // Process ClientHello
    try conn.tls.processCrypto(...);

    // If handshake progressed, add to accepted list
    if (conn.handshake_state == .SomeState) {
        try endpoint.accepted.append(conn);
    }
}
```

### Step 4: Verify TLS Handshake (2 hours)
**Goal**: Confirm TLS handshake actually completes

**Tasks**:
1. Verify TLS context initialization (client & server)
2. Verify Initial secret derivation (RFC 9001 §5.2)
3. Verify ClientHello generation and parsing
4. Verify ServerHello generation and parsing
5. Verify Finished message exchange
6. Verify handshake_done_sent/seen flags set correctly

**Required Checks**:
- [ ] Client TLS context created with role=.Client
- [ ] Server TLS context created with role=.Server
- [ ] Initial secrets derived from client's original DCID
- [ ] ClientHello includes QUIC transport parameters extension
- [ ] Server accepts ClientHello and generates ServerHello
- [ ] Server sends Certificate + CertificateVerify + Finished
- [ ] Client verifies server certificate (or skips with allow_insecure)
- [ ] Client sends Finished message
- [ ] Both sides set handshake_done flags

## Implementation Tasks

Based on root cause analysis, implement fixes for identified issues.

### Task 1: Fix Packet Transport Issues (if found) (1-2 hours)
- Fix loopback queue routing
- Fix packet corruption issues
- Fix address matching issues

### Task 2: Fix Server Packet Processing (2-3 hours)
- Ensure server accepts Initial packets
- Ensure Initial packet decryption works
- Ensure CRYPTO frame extraction works
- Ensure new connection creation works

### Task 3: Fix Server Acceptance Logic (1 hour)
- Find correct place to append to accepted list
- Add missing condition checks
- Verify acceptance happens at right time

### Task 4: Fix TLS Handshake Integration (3-5 hours)
- Ensure TLS context properly initialized
- Ensure CRYPTO frame data flows to TLS
- Ensure TLS responses flow back to CRYPTO frames
- Ensure handshake completion detected
- Ensure handshake_done flags set

### Task 5: Enable Remaining Tests (2-3 hours)
- Enable all 84 Tier 1 tests
- Fix test-specific issues
- Verify all tests pass
- Document known limitations

## Success Criteria

### Minimal Success (First test passing):
- ✅ 1/84 tests compiling (achieved in Phase 14)
- ✅ Initial packet sent from client (achieved)
- ✅ Initial packet received by server (TBD)
- ✅ Server creates connection (TBD)
- ✅ Server sends Handshake packet (TBD)
- ✅ Handshake completes (TBD)
- ✅ Test passes without timeout (TBD)

### Full Success (All Tier 1 tests):
- ✅ 84/84 Tier 1 tests enabled
- ✅ Connection establishment tests pass (26/26)
- ✅ Loss recovery tests pass (26/26)
- ✅ Packet processing tests pass (32/32)
- ✅ No regressions in existing tests
- ✅ Build maintains 99%+ pass rate

## Next Steps

1. **Immediate** (today): Execute Root Cause Investigation Steps 1-4
2. **This Week**: Implement fixes for identified issues (Tasks 1-4)
3. **Next Week**: Enable remaining tests, fix test-specific issues (Task 5)
4. **Completion**: All 84 Tier 1 tests passing

## Files to Modify

Based on investigation, likely changes needed in:
1. `src/quic/endpoint.zig` - Server packet processing, acceptance logic
2. `src/quic/endpoint/incoming.zig` - Initial packet handling
3. `src/quic/endpoint/server.zig` - Server connection creation
4. `src/quic/endpoint/handshake_integration.zig` - TLS integration
5. `src/quic/conn.zig` - Connection TLS context, handshake state
6. `tests/integration/connection_pair.zig` - Potentially debug helpers
7. `tests/integration/rfc9000_section7.zig` - Enable remaining tests

## Dependencies

- ✅ Phase 14 infrastructure (completed)
- ✅ Endpoint.initWithTransport() (working)
- ✅ ConnectionPair.connect() (working, needs fixes)
- ⚠️ TLS handshake implementation (partially working)
- ⚠️ Packet protection/encryption (exists, needs verification)
- ⚠️ Server acceptance logic (needs investigation)

## Estimated Timeline

- **Investigation**: 4-5 hours (Steps 1-4)
- **Implementation**: 7-11 hours (Tasks 1-5)
- **Total**: 11-16 hours

## References

- Phase 14: Production Endpoint Integration (completed)
- Phase 19: TLS Integration Foundation (component validation)
- Phase 20: Full Handshake Validation (component validation)
- RFC 9000 §7: Cryptographic and Transport Handshake
- RFC 9001: Using TLS to Secure QUIC
- RFC 9002: QUIC Loss Detection and Congestion Control
