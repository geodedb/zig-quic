# Phase 4b.5 Session 3 Work Breakdown
# RX Pipeline - Short Header Extraction

**Created**: 2025-11-09
**Status**: NOT STARTED
**Estimated Total Effort**: 12-16 hours (reduced from original 20-30 hours)

---

## Executive Summary

Session 3 extracts short header (1-RTT) packet processing from the monolithic `endpoint.zig` into the modular `incoming.zig`. **Significant progress has already been made** - many supporting functions are already extracted. The main remaining work is implementing `processShortHeader()` and integrating it with endpoint.zig.

### Current Status Discovery

**Already Extracted (✅ COMPLETE)**:
- ✅ `lookup.zig:findConnectionByDcid()` (209 lines) - Connection routing logic
- ✅ `incoming.zig:enumerateDcidLength()` (67 lines) - DCID length discovery (Bug #6 fix)
- ✅ `incoming.zig:decryptShortHeaderWithKeyRotation()` (135 lines) - Decryption with key update
- ✅ `incoming.zig:promoteToNextKeys()` (33 lines) - NEXT key promotion
- ✅ `incoming.zig:decrementPrevKeyAllowance()` (61 lines) - PREV key cleanup
- ✅ `incoming.zig:processFrames()` (96 lines) - Frame parsing loop
- ✅ `incoming.zig:generateAndSendAck()` (254 lines) - ACK generation

**Not Yet Extracted (⏳ TODO)**:
- ⏳ `incoming.zig:processShortHeader()` - Currently a stub, needs full implementation
- ⏳ Integration of processShortHeader() into endpoint.zig
- ⏳ Test conversion (2 placeholder tests)

### Revised Effort Estimate

Original estimate: 20-30 hours
**Revised estimate: 12-16 hours**

Rationale:
- Connection lookup: ✅ DONE (saved 2-3 hours)
- DCID enumeration: ✅ DONE (saved 2-3 hours)
- Decryption/key rotation: ✅ DONE (saved 3-4 hours)
- Remaining: processShortHeader() implementation and integration (12-16 hours)

---

## Sub-Task Breakdown

### Sub-Task 1: Implement processShortHeader() Core Logic (6-8 hours)

**Objective**: Complete the processShortHeader() function in incoming.zig using already-extracted helper functions.

**Current State**:
- File: `src/quic/endpoint/incoming.zig`
- Function exists at line 2124 but is a stub
- All helper functions already extracted and tested

**Implementation Steps**:

#### Step 1.1: Connection Lookup Integration (1 hour)
- [ ] Use `lookup.findConnectionByDcid()` to find connection
- [ ] Handle NAT rebinding detection
- [ ] Return early if no connection found
- [ ] Code reference: endpoint.zig lines 1109-1124

**Code Pattern**:
```zig
const lookup = @import("lookup.zig");

const lookup_result = lookup.findConnectionByDcid(
    ctx.conns,
    peer,
    bytes,
    null, // No path_changed_fn callback - handled by caller
);

const conn = lookup_result.conn orelse return; // No connection found
const dcid_len = lookup_result.dcid_len;
```

#### Step 1.2: ECN and Anti-Amplification Tracking (30 minutes)
- [ ] Call conn.onEcnMark() if ecn_bits provided
- [ ] Call conn.addRxUnvalidated() for anti-amplification
- [ ] Code reference: endpoint.zig lines 1143-1145

**Code Pattern**:
```zig
if (ecn_bits) |e| conn.onEcnMark(.Application, e);
conn.addRxUnvalidated(bytes.len);
```

#### Step 1.3: DCID Length Caching and Key Check (30 minutes)
- [ ] Use conn.expected_rx_dcid_len if available
- [ ] Fall back to dcid_len from lookup
- [ ] Verify app_rx_keys are available
- [ ] Return early if no RX keys
- [ ] Code reference: endpoint.zig lines 1127-1146

**Code Pattern**:
```zig
const try_dcid_len = if (conn.expected_rx_dcid_len) |cached_len|
    cached_len
else
    dcid_len;

const rx_keys = conn.app_rx_keys orelse return; // No keys yet
```

#### Step 1.4: Packet Decryption with Key Rotation (2 hours)
- [ ] Call `decryptShortHeaderWithKeyRotation()`
- [ ] Handle error.StatelessReset (close connection)
- [ ] Extract decoded result, used_next, used_prev flags
- [ ] Defer payload cleanup
- [ ] Code reference: endpoint.zig lines 1158-1173

**Code Pattern**:
```zig
const decrypt_result = decryptShortHeaderWithKeyRotation(
    ctx.allocator.*,
    conn,
    bytes,
    @intCast(try_dcid_len),
) catch |err| {
    if (err == error.StatelessReset) {
        conn.closed = true;
    }
    return;
};

const dec_res = decrypt_result.decoded;
const used_next = decrypt_result.used_next;
const used_prev = decrypt_result.used_prev;
defer ctx.allocator.free(dec_res.payload);
```

#### Step 1.5: NEXT Key Promotion (1 hour)
- [ ] Check if used_next flag is set
- [ ] Get current RX secret from connection
- [ ] Derive next secret using key_schedule.updateTrafficSecret()
- [ ] Derive next keys (v1 or v2 based on version)
- [ ] Call promoteToNextKeys()
- [ ] Code reference: endpoint.zig lines 1176-1189

**Code Pattern**:
```zig
if (used_next) {
    if (conn.app_rx_secret) |cur_rx_secret| {
        const next_secret = key_schedule.updateTrafficSecret(cur_rx_secret);
        const next_keys = if (conn.version_v2)
            key_schedule.deriveKeyIvHpV2(next_secret)
        else
            key_schedule.deriveKeyIvHp(next_secret);
        promoteToNextKeys(conn, next_secret, .{
            .key = next_keys.key,
            .iv = next_keys.iv,
            .hp = next_keys.hp,
        });
    }
}
```

#### Step 1.6: Packet Number Tracking (30 minutes)
- [ ] Extract full packet number from decoded result
- [ ] Call conn.trackRecvPnApp()
- [ ] Code reference: endpoint.zig lines 1191-1194

**Code Pattern**:
```zig
const pn_full: u64 = dec_res.packet_number;
conn.trackRecvPnApp(pn_full);
```

#### Step 1.7: PREV Key Cleanup (30 minutes)
- [ ] Check if used_prev flag is set
- [ ] Call decrementPrevKeyAllowance()
- [ ] Code reference: endpoint.zig lines 1197-1199

**Code Pattern**:
```zig
if (used_prev) {
    decrementPrevKeyAllowance(conn);
}
```

#### Step 1.8: Frame Processing Integration (1 hour)
- [ ] Call processFrames() with decoded payload
- [ ] Pass FrameContext with send_fn
- [ ] Capture FrameProcessingResult
- [ ] Handle saw_handshake_done flag (drop Handshake keys)
- [ ] Handle saw_close flag (set conn.closed)
- [ ] Code reference: endpoint.zig lines 1200-1327

**Code Pattern**:
```zig
const frame_result = processFrames(
    ctx.allocator,
    conn,
    dec_res.payload,
    peer,
    .Application,
    ctx.cfg,
    send_fn,
) catch return;

if (frame_result.saw_handshake_done) {
    conn.handshake_done_seen = true;
    conn.hs_rx_keys = null;
    conn.hs_tx_keys = null;
}

if (frame_result.saw_close) {
    conn.closed = true;
    return;
}
```

#### Step 1.9: ACK Generation (30 minutes)
- [ ] Check if ack-eliciting frames were received
- [ ] Call conn.recordAckElicitingRx() with timestamp
- [ ] Check if deferred ACK_ECN needs sending
- [ ] Call generateAndSendAck() if needed
- [ ] Code reference: endpoint.zig lines 1315-1350

**Code Pattern**:
```zig
if (frame_result.saw_ack_eliciting) {
    const now_ns: u64 = @intCast(std.time.nanoTimestamp());
    conn.recordAckElicitingRx(.Application, now_ns);
}

if (conn.ecn_app_ack_pending and conn.canSendUnderAmplification()) {
    generateAndSendAck(
        ctx.allocator,
        conn,
        peer,
        .Application,
        send_fn,
        ctx.test_capture_enabled,
    ) catch {};
}
```

**Deliverables**:
- ✅ Fully implemented `processShortHeader()` function (~150-200 lines)
- ✅ Uses all extracted helper functions
- ✅ Handles all error paths
- ✅ Maintains backward compatibility with current behavior

---

### Sub-Task 2: Integrate processShortHeader() into endpoint.zig (3-4 hours)

**Objective**: Replace inline short header processing in endpoint.zig with call to incoming.processShortHeader().

**Current State**:
- File: `src/quic/endpoint.zig`
- Lines to replace: 1097-1350 (~253 lines)
- Current implementation is inline within processIncomingDatagram()

**Implementation Steps**:

#### Step 2.1: Create RxContext Setup (1 hour)
- [ ] Add RxContext creation before short header block
- [ ] Populate all required fields (allocator, conns, cfg, etc.)
- [ ] Create send_fn wrapper for self.sendTo
- [ ] Code location: endpoint.zig line 1097

**Code Pattern**:
```zig
if (!is_long) {
    // Create RxContext for incoming.processShortHeader()
    const sendFn = struct {
        ep: *Endpoint,
        fn send(ep: *Endpoint, peer_addr: conn_mod.SockAddr, data: []const u8) anyerror!usize {
            return ep.sendTo(peer_addr, data);
        }
    };

    var rx_ctx = incoming.RxContext{
        .allocator = self.allocator,
        .conns = &self.conns,
        .accepted = &self.accepted,
        .cfg = &self.cfg,
        .send_fn = sendFn.send,
        .schedule_timer_fn = undefined, // Not used by processShortHeader
        .send_initial_probe_fn = undefined, // Not used by processShortHeader
        .test_capture_enabled = self.test_capture_enabled,
        .endpoint_role = self.role,
    };

    incoming.processShortHeader(&rx_ctx, peer, bytes, ecn_bits, sendFn.send);
    return;
}
```

#### Step 2.2: Remove Inline Implementation (1 hour)
- [ ] Delete lines 1097-1350 (inline short header processing)
- [ ] Verify no dangling references
- [ ] Ensure all error paths are handled

**Expected Line Count Reduction**: ~250 lines

#### Step 2.3: Build and Compile (30 minutes)
- [ ] Run `make clean && make`
- [ ] Fix any compilation errors
- [ ] Verify all imports are correct

#### Step 2.4: Integration Testing (1-2 hours)
- [ ] Run full test suite
- [ ] Verify 811/818 tests still pass
- [ ] Check for regressions in 1-RTT packet handling
- [ ] Test NAT rebinding scenarios
- [ ] Test key rotation scenarios

**Deliverables**:
- ✅ endpoint.zig reduced by ~250 lines
- ✅ Short header processing delegated to incoming.zig
- ✅ All existing tests passing
- ✅ No regressions

---

### Sub-Task 3: Write and Convert Tests (3-4 hours)

**Objective**: Convert 2 placeholder tests and add new unit tests for processShortHeader().

**Current State**:
- Test file: `tests/unit/endpoint/test_incoming.zig`
- Placeholder tests exist but not converted
- Helper tests already passing (8 tests)

**Implementation Steps**:

#### Step 3.1: Unit Test for findConnectionByDcid() (1 hour)
- [ ] Test normal connection lookup (peer_hash + dcid_hash)
- [ ] Test server prioritization (prefer connections with both RX/TX keys)
- [ ] Test NAT rebinding fallback (DCID-only match)
- [ ] Test no connection found case
- [ ] Test DCID length tie-breaking

**Test Case Template**:
```zig
test "findConnectionByDcid - normal lookup" {
    // Setup: Create connection table with test connection
    // Action: Call findConnectionByDcid with matching packet
    // Assert: Returns correct connection and DCID length
}

test "findConnectionByDcid - NAT rebinding" {
    // Setup: Create connection with different peer_hash
    // Action: Call findConnectionByDcid with DCID match only
    // Assert: Returns connection with nat_rebinding=true
}
```

#### Step 3.2: Unit Test for processShortHeader() (1 hour)
- [ ] Test successful packet decryption and frame processing
- [ ] Test DCID enumeration fallback
- [ ] Test key rotation (NEXT key usage)
- [ ] Test PREV key cleanup
- [ ] Test ACK generation
- [ ] Test HANDSHAKE_DONE handling
- [ ] Test CONNECTION_CLOSE handling
- [ ] Test stateless reset detection

**Test Case Template**:
```zig
test "processShortHeader - normal 1-RTT packet" {
    // Setup: Create endpoint, connection with app keys
    // Action: Inject short header packet
    // Assert: Packet decrypted, frames processed, ACK generated
}

test "processShortHeader - key rotation to NEXT" {
    // Setup: Create connection with NEXT keys ready
    // Action: Inject packet encrypted with NEXT keys
    // Assert: Keys promoted, packet processed successfully
}
```

#### Step 3.3: Convert RFC Compliance Test 1 (30 minutes)
**Test**: "RFC 9000 §17.3 - Short header format"

- [ ] Convert from placeholder to real implementation
- [ ] Test short header packet structure
- [ ] Verify DCID field parsing
- [ ] Verify packet number encoding/decoding
- [ ] Reference: RFC_COMPLIANCE_TEST_PLAN.md

**Test Location**: `test_incoming.zig` (find placeholder test)

#### Step 3.4: Convert RFC Compliance Test 2 (30 minutes)
**Test**: "RFC 9000 §12.3 - Packet number encoding"

- [ ] Convert from placeholder to real implementation
- [ ] Test PN truncation (1-4 bytes)
- [ ] Test PN reconstruction from largest_pn
- [ ] Verify PN space wrapping
- [ ] Reference: RFC_COMPLIANCE_TEST_PLAN.md

**Test Location**: `test_incoming.zig` (find placeholder test)

#### Step 3.5: Integration Test (1 hour)
- [ ] Test full RX pipeline with processShortHeader()
- [ ] Test client-server 1-RTT packet exchange
- [ ] Test multiple packets in sequence
- [ ] Test connection migration (NAT rebinding)
- [ ] Verify metrics and statistics

**Test Case Template**:
```zig
test "integration - client-server 1-RTT exchange" {
    // Setup: Create client and server endpoints
    // Action: Client sends APPLICATION_DATA, server processes
    // Assert: Server decrypts, processes frames, sends ACK
    // Action: Server sends APPLICATION_DATA, client processes
    // Assert: Client decrypts, processes frames, sends ACK
}
```

**Deliverables**:
- ✅ 6+ new unit tests for processShortHeader()
- ✅ 2 RFC compliance tests converted
- ✅ 1 integration test
- ✅ Test count: 813/818 tests passing (+2 from baseline)

---

## Dependency Graph

```
Sub-Task 1: Implement processShortHeader()
    ↓
Sub-Task 2: Integrate into endpoint.zig
    ↓
Sub-Task 3: Write and convert tests
```

**Critical Path**: Sub-Task 1 must complete before Sub-Task 2. Sub-Task 3 can run in parallel with Sub-Task 2 for unit tests, but integration tests require Sub-Task 2 completion.

---

## Risk Assessment

### Low Risk ✅
- All helper functions already extracted and tested
- Clear integration pattern established (RxContext)
- Existing tests provide regression detection

### Medium Risk ⚠️
- SendFn wrapper for self.sendTo may need debugging
- RxContext field population requires care
- Frame processing integration may reveal edge cases

### Mitigation Strategies
1. **Incremental Development**: Implement processShortHeader() in stages, testing each step
2. **Comparison Testing**: Run side-by-side comparison of inline vs extracted code
3. **Verbose Logging**: Add debug prints during development, remove before commit
4. **Backup Point**: Create feature branch before integration

---

## Testing Strategy

### Phase 1: Unit Testing (During Sub-Task 1)
- Test each step of processShortHeader() in isolation
- Use mock connections and packets
- Verify helper function calls
- Check error handling

### Phase 2: Integration Testing (During Sub-Task 2)
- Test processShortHeader() within endpoint.zig
- Verify backward compatibility
- Check all existing tests still pass
- Monitor for regressions

### Phase 3: RFC Compliance (During Sub-Task 3)
- Convert 2 placeholder tests
- Verify RFC 9000 §17.3 compliance
- Verify RFC 9000 §12.3 compliance

### Phase 4: End-to-End Testing (After Sub-Task 3)
- Test full client-server handshake + 1-RTT exchange
- Test connection migration scenarios
- Test key rotation scenarios
- Verify PMTUD, ECN, anti-amplification

---

## Success Criteria

### Code Quality
- ✅ processShortHeader() implemented with <200 lines
- ✅ endpoint.zig reduced by ~250 lines
- ✅ All helper functions reused (no code duplication)
- ✅ Error handling comprehensive
- ✅ RFC comments and references included

### Testing
- ✅ All existing tests pass (811/818 baseline)
- ✅ 2 new tests added (813/818 target)
- ✅ 2 placeholder tests converted
- ✅ 6+ unit tests for processShortHeader()
- ✅ 1 integration test for full RX pipeline

### Documentation
- ✅ processShortHeader() has comprehensive doc comments
- ✅ RFC references included for all logic
- ✅ PHASE_4B5_SESSION_2_8_STATUS.md updated
- ✅ PHASE_4B5_VERIFICATION_SUMMARY.md updated

### Build
- ✅ `make clean && make` successful
- ✅ No compilation warnings
- ✅ No regressions detected

---

## Estimated Timeline

### Option A: Single Focused Session (12-16 hours)
**Day 1 (8 hours)**:
- Morning: Sub-Task 1.1-1.5 (Connection lookup, decryption, key rotation)
- Afternoon: Sub-Task 1.6-1.9 (Packet tracking, frame processing, ACK)

**Day 2 (4-8 hours)**:
- Morning: Sub-Task 2 (Integration into endpoint.zig)
- Afternoon: Sub-Task 3 (Testing and RFC compliance)

### Option B: Split Sessions (2-3 sessions of 4-6 hours each)
**Session 1** (4-6 hours): Sub-Task 1 (Implement processShortHeader)
**Session 2** (3-4 hours): Sub-Task 2 (Integration)
**Session 3** (3-4 hours): Sub-Task 3 (Testing)

### Option C: Incremental Approach (5-6 sessions of 2-3 hours each)
**Session 1** (2 hours): Steps 1.1-1.3
**Session 2** (3 hours): Steps 1.4-1.5
**Session 3** (2 hours): Steps 1.6-1.9
**Session 4** (3 hours): Sub-Task 2
**Session 5** (2 hours): Sub-Task 3 (unit tests)
**Session 6** (2 hours): Sub-Task 3 (RFC tests + integration)

**Recommended**: Option B for balance of focus and flexibility

---

## Progress Tracking

Use TodoWrite tool to track progress:

```zig
// Session 3 Task List
1. [pending] Implement processShortHeader() core logic (6-8 hours)
   - Connection lookup integration
   - Packet decryption and key rotation
   - Frame processing and ACK generation
2. [pending] Integrate into endpoint.zig (3-4 hours)
   - Create RxContext setup
   - Replace inline implementation
   - Integration testing
3. [pending] Write and convert tests (3-4 hours)
   - Unit tests for processShortHeader()
   - Convert 2 RFC compliance tests
   - Integration test
```

---

## Files Modified

### Implementation
- `src/quic/endpoint/incoming.zig` - processShortHeader() implementation (~150 lines added)
- `src/quic/endpoint.zig` - Integration and inline removal (~250 lines removed, ~30 lines added)

### Testing
- `tests/unit/endpoint/test_incoming.zig` - New tests (~200 lines added)

### Documentation
- `PHASE_4B5_SESSION_2_8_STATUS.md` - Update Session 3 status
- `PHASE_4B5_VERIFICATION_SUMMARY.md` - Update completion checklist

**Net Line Count Change**: ~-100 lines (reduction in monolithic code)

---

## Rollback Plan

If issues are encountered:

1. **Before Integration** (Sub-Task 1 complete):
   - Rollback: Delete processShortHeader() implementation
   - Impact: None (not yet integrated)

2. **After Integration** (Sub-Task 2 complete):
   - Rollback: Revert endpoint.zig changes, restore inline implementation
   - Impact: Lost 3-4 hours of work

3. **After Testing** (Sub-Task 3 complete):
   - Rollback: Full Session 3 revert via git
   - Impact: Lost 12-16 hours of work

**Recommendation**: Use feature branch (`session-3-rx-pipeline`) and test thoroughly before merging to main.

---

## Additional Notes

### Already Extracted Functions (Reference)

These functions are already implemented and tested in incoming.zig:

1. **enumerateDcidLength()** (line 367)
   - Systematic DCID length discovery (0-20 bytes)
   - Stateless reset detection
   - Bug #6 fix

2. **decryptShortHeaderWithKeyRotation()** (line 1445)
   - Tries CURRENT → NEXT → PREV keys
   - Returns which key succeeded
   - Handles stateless reset detection

3. **promoteToNextKeys()** (line 1580)
   - Moves NEXT → CURRENT → PREV
   - Updates connection secrets
   - Resets PREV key allowance

4. **decrementPrevKeyAllowance()** (line 1613)
   - Tracks PREV key usage count
   - Clears PREV keys when allowance exhausted
   - Prevents indefinite PREV key retention

5. **processFrames()** (line 1674)
   - Frame parsing loop
   - Delegates to frame_handler module
   - Handles endpoint-specific operations (PTO, PMTUD, path validation)
   - Returns FrameProcessingResult

6. **generateAndSendAck()** (line 1770)
   - Builds ACK frame with ranges
   - Includes ECN counts if available
   - Encrypts and sends Short header packet
   - Handles anti-amplification limits

### Integration with Existing Modules

processShortHeader() will use:
- `lookup.findConnectionByDcid()` - Connection routing
- `frame_handler.processFrame()` - Frame processing (Session 4)
- `handshake_integration.*` - TLS handshake coordination (Session 6)

### Future Sessions Impact

Completing Session 3 unblocks:
- **Session 5**: Initial packet processing (similar pattern)
- **Session 6**: TLS integration extraction (uses same RxContext)
- **Session 8**: Handshake packet extraction (similar pattern)

---

**Last Updated**: 2025-11-09
**Next Review**: Before starting Sub-Task 1
**Status**: Ready to begin implementation
