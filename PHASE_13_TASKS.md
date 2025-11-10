# Phase 13: Detailed Task Breakdown

**Created**: 2025-11-10
**Based On**: ENDPOINT_AUDIT.md + TEST_COVERAGE_AUDIT.md
**Target**: endpoint.zig from 2,867 → <500 lines
**Status**: ⏳ Ready for Stage 2 Implementation

---

## Executive Summary

This document breaks down Phase 13 implementation into **41 specific tasks** organized into **6 priority levels** with **estimated times** and **acceptance criteria**. Tasks are ordered by dependency to enable incremental, testable progress.

### Task Summary

| Priority | Tasks | Total Time | Description |
|----------|-------|------------|-------------|
| **P0 - Blockers** | 3 | 30 min | Critical verifications before work |
| **P1 - Quick Wins** | 8 | 2.5 hours | Remove confirmed duplicates |
| **P2 - The Big One** | 5 | 4-6 hours | Refactor processIncomingDatagram() |
| **P3 - Extraction** | 10 | 3-4 hours | Extract init/utils/client logic |
| **P4 - Verification** | 12 | 2-3 hours | Verify and remove potential duplicates |
| **P5 - Polish** | 3 | 1-2 hours | Final cleanup and verification |
| **TOTAL** | **41** | **13-18 hours** | **Complete Phase 13** |

---

## Priority 0: Blockers (30 minutes)

These tasks MUST be completed before any code changes to establish baseline.

### Task P0.1: Verify Build & Test Status (10 min)

**Goal**: Establish clean baseline before refactoring

**Steps**:
```bash
make clean
make
make test
```

**Acceptance Criteria**:
- ✅ Build completes with exit code 0
- ✅ No compiler warnings
- ✅ All 2,085 tests pass
- ✅ Test output saved for comparison

**Time**: 10 minutes

---

### Task P0.2: Create Git Branch (5 min)

**Goal**: Enable easy rollback if needed

**Steps**:
```bash
git checkout -b phase-13-endpoint-modularization
git add ENDPOINT_AUDIT.md TEST_COVERAGE_AUDIT.md PHASE_13_TASKS.md
git commit -m "docs: Phase 13 Stage 1 complete - audits and task breakdown"
```

**Acceptance Criteria**:
- ✅ Working on phase-13-endpoint-modularization branch
- ✅ Stage 1 deliverables committed
- ✅ Can easily revert to main if needed

**Time**: 5 minutes

---

### Task P0.3: Backup endpoint.zig (5 min)

**Goal**: Keep original for comparison

**Steps**:
```bash
cp src/quic/endpoint.zig src/quic/endpoint.zig.phase12.backup
ls -lh src/quic/endpoint.zig*
```

**Acceptance Criteria**:
- ✅ Backup file created
- ✅ Backup is 2,867 lines
- ✅ Can compare changes easily

**Time**: 5 minutes

---

## Priority 1: Quick Wins - Remove Confirmed Duplicates (2.5 hours)

These tasks remove code that is **confirmed duplicated** in modules. Low risk, high impact.

### Task P1.1: Remove sendTo() Duplication (20 min)

**Lines**: 426-467 (42 lines)
**Module**: io.zig has io_mod.sendTo()

**Steps**:
1. Read io_mod.sendTo() signature in endpoint/io.zig:198-236
2. Verify endpoint.sendTo() (lines 426-467) is functionally identical
3. Remove endpoint.sendTo() implementation
4. Replace with wrapper:
   ```zig
   pub fn sendTo(self: *Endpoint, peer: conn_mod.SockAddr, data: []const u8) !usize {
       return io_mod.sendTo(self.sock_fd, peer, data, self.test_capture_enabled, &self.captures);
   }
   ```
5. Update all callers if signature changed
6. Build and test

**Acceptance Criteria**:
- ✅ endpoint.sendTo() is ~5 lines (wrapper)
- ✅ All tests passing
- ✅ Functionality unchanged

**Time**: 20 minutes
**Reduction**: 37 lines (42 → 5)

---

### Task P1.2: Remove recvFrom() Duplication (15 min)

**Lines**: 468-475 (8 lines)
**Module**: io.zig has io_mod.recvFrom()

**Steps**:
1. Read io_mod.recvFrom() signature in endpoint/io.zig:146-196
2. Verify endpoint.recvFrom() (lines 468-475) is wrapper
3. Confirm it already delegates to io_mod, or replace
4. Build and test

**Acceptance Criteria**:
- ✅ endpoint.recvFrom() delegates to io_mod
- ✅ All tests passing

**Time**: 15 minutes
**Reduction**: 0-3 lines (already thin)

---

### Task P1.3: Remove closeStaleConnectionsForPeer() Duplication (15 min)

**Lines**: 2716-2727 (12 lines)
**Module**: lifecycle.zig has lifecycle_mod.closeStaleConnectionsForPeer()

**Steps**:
1. Read lifecycle_mod.closeStaleConnectionsForPeer() in endpoint/lifecycle.zig:19-56
2. Verify endpoint version (lines 2716-2727) is duplicate
3. Remove endpoint implementation
4. Replace with wrapper:
   ```zig
   pub fn closeStaleConnectionsForPeer(self: *Endpoint, new_conn: *conn_mod.Connection) void {
       var ctx = lifecycle_mod.LifecycleContext{
           .conns = &self.conns,
           .timers = &self.timers,
           .retired = &self.retired,
       };
       lifecycle_mod.closeStaleConnectionsForPeer(&ctx, new_conn);
   }
   ```
5. Build and test

**Acceptance Criteria**:
- ✅ endpoint version is ~5-line wrapper
- ✅ All tests passing

**Time**: 15 minutes
**Reduction**: 7 lines (12 → 5)

---

### Task P1.4: Remove Dead hashSockaddr() Implementation (10 min)

**Lines**: 89-144 (56 lines)
**Module**: utils.zig has utils.hashSockaddr()

**Steps**:
1. Verify line 89 is already a wrapper: `pub fn hashSockaddr(...) { return utils.hashSockaddr(...); }`
2. The implementation at lines 90-144 is likely NOT part of the function (it's likely init())
3. This was a false positive from the grep - verify actual structure
4. If duplicate exists, remove; otherwise skip

**Acceptance Criteria**:
- ✅ Only wrapper remains (if duplicate found)
- ✅ All tests passing

**Time**: 10 minutes
**Reduction**: 0-50 lines (verify first)

---

### Task P1.5: Remove Legacy poll_*() Functions (10 min)

**Lines**: 2766-2792 (27 lines)
**Functions**: poll_epoll(), poll_kqueue(), poll_iocp()

**Steps**:
1. Verify these are NOT called anywhere (dead code)
2. Search for references: `grep -r "poll_epoll\|poll_kqueue\|poll_iocp" src/`
3. Confirm only poll_*_backend() versions are used
4. Remove lines 2766-2792
5. Build and test

**Acceptance Criteria**:
- ✅ Legacy functions removed
- ✅ No references found
- ✅ All tests passing

**Time**: 10 minutes
**Reduction**: 27 lines

---

### Task P1.6: Verify drainReadable() Not Duplicated (20 min)

**Lines**: 708-740 (33 lines)
**Check**: io.zig might have this

**Steps**:
1. Search io.zig for drainReadable implementation
2. Compare signatures and logic
3. If duplicate: remove and delegate to io_mod
4. If not duplicate: keep as-is and document why
5. Build and test

**Acceptance Criteria**:
- ✅ Duplication status determined
- ✅ If duplicate: removed and delegated
- ✅ If not duplicate: documented in code comment
- ✅ All tests passing

**Time**: 20 minutes
**Reduction**: 0-28 lines (if duplicate)

---

### Task P1.7: Verify drainErrorQueue() Not Duplicated (20 min)

**Lines**: 741-769 (29 lines)
**Check**: io.zig might have this

**Steps**:
1. Search io.zig for drainErrorQueue implementation
2. Compare signatures and logic
3. If duplicate: remove and delegate to io_mod
4. If not duplicate: keep as-is and document why
5. Build and test

**Acceptance Criteria**:
- ✅ Duplication status determined
- ✅ If duplicate: removed and delegated
- ✅ If not duplicate: documented in code comment
- ✅ All tests passing

**Time**: 20 minutes
**Reduction**: 0-24 lines (if duplicate)

---

### Task P1.8: Verify pruneClosed() Not Duplicated (20 min)

**Lines**: 2728-2739 (12 lines)
**Check**: lifecycle.zig might have this

**Steps**:
1. Search lifecycle.zig for pruneClosed implementation
2. Compare signatures and logic
3. If duplicate: remove and delegate to lifecycle_mod
4. If not duplicate: keep as-is and document why
5. Build and test

**Acceptance Criteria**:
- ✅ Duplication status determined
- ✅ If duplicate: removed and delegated
- ✅ If not duplicate: documented in code comment
- ✅ All tests passing

**Time**: 20 minutes
**Reduction**: 0-7 lines (if duplicate)

---

**Priority 1 Total**: 2.5 hours, **100-150 lines reduced** (2,867 → ~2,717)

---

## Priority 2: The Big One - Refactor processIncomingDatagram() (4-6 hours)

This is the **critical path** - the massive 1,712-line monolithic function.

### Task P2.1: Read & Understand incoming.zig (1 hour)

**Goal**: Verify incoming.zig has all necessary packet processing logic

**Steps**:
1. Read endpoint/incoming.zig (2,608 lines)
2. Identify what processIncomingDatagram() does vs what incoming.zig does
3. Create comparison matrix:
   - Version Negotiation: endpoint.zig vs incoming.zig
   - Long Header (Initial, Handshake): endpoint.zig vs incoming.zig
   - Short Header (1-RTT): endpoint.zig vs incoming.zig
   - Connection lookup: endpoint.zig vs incoming.zig
4. Document gaps (if any)

**Acceptance Criteria**:
- ✅ Understand incoming.zig capabilities
- ✅ Identified gaps (if any)
- ✅ Ready to refactor

**Time**: 1 hour
**Reduction**: 0 lines (analysis only)

---

### Task P2.2: Verify incoming.zig Has VN Handling (30 min)

**Lines to Replace**: endpoint.zig:904-948 (Version Negotiation handling)

**Steps**:
1. Search incoming.zig for "Version Negotiation" or "VN" handling
2. Verify it decodes VN packets
3. Verify it updates connection version
4. If missing: add to incoming.zig first
5. Document findings

**Acceptance Criteria**:
- ✅ incoming.zig VN handling verified or added
- ✅ Ready to delegate

**Time**: 30 minutes
**Reduction**: 0 lines (preparation)

---

### Task P2.3: Verify incoming.zig Has Long Header Processing (30 min)

**Lines to Replace**: endpoint.zig:950-2599 (Long header processing)

**Steps**:
1. Search incoming.zig for Initial packet processing
2. Search incoming.zig for Handshake packet processing
3. Verify connection lookup logic
4. Verify frame dispatching
5. If missing: add to incoming.zig first
6. Document findings

**Acceptance Criteria**:
- ✅ incoming.zig long header processing verified or added
- ✅ Ready to delegate

**Time**: 30 minutes
**Reduction**: 0 lines (preparation)

---

### Task P2.4: Replace processIncomingDatagram() with Coordinator (2 hours)

**Lines**: 888-2599 (1,712 lines)
**Target**: ~40-line coordinator function

**Steps**:
1. Keep function signature: `fn processIncomingDatagram(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, ecn_bits: ?u8) void`
2. Replace body with:
   ```zig
   fn processIncomingDatagram(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, ecn_bits: ?u8) void {
       // Create SendFn wrapper
       const SendContext = struct {
           ep: *Endpoint,
           pub fn send(ctx: *anyopaque, peer_addr: conn_mod.SockAddr, data: []const u8) !usize {
               const send_ctx: *@This() = @ptrCast(@alignCast(ctx));
               return send_ctx.ep.sendTo(peer_addr, data);
           }
       };
       var send_ctx = SendContext{ .ep = self };
       const send_fn = SendContext.send;

       // Create RxContext
       var rx_ctx = incoming.RxContext{
           .allocator = self.allocator,
           .conns = &self.conns,
           .accepted = &self.accepted,
           .cfg = &self.cfg,
           .send_fn = send_fn,
           .send_fn_ctx = &send_ctx,
           .schedule_timer_fn = scheduleTimerWrapper,
           .send_initial_probe_fn = sendInitialProbeWrapper,
           .test_capture_enabled = self.test_capture_enabled,
           .endpoint_role = @as(ep_types.EndpointRole, @enumFromInt(@intFromEnum(self.role))),
           .endpoint_ctx = self,
       };

       // DELEGATE EVERYTHING to incoming.zig
       incoming.processIncomingDatagram(&rx_ctx, peer, bytes, ecn_bits);
   }
   ```
3. Add wrapper functions if needed (scheduleTimerWrapper, etc.)
4. Build (expect errors)
5. Fix compilation errors incrementally
6. Run tests after each fix

**Acceptance Criteria**:
- ✅ processIncomingDatagram() is ~40-50 lines
- ✅ All logic delegated to incoming.zig
- ✅ Builds successfully
- ✅ All tests passing (this is critical!)

**Time**: 2 hours
**Reduction**: ~1,662 lines (1,712 → 50)

---

### Task P2.5: Verify & Test Packet Processing (1 hour)

**Goal**: Ensure all packet types still work

**Steps**:
1. Run full test suite: `make test`
2. Run specific packet tests:
   - Initial packets: `zig test tests/test_server_initial_processing.zig`
   - Handshake packets: `zig test tests/test_initial_handshake_loop.zig`
   - 1-RTT packets: `zig test tests/test_shortrtt_roundtrip.zig`
   - Version Negotiation: `zig test tests/test_version_negotiation.zig`
3. If any failures: debug and fix
4. Document any changes needed

**Acceptance Criteria**:
- ✅ All 2,085 tests passing
- ✅ All packet types processed correctly
- ✅ No regressions

**Time**: 1 hour
**Reduction**: 0 lines (verification)

---

**Priority 2 Total**: 5 hours, **~1,662 lines reduced** (2,717 → ~1,055)

---

## Priority 3: Extraction - Move Logic to Modules (3-4 hours)

### Task P3.1: Extract Socket Setup from init() (1 hour)

**Lines**: 145-298 (154 lines)
**Target**: Reduce init() to ~50 lines

**Steps**:
1. Create `io_mod.createAndBindSocket()` in endpoint/io.zig
2. Move lines 146-256 (socket creation, binding, setup) to io.zig
3. Replace in init() with:
   ```zig
   const socket_info = try io_mod.createAndBindSocket(alloc, bind_addr, cfgp);
   ```
4. Update init() to use returned socket_info
5. Build and test

**Acceptance Criteria**:
- ✅ init() is ~50-60 lines
- ✅ Socket setup logic in io.zig
- ✅ All tests passing

**Time**: 1 hour
**Reduction**: ~100 lines (154 → 54)

---

### Task P3.2: Simplify deinit() (30 min)

**Lines**: 299-395 (97 lines)
**Target**: Reduce deinit() to ~30 lines

**Steps**:
1. Identify lifecycle cleanup that should be in lifecycle.zig
2. Move complex cleanup logic to lifecycle_mod.cleanupEndpoint()
3. Replace with delegation calls
4. Build and test

**Acceptance Criteria**:
- ✅ deinit() is ~30-40 lines
- ✅ Complex cleanup in lifecycle.zig
- ✅ All tests passing

**Time**: 30 minutes
**Reduction**: ~57 lines (97 → 40)

---

### Task P3.3: Move nowMsMonotonic() to utils.zig (10 min)

**Lines**: 61-88 (28 lines)

**Steps**:
1. Move function to endpoint/utils.zig
2. Replace with inline wrapper: `inline fn nowMsMonotonic() i64 { return utils.nowMsMonotonic(); }`
3. Build and test

**Acceptance Criteria**:
- ✅ Function in utils.zig
- ✅ Wrapper is 1 line
- ✅ All tests passing

**Time**: 10 minutes
**Reduction**: 27 lines (28 → 1)

---

### Task P3.4: Move sockToIsize() to utils.zig (10 min)

**Lines**: 417-425 (9 lines)

**Steps**:
1. Move function to endpoint/utils.zig
2. Replace with inline wrapper
3. Build and test

**Acceptance Criteria**:
- ✅ Function in utils.zig
- ✅ Wrapper is 1 line
- ✅ All tests passing

**Time**: 10 minutes
**Reduction**: 8 lines (9 → 1)

---

### Task P3.5: Move parseIpv4() to utils.zig (10 min)

**Lines**: 2793-2806 (14 lines)

**Steps**:
1. Move function to endpoint/utils.zig
2. Make public: `pub fn parseIpv4()`
3. Update callers to use `utils.parseIpv4()`
4. Build and test

**Acceptance Criteria**:
- ✅ Function in utils.zig
- ✅ Callers updated
- ✅ All tests passing

**Time**: 10 minutes
**Reduction**: 14 lines

---

### Task P3.6: Move resolveAny() to utils.zig (15 min)

**Lines**: 2807-2867 (61 lines)

**Steps**:
1. Move function to endpoint/utils.zig
2. Make public: `pub fn resolveAny()`
3. Update callers to use `utils.resolveAny()`
4. Build and test

**Acceptance Criteria**:
- ✅ Function in utils.zig
- ✅ Callers updated
- ✅ All tests passing

**Time**: 15 minutes
**Reduction**: 61 lines

---

### Task P3.7: Check connectClient() for Duplication (30 min)

**Lines**: 508-547 (40 lines)
**Check**: client.zig might have this

**Steps**:
1. Read endpoint/client.zig
2. Check if it has connectClient() or createClientConnection()
3. If duplicate: remove endpoint version and delegate
4. If not: keep but document why
5. Build and test

**Acceptance Criteria**:
- ✅ Duplication checked
- ✅ If duplicate: delegated to client.zig
- ✅ All tests passing

**Time**: 30 minutes
**Reduction**: 0-35 lines (if duplicate)

---

### Task P3.8: Check clientSendInitialProbe() for Duplication (30 min)

**Lines**: 548-613 (66 lines)
**Check**: client.zig might have this

**Steps**:
1. Read endpoint/client.zig
2. Check if it has clientSendInitialProbe() or sendInitialProbe()
3. If duplicate: remove endpoint version and delegate
4. If not: keep but document why
5. Build and test

**Acceptance Criteria**:
- ✅ Duplication checked
- ✅ If duplicate: delegated to client.zig
- ✅ All tests passing

**Time**: 30 minutes
**Reduction**: 0-61 lines (if duplicate)

---

### Task P3.9: Check sendPtoProbe() for Duplication (20 min)

**Lines**: 2692-2715 (24 lines)
**Check**: pto.zig has pto_mod.sendPtoProbe()

**Steps**:
1. Read endpoint/pto.zig
2. Compare sendPtoProbe() implementations
3. If duplicate: remove endpoint version and delegate
4. If not: keep as thin wrapper
5. Build and test

**Acceptance Criteria**:
- ✅ Duplication checked
- ✅ If duplicate: delegated to pto.zig
- ✅ All tests passing

**Time**: 20 minutes
**Reduction**: 0-19 lines (if duplicate)

---

### Task P3.10: Check handleIcmpPtb() for Module Location (20 min)

**Lines**: 770-792 (23 lines)
**Check**: Should be in pmtud.zig or io.zig

**Steps**:
1. Determine best module for ICMP PTB handling
2. Check if logic already exists elsewhere
3. If duplicate: remove and delegate
4. If not: consider moving to appropriate module
5. Build and test

**Acceptance Criteria**:
- ✅ Best location determined
- ✅ Duplication checked
- ✅ All tests passing

**Time**: 20 minutes
**Reduction**: 0-18 lines (if moved)

---

**Priority 3 Total**: 3.5 hours, **~300-400 lines reduced** (1,055 → ~655-755)

---

## Priority 4: Verification & Simplification (2-3 hours)

### Task P4.1: Simplify poll() Function (30 min)

**Lines**: 661-707 (47 lines)
**Target**: ~30 lines

**Steps**:
1. Review poll() for redundant logic
2. Ensure proper delegation to:
   - `drainReadable()`
   - `drainErrorQueue()`
   - `processExpiredTimers()`
   - Platform backends
3. Simplify conditionals
4. Build and test

**Acceptance Criteria**:
- ✅ poll() is ~30 lines
- ✅ All delegation verified
- ✅ All tests passing

**Time**: 30 minutes
**Reduction**: ~17 lines (47 → 30)

---

### Task P4.2: Simplify processExpiredTimers() (30 min)

**Lines**: 2639-2682 (44 lines)
**Target**: ~25 lines

**Steps**:
1. Review timer dispatch logic
2. Check if any logic should be in timer.zig or pto.zig
3. Simplify switch statement
4. Build and test

**Acceptance Criteria**:
- ✅ processExpiredTimers() is ~25 lines
- ✅ Timer dispatch clear and simple
- ✅ All tests passing

**Time**: 30 minutes
**Reduction**: ~19 lines (44 → 25)

---

### Task P4.3: Verify All I/O Wrappers Are Thin (30 min)

**Functions**: sendTo, recvFrom, drainReadable, drainErrorQueue

**Steps**:
1. Verify each I/O function is <10 lines
2. Ensure they delegate to io_mod
3. No inline logic in wrappers
4. Build and test

**Acceptance Criteria**:
- ✅ All I/O wrappers are <10 lines
- ✅ All delegate to io_mod
- ✅ All tests passing

**Time**: 30 minutes
**Reduction**: 0 lines (verification)

---

### Task P4.4: Verify All Lifecycle Wrappers Are Thin (30 min)

**Functions**: closeStaleConnectionsForPeer, pruneClosed

**Steps**:
1. Verify each lifecycle function is <10 lines
2. Ensure they delegate to lifecycle_mod
3. No inline logic in wrappers
4. Build and test

**Acceptance Criteria**:
- ✅ All lifecycle wrappers are <10 lines
- ✅ All delegate to lifecycle_mod
- ✅ All tests passing

**Time**: 30 minutes
**Reduction**: 0 lines (verification)

---

### Task P4.5: Verify All Client Wrappers Are Thin (30 min)

**Functions**: connectTo, connectClient, clientSendInitialProbe

**Steps**:
1. Verify each client function is <15 lines (or delegated)
2. Ensure proper delegation to client.zig if available
3. No complex logic in wrappers
4. Build and test

**Acceptance Criteria**:
- ✅ All client functions are thin or delegated
- ✅ All tests passing

**Time**: 30 minutes
**Reduction**: 0 lines (verification)

---

### Task P4.6: Verify All Timer Wrappers Are Thin (30 min)

**Functions**: scheduleTimer, scheduleConnPto, cancelTimer, flushTimers

**Steps**:
1. Verify each timer function is <15 lines
2. Ensure proper delegation to timer heap
3. No complex logic in wrappers
4. Build and test

**Acceptance Criteria**:
- ✅ All timer functions are thin
- ✅ All tests passing

**Time**: 30 minutes
**Reduction**: 0 lines (verification)

---

### Task P4.7: Review Path Management Callbacks (20 min)

**Functions**: onPathAddressChanged, onPathValidated

**Steps**:
1. Verify these are appropriate as callbacks
2. Check if logic should be in path module
3. Keep as-is if appropriate
4. Build and test

**Acceptance Criteria**:
- ✅ Callbacks reviewed
- ✅ Appropriate location confirmed
- ✅ All tests passing

**Time**: 20 minutes
**Reduction**: 0 lines (verification)

---

### Task P4.8: Review Test Helpers (20 min)

**Functions**: captureClear, captureLen, capturePop, testInject, etc.

**Steps**:
1. Verify test helpers are appropriate in endpoint.zig
2. Consider moving to test_utils.zig if too many
3. Keep as-is for now (low priority)
4. Build and test

**Acceptance Criteria**:
- ✅ Test helpers reviewed
- ✅ Decision documented
- ✅ All tests passing

**Time**: 20 minutes
**Reduction**: 0 lines (verification)

---

### Task P4.9: Remove Inline Utility Wrappers (20 min)

**Functions**: portFromNetwork, portToNetwork, hashBytes, normalizeAddr, etc.

**Lines**: ~40 lines total

**Steps**:
1. Verify these are inline wrappers to utils.zig
2. Keep wrappers for backward compatibility (only 1 line each)
3. Ensure no duplicate implementations
4. Build and test

**Acceptance Criteria**:
- ✅ All wrappers are 1-line inline functions
- ✅ No duplicate implementations
- ✅ All tests passing

**Time**: 20 minutes
**Reduction**: 0 lines (already optimal)

---

### Task P4.10: Check Poll Backend Wrappers (20 min)

**Functions**: poll_epoll_backend, poll_kqueue_backend, poll_iocp_backend

**Lines**: ~90 lines total

**Steps**:
1. Verify these properly delegate to io_mod
2. Check if they can be simplified further
3. Keep as-is if already optimal
4. Build and test

**Acceptance Criteria**:
- ✅ Poll backends reviewed
- ✅ Delegation verified
- ✅ All tests passing

**Time**: 20 minutes
**Reduction**: 0 lines (already delegated)

---

### Task P4.11: Verify Endpoint Struct Size (10 min)

**Lines**: 98-143 (46 lines)

**Steps**:
1. Review Endpoint struct fields
2. Verify all fields are necessary
3. Check if any can be moved to modules
4. Document rationale for each field

**Acceptance Criteria**:
- ✅ Struct reviewed
- ✅ All fields justified
- ✅ No changes needed (struct is already appropriate)

**Time**: 10 minutes
**Reduction**: 0 lines (verification)

---

### Task P4.12: Final Line Count Check (10 min)

**Goal**: Verify we're at target (<500 lines)

**Steps**:
```bash
wc -l src/quic/endpoint.zig
# Expected: ~400-500 lines
```

**Acceptance Criteria**:
- ✅ endpoint.zig is <500 lines
- ✅ If >500: identify what remains
- ✅ If <400: great! Document final count

**Time**: 10 minutes
**Reduction**: 0 lines (verification)

---

**Priority 4 Total**: 2.5 hours, **~36 lines reduced** (655-755 → ~619-719)

---

## Priority 5: Polish & Documentation (1-2 hours)

### Task P5.1: Update All Module Documentation (30 min)

**Files**: endpoint.zig, io.zig, incoming.zig, lifecycle.zig, utils.zig, client.zig

**Steps**:
1. Update file header comments with current responsibilities
2. Add/update function documentation
3. Ensure RFC section references are accurate
4. Build

**Acceptance Criteria**:
- ✅ All module headers updated
- ✅ Function docs accurate
- ✅ RFC references correct

**Time**: 30 minutes

---

### Task P5.2: Run Full Test Suite & Verify (30 min)

**Steps**:
```bash
make clean
make
make test
```

**Acceptance Criteria**:
- ✅ Build with exit code 0
- ✅ All 2,085 tests pass
- ✅ No new warnings
- ✅ Compare with baseline from P0.1

**Time**: 30 minutes

---

### Task P5.3: Convert 3 Placeholder Tests (1 hour)

**Tests**:
1. tests/unit/endpoint/test_incoming.zig:596
2. tests/unit/endpoint/test_client.zig:94
3. tests/unit/endpoint/test_pto.zig:164

**Steps**:
For each test:
1. Read surrounding context
2. Identify what should be tested
3. Write proper test with assertions
4. Build and test

**Acceptance Criteria**:
- ✅ All 3 placeholders converted
- ✅ Tests have real assertions
- ✅ All tests passing

**Time**: 1 hour (20 min per test)

---

**Priority 5 Total**: 2 hours

---

## Final Verification Checklist

Before marking Phase 13 complete:

### Code Metrics
- ✅ endpoint.zig is <500 lines (target: 400-500)
- ✅ All duplicates removed
- ✅ processIncomingDatagram() is ~40-50 lines
- ✅ All wrappers are thin (<10 lines each)
- ✅ init() is ~50 lines
- ✅ deinit() is ~30 lines

### Test Metrics
- ✅ All 2,085 tests passing
- ✅ 3 placeholder tests converted
- ✅ Test count increased to 2,088 (3 new real tests)
- ✅ No regressions

### Documentation Metrics
- ✅ ENDPOINT_AUDIT.md created
- ✅ TEST_COVERAGE_AUDIT.md created
- ✅ PHASE_13_TASKS.md created
- ✅ All module docs updated
- ✅ PHASE_13_COMPLETION_REPORT.md created (Stage 3)

### Quality Metrics
- ✅ No compiler warnings
- ✅ All tests passing
- ✅ Code follows project conventions
- ✅ RFC compliance maintained
- ✅ No functionality lost

---

## Time Estimates by Phase

| Phase | Priority | Tasks | Estimate | Actual | Status |
|-------|----------|-------|----------|--------|--------|
| Stage 1 | Investigation | 3 | 3-4h | ___ | ✅ Complete |
| Stage 2 | P0 (Blockers) | 3 | 0.5h | ___ | ⏳ Pending |
| Stage 2 | P1 (Quick Wins) | 8 | 2.5h | ___ | ⏳ Pending |
| Stage 2 | P2 (Big One) | 5 | 5h | ___ | ⏳ Pending |
| Stage 2 | P3 (Extraction) | 10 | 3.5h | ___ | ⏳ Pending |
| Stage 2 | P4 (Verification) | 12 | 2.5h | ___ | ⏳ Pending |
| Stage 2 | P5 (Polish) | 3 | 2h | ___ | ⏳ Pending |
| **TOTAL** | | **44** | **19-20h** | **___** | ⏳ **In Progress** |

---

## Risk Mitigation

### High Risk: processIncomingDatagram() Refactoring

**Risk**: Massive function, could break packet processing

**Mitigation**:
- ✅ Task P2.1: Thoroughly understand incoming.zig first
- ✅ Task P2.2-P2.3: Verify all logic exists
- ✅ Task P2.5: Comprehensive testing after refactor
- ✅ Git branch allows easy rollback
- ✅ Incremental fixes during Task P2.4

### Medium Risk: Init/Deinit Extraction

**Risk**: Complex initialization, could break startup

**Mitigation**:
- ✅ Task P3.1: Extract incrementally
- ✅ Test after each extraction
- ✅ Keep backup for comparison

### Low Risk: Duplicate Removal

**Risk**: Minimal - duplicates are confirmed

**Mitigation**:
- ✅ P1 tasks have clear verification steps
- ✅ Test after each removal
- ✅ Easy to revert if issues

---

## Next Steps

1. ✅ **Stage 1 Complete** - All audits and task breakdown done
2. ⏳ **Begin Stage 2** - Start with P0 (Blockers)
3. ⏳ **Work through P1-P5** - Complete implementation
4. ⏳ **Stage 3** - Documentation and completion report

---

## References

- ENDPOINT_AUDIT.md - Function-by-function analysis
- TEST_COVERAGE_AUDIT.md - Test coverage analysis
- PHASE_13_COMPLETION_PLAN.md - Overall plan
- GAP_ANALYSIS.md - Gap analysis
- src/quic/endpoint.zig - File to refactor (2,867 lines → <500)

---

**Document Status**: ✅ Complete
**Total Tasks**: 44 tasks
**Estimated Time**: 19-20 hours
**Target Reduction**: 2,367 lines (2,867 → <500)
**Ready for Implementation**: ✅ YES

---

**Last Updated**: 2025-11-10
**Next Review**: After Stage 2 completion
