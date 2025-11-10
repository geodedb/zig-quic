# Endpoint Transport Integration Plan (Phase 8)

## Overview

This document provides a detailed, step-by-step plan for integrating the transport abstraction layer (Phase 7) with the production QUIC endpoint (`src/quic/endpoint.zig`). This enables the endpoint to work with both real UDP sockets (production) and loopback transport (testing) without code duplication.

**Status**: Planning phase complete ✅
**Implementation**: Deferred to future phase when ready
**Risk Level**: HIGH - Modifies production code
**Estimated Effort**: 2-3 days of careful implementation + testing

## Background

### Current State

The production endpoint (`src/quic/endpoint.zig`, 2,878 lines) uses real UDP sockets:

```zig
pub const Endpoint = struct {
    sock_fd: posix.socket_t,  // Direct UDP socket
    // ... rest of fields ...

    pub fn sendTo(self: *Endpoint, peer: SockAddr, data: []const u8) !usize {
        return io_mod.sendTo(self.sock_fd, peer, data);  // Direct UDP call
    }

    pub fn recvFrom(self: *Endpoint, buf: []u8) !struct { n: usize, peer: SockAddr } {
        const result = try io_mod.recvFrom(self.sock_fd, buf);  // Direct UDP call
        return .{ .n = result.n, .peer = result.peer };
    }
};
```

**Key Observations**:
1. UDP I/O is already modularized in `src/quic/endpoint/io.zig`
2. `sendTo()` and `recvFrom()` delegate to `io_mod` functions
3. Socket FD is stored directly in Endpoint struct
4. All connection callbacks reference `sock_fd`

### Target State

After integration, endpoint will support pluggable transports:

```zig
pub const Endpoint = struct {
    transport: Transport,  // Pluggable transport abstraction
    // ... rest of fields ...

    /// Backward compatible: create with UDP transport
    pub fn init(allocator: *std.mem.Allocator, bind_addr: []const u8, config: *const Config) !Endpoint {
        var udp = try UdpTransport.init(bind_addr);
        return try initWithTransport(allocator, udp.asTransport(), config);
    }

    /// New: create with custom transport
    pub fn initWithTransport(allocator: *std.mem.Allocator, transport: Transport, config: *const Config) !Endpoint {
        var ep = Endpoint{
            .allocator = allocator,
            .transport = transport,
            .cfg = config.*,
            // ... initialize other fields ...
        };
        return ep;
    }

    pub fn sendTo(self: *Endpoint, peer: SockAddr, data: []const u8) !usize {
        return self.transport.send(peer, data);  // Uses transport abstraction
    }

    pub fn recvFrom(self: *Endpoint, buf: []u8) !struct { n: usize, peer: SockAddr } {
        const result = try self.transport.recv(buf);
        return .{ .n = result.n, .peer = result.peer };
    }
};
```

## Integration Strategy

### Approach: Minimal Disruption Migration

**Philosophy**: Make the smallest possible changes to endpoint.zig while enabling transport abstraction.

**Key Principles**:
1. **Backward compatibility first**: Existing `init()` must continue to work
2. **Incremental migration**: Add new functionality alongside old
3. **Test at every step**: Run full test suite after each change
4. **Easy rollback**: Each step should be independently revertible

### Three-Phase Migration

#### Phase 8a: Add Transport Field (Non-Breaking)

Add transport field alongside existing sock_fd:

```zig
pub const Endpoint = struct {
    sock_fd: posix.socket_t,        // Keep for backward compat
    transport: ?Transport = null,    // Optional new transport

    pub fn sendTo(self: *Endpoint, peer: SockAddr, data: []const u8) !usize {
        // Use transport if available, otherwise fallback to sock_fd
        if (self.transport) |*t| {
            return t.send(peer, data);
        }
        return io_mod.sendTo(self.sock_fd, peer, data);
    }
};
```

**Changes Required**:
- Add `transport: ?Transport = null` field to Endpoint struct
- Modify `sendTo()` to check transport first
- Modify `recvFrom()` to check transport first
- Add `initWithTransport()` method
- Keep existing `init()` unchanged

**Risk**: LOW - Purely additive changes
**Testing**: Existing tests should pass unchanged

#### Phase 8b: Implement UdpTransport (Parallel Path)

Create full UdpTransport implementation in `tests/integration/transport.zig`:

```zig
pub const UdpTransport = struct {
    fd: posix.socket_t,
    family: u16,
    local_addr: SockAddr,

    pub fn init(bind_addr: []const u8) !UdpTransport {
        // Parse bind_addr (e.g., "127.0.0.1:4433")
        const addr_port = try parseBindAddr(bind_addr);

        // Create socket
        const fd = try posix.socket(
            addr_port.family,
            posix.SOCK.DGRAM | posix.SOCK.NONBLOCK,
            posix.IPPROTO.UDP
        );
        errdefer posix.close(fd);

        // Set socket options
        try setSockOpt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &@as(c_int, 1));

        // Bind to address
        try posix.bind(fd, @ptrCast(&addr_port.storage), addr_port.len);

        // Get actual bound address (if port was 0)
        var actual_addr: posix.sockaddr.storage = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        try posix.getsockname(fd, @ptrCast(&actual_addr), &addr_len);

        return UdpTransport{
            .fd = fd,
            .family = addr_port.family,
            .local_addr = SockAddr{ .storage = actual_addr, .len = addr_len },
        };
    }

    pub fn asTransport(self: *UdpTransport) Transport {
        return Transport{
            .sendFn = sendFn,
            .recvFn = recvFn,
            .pollFn = pollFn,
            .closeFn = closeFn,
            .getLocalAddrFn = getLocalAddrFn,
            .context = @ptrCast(self),
        };
    }

    fn sendFn(ctx: *anyopaque, peer: SockAddr, data: []const u8) !usize {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        return try posix.sendto(self.fd, data, 0, @ptrCast(&peer.storage), peer.len);
    }

    fn recvFn(ctx: *anyopaque, buf: []u8) !RecvResult {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        var peer_storage: posix.sockaddr.storage = undefined;
        var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);

        const n = try posix.recvfrom(
            self.fd,
            buf,
            0,
            @ptrCast(&peer_storage),
            &peer_len,
        );

        return RecvResult{
            .n = n,
            .peer = SockAddr{ .storage = peer_storage, .len = peer_len },
            .ecn = null,  // TODO: Extract from ancillary data
        };
    }

    fn pollFn(ctx: *anyopaque, timeout_ms: i32) !void {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        var fds = [1]posix.pollfd{
            .{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 },
        };

        const ready = try posix.poll(&fds, timeout_ms);
        if (ready == 0) return error.Timeout;
    }

    fn closeFn(ctx: *anyopaque) void {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        posix.close(self.fd);
    }

    fn getLocalAddrFn(ctx: *anyopaque) !SockAddr {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        return self.local_addr;
    }
};
```

**Changes Required**:
- Implement full UdpTransport in transport.zig
- Add address parsing helper
- Add socket option helpers
- Comprehensive error handling

**Risk**: LOW - Isolated to test directory
**Testing**: Add UDP transport tests

#### Phase 8c: Deprecate Direct Socket Access (Breaking)

Once transport abstraction is stable and tested:

```zig
pub const Endpoint = struct {
    transport: Transport,  // Now required, not optional
    // sock_fd removed

    pub fn init(allocator: *std.mem.Allocator, bind_addr: []const u8, config: *const Config) !Endpoint {
        var udp = try UdpTransport.init(bind_addr);
        return try initWithTransport(allocator, udp.asTransport(), config);
    }

    pub fn sendTo(self: *Endpoint, peer: SockAddr, data: []const u8) !usize {
        return self.transport.send(peer, data);  // Direct transport use
    }
};
```

**Changes Required**:
- Remove `sock_fd` field
- Remove fallback logic in sendTo/recvFrom
- Make `transport` required (not optional)
- Update all Connection structs to not reference sock_fd

**Risk**: MEDIUM - Breaking change
**Testing**: All tests must pass with new transport

## Detailed Implementation Steps

### Step 1: Prepare UdpTransport Implementation

**File**: `tests/integration/transport.zig`

**Tasks**:
1. Implement `parseBindAddr()` helper
   ```zig
   fn parseBindAddr(bind_addr: []const u8) !SockAddr {
       // Parse "127.0.0.1:4433" or "[::1]:4433"
       // Return SockAddr with family, storage, len
   }
   ```

2. Implement full `UdpTransport.init()`
   - Socket creation with SOCK_NONBLOCK
   - SO_REUSEADDR option
   - Bind to address
   - Query actual address (for port 0)

3. Implement sendFn/recvFn/pollFn
   - Direct POSIX calls
   - Proper error handling
   - ECN support (optional)

4. Add tests for UdpTransport
   ```zig
   test "UdpTransport: Create and bind" { ... }
   test "UdpTransport: Send and receive localhost" { ... }
   test "UdpTransport: Poll with timeout" { ... }
   ```

**Estimated Time**: 4 hours
**Validation**: All UdpTransport tests pass

### Step 2: Add Transport Field to Endpoint

**File**: `src/quic/endpoint.zig`

**Changes**:
```zig
// Add import
const transport_mod = @import("transport");  // When available

pub const Endpoint = struct {
    allocator: *std.mem.Allocator,
    sock_fd: posix.socket_t,
    transport: ?transport_mod.Transport = null,  // NEW FIELD
    // ... rest of fields unchanged ...
```

**Validation**:
- Compilation succeeds
- `sizeof(Endpoint)` increases by 48 bytes (acceptable)

**Estimated Time**: 30 minutes

### Step 3: Add initWithTransport Method

**File**: `src/quic/endpoint.zig`

**Changes**:
```zig
/// Initialize endpoint with custom transport (new in Phase 8)
pub fn initWithTransport(
    allocator: *std.mem.Allocator,
    transport: transport_mod.Transport,
    config: *const cfg.QuicConfig,
) !Endpoint {
    var ep = Endpoint{
        .allocator = allocator,
        .sock_fd = -1,  // Not used when transport is provided
        .transport = transport,
        .cfg = config.*,
        .role = .Server,  // Default, can be overridden
        .token_key = undefined,
        .conns = std.AutoHashMap(Key, *conn_mod.Connection).init(allocator),
        .timeouts = std.ArrayList(Timer).init(allocator),
        .capture_out = null,
    };

    // Initialize token key
    std.crypto.random.bytes(&ep.token_key);

    // Get local address from transport
    const local_addr = try transport.getLocalAddr();
    ep.local_addr = local_addr;

    return ep;
}
```

**Validation**:
- Compilation succeeds
- Can create endpoint with loopback transport in tests

**Estimated Time**: 1 hour

### Step 4: Update sendTo/recvFrom with Transport Fallback

**File**: `src/quic/endpoint.zig`

**Changes**:
```zig
pub fn sendTo(self: *Endpoint, peer: conn_mod.SockAddr, data: []const u8) !usize {
    // Use transport if available, otherwise fallback to UDP
    if (self.transport) |*t| {
        return try t.send(peer, data);
    }

    // Fallback to direct UDP (backward compatibility)
    return io_mod.sendTo(self.sock_fd, peer, data);
}

pub fn recvFrom(self: *Endpoint, buf: []u8) !struct { n: usize, peer: conn_mod.SockAddr } {
    if (self.transport) |*t| {
        const result = try t.recv(buf);
        return .{ .n = result.n, .peer = result.peer };
    }

    // Fallback to direct UDP (backward compatibility)
    const result = try io_mod.recvFrom(self.sock_fd, buf);
    return .{ .n = result.n, .peer = result.peer };
}
```

**Validation**:
- All existing tests pass (using fallback path)
- New loopback tests work (using transport path)

**Estimated Time**: 2 hours

### Step 5: Update poll() Method

**File**: `src/quic/endpoint.zig`

**Changes**:
```zig
pub fn poll(self: *Endpoint, timeout_ms: i32) !void {
    // Use transport poll if available
    if (self.transport) |*t| {
        try t.poll(timeout_ms);

        // Drain readable packets
        var buf: [4096]u8 = undefined;
        while (true) {
            const result = self.recvFrom(&buf) catch |err| {
                if (err == error.WouldBlock) break;
                return err;
            };

            // Process packet
            try self.processIncoming(result.peer, buf[0..result.n]);
        }

        return;
    }

    // Fallback to original epoll-based poll (backward compatibility)
    // ... existing poll implementation ...
}
```

**Validation**:
- Existing tests with UDP still work
- Loopback tests work without epoll

**Estimated Time**: 3 hours

### Step 6: Make init() Use initWithTransport()

**File**: `src/quic/endpoint.zig`

**Changes**:
```zig
pub fn init(
    allocator: *std.mem.Allocator,
    bind_addr: []const u8,
    config: *const cfg.QuicConfig,
) !Endpoint {
    // Create UDP transport
    var udp_transport = try transport_mod.UdpTransport.init(bind_addr);

    // Delegate to initWithTransport
    return try initWithTransport(allocator, udp_transport.asTransport(), config);
}
```

**Validation**:
- All existing integration tests pass
- No change in behavior from user perspective

**Estimated Time**: 1 hour

## Testing Strategy

### Phase 8a Testing (Transport Field Added)

**Objective**: Verify backward compatibility

**Tests**:
1. Run full existing test suite
   ```bash
   zig build test
   ```
   **Expected**: All tests pass unchanged

2. Test with loopback transport
   ```zig
   test "Endpoint with loopback transport" {
       var loopback = try LoopbackTransport.init(allocator, .{});
       defer loopback.deinit();

       var adapter = LoopbackTransportAdapter.init(&loopback, .A, local_addr, peer_addr);
       var transport = adapter.asTransport();

       var ep = try Endpoint.initWithTransport(allocator, transport, &config);
       defer ep.deinit();

       // Verify endpoint can send/recv via loopback
       const sent = try ep.sendTo(peer_addr, "test");
       try testing.expectEqual(@as(usize, 4), sent);
   }
   ```

3. Performance regression test
   ```bash
   # Measure UDP throughput before and after
   # Should be <1% difference
   ```

### Phase 8b Testing (UdpTransport Implementation)

**Objective**: Verify UdpTransport works correctly

**Tests**:
1. UdpTransport unit tests
   ```zig
   test "UdpTransport: Bind to IPv4"
   test "UdpTransport: Bind to IPv6"
   test "UdpTransport: Send/recv localhost"
   test "UdpTransport: Port 0 assignment"
   test "UdpTransport: Poll with data"
   test "UdpTransport: Poll timeout"
   test "UdpTransport: Get local address"
   ```

2. Integration with existing endpoint tests
   ```zig
   test "Endpoint via UdpTransport matches direct UDP behavior"
   ```

### Phase 8c Testing (Remove sock_fd)

**Objective**: Verify clean migration

**Tests**:
1. Full test suite with transport-only endpoint
2. Performance benchmarks (should match UDP baseline)
3. All 474 skip tests enabled with loopback
4. Stress tests with both UDP and loopback

## Risks and Mitigation

### Risk 1: Performance Regression

**Description**: Transport abstraction adds overhead

**Likelihood**: LOW
**Impact**: MEDIUM
**Mitigation**:
- Use function pointers (inlined by compiler)
- Benchmark at each step
- Profile hot paths
- Consider comptime dispatch if needed

### Risk 2: Breaking Existing Code

**Description**: Changes break existing endpoint users

**Likelihood**: MEDIUM
**Impact**: HIGH
**Mitigation**:
- Maintain backward compatibility in Phase 8a
- Deprecate gradually with warnings
- Provide migration guide
- Run full test suite at each step

### Risk 3: Complex Rollback

**Description**: Hard to revert if issues found

**Likelihood**: LOW
**Impact**: HIGH
**Mitigation**:
- Keep sock_fd field during Phase 8a/8b
- Make changes incrementally
- Tag each phase in version control
- Document rollback procedure

### Risk 4: Incomplete Testing

**Description**: Edge cases not covered

**Likelihood**: MEDIUM
**Impact**: MEDIUM
**Mitigation**:
- Add transport-specific tests
- Run stress tests with both UDP and loopback
- Test error paths (EADDRINUSE, EACCES, etc.)
- Fuzzing with transport abstraction

## Success Criteria

### Phase 8a Success Criteria

✅ Transport field added to Endpoint
✅ initWithTransport() method implemented
✅ sendTo/recvFrom support transport
✅ All existing tests pass unchanged
✅ Loopback transport works with endpoint
✅ No performance regression (<1%)

### Phase 8b Success Criteria

✅ UdpTransport fully implemented
✅ All UdpTransport tests pass
✅ init() uses initWithTransport() internally
✅ Behavior identical to previous UDP code
✅ Documentation updated

### Phase 8c Success Criteria

✅ sock_fd field removed
✅ All code uses transport abstraction
✅ 474 skip tests enabled
✅ All tests pass
✅ Performance matches baseline

## Timeline Estimate

| Phase | Task | Estimated Time | Risk |
|-------|------|---------------|------|
| 8a | Add transport field | 4 hours | LOW |
| 8a | Add initWithTransport() | 1 hour | LOW |
| 8a | Update sendTo/recvFrom | 2 hours | LOW |
| 8a | Update poll() | 3 hours | MEDIUM |
| 8a | Testing & validation | 4 hours | LOW |
| 8b | Implement UdpTransport | 4 hours | LOW |
| 8b | UdpTransport tests | 2 hours | LOW |
| 8b | Update init() | 1 hour | LOW |
| 8b | Integration testing | 4 hours | MEDIUM |
| 8c | Remove sock_fd | 2 hours | HIGH |
| 8c | Enable skip tests | 8 hours | MEDIUM |
| 8c | Full validation | 8 hours | MEDIUM |
| **Total** | **All phases** | **43 hours** | **MEDIUM** |

**Note**: This is ~1-2 weeks of careful, methodical work with thorough testing at each step.

## Current Status (Phase 8)

**Completed**:
- ✅ Analyzed endpoint UDP implementation
- ✅ Designed transport integration strategy
- ✅ Created detailed implementation plan
- ✅ Documented risks and mitigation
- ✅ Estimated timeline and effort

**Deferred to Future**:
- 📝 Actual endpoint.zig modification (Phase 8a)
- 📝 UdpTransport full implementation (Phase 8b)
- 📝 Clean migration to transport-only (Phase 8c)

**Rationale for Deferral**:
Modifying production endpoint.zig requires:
1. Significant testing infrastructure
2. Dedicated focus period (1-2 weeks)
3. Risk mitigation planning
4. Backup/rollback procedures

Phase 8 successfully delivers the **complete integration plan** needed for future implementation.

## Next Steps

### Immediate (Phase 8 Completion)

1. ✅ Complete integration planning document (this file)
2. 📝 Update IMPLEMENTATION_SUMMARY.md with Phase 8 status
3. 📝 Update README.md with Phase 8 section
4. 📝 Document proof-of-concept example

### Future (Phase 9+)

1. Schedule dedicated integration sprint
2. Create backup branch for rollback
3. Implement Phase 8a (transport field)
4. Test thoroughly
5. Implement Phase 8b (UdpTransport)
6. Test thoroughly
7. Implement Phase 8c (clean migration)
8. Enable all 474 skip tests
9. Performance validation

## References

- `tests/integration/transport.zig`: Transport abstraction implementation
- `tests/integration/TRANSPORT_ABSTRACTION_RFC.md`: Design rationale
- `src/quic/endpoint.zig`: Production endpoint (2,878 lines)
- `src/quic/endpoint/io.zig`: UDP I/O operations
- `tests/integration/loopback.zig`: Loopback transport for testing
- RFC 9000: QUIC Transport Protocol
- RFC 9001: Using TLS to Secure QUIC
- RFC 9002: QUIC Loss Detection and Congestion Control

## Appendix A: Example Usage

### Before Integration (Current)

```zig
// Create endpoint with UDP
var ep = try Endpoint.init(allocator, "127.0.0.1:4433", &config);
defer ep.deinit();

// Use endpoint
const conn = try ep.connectClient("127.0.0.1:4434");
```

### After Integration (Phase 8a+)

```zig
// Option 1: UDP transport (backward compatible)
var ep = try Endpoint.init(allocator, "127.0.0.1:4433", &config);
defer ep.deinit();

// Option 2: Custom transport (new capability)
var loopback = try LoopbackTransport.init(allocator, .{});
defer loopback.deinit();

var adapter = LoopbackTransportAdapter.init(&loopback, .A, local_addr, peer_addr);
var transport = adapter.asTransport();

var ep = try Endpoint.initWithTransport(allocator, transport, &config);
defer ep.deinit();

// Use endpoint identically
const conn = try ep.connectClient("127.0.0.1:4434");
```

## Appendix B: Rollback Procedure

If integration causes issues:

### Phase 8a Rollback

```bash
# Revert transport field addition
git revert <phase-8a-commit>
git push

# Verify tests pass
zig build test
```

### Phase 8b Rollback

```bash
# Revert init() changes
git revert <phase-8b-commit>
git push

# Restore direct UDP path
# Edit endpoint.zig to remove transport fallback
```

### Phase 8c Rollback

```bash
# This is harder - need to restore sock_fd
git revert <phase-8c-commit>
git push

# May need manual fixes
```

**Recommendation**: Don't proceed to Phase 8c until 8a/8b are stable and well-tested.
