# Endpoint Extraction Interfaces Design

**Phase 4b.5 Session 1**
**Date**: 2025-11-07

## Overview

This document defines the extraction interfaces for migrating endpoint.zig from a 3,698-line monolith to modular subsystems. The key strategy is **focused context structs** instead of passing the full Endpoint pointer.

---

## 1. RX Pipeline Interface (`endpoint/incoming.zig`)

### Context Struct

```zig
/// Context for RX packet processing - contains only what's needed
pub const RxContext = struct {
    allocator: *std.mem.Allocator,
    conns: *std.AutoHashMap(Key, *conn_mod.Connection),
    accepted: *std.ArrayList(*conn_mod.Connection),
    cfg: *const cfg.QuicConfig,
    send_fn: SendFn,
    schedule_timer_fn: ScheduleTimerFn,
    send_initial_probe_fn: SendInitialProbeFn,
    test_capture_enabled: bool,
    endpoint_role: EndpointRole,
};

/// Function signature for sending UDP datagrams
pub const SendFn = *const fn (peer: conn_mod.SockAddr, data: []const u8) anyerror!usize;

/// Function signature for scheduling timers
pub const ScheduleTimerFn = *const fn (conn: *conn_mod.Connection, kind: TimerKind, delay_ms: u32) anyerror!u64;

/// Function signature for sending Initial probe (after VN, path migration, etc.)
pub const SendInitialProbeFn = *const fn (conn: *conn_mod.Connection) anyerror!void;
```

### Public API

```zig
/// Main entry point for incoming datagram processing
pub fn processIncomingDatagram(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    ecn_bits: ?u8,
) void;

/// Process Version Negotiation packet
fn processVersionNegotiation(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
) void;

/// Process Short Header (1-RTT) packet
fn processShortHeader(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    ecn_bits: ?u8,
) void;

/// Process Initial packet
fn processInitial(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    ecn_bits: ?u8,
) void;

/// Process Handshake packet
fn processHandshake(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    ecn_bits: ?u8,
) void;

/// Process 0-RTT packet (future)
fn processZeroRtt(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    ecn_bits: ?u8,
) void;
```

### Usage from Endpoint

```zig
// In endpoint.zig
fn drainReadable(self: *Endpoint) void {
    var buf: [2048]u8 = undefined;
    while (true) {
        const result = self.recvFrom(&buf) catch break;

        // Create focused context
        var rx_ctx = incoming.RxContext{
            .allocator = self.allocator,
            .conns = &self.conns,
            .accepted = &self.accepted,
            .cfg = &self.cfg,
            .send_fn = sendToWrapper,
            .schedule_timer_fn = scheduleTimerWrapper,
            .send_initial_probe_fn = sendInitialProbeWrapper,
            .test_capture_enabled = self.test_capture_enabled,
            .endpoint_role = self.role,
        };

        // Delegate to modular RX pipeline
        incoming.processIncomingDatagram(&rx_ctx, result.peer, buf[0..result.n], null);
    }
}

fn sendToWrapper(peer: conn_mod.SockAddr, data: []const u8) anyerror!usize {
    // Access endpoint via closure or global context
    return endpoint_instance.sendTo(peer, data);
}
```

### Benefits

- **Testable**: Can create `RxContext` with mocks in unit tests
- **Focused**: Only 9 fields instead of 15+ in full Endpoint
- **Clear Dependencies**: Function signatures make data flow explicit

---

## 2. Frame Handler Interface (`endpoint/frame_handler.zig`)

### Context Struct

```zig
/// Context for frame processing
pub const FrameContext = struct {
    conn: *conn_mod.Connection,
    send_fn: SendFn,
    peer: conn_mod.SockAddr,
    space: PacketNumberSpace,
    allocator: *std.mem.Allocator,
};

pub const SendFn = *const fn (peer: conn_mod.SockAddr, data: []const u8) anyerror!usize;
```

### Public API

```zig
/// Process a single frame
pub fn processFrame(ctx: *FrameContext, fr: frame.Frame) !void;

/// Specialized handlers
fn handleStreamFrame(ctx: *FrameContext, s: frame.StreamFrame) !void;
fn handleAckFrame(ctx: *FrameContext, a: frame.AckFrame) !void;
fn handlePathChallenge(ctx: *FrameContext, pc: frame.PathChallengeFrame) !void;
fn handlePathResponse(ctx: *FrameContext, pr: frame.PathResponseFrame) !void;
fn handleMaxData(ctx: *FrameContext, md: frame.MaxDataFrame) !void;
fn handleMaxStreamData(ctx: *FrameContext, msd: frame.MaxStreamDataFrame) !void;
fn handleNewConnectionId(ctx: *FrameContext, ncid: frame.NewConnectionIdFrame) !void;
fn handleRetireConnectionId(ctx: *FrameContext, rcid: frame.RetireConnectionIdFrame) !void;
fn handleConnectionClose(ctx: *FrameContext, cc: frame.ConnectionCloseFrame) !void;
fn handleHandshakeDone(ctx: *FrameContext) !void;
fn handleDatagram(ctx: *FrameContext, d: frame.DatagramFrame) !void;
```

### Usage from RX Pipeline

```zig
// In processShortHeader()
var frame_ctx = frame_handler.FrameContext{
    .conn = conn,
    .send_fn = ctx.send_fn,
    .peer = peer,
    .space = .Application,
    .allocator = ctx.allocator,
};

while (offset < payload.len) {
    const fr = frame.decodeOne(payload[offset..]) catch break;
    offset += fr.n;
    frame_handler.processFrame(&frame_ctx, fr.f) catch |err| {
        std.debug.print("Frame processing error: {}\n", .{err});
    };
}
```

---

## 3. TLS Integration Interface (`endpoint/handshake_integration.zig`)

### Context Struct

```zig
/// Context for TLS handshake processing
pub const HandshakeContext = struct {
    conn: *conn_mod.Connection,
    allocator: *std.mem.Allocator,
    send_fn: SendFn,
    peer: conn_mod.SockAddr,
    cfg: *const cfg.QuicConfig,
};
```

### Public API

```zig
/// Process CRYPTO frame and advance TLS state machine
pub fn processCryptoFrame(
    ctx: *HandshakeContext,
    space: PacketNumberSpace,
    crypto_data: []const u8,
    offset: u64,
) !void;

/// Install Handshake keys after deriving from TLS secrets
pub fn installHandshakeKeys(
    ctx: *HandshakeContext,
    client_secret: [32]u8,
    server_secret: [32]u8,
) !void;

/// Install Application (1-RTT) keys
pub fn installApplicationKeys(
    ctx: *HandshakeContext,
    client_secret: [32]u8,
    server_secret: [32]u8,
) !void;

/// Send ServerHello in Initial packet (server-only)
pub fn sendServerHello(ctx: *HandshakeContext) !void;

/// Send HANDSHAKE_DONE (server-only, RFC 9000 §4.1.2)
pub fn sendHandshakeDone(ctx: *HandshakeContext) !void;
```

### Usage from RX Pipeline

```zig
// In processInitial() after extracting CRYPTO frame
var hs_ctx = handshake_integration.HandshakeContext{
    .conn = conn,
    .allocator = ctx.allocator,
    .send_fn = ctx.send_fn,
    .peer = peer,
    .cfg = ctx.cfg,
};

handshake_integration.processCryptoFrame(
    &hs_ctx,
    .Initial,
    crypto_frame.data,
    crypto_frame.offset,
) catch |err| {
    std.debug.print("TLS processing failed: {}\n", .{err});
};
```

---

## 4. Client Connection Interface (`endpoint/client.zig`)

### Context Struct

```zig
/// Context for client connection establishment
pub const ClientContext = struct {
    allocator: *std.mem.Allocator,
    conns: *std.AutoHashMap(Key, *conn_mod.Connection),
    cfg: *const cfg.QuicConfig,
    sock_fd: posix.socket_t,
    schedule_timer_fn: ScheduleTimerFn,
};
```

### Public API

```zig
/// Create basic connection struct (not fully initialized)
/// Current signature in endpoint.zig line 501
pub fn connectTo(
    ctx: *ClientContext,
    hostport: []const u8,
) !conn_mod.Connection;

/// Create and fully initialize client connection
/// Current signature in endpoint.zig line 507
pub fn connectClient(
    ctx: *ClientContext,
    hostport: []const u8,
) !*conn_mod.Connection;

/// Send Initial packet with ClientHello
/// Current signature in endpoint.zig line 547
pub fn clientSendInitialProbe(
    ctx: *ClientContext,
    conn: *conn_mod.Connection,
) !void;
```

### Usage from Main Endpoint API

```zig
// In endpoint.zig
pub fn connectClient(self: *Endpoint, hostport: []const u8) !*conn_mod.Connection {
    var client_ctx = client_mod.ClientContext{
        .allocator = self.allocator,
        .conns = &self.conns,
        .cfg = &self.cfg,
        .sock_fd = self.sock_fd,
        .schedule_timer_fn = scheduleTimerWrapper,
    };

    return client_mod.connectClient(&client_ctx, hostport);
}
```

---

## 5. Server Connection Interface (`endpoint/server.zig`)

### Context Struct

```zig
/// Context for server connection acceptance
pub const ServerContext = struct {
    allocator: *std.mem.Allocator,
    sock_fd: posix.socket_t,
};
```

### Public API

```zig
/// Accept a server connection from peer address
/// Current signature in endpoint.zig line 475
pub fn acceptFrom(
    ctx: *ServerContext,
    peer: conn_mod.SockAddr,
) conn_mod.Connection;

/// Enqueue accepted connection
/// Current signature in endpoint.zig line 480
pub fn pushAccepted(
    allocator: std.mem.Allocator,
    accepted: *std.ArrayList(*conn_mod.Connection),
    conn: *conn_mod.Connection,
) void;

/// Pop next accepted connection
/// Current signature in endpoint.zig line 485
pub fn popAccepted(
    accepted: *std.ArrayList(*conn_mod.Connection),
) ?*conn_mod.Connection;
```

**Note**: These functions are already implemented in `endpoint/server.zig` (lines 31-66). Need to update signatures to use context structs.

---

## 6. PTO Probe Interface (`endpoint/pto.zig`)

### Context Struct

```zig
/// Context for PTO probe generation
pub const PtoContext = struct {
    conn: *conn_mod.Connection,
    allocator: *std.mem.Allocator,
    send_fn: SendFn,
    peer: conn_mod.SockAddr,
    schedule_timer_fn: ScheduleTimerFn,
};
```

### Public API

```zig
/// Generate and send PTO probe packet
/// Current signature in endpoint.zig line 3392
pub fn sendPtoProbe(
    ctx: *PtoContext,
    kind: TimerKind,
) !void;

/// Build PTO probe payload (PING + CRYPTO/STREAM)
fn buildPtoProbePayload(
    ctx: *PtoContext,
    kind: TimerKind,
) ![]u8;
```

---

## 7. Platform I/O Interface (`endpoint/io.zig`)

### Context Struct

```zig
/// Context for UDP I/O operations
pub const IoContext = struct {
    sock_fd: posix.socket_t,
    captures: *std.ArrayList(OutCaptured),
    test_capture_enabled: bool,
};
```

### Public API

```zig
/// Send UDP datagram with ECN marking
/// Current signature in endpoint.zig line 425
pub fn sendTo(
    ctx: *IoContext,
    peer: conn_mod.SockAddr,
    data: []const u8,
) !usize;

/// Receive UDP datagram
/// Current signature in endpoint.zig line 467
pub fn recvFrom(
    sock_fd: posix.socket_t,
    buf: []u8,
) !struct { n: usize, peer: conn_mod.SockAddr };

/// Read all available datagrams
/// Current signature in endpoint.zig line 719
pub fn drainReadable(
    sock_fd: posix.socket_t,
    process_fn: ProcessDatagramFn,
) void;

pub const ProcessDatagramFn = *const fn (peer: conn_mod.SockAddr, data: []const u8, ecn_bits: ?u8) void;
```

**Note**: `sendTo()` is already implemented in `endpoint/io.zig` (lines 18-59). Need to enhance with context pattern.

---

## 8. Timer Interface (`endpoint/timer.zig`)

### Existing API (Already Modular)

`endpoint/timer.zig` already exists with 63 lines and provides:

```zig
/// Schedule timer in heap
pub fn schedule(
    timers: *std.ArrayList(Timer),
    deadline_ms: i64,
    id: u64,
    kind: TimerKind,
    conn: ?*conn_mod.Connection,
) void;

/// Cancel timer by ID
pub fn cancel(timers: *std.ArrayList(Timer), id: u64) bool;

/// Get next timeout
pub fn nextTimeout(timers: *std.ArrayList(Timer), now_ms: i64) ?i64;

/// Process expired timers
pub fn processExpired(
    timers: *std.ArrayList(Timer),
    now_ms: i64,
    handler_fn: TimerHandlerFn,
) void;

pub const TimerHandlerFn = *const fn (timer: Timer) void;
```

**Enhancement Needed**: Add timer dispatch logic from endpoint.zig line 3339.

---

## 9. Connection Lifecycle Interface (`endpoint/lifecycle.zig`)

### Context Struct

```zig
/// Context for connection lifecycle management
pub const LifecycleContext = struct {
    allocator: *std.mem.Allocator,
    conns: *std.AutoHashMap(Key, *conn_mod.Connection),
    retired: *std.ArrayList(*conn_mod.Connection),
};
```

### Public API

```zig
/// Close duplicate connections for same peer
/// Current signature in endpoint.zig line 3452
pub fn closeStaleConnectionsForPeer(
    ctx: *LifecycleContext,
    new_conn: *conn_mod.Connection,
) void;

/// Remove closed connections from table
/// Current signature in endpoint.zig line 3515
pub fn pruneClosed(ctx: *LifecycleContext) void;
```

---

## 10. Path Validation Interface (`endpoint/path.zig`)

### Context Struct

```zig
/// Context for path validation
pub const PathContext = struct {
    conn: *conn_mod.Connection,
    send_fn: SendFn,
};
```

### Public API

```zig
/// Handle path address change (migration)
/// Current signature in endpoint.zig line 3300
pub fn onPathAddressChanged(
    ctx: *PathContext,
    new_peer: conn_mod.SockAddr,
    new_peer_hash: u64,
    dcid_len: usize,
) void;

/// Complete path validation
/// Current signature in endpoint.zig line 3314
pub fn onPathValidated(ctx: *PathContext) void;
```

---

## Integration Strategy

### Endpoint Struct After Extraction

```zig
pub const Endpoint = struct {
    // Core resources
    sock_fd: posix.socket_t,
    sock_family: u16,
    allocator: *std.mem.Allocator,

    // State
    conns: std.AutoHashMap(Key, *conn_mod.Connection),
    accepted: std.ArrayList(*conn_mod.Connection),
    retired: std.ArrayList(*conn_mod.Connection),
    timers: std.ArrayList(Timer),

    // Configuration
    cfg: cfg.QuicConfig,
    role: EndpointRole,

    // Platform-specific
    loop_backend: lb.LoopBackend,
    epoll_fd: ?posix.fd_t,

    // Test infrastructure
    test_capture_enabled: bool,
    captures: std.ArrayList(OutCaptured),

    // ID generation
    next_timer_id: u64,

    // Thin wrapper methods
    pub fn poll(self: *Endpoint, timeout_ms: i32) !void {
        // Delegate to io module
    }

    pub fn connectClient(self: *Endpoint, hostport: []const u8) !*conn_mod.Connection {
        var ctx = client_mod.ClientContext{
            .allocator = self.allocator,
            .conns = &self.conns,
            .cfg = &self.cfg,
            .sock_fd = self.sock_fd,
            .schedule_timer_fn = scheduleTimerWrapper,
        };
        return client_mod.connectClient(&ctx, hostport);
    }

    // ... other thin wrappers
};
```

### Migration Path

**Phase 1**: Extract RX pipeline (Week 3-4)
- Move `processIncomingDatagram()` to `incoming.zig`
- Update `drainReadable()` to use `RxContext`
- **Unblocks**: 6 Initial packet tests

**Phase 2**: Extract TLS integration (Week 5-6)
- Move CRYPTO processing to `handshake_integration.zig`
- Move `clientSendInitialProbe()` to `client.zig`
- **Unblocks**: 6 transport parameter tests

**Phase 3**: Extract TX pipeline (Week 7-8)
- Move `sendPtoProbe()` to `pto.zig`
- Create `pacing.zig` for paced transmission

**Phase 4**: Extract lifecycle (Week 9-10)
- Move connection cleanup to `lifecycle.zig`
- Enhance accept queue management

**Phase 5**: Consolidate I/O (Week 11-12)
- Move platform poll backends to `io.zig`
- Complete module extraction

---

## Testing Strategy

### Unit Testing with Context Mocks

```zig
test "RX: Process Version Negotiation" {
    var conns = std.AutoHashMap(Key, *conn_mod.Connection).init(test_allocator);
    defer conns.deinit();

    var accepted = std.ArrayList(*conn_mod.Connection){};
    defer accepted.deinit();

    const cfg = cfg.QuicConfig{};

    var rx_ctx = incoming.RxContext{
        .allocator = test_allocator,
        .conns = &conns,
        .accepted = &accepted,
        .cfg = &cfg,
        .send_fn = mockSendFn,
        .schedule_timer_fn = mockScheduleTimerFn,
        .send_initial_probe_fn = mockSendInitialProbeFn,
        .test_capture_enabled = true,
        .endpoint_role = .Client,
    };

    const vn_packet = try packet.encodeVersionNegotiation(...);
    defer test_allocator.free(vn_packet);

    incoming.processVersionNegotiation(&rx_ctx, test_peer, vn_packet);

    // Assertions
}

fn mockSendFn(peer: conn_mod.SockAddr, data: []const u8) !usize {
    return data.len;
}

fn mockScheduleTimerFn(conn: *conn_mod.Connection, kind: TimerKind, delay_ms: u32) !u64 {
    return 1;
}

fn mockSendInitialProbeFn(conn: *conn_mod.Connection) !void {
    // Mock: no-op or track call
}
```

### Integration Testing with Real Endpoint

```zig
test "Integration: Client connects to server" {
    var server_ep = try Endpoint.init(test_allocator, "127.0.0.1:4433", &server_cfg);
    defer server_ep.deinit();

    var client_ep = try Endpoint.init(test_allocator, "127.0.0.1:0", &client_cfg);
    defer client_ep.deinit();

    const conn = try client_ep.connectClient("127.0.0.1:4433");
    try client_ep.clientSendInitialProbe(conn);

    try server_ep.poll(1000);
    const accepted = server_ep.popAccepted();
    try testing.expect(accepted != null);
}
```

---

## Key Design Principles

1. **Focused Contexts**: Each module receives only the state it needs
2. **Function Pointers**: Use callbacks for cross-module communication
3. **No Global State**: All state passed explicitly via context
4. **Testability First**: Design interfaces for easy mocking
5. **Backward Compatibility**: Endpoint keeps same public API
6. **Incremental Migration**: Each module extraction is independent

---

## Metrics

### Before Extraction
- **endpoint.zig**: 3,698 lines, 1 file
- **Largest function**: `processIncomingDatagram()` 2,256 lines
- **Test coverage**: 32/70 server tests (45.7%)

### After Extraction (Goal)
- **endpoint.zig**: ~500 lines (thin coordinator)
- **Modules**: 10+ files averaging ~300 lines each
- **Largest function**: <400 lines
- **Test coverage**: 70/70 server tests (100%)

---

## Success Criteria

- ✅ All modules use focused context structs
- ✅ No function exceeds 400 lines
- ✅ All 12 placeholder tests converted (6 Initial + 6 TP)
- ✅ Build passes with 818/818 tests
- ✅ Endpoint public API unchanged
- ✅ Each module has comprehensive unit tests
