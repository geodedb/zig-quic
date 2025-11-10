# RFC: Transport Abstraction Layer for QUIC Endpoint

## Status

**Phase**: 7
**Status**: Implementation
**Authors**: Integration Test Framework Team
**Created**: 2025-11-10
**Updated**: 2025-11-10

## Abstract

This RFC proposes a transport abstraction layer for the QUIC endpoint implementation that enables pluggable transport backends. The primary goal is to support both production UDP sockets and test loopback transports without code duplication or performance penalties.

## Motivation

### Current State

The QUIC implementation has two separate transport mechanisms:

1. **Production Endpoint** (`src/quic/endpoint.zig`):
   - Uses real UDP sockets via `std.posix.socket`
   - Direct OS system calls for send/receive
   - Blocking/non-blocking I/O via `poll()`
   - Production-ready, performant

2. **Test Loopback** (`tests/integration/loopback.zig`):
   - In-memory packet queues
   - Deterministic delivery with configurable faults
   - Mock time control
   - Perfect for integration testing

**Problem**: These are incompatible - endpoint cannot use loopback transport, leaving 474 integration tests unable to run against the real endpoint.

### Goals

1. **Enable 474 skip tests**: Allow loopback transport with real endpoint
2. **Zero production overhead**: No performance penalty for UDP path
3. **Maintain compatibility**: Existing UDP code continues to work
4. **Support fault injection**: Enable deterministic testing with real endpoint
5. **Clean abstraction**: Simple, type-safe transport interface

### Non-Goals

1. **Not changing packet format**: Transport abstraction is orthogonal to QUIC packet structure
2. **Not supporting exotic transports**: Focus on UDP and loopback only
3. **Not changing public API**: Endpoint initialization remains compatible

## Design

### Transport Interface

```zig
//! Transport abstraction for QUIC endpoint
//!
//! Enables pluggable transport backends (UDP, loopback, etc.) while maintaining
//! performance and type safety.

const std = @import("std");
const conn_mod = @import("quic_conn");

/// Socket address type (common across transports)
pub const SockAddr = conn_mod.SockAddr;

/// Result of receive operation
pub const RecvResult = struct {
    /// Number of bytes received
    n: usize,

    /// Peer address
    peer: SockAddr,

    /// ECN marking (if available)
    ecn: ?u8 = null,
};

/// Transport backend interface
///
/// This is a fat pointer pattern: vtable + context pointer
/// Zero-cost abstraction when statically dispatched
pub const Transport = struct {
    /// Send function pointer
    sendFn: *const fn (ctx: *anyopaque, peer: SockAddr, data: []const u8) anyerror!usize,

    /// Receive function pointer
    recvFn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!RecvResult,

    /// Poll function pointer (optional, for event-driven I/O)
    pollFn: ?*const fn (ctx: *anyopaque, timeout_ms: i32) anyerror!void,

    /// Close function pointer
    closeFn: *const fn (ctx: *anyopaque) void,

    /// Opaque context pointer (cast to concrete type in implementations)
    context: *anyopaque,

    /// Send packet to peer
    pub fn send(self: *Transport, peer: SockAddr, data: []const u8) !usize {
        return self.sendFn(self.context, peer, data);
    }

    /// Receive packet from any peer
    pub fn recv(self: *Transport, buf: []u8) !RecvResult {
        return self.recvFn(self.context, buf);
    }

    /// Poll for events (if supported)
    pub fn poll(self: *Transport, timeout_ms: i32) !void {
        if (self.pollFn) |poll_fn| {
            try poll_fn(self.context, timeout_ms);
        }
    }

    /// Close transport
    pub fn close(self: *Transport) void {
        self.closeFn(self.context);
    }
};
```

### UDP Transport Adapter

```zig
//! UDP transport adapter for production use

pub const UdpTransport = struct {
    /// Socket file descriptor
    fd: std.posix.socket_t,

    /// Socket address family
    family: u16,

    /// Initialize UDP transport
    pub fn init(bind_addr: []const u8) !UdpTransport {
        // Existing UDP socket initialization code from endpoint.zig
        // ...
    }

    /// Convert to generic transport interface
    pub fn asTransport(self: *UdpTransport) Transport {
        return Transport{
            .sendFn = sendFn,
            .recvFn = recvFn,
            .pollFn = pollFn,
            .closeFn = closeFn,
            .context = @ptrCast(self),
        };
    }

    fn sendFn(ctx: *anyopaque, peer: SockAddr, data: []const u8) !usize {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        // Existing UDP sendto implementation
        // ...
    }

    fn recvFn(ctx: *anyopaque, buf: []u8) !RecvResult {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        // Existing UDP recvfrom implementation
        // ...
    }

    fn pollFn(ctx: *anyopaque, timeout_ms: i32) !void {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        // Existing poll implementation
        // ...
    }

    fn closeFn(ctx: *anyopaque) void {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        std.posix.close(self.fd);
    }
};
```

### Loopback Transport Adapter

```zig
//! Loopback transport adapter for testing

pub const LoopbackTransportAdapter = struct {
    /// Underlying loopback transport
    loopback: *loopback_mod.LoopbackTransport,

    /// Which side of the loopback (A or B)
    side: enum { A, B },

    /// Initialize from existing loopback transport
    pub fn init(loopback: *loopback_mod.LoopbackTransport, side: enum { A, B }) LoopbackTransportAdapter {
        return .{
            .loopback = loopback,
            .side = side,
        };
    }

    /// Convert to generic transport interface
    pub fn asTransport(self: *LoopbackTransportAdapter) Transport {
        return Transport{
            .sendFn = sendFn,
            .recvFn = recvFn,
            .pollFn = null,  // Loopback is synchronous
            .closeFn = closeFn,
            .context = @ptrCast(self),
        };
    }

    fn sendFn(ctx: *anyopaque, peer: SockAddr, data: []const u8) !usize {
        const self: *LoopbackTransportAdapter = @ptrCast(@alignCast(ctx));
        // Delegate to loopback.send() based on side
        return switch (self.side) {
            .A => self.loopback.sendFromA(peer, data),
            .B => self.loopback.sendFromB(peer, data),
        };
    }

    fn recvFn(ctx: *anyopaque, buf: []u8) !RecvResult {
        const self: *LoopbackTransportAdapter = @ptrCast(@alignCast(ctx));
        // Delegate to loopback.recv() based on side
        const result = switch (self.side) {
            .A => try self.loopback.recvFromB(buf),
            .B => try self.loopback.recvFromA(buf),
        };

        return RecvResult{
            .n = result.n,
            .peer = result.peer,
            .ecn = null,  // Loopback doesn't currently support ECN
        };
    }

    fn closeFn(ctx: *anyopaque) void {
        _ = ctx;
        // Loopback is managed externally, no-op
    }
};
```

### Endpoint Integration

```zig
//! Updated Endpoint to support transport abstraction

pub const Endpoint = struct {
    // ... existing fields ...

    /// Transport backend (UDP or loopback)
    transport: Transport,

    /// Initialize with default UDP transport (backward compatible)
    pub fn init(allocator: *std.mem.Allocator, bind_addr: []const u8, config: *const Config) !Endpoint {
        var udp = try UdpTransport.init(bind_addr);
        return try initWithTransport(allocator, udp.asTransport(), config);
    }

    /// Initialize with custom transport (new)
    pub fn initWithTransport(
        allocator: *std.mem.Allocator,
        transport: Transport,
        config: *const Config,
    ) !Endpoint {
        var ep = Endpoint{
            .allocator = allocator,
            .transport = transport,
            .cfg = config.*,
            // ... initialize other fields ...
        };
        return ep;
    }

    /// Send packet (now uses transport abstraction)
    pub fn sendTo(self: *Endpoint, peer: SockAddr, data: []const u8) !usize {
        return try self.transport.send(peer, data);
    }

    /// Receive packet (now uses transport abstraction)
    pub fn recvFrom(self: *Endpoint, buf: []u8) !RecvResult {
        return try self.transport.recv(buf);
    }

    /// Poll for events
    pub fn poll(self: *Endpoint, timeout_ms: i32) !void {
        try self.transport.poll(timeout_ms);
        // ... rest of poll implementation ...
    }
};
```

## Performance Analysis

### Zero-Cost Abstraction

The transport interface uses function pointers, which are statically dispatched at compile time when the concrete type is known. Modern compilers inline these calls aggressively.

**Benchmark** (hypothetical, needs actual measurement):

```
UDP direct:           1.2µs per packet
UDP via Transport:    1.2µs per packet (0% overhead)
Loopback direct:      0.1µs per packet
Loopback via Transport: 0.1µs per packet (0% overhead)
```

### Memory Overhead

```
sizeof(Transport) = 40 bytes (5 function pointers + 1 context pointer on 64-bit)
```

This is negligible compared to Endpoint size (~several KB).

### Call Overhead

Function pointer call is ~1 CPU cycle on modern processors. The actual I/O operation dominates (thousands of cycles for UDP system call, hundreds for loopback queue operations).

## Migration Strategy

### Phase 1: Add Transport Abstraction (No Breaking Changes)

1. Add `transport.zig` module with interface
2. Create `UdpTransport` adapter wrapping existing UDP code
3. Add `Endpoint.initWithTransport()` alongside existing `init()`
4. **Backward compatible**: Existing code continues to use `init()`

### Phase 2: Migrate Endpoint Internals

1. Replace direct socket operations with `transport.send()/recv()`
2. Test thoroughly with UDP transport
3. Verify no performance regression

### Phase 3: Add Loopback Support

1. Create `LoopbackTransportAdapter`
2. Update integration tests to use `initWithTransport()`
3. Enable skip tests incrementally

### Phase 4: Deprecate Direct Socket Access (Optional)

1. Make UDP operations private
2. Encourage transport abstraction for new code
3. Maintain `init()` as sugar over `initWithTransport()`

## Testing Strategy

### Unit Tests

```zig
test "Transport interface: UDP send/recv" {
    var udp = try UdpTransport.init("127.0.0.1:0");
    defer udp.close();

    var transport = udp.asTransport();

    // Test send
    const sent = try transport.send(peer_addr, "test");
    try testing.expectEqual(@as(usize, 4), sent);

    // Test recv
    var buf: [1024]u8 = undefined;
    const result = try transport.recv(&buf);
    try testing.expectEqual(@as(usize, 4), result.n);
}

test "Transport interface: Loopback send/recv" {
    var loopback = try LoopbackTransport.init(allocator, .{});
    defer loopback.deinit();

    var adapter_a = LoopbackTransportAdapter.init(&loopback, .A);
    var transport_a = adapter_a.asTransport();

    var adapter_b = LoopbackTransportAdapter.init(&loopback, .B);
    var transport_b = adapter_b.asTransport();

    // Send from A
    const sent = try transport_a.send(peer_addr, "test");
    try testing.expectEqual(@as(usize, 4), sent);

    // Recv on B
    var buf: [1024]u8 = undefined;
    const result = try transport_b.recv(&buf);
    try testing.expectEqual(@as(usize, 4), result.n);
}
```

### Integration Tests

```zig
test "Endpoint with loopback transport: Basic handshake" {
    var loopback = try LoopbackTransport.init(allocator, .{});
    defer loopback.deinit();

    // Server endpoint with loopback
    var server_adapter = LoopbackTransportAdapter.init(&loopback, .A);
    var server = try Endpoint.initWithTransport(
        allocator,
        server_adapter.asTransport(),
        &server_config,
    );
    defer server.deinit();

    // Client endpoint with loopback
    var client_adapter = LoopbackTransportAdapter.init(&loopback, .B);
    var client = try Endpoint.initWithTransport(
        allocator,
        client_adapter.asTransport(),
        &client_config,
    );
    defer client.deinit();

    // Now can run full handshake with deterministic loopback!
    // This enables all 474 skip tests
}
```

## Security Considerations

1. **Type Safety**: Function pointer casts are type-checked at compile time
2. **No Data Leakage**: Context pointer is opaque; implementations control access
3. **No New Attack Surface**: Transport abstraction doesn't add network exposure
4. **Maintainability**: Centralized transport code is easier to audit

## Alternatives Considered

### Alternative 1: Template/Generic Endpoint

```zig
pub fn Endpoint(comptime T: type) type {
    return struct {
        transport: T,
        // ...
    };
}
```

**Rejected**: Code duplication for each transport type, harder to use.

### Alternative 2: Interface Union

```zig
pub const Transport = union(enum) {
    udp: UdpTransport,
    loopback: LoopbackTransport,
};
```

**Rejected**: All transport types must be known at compile time; not extensible.

### Alternative 3: Callbacks in Config

```zig
pub const Config = struct {
    sendFn: ?*const fn(...) void,
    recvFn: ?*const fn(...) void,
};
```

**Rejected**: Scattered interface; harder to maintain; no clear ownership.

## Implementation Checklist

- [x] Design transport interface
- [x] Write RFC document
- [ ] Implement `transport.zig` module
- [ ] Create `UdpTransport` adapter
- [ ] Create `LoopbackTransportAdapter`
- [ ] Update `Endpoint` to support transport
- [ ] Add unit tests for transport interface
- [ ] Add integration tests with loopback
- [ ] Performance benchmarks
- [ ] Update documentation
- [ ] Enable skip tests incrementally

## References

- **Existing Code**:
  - `src/quic/endpoint.zig` - Current UDP implementation
  - `tests/integration/loopback.zig` - Loopback transport
  - `tests/integration/ENDPOINT_INTEGRATION_GUIDE.md` - Integration strategy

- **Similar Patterns**:
  - Rust `std::io::Read`/`Write` traits
  - Go `io.Reader`/`Writer` interfaces
  - Java `java.nio.channels.Channel`

## Appendix: Full Code Example

See `tests/integration/transport.zig` for complete implementation.

## Changelog

- **2025-11-10**: Initial RFC created for Phase 7
