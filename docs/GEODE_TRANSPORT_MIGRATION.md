# Geode And Dependent-System Transport Migration Guide

Last updated: 2026-02-16

This guide documents how to migrate from application-local QUIC bootstrap code (for example `geode/src/transport/quic.zig`) to the library transport API in `src/quic/transport.zig`.

## Audience

- Geode maintainers migrating off local transport shims.
- Other dependent services that copied geode's bootstrap patterns.
- Integrators standardizing on this library's transport contract.

## Scope

The APIs and behaviors below are now implemented in this library and should not be re-implemented in downstream applications:

- Poll/I-O synchronization for thread safety (`PollSync`).
- Deferred connection destruction (`destroyConnection` + `drainPendingDestroy`).
- Non-blocking accept (`tryAccept`) and `WouldBlock` semantics.
- Client handshake timeout API (`waitForHandshake(timeout_secs)`).
- Client stream open/poll API (`openStream`, `poll`).
- Stream read semantics (`WouldBlock`, retrying line reads, interrupt-aware line reads).
- Localhost normalization and insecure SNI behavior.
- Self-signed certificate generation using ECDSA P-256.

## API Mapping (Bootstrap -> Library)

| Bootstrap usage pattern | Library API |
|---|---|
| `transport.PollSync` wrapper in app code | Use built-in `transport.PollSync` (already wired into `QuicTransport`, `QuicConnection`, `QuicStream`) |
| Manual queued cleanup + endpoint-safe destruction | `QuicTransport.destroyConnection(conn)` from workers + `QuicTransport.drainPendingDestroy()` on poll/accept thread |
| App-local nonblocking accept helper | `QuicTransport.tryAccept() ?*QuicConnection` |
| App-local timeout handshake loops | `QuicClient.waitForHandshake(timeout_secs)` |
| App-local `openStream` helper | `QuicClient.openStream(bidirectional)` |
| App-local endpoint poll wrapper | `QuicClient.poll(timeout_ms)` and `QuicTransport.poll(timeout_ms)` |
| App-local peer cert extraction | `QuicConnection.getPeerCertificateDer()` |
| App-local stream cleanup helper | `QuicConnection.destroyStream(stream)` |
| Localhost special-casing | Built in to `connectInsecure`, `connectEx`, and listener bind path |
| App-local cert generation scripts | `QuicTransport.Config.auto_generate_certs = true` (ECDSA P-256 OpenSSL path) |

## Server Migration

### Before (bootstrap pattern)

- App called endpoint poll/accept and stream synchronization manually.
- App owned connection lifecycle and cleanup queues.

### After (library-owned pattern)

```zig
const transport = @import("transport");

var qt = try transport.QuicTransport.init(allocator, .{
    .address = "0.0.0.0",
    .port = 7567,
    .cert_path = "certs/server.crt",
    .key_path = "certs/server.key",
    .max_connections = 1000,
});
defer qt.deinit();
try qt.listen();

while (true) {
    qt.drainPendingDestroy(); // main/poll thread only
    const conn = qt.accept() catch |err| {
        if (err == transport.QuicError.WouldBlock) {
            std.Thread.sleep(1 * std.time.ns_per_ms);
            continue;
        }
        return err;
    };

    // Worker ownership of connection
    defer qt.destroyConnection(conn);
    const stream = try conn.acceptStream();
    defer conn.destroyStream(stream);
}
```

## Client Migration

### Before (bootstrap pattern)

- App implemented handshake timeout loops and stream-open wrappers.
- App manually normalized localhost and managed SNI edge cases.

### After (library-owned pattern)

```zig
const transport = @import("transport");

var client = transport.QuicClient.init(allocator);
defer client.deinit();

try client.connectInsecure("localhost", 7567, true); // localhost normalized internally
try client.waitForHandshake(5);

var stream = try client.openStream(true);
defer stream.deinit();

try stream.writeAll("ping\n");
try stream.finish();

const line = try stream.readLineWithInterrupt(1024, null);
defer allocator.free(line);
```

## Behavioral Contracts

1. `WouldBlock` is a normal control-flow signal for non-ready reads/accept paths.
2. `destroyConnection` removes wrapper tracking immediately and defers endpoint destruction safely.
3. `drainPendingDestroy` must run on the thread that drives poll/accept.
4. `waitForHandshake(timeout_secs)` is required before opening/using streams.
5. `connectEx` is fail-closed when CA material is missing.
6. Client idle timeout defaults to 300s for parity with long-running stream workloads.

## Certificate And TLS Notes

1. Secure defaults require explicit TLS material unless `auto_generate_certs` is enabled.
2. Auto-generated certs are ECDSA P-256.
3. Insecure mode (`allow_insecure = true` / `connectInsecure(..., true)`) is for test/dev only.

## Validation Checklist For Dependents

1. Remove app-local transport wrappers that duplicate library APIs above.
2. Update handshake calls to `waitForHandshake(timeout_secs)`.
3. Replace app-local stream open helpers with `openStream(bidirectional)`.
4. Route worker cleanup through `destroyConnection`.
5. Ensure accept/poll loop calls `drainPendingDestroy`.
6. Verify `WouldBlock` paths are treated as retryable, not fatal.
7. Run migration tests:
   - `zig build test --test-filter "transport geode compat"`
   - `zig build -Dfull-test-graph=true test --test-filter "transport geode compat"`

## Reference Implementations

- `src/quic/transport.zig`
- `tests/test_transport_geode_compat.zig`
- `examples/client_transport.zig`
- `examples/server_transport.zig`
