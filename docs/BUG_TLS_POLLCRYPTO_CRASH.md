# TLS pollCrypto Crash Under Concurrent Long-Header Dispatch

Reported downstream by Geode on 2026-05-28.

## Summary

High connection churn can drive two endpoint poll workers into the same connection's TLS context at the same time. The visible panic is usually:

```text
thread panic: source and destination arguments have non-equal lengths
  std/array_list.zig in toOwnedSlice
  tls13/context.zig in pollCrypto
  quic/endpoint.zig in pollWithStats
```

`tls13.Context.pollCrypto()` transfers the outbound CRYPTO buffer with `ArrayList.toOwnedSlice()`. If another worker appends to that same buffer while ownership is being transferred, the source length can change between allocation and copy, which trips Zig's runtime length check.

## Root Cause

The endpoint had already serialized the normal burst-drain Initial and Handshake receive paths, plus the deferred pending-handshake retry path. The remaining gap was the generic `processIncomingDatagram()` dispatcher used by backend callbacks, test injection, and coalesced long-header datagrams. That path called `incoming.processInitial()` and `incoming.processHandshake()` directly, bypassing:

- `Endpoint.mu` around `prepareInitialConnection()`
- `Connection.endpoint_rx_serial_mu` around per-connection Initial/Handshake processing
- the established lock order that keeps TLS `processCrypto()` and `pollCrypto()` single-writer for one connection

That made coalesced Initial/Handshake packets a remaining path back to concurrent TLS buffer mutation.

## Fix

`REQ-QUIC-HC-168` routes generic long-header dispatch through the same serialized wrappers used by the optimized receive drain:

- `processInitialDatagramConcurrent()`
- `processHandshakeDatagramConcurrent()`

The fallback drain no longer takes `Endpoint.mu` around `processIncomingDatagram()`, because the dispatcher now performs the necessary endpoint and connection serialization internally for long-header handshake packets. The endpoint callback thread-local now saves and restores the previous value so nested dispatch through the wrappers does not clear the outer callback context before a coalesced datagram finishes.

## Regression Coverage

Focused coverage:

```sh
zig build test -Dtest-filter=thread_safety --summary all
zig build test -Dtest-filter=pending_hs_send --summary all
zig build --summary all
```

The thread-safety test includes `generic_long_header_dispatch_uses_serialized_tls_wrappers`; the pending-handshake test continues to verify the earlier deferred retry serialization.

## Operational Guidance

QUIC consumers should pull a revision containing `REQ-QUIC-HC-168` when running multiple endpoint poll workers or when accepting high rates of new connections. The TLS context remains a single-writer object; all QUIC-owned calls into TLS handshake mutation must stay behind the connection-local serializers.
