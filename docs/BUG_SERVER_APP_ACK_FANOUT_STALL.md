# Server Application ACK Fanout Contention

## Status

Fixed in the QUIC library after `v0.1.21`.

## Summary

High fan-in request/response workloads were spending excessive endpoint poll time
building and sending standalone Application ACK packets. Geode reproduced this
with 4096 parallel QUIC requests and a 250 microsecond request stagger: the
database scheduler was idle, response writes were not blocked, but QUIC
short-header processing showed multi-second poll cycles concentrated in frame
processing and ACK send work.

The hot shape was a server receiving one STREAM request packet per connection,
then immediately sending a standalone ACK before the application response had a
chance to write. `writeStream()` already prepends a pending Application ACK to
outgoing STREAM packets, so the standalone ACK was usually redundant for
request/response traffic.

## Fix

The server Application ACK policy now:

- Sends ACKs immediately for ECN, control/non-STREAM ack-eliciting frames, and
  client-side processing.
- Defers the first server-side STREAM-only standalone ACK so the response packet
  can piggyback the ACK.
- Sends a standalone ACK on the second server-side STREAM-only ack-eliciting
  packet, matching RFC 9000 section 13.2.1 guidance.
- Schedules an `AppAckDelay` timer for deferred ACKs so upload-only or quiet
  peers still receive an ACK within `max_ack_delay`.
- Clears the deferred ACK counter when either a standalone ACK is sent or a
  STREAM packet carries a piggybacked ACK.

The fix is intentionally scoped to server-side STREAM-only first packets. It
does not delay ECN feedback, control frame acknowledgement, client ACK behavior,
or large uploads.

## Files

- `src/quic/conn.zig`: Application ACK accounting and immediate/deferred policy.
- `src/quic/endpoint/incoming/module_c.zig`: receive-path policy decision and
  delayed ACK timer scheduling.
- `src/quic/endpoint.zig`: `AppAckDelay` timer callback.
- `src/quic/connection/methods_b.zig`: ACK counter reset when `writeStream()`
  piggybacks an ACK.
- `tests/unit/endpoint/test_incoming_session3.zig`: policy regression tests.

## Verification

Focused verification:

```sh
zig build test -Dtest-filter=app_ack_policy --summary all
zig build --summary all
zig build -Doptimize=ReleaseFast --summary all
```

Known unrelated broad-test failures at the time this was fixed:

- `tests/test_tls_handshake_context.zig`: tampered client Finished now reports
  `.terminated` instead of the older `.keys_installed` expectation.
- `tests/unit/endpoint/test_server.zig`: FIFO queue expectation does not match
  the existing `swapRemove(0)` pop behavior.

## Operational Notes

For request/response services such as Geode, this removes one UDP send and one
short-header packet build from the common first-request path on each server-side
connection. Under synchronized fan-in, that directly reduces endpoint poll-cycle
duration and gives response writers more opportunity to piggyback ACKs.

If a workload is upload-only and the server does not write a response, the
delayed ACK timer emits the pending ACK within the connection's negotiated
`max_ack_delay`, and every second STREAM packet still triggers an immediate ACK.
