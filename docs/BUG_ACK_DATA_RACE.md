# BUG: ACK Frame Data Race (PnWindow / ack_ranges_buf)

## Symptom

QUIC clients (e.g., quic-go) report `PROTOCOL_VIOLATION` or `FRAME_ENCODING_ERROR`
when communicating with the Zig QUIC library under moderate-to-high load (observed
at 77+ QPS during Geode load testing). ACK frames sent by the server contain:

1. ACKs for skipped packet numbers (PnWindow.max updated before bitset shifted)
2. Invalid ACK ranges (ack_ranges_buf corrupted by concurrent writes)

## Root Cause

Two threads access the same connection's `PnWindow` and `ack_ranges_buf`
concurrently without mutual exclusion:

- **Poll thread** (in `endpoint/incoming/module_c.zig` and `module_b.zig`):
  calls `conn.trackRecvPnApp()` (WRITES PnWindow) and `conn.buildAckApp()`
  (READS PnWindow, WRITES ack_ranges_buf) WITHOUT holding `conn.mu`.

- **Worker thread** (in `connection/methods_b.zig`): calls `conn.buildAckApp()`
  (READS PnWindow, WRITES ack_ranges_buf) UNDER `conn.mu`.

The library's own documented threading model (`conn.zig:7-9`) requires that all
connection state access be protected by `conn.mu`, but the incoming packet
processing path did not follow this contract.

## Fix

Acquire `conn.mu` in the incoming packet processing path around all connection
state mutations and reads that race with worker threads:

### `module_c.zig` (processShortHeader - 1-RTT packets)

- **Lock acquired** before STEP 5 (key promotion) through STEP 7 (prev key cleanup),
  covering `trackRecvPnApp()` and key state mutations.
- **Lock released** before STEP 8 (`processFrames()`) because the frame handler
  calls `pushStreamFrame()` which acquires `conn.mu` internally (Zig mutexes
  are non-recursive; nested locking would deadlock).
- **Lock re-acquired** after `processFrames()` for STEP 9 (ACK generation via
  `buildAckApp()`) and post-frame state mutations (HANDSHAKE_DONE, CONNECTION_CLOSE).
- **Lock released** via `defer conn.mu.unlock()` covering all return paths.

### `module_b.zig` (processHandshake - Handshake packets)

- **Lock acquired** at function entry (after connection lookup) with
  `defer conn.*.mu.unlock()` covering the entire function.
- Safe to hold across the entire function because Handshake frame processing
  only handles CRYPTO, ACK, PING, and PADDING frames (no `pushStreamFrame()`
  calls that would cause deadlock).

## Affected Versions

All versions of the Zig QUIC library prior to this fix.

## Discovery

Geode graph database load testing, 2026-03-27. The race manifested as
intermittent `FRAME_ENCODING_ERROR` disconnections from quic-go clients under
sustained query load exceeding 77 queries per second.

## Verification

- `zig build test` passes
- `zig build` succeeds
- The race between poll thread and worker thread is eliminated because both
  now hold `conn.mu` when accessing PnWindow and ack_ranges_buf
