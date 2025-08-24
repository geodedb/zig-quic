# NEXT — Near‑term Plan (rolling)

Date: 2025-08-23 12:00 UTC

This document tracks the next actionable slices, matching RFC 9000/9001/9002 scope and repo process rules.

## 1) CUBIC + benches

- Implement CUBIC controller alongside NewReno; select via `-Dcc=cubic`.
- Benchmarks: NR vs CUBIC across fixed BDP/RTT/loss profiles; record throughput/RTT.
- Acceptance:
  - `zig build bench` succeeds, benches print comparative results.
  - Unit tests cover CUBIC growth/epoch transitions.

## 2) Streams and flow control basics

- FIN-aware reassembly and readable byte accounting.
- STOP_SENDING/RESET_STREAM handling.
- Emit MAX_DATA/MAX_STREAM_DATA on thresholds.
- Acceptance:
  - New unit tests for FIN, reset, and MAX\* emissions pass in Debug/ReleaseSafe.

## 3) Extensions to CLI and wire toggles

- Wire RFC 9221 DATAGRAM to CLI client/server.
- Add Spin Bit and GREASE toggles; plumb to packet formatting.
- Groundwork for Compatible VN and QUIC v2 vectors.
- Acceptance:
  - CLI flags work; DATAGRAM echo roundtrip in tests.

## 4) Migration and tokens

- Persist NEW_TOKEN and use on reconnect.
- Path validation/migration (NAT rebinding); stateless reset detector.
- Acceptance:
  - Unit tests that simulate token use, rebinding, and stateless reset recognition.

## 5) Event loop parity + logging

- Validate pacing across epoll/kqueue/IOCP; tune pacing policy.
- Add JSON Lines logs (INFO/ERROR); pin deterministic seeds in CI.
- Acceptance:
  - CI remains green on ubuntu/macos/windows; logs are structured JSON.

## Process gates for each slice

- Update `docs/GAP.md` (status bump + risks + next slice).
- Update `docs/DESIGN.md` where public APIs or tricky logic change.
- `zig build` / `zig build test` must pass; `zig build fuzz` and `zig build bench` must build.
- Run `./zig-out/bin/doccheck` and fix missing doc comments.
