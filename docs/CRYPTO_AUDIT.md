# Crypto Audit

Last updated: 2026-04-26

Scope: GitLab #136 and the implemented subset of #142. This document records evidence for current QUIC crypto-sensitive operations. GAP-0013 remains open for skipped advanced key lifecycle, key update, and AEAD-limit vectors.

## Summary

- Retry integrity tag derivation is fallible, validates CID/AAD sizes, and no longer hides key-schedule errors behind `catch unreachable`.
- Retry integrity verification uses constant-time tag comparison.
- RFC 9001 key update derivation is centralized in `src/quic/connection/key_update.zig` and used by connection and endpoint install paths.
- Stateless reset token derivation is fallible and reset-token comparison uses constant-time equality.
- No active QUIC crypto/key-derivation path currently contains `catch unreachable`; the only `rg` match is an explanatory comment in `src/quic/connection/key_update.zig`.

## Evidence Map

| Area | Code evidence | Test / verification evidence | Remaining risk |
|---|---|---|---|
| Retry integrity tag | `src/quic/crypto_quic.zig:158-196` derives v1/v2 Retry key/IV with `try`, validates ODCID length, and bounds pseudo-packet AAD. | `tests/test_retry.zig:62-115` validates Retry structure and integrity tag; `tests/test_retry.zig:221-237` verifies a captured interop Retry vector. | None for the former `catch unreachable` path; broader Retry interop stays covered by full interop. |
| Retry validation comparison | `src/quic/packet.zig` calls `crypto.computeRetryIntegrityTag(...) catch return false` and compares tags with `std.crypto.timing_safe.eql`. | `zig build test --summary failures` and `zig build -Dfull-test-graph=true test --summary failures` passed during this pass. | None identified for tag comparison. |
| Retry-before-allocation | `src/quic/endpoint/incoming.zig:379-386` parses token bytes before new server allocation; `src/quic/endpoint/incoming.zig:438-483` sends stateless Retry before `max_connections`/`createServerConnection`; `src/quic/endpoint/incoming.zig:502-508` passes verified Retry state into server creation. | `tests/test_retry.zig:62-70` asserts no server connection exists after first Retry; `tests/test_retry.zig:211-218` asserts a validated Retry creates an accepted connection with restored SCID and ODCID. | GitLab issue #188 is no longer accessible via `glab` (`404 Not Found`); a replacement GitLab record is needed if GitLab must retain the resolved issue history. |
| Key update derivation | `src/quic/connection/key_update.zig:1-14` implements fallible RFC 9001 Section 6 `"quic ku"` derivation; `src/quic/connection/methods_b.zig:1584-1628` uses it on TX and RX-triggered update paths. | `src/quic/connection/key_update.zig:16-28` tests deterministic non-identical derivation; `make interop-full` passed `105`, failed `0`, skipped `50` after the CID latch fix, including supported keyupdate pairings. | `tests/integration/key_update.zig` still contains 52 skipped scenarios; tracked by GAP-0013 / #142. |
| Packet protection / RFC vectors | `src/quic/crypto_quic.zig:65-130` handles nonce construction and AEAD protect/open paths; handshake integration tests contain RFC 9001 Appendix A vectors in `tests/unit/endpoint/test_handshake_integration.zig`. | `zig build -Dtest-filter=max_udp_payload test --summary failures` exited `0`; broader default and full graph tests passed before final doc updates. | `tests/integration/rfc9001_advanced.zig` still contains 27 skipped scenarios; tracked by GAP-0013 / #142. |
| Stateless reset | `src/quic/connection/reset_token.zig` returns `![16]u8` from derivation; `src/quic/conn.zig` reset-token checks use `std.crypto.timing_safe.eql`. | Existing connection ID/reset-token unit coverage remains in the full graph. | No new risk identified in this pass. |
| Secret teardown | `src/quic/connection/methods_b.zig:1613-1617` and related RX/TX update paths zero old keys before clearing references. | Covered by default/full graph test passes; advanced lifecycle vectors remain skipped. | Full lifecycle proof remains open under GAP-0013 / #142. |

## Commands

- `rg -n "catch unreachable|unreachable" src/quic/crypto_quic.zig src/quic/connection src/quic/endpoint/handshake_integration.zig src/quic/endpoint/incoming/module_b.zig src/quic/packet.zig` - only matched the explanatory comment in `src/quic/connection/key_update.zig:8`.
- `zig build test --summary failures` - exited `0`.
- `zig build -Dfull-test-graph=true test --summary failures` - exited `0` in the implementation pass.
- `INTEROP_IMPLS=quic-go INTEROP_TESTCASES=http3 make interop-full` - exited `0` after the CID latch fix; the targeted matrix passed `nginx_zig_http3` and four other HTTP/3 pairings.
- `make interop-full` - exited `0`; final matrix passed `105`, failed `0`, skipped `50` implementation/harness-unsupported cases.

## Remaining Work

- GAP-0013 / #142 remains open for executable key lifecycle, key update, and AEAD-limit integration vectors.
- Full interop is clean after the CID latch fix. Rerun `make interop-full` after future protocol code edits.
