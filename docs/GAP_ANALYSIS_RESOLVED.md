# Resolved Gap Analysis Items

Generated: 2026-04-25

GitLab is authoritative for issue status. This file mirrors resolved or invalidated items that were removed from `docs/GAP_ANALYSIS.md`.

## Re-audited and Closed During 2026-04-25 Analysis

### GAP-0051: requirements.md contained factual inaccuracies
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/173
- **Resolution status:** Closed after this documentation update.
- **Resolution evidence:**
  - `docs/requirements.md:1-8` now states GitLab is authoritative and points to the generated mirror instead of duplicating stale implementation claims.
  - `docs/REQUIREMENTS.md:1-12` now identifies the mirror as non-authoritative and links GitLab issues.
  - `docs/REQUIREMENTS.md:14-20` records current verification caveats, including Zig 0.16.0 and 528 skipped tests.
- **Notes:** The previous all-implemented claims were removed rather than repeated.

### GitLab #189: SSLKEYLOGFILE writes TLS session keys in production builds
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/189
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `src/quic/connection/methods_a.zig:36-40` gates key logging behind Debug/test builds with `builtin.mode` and `builtin.is_test`.
- **Notes:** No open gap remains for this item.

### GitLab #190: Congestion window check was log-only
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/190
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `src/quic/connection/methods_b.zig:431-438` returns `0` when `bytes_in_flight >= cwnd`.
  - `rg -n 'CC-OVERRIDE' src tests` produced no current production hit during the audit.
- **Notes:** Congestion-window enforcement is no longer tracked as an open gap.

### GitLab #127: Duplicate StreamRx in conn.zig and connection/stream.zig
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/127
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `src/quic/conn.zig:425-426` aliases `StreamTx` from the canonical stream module.
  - `src/quic/connection/stream.zig:21-106` contains the canonical `StreamRx` implementation.
- **Notes:** Remaining stream-state modeling issues are tracked separately as GAP-0011 and GAP-0014.

### GitLab #128: No QUIC-layer performance benchmarks in CI
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/128
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `.gitlab-ci.yml:528-538` runs `scripts/perf-gate.sh` and UDP batch smoke checks.
  - `.gitlab-ci.yml:540-590` defines a 20x stress integration benchmark job.
  - `build.zig:1868-2027` wires the benchmark suite.
- **Notes:** Performance requirements with remaining implementation gaps are tracked by open GitLab issues and relevant gaps.

### GitLab #130: ArrayList frame buffer allocation per sendDatagram
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/130
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `src/quic/connection/methods_b.zig:160-168` uses a fixed stack buffer and fixed buffer writer for DATAGRAM send frame construction.
- **Notes:** No open gap remains for this allocation site.

### GitLab #131: Recovery mutex serialized congestion reads
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/131
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `src/quic/recovery/recovery.zig:741-745` provides `getCongestionState()`.
  - `src/quic/connection/methods_b.zig:431-435` uses the congestion state snapshot for send-window checks.
- **Notes:** Broader recovery critical-section performance remains tracked by non-gap performance issues.

### GAP-0059: API stream-finished contract was ambiguous
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/176
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `src/quic/api.zig:328-330` documents `isStreamFinished` as RX-side completion.
  - `src/quic/api.zig:146-150` marks `closeConnection` as deprecated in favor of `Connection.close()`.
- **Notes:** No open gap remains for this API wording.

### GAP-0063: H3 varint codec was duplicated
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/179
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `rg -n 'pub fn encodeVarint|pub fn decodeVarint|fn encodeVarint|fn decodeVarint' src/h3 src/quic` returns H3 varint definitions in `src/h3/varint.zig` only for the H3 layer.
- **Notes:** H3 error propagation remains open as GAP-0050.

### GitLab #184: readStreamUnlocked shifted inbox on every read
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/184
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `src/quic/connection/stream.zig` now tracks `StreamRx.inbox_read_off` and exposes `readInto()`; `src/quic/connection/methods_b.zig` and `src/quic/connection/methods_c.zig` use cursor reads instead of per-read `copyForwards` shifts.
- **Verification:** `zig build -Dtest-filter=stream_edges test` exited `0`.

### GitLab #185: remaining orderedRemove call sites in src/quic
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/185
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `rg -n "orderedRemove" src/quic` returns no matches. Timer, retired-list, and stream-buffer removals use `swapRemove`; `src/quic/conn.zig` now stores stateless reset tokens as `ResetTokenEntry{ sequence, token }` so retire-prior-to semantics survive unordered removal.
- **Verification:** `zig build -Dtest-filter=packet_pool test` exited `0`.

### GitLab #186: StreamRx tryDrain O(N^2) worst case
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/186
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `src/quic/connection/stream.zig` sorts buffered segments by offset and drains them in one compaction pass.
- **Verification:** `zig build -Dtest-filter=stream_edges test` exited `0`.

### GitLab #187: PacketBufferPool.release linear scan
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/187
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `src/quic/conn.zig` computes the packet-pool slot index from pointer offset with bounds and alignment checks instead of scanning 16 slots.
- **Verification:** `zig build -Dtest-filter=packet_pool test` exited `0`.

### GAP-0065: Interop Docker image baked static test certificates
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/193
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `interop/Dockerfile` no longer copies `tests/certs/cert.pem` or `tests/certs/key.pem`; `interop/run_endpoint.sh` generates ephemeral fallback TLS material at startup; `interop/README.md` documents the runtime-generated fallback.
- **Verification:** `bash -n interop/run_endpoint.sh` exited `0`.

### GAP-0066: Crypto debug global mutable state needed thread-local/local storage
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/194
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `src/quic/packet.zig` uses `threadlocal` test-only debug state and `src/quic/crypto_quic.zig` uses function-local Retry tag temporary ciphertext storage.

## Previously Closed Gap Issues

The following issues are closed in GitLab and were not reopened during the 2026-04-25 audit. Where implementation evidence was not re-collected in this pass, the resolution evidence is the GitLab closed state.

- **Governance boundary:** CI/CD external-tool hash/toolchain pinning (#54), Docker tag/digest pinning (#55), and pre-commit hook pinning/enforcement are intentionally not repo-local implementation gaps. #54 and #55 are closed as won't-do under external controls; pre-commit enforcement is also externalized unless governance ownership changes.
- **GAP-0001:** https://gitlab.com/devnw/zig/quic/-/issues/84 - build break. Current command evidence: `zig build test` exited `0` on 2026-04-25, with the CA-certificate diagnostic recorded in `docs/REQUIREMENTS.md`.
- **GAP-0002:** https://gitlab.com/devnw/zig/quic/-/issues/85 - stale RESET_STREAM/STOP_SENDING docs. Current related implementation evidence: `src/quic/endpoint/frame_handler.zig:448-500` and `src/quic/connection/methods_b.zig:620-724`.
- **GAP-0003:** https://gitlab.com/devnw/zig/quic/-/issues/86 - STREAMS_BLOCKED response handling. Status evidence: GitLab issue is closed.
- **GAP-0005:** https://gitlab.com/devnw/zig/quic/-/issues/91 - old `module_c.zig` NotImplemented path. Status evidence: GitLab issue is closed.
- **GAP-0006:** https://gitlab.com/devnw/zig/quic/-/issues/92 - stale triage labels. Status evidence: GitLab issue is closed.
- **GAP-0018:** https://gitlab.com/devnw/zig/quic/-/issues/149 - Retry integrity tag timing-safe comparison. Current evidence: `src/quic/packet.zig:1267` uses `std.crypto.timing_safe.eql`.
- **GAP-0047:** https://gitlab.com/devnw/zig/quic/-/issues/155 - misleading frame handler comment. Status evidence: GitLab issue is closed.
- **H3 plumbing issues:** https://gitlab.com/devnw/zig/quic/-/issues/132, https://gitlab.com/devnw/zig/quic/-/issues/133, https://gitlab.com/devnw/zig/quic/-/issues/134, https://gitlab.com/devnw/zig/quic/-/issues/135 - closed in GitLab. Remaining H3 adapter gap is GAP-0050.
