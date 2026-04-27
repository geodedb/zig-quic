<!-- markdownlint-disable MD029 MD036 -->
# Connection Method-Module Domain Refactor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Performance gating per `.claude/skills/quic-performance-gating/SKILL.md` is REQUIRED at every stage boundary.

**Status:** Draft
**Date:** 2026-04-26
**Owner:** Core QUIC
**GitLab issues:** [#115](https://gitlab.com/devnw/zig/quic/-/issues/115), [#177](https://gitlab.com/devnw/zig/quic/-/issues/177)
**Closes:** GAP-0060 (`docs/GAP_ANALYSIS.md` §GAP-0060) and `docs/QUALITY_GAP_ANALYSIS.md` row 14

**Goal:** Eliminate the non-domain-aligned `connection/methods_a.zig`, `methods_b.zig`, `methods_c.zig` triplet by moving every public method to a domain-named module (`connection/handshake.zig`, `connection/streams.zig`, etc.), preserving every external API and behavior, and shrinking `src/quic/conn.zig` from 1895 LOC toward < 1000 LOC of orchestration + state struct.

**Architecture:** The `methods_*.zig` files use the `bind(comptime Connection: type) type` pattern — they each return an inner struct that exposes methods, which `conn.zig` then re-exports via `pub const fooMethod = methods_x.fooMethod;` lines (1758–~1900). The refactor preserves this exact `bind`-and-re-export shape for the new domain modules, so `conn.zig` orchestration is unchanged from the caller's perspective. Each stage extracts one cohesive domain into its own `bind`-style module, updates the re-export table in `conn.zig`, and drops the moved method bodies from `methods_a/b/c.zig`. Stage 5 retires the residual `methods_a/b/c.zig` files entirely.

**Tech Stack:** Zig 0.16.0, existing `connection/` module layout, paired A/B perf gating via `scripts/perf-gate.sh` (per `.claude/skills/quic-performance-gating/SKILL.md`).

**Spec / supporting docs:**

- `docs/GAP_ANALYSIS.md` GAP-0060 (Non-domain method module naming obscures ownership)
- `docs/QUALITY_GAP_ANALYSIS.md` row 14 (#115/#177 — Connection struct 1711 LOC + non-domain-aligned method split)
- `.claude/skills/quic-performance-gating/SKILL.md` (Iron Law: paired same-session A/B gate per stage)

---

## Goals

1. Split `connection/methods_a.zig`, `methods_b.zig`, `methods_c.zig` into domain-named modules whose names map 1:1 to RFC 9000/9001/9002 sections (handshake, streams, recovery, path, datagram, key update, packet number space, connection ID, flow control).
2. Reduce `src/quic/conn.zig` size from **1895 LOC** to **< 1000 LOC**, leaving only the `Connection` struct definition, the orchestrator helpers (init/deinit/setPeer/onNewConnectionId/etc.), and a flat re-export table that points each public method at its new domain module.
3. Preserve every public API name, signature, and visible behavior. No caller (test, binary, downstream consumer) should need to change a single import or call site.
4. Keep performance flat at every stage boundary — paired A/B perf gate must pass per stage.
5. Make ownership readable: a developer hunting "where does stream window expansion live?" can answer it from the file tree without `rg`-ing 3 anonymous-suffix files.

---

## Non-goals

1. **No public API changes.** Every name re-exported from `conn.zig` keeps its identity. Renames (e.g. `pushStreamFrame` → `streams.pushFrame`) are explicitly out of scope; if desired, schedule them as a separate later MR after this refactor stabilizes.
2. **No performance optimizations.** This refactor is structural only. Any performance work that touches the same hot paths must wait for this plan to complete and gate independently.
3. **No test churn beyond cross-references.** Existing tests under `tests/` and `src/quic/connection/key_update.zig` keep their assertion bodies; only `@import` lines change if a test file currently imports a `methods_*.zig` directly (none do today, but future-proof).
4. **No struct field renames or reorderings.** The 160 `Connection` fields stay where they are — the methods move out, the data does not.
5. **No removal of the `bind(comptime Connection: type) type` pattern.** It is the load-bearing trick that lets these files reach into the connection struct without circular imports; preserve it.

---

## Constraints

1. **Perf gate per stage.** Per `.claude/skills/quic-performance-gating/SKILL.md` Iron Law, "no performance-claiming change lands without a paired same-session A/B run against `benchmarks/results/baseline.json`." Every stage in this plan completes with a `scripts/perf-gate.sh --suite=integration` paired A/B (Stage 1 covers ack/recovery → integration tier captures regression; Stage 4 covers handshake → re-run integration). Stages 2, 3, and 5 must additionally invoke `--suite=micro` because the pure-function paths (varint/frame_serialization/connection_lookup) sit beneath the moved methods. The gate failing blocks the stage's commit.
2. **Interop must remain 105/0/50.** `make interop-full` runs the dockerized cross-impl matrix at `interop/`. Current passing baseline is **105 PASS / 0 FAIL / 50 SKIP** (recorded in recent commit history). Any stage that drops a single PASS or flips any SKIP→FAIL is rolled back.
3. **Full test graph green.** `zig build -Dfull-test-graph=true test` must end every stage with the same pass/fail counts as before the stage started, modulo the pre-existing `tests/test_transport_geode_compat.zig:246` CA-cert assertion documented in `CLAUDE.md` "Known Pre-existing Issues" item #1. Anything new that fails is a regression.
4. **No source-code edits outside `src/quic/conn.zig` and `src/quic/connection/*.zig`.** This refactor does not touch `src/h3/`, `cmd/`, `tests/`, `benchmarks/`, or `lib.zig` / `quic.zig`. If a stage uncovers an external import that needs updating, that's a sign the public surface was not preserved — stop and rework the stage.
5. **Each stage is independently committable and revertible.** No stage depends on the next being merged in the same MR. Reviewers can land Stage 1, observe production for a release cycle, then proceed to Stage 2.
6. **Zig 0.16.0 idioms only.** No regression to 0.15.1 ArrayList / process / posix patterns — see `docs/superpowers/plans/2026-04-20-perf-bench-suite-and-gating.md` Phase 0 for the established 0.16.0 baseline.

---

## Inventory (current state, captured 2026-04-26)

### Line counts (`wc -l`)

| File | LOC |
|---|---|
| `src/quic/conn.zig` | **1895** |
| `src/quic/connection/methods_a.zig` | **1187** |
| `src/quic/connection/methods_b.zig` | **1651** |
| `src/quic/connection/methods_c.zig` | **737** |
| `src/quic/connection/key_update.zig` | 28 (already domain-extracted, RFC 9001 §6) |
| `src/quic/connection/handshake.zig` | 32 (state struct only — no methods yet) |
| `src/quic/connection/path.zig` | 19 (state struct only — no methods yet) |
| `src/quic/connection/flow_control.zig` | 108 (pure helper functions, no `bind` methods) |
| `src/quic/connection/stream.zig` | 236 (`StreamRx` / `StreamTx` types + helpers) |
| `src/quic/connection/packet_number.zig` | 140 (`PnWindow` + `expandTruncatedPn` helper) |
| **Total `methods_*` LOC to redistribute** | **3575** |

### Public-function counts

- `methods_a.zig` — **53 public methods** inside `bind(...).struct` (handshake/crypto/keylog/ALPN/transport-params/0-RTT/control-frames/path-validation/PTO-arming/stream-frame-push/datagram-push)
- `methods_b.zig` — **42 public methods** (streams open/write/read/close/reset, ACK reception, PTO probes, PMTUD timer, connection close, handshake key derivation, key update on send/ack/sync)
- `methods_c.zig` — **22 public methods** (stream iteration, packet-sent bookkeeping, PMTUD probe send, ICMP/AEAD failure handling, stream limit/known/queue checks, connection-ID issuance/retire/rotation)
- `methods_a` + `methods_b` + `methods_c` total: **117 public methods** moved through the `bind(Connection)` shape
- `conn.zig` direct public methods on `Connection` (not via `methods_*`): **43 public functions** (init/deinit, ack-bookkeeping, packet-number expansion/tracking, build-ack, peer/CID, ECN, amplification, sender-set), of which the candidates for relocation in Stage 5 are listed below

### Function → target module mapping

The table below maps every public method exported via `methods_*.zig` `bind` to its new domain home, plus the relocatable orchestrator methods on the `Connection` struct itself. Every name is a real symbol verified by `rg -n '^        pub fn |^    pub fn ' src/quic/connection/methods_*.zig src/quic/conn.zig` on 2026-04-26.

#### Stage 1 — `connection/recovery.zig` (loss detection, ACK reception, PTO arming, ECN, congestion control bookkeeping)

| Function | Source | Stage |
|---|---|---|
| `onAckReceived` | `methods_b.zig:787` | 1 |
| `onAckReceivedSpace` | `methods_b.zig:795` | 1 |
| `resetPtoBackoffInitial` | `methods_b.zig:884` | 1 |
| `resetPtoBackoffHandshake` | `methods_b.zig:888` | 1 |
| `resetPtoBackoffApp` | `methods_b.zig:892` | 1 |
| `cancelPtoInitial` | `methods_b.zig:898` | 1 |
| `cancelPtoHandshake` | `methods_b.zig:907` | 1 |
| `cancelPtoApp` | `methods_b.zig:916` | 1 |
| `computeAndMaybeArmPto` | `methods_b.zig:927` | 1 |
| `computeAndMaybeArmPtoInitial` | `methods_b.zig:1010` | 1 |
| `computeAndMaybeArmPtoHandshake` | `methods_b.zig:1031` | 1 |
| `sendPtoProbeInitial` | `methods_b.zig:1055` | 1 |
| `sendPtoProbeHandshake` | `methods_b.zig:1204` | 1 |
| `sendPtoProbeApp` | `methods_b.zig:1278` | 1 |
| `scheduleConnPto` | `methods_a.zig:886` | 1 |
| `setPtoExpiredInitial` | `methods_a.zig:897` | 1 |
| `setPtoExpiredHandshake` | `methods_a.zig:907` | 1 |
| `setPtoExpiredApp` | `methods_a.zig:917` | 1 |
| `ccOnPacketSent` | `methods_a.zig:735` | 1 |
| `ccOnAck` | `methods_a.zig:743` | 1 |
| `ccOnLoss` | `methods_a.zig:750` | 1 |
| `setUseCubic` | `methods_a.zig:729` | 1 |
| `onPacketSent` | `methods_c.zig:191` | 1 |
| `onShortHeaderPacketSent` | `methods_c.zig:69` | 1 |

#### Stage 2 — `connection/streams.zig` (stream open/write/read/close/reset, stream init/queueing, peer-stream limit, MAX_STREAM_DATA emission)

| Function | Source | Stage |
|---|---|---|
| `openStream` | `methods_b.zig:199` | 2 |
| `writeStream` | `methods_b.zig:282` | 2 |
| `writeStreamUnlocked` | `methods_b.zig:289` | 2 |
| `readStream` | `methods_b.zig:504` | 2 |
| `readStreamUnlocked` | `methods_b.zig:511` | 2 |
| `closeStream` | `methods_b.zig:579` | 2 |
| `resetStream` | `methods_b.zig:625` | 2 |
| `handleStopSending` | `methods_b.zig:674` | 2 |
| `handleResetStream` | `methods_b.zig:722` | 2 |
| `teardownStream` | `methods_b.zig:763` | 2 |
| `pushStreamFrame` | `methods_a.zig:783` | 2 |
| `readAnyStream` | `methods_c.zig:22` | 2 |
| `ensureStreamTxInit` | `methods_c.zig:223` | 2 |
| `ensureStreamRx` | `methods_c.zig:230` | 2 |
| `isPeerInitiatedStream` | `methods_c.zig:251` | 2 |
| `validatePeerStreamLimit` | `methods_c.zig:270` | 2 |
| `isStreamKnown` | `methods_c.zig:299` | 2 |
| `queueIncomingStream` | `methods_c.zig:314` | 2 |
| `acceptStream` | `methods_c.zig:391` | 2 |
| `hasIncomingStreams` | `methods_c.zig:423` | 2 |
| `getFirstStream` | `methods_c.zig:428` | 2 |
| `isStreamFinished` | `conn.zig:957` | 2 |
| `markStreamFlowControlDirty` | `conn.zig:966` | 2 |
| `appendDirtyMaxStreamDataFrames` | `conn.zig:979` | 2 |
| `advertiseInitialFlowControl` | `methods_a.zig:1130` | 2 |
| `pushDatagram` | `methods_a.zig:865` | 2 (datagram is co-located with stream tx queues; note in §Risk: split to `connection/datagram.zig` if Stage 2 grows past 800 LOC) |
| `popDatagram` | `methods_a.zig:874` | 2 (same caveat) |
| `sendDatagram` | `methods_b.zig:150` | 2 (same caveat) |

#### Stage 3 — `connection/path.zig` (path validation, migration, PMTUD probing, ICMP, peer address rotation)

| Function | Source | Stage |
|---|---|---|
| `sendPathChallenge` | `methods_a.zig:1013` | 3 |
| `sendPathChallengeAt` | `methods_a.zig:973` | 3 |
| `onPathResponse` | `methods_a.zig:1019` | 3 |
| `onPathValidationTimeout` | `methods_a.zig:1035` | 3 |
| `pmtudStart` | `methods_b.zig:951` | 3 |
| `pmtudArm` | `methods_b.zig:958` | 3 |
| `pmtudOnTimer` | `methods_b.zig:968` | 3 |
| `pmtudOnAckProgress` | `methods_b.zig:1000` | 3 |
| `sendPmtudProbe` | `methods_c.zig:115` | 3 |
| `onIcmpPacketTooBig` | `methods_c.zig:167` | 3 |
| `setPeer` | `conn.zig:1396` | 3 |
| `canSendUnderAmplification` | `conn.zig:1647` | 3 |
| `isLocalhost` | `conn.zig:1671` | 3 |
| `overAmplification` | `conn.zig:1714` | 3 |
| `addRxUnvalidated` | `conn.zig:1731` | 3 |
| `addTxUnvalidated` | `conn.zig:1746` | 3 |

#### Stage 4 — `connection/handshake.zig` (TLS integration, crypto frame buffering/pushing, ALPN, transport params, 0-RTT, key derivation, key update propagation, HANDSHAKE_DONE control)

| Function | Source | Stage |
|---|---|---|
| `maybeEmitHandshakeKeyLog` | `methods_a.zig:81` | 4 |
| `maybeEmitApplicationKeyLog` | `methods_a.zig:95` | 4 |
| `maybeEmitTxKeyUpdateLog` | `methods_a.zig:111` | 4 |
| `maybeEmitRxKeyUpdateLog` | `methods_a.zig:119` | 4 |
| `storeNegotiatedAlpn` | `methods_a.zig:127` | 4 |
| `storePeerTransportParams` | `methods_a.zig:136` | 4 |
| `storeLocalTransportParams` | `methods_a.zig:145` | 4 |
| `cacheNegotiatedAlpn` | `methods_a.zig:155` | 4 |
| `cachePeerTransportParams` | `methods_a.zig:160` | 4 |
| `setLocalTransportParameters` | `methods_a.zig:165` | 4 |
| `hasConfirmedAppTxKeys` | `methods_a.zig:173` | 4 |
| `sendHandshakeDoneControl` | `methods_a.zig:182` | 4 |
| `updatePeerFinishedStatus` | `methods_a.zig:222` | 4 |
| `send` | `methods_a.zig:239` | 4 (note: `send` here is the post-handshake bytes-on-the-wire entry — kept with handshake because it gates on key-availability) |
| `sendInitialCrypto` | `methods_a.zig:282` | 4 |
| `sendHandshakeCrypto` | `methods_a.zig:340` | 4 |
| `pushCrypto` | `methods_a.zig:382` | 4 |
| `afterInitialCryptoChunk` | `methods_a.zig:531` | 4 |
| `processBufferedInitial` | `methods_a.zig:535` | 4 |
| `processBufferedHandshake` | `methods_a.zig:553` | 4 |
| `handleCryptoFrameGeneric` | `methods_a.zig:570` | 4 |
| `afterInitialWrapper` | `methods_a.zig:620` | 4 |
| `afterHandshakeWrapper` | `methods_a.zig:624` | 4 |
| `continueInitial` | `methods_a.zig:629` | 4 |
| `continueHandshake` | `methods_a.zig:633` | 4 |
| `handleInitialCrypto` | `methods_a.zig:637` | 4 |
| `handleHandshakeCrypto` | `methods_a.zig:655` | 4 |
| `maybeDeriveAppKeysAfterFlush` | `methods_a.zig:675` | 4 |
| `getNegotiatedAlpn` | `methods_a.zig:701` | 4 |
| `getPeerTransportParams` | `methods_a.zig:710` | 4 |
| `getLocalTransportParams` | `methods_a.zig:719` | 4 |
| `applyPeerTransportParameters` | `methods_c.zig:455` | 4 |
| `setPeerInitialCids` | `methods_a.zig:758` | 4 |
| `enable0RTT` | `methods_a.zig:1073` | 4 |
| `accept0RTT` | `methods_a.zig:1093` | 4 |
| `sendControlFrames` | `methods_a.zig:1048` | 4 |
| `sendConnectionClose` | `methods_b.zig:1373` | 4 |
| `deriveHandshakeKeys` | `methods_b.zig:1412` | 4 |
| `deriveAppKeys` | `methods_b.zig:1434` | 4 |
| `shortHeaderDcid` | `methods_b.zig:1530` | 4 |
| `zeroKeys` | `methods_b.zig:1565` | 4 |
| `maybeTriggerKeyUpdateOnSend` | `methods_b.zig:1573` | 4 |
| `maybeFinalizeKeyUpdateOnAck` | `methods_b.zig:1609` | 4 |
| `syncTxKeysAfterRxUpdate` | `methods_b.zig:1623` | 4 |
| `onAeadAuthFailure` | `methods_c.zig:179` | 4 |

#### Stage 5 — Slim `conn.zig` + retire `methods_a/b/c.zig` + relocate residual `Connection` methods

| Function | Source | Target | Stage |
|---|---|---|---|
| `recordAckElicitingRx` | `conn.zig:880` | `connection/recovery.zig` | 5 |
| `getAckDelayEncoded` | `conn.zig:892` | `connection/recovery.zig` | 5 |
| `expandPnInitial` | `conn.zig:908` | `connection/pn_space.zig` (new — wraps `packet_number.expandTruncatedPn`) | 5 |
| `expandPnHandshake` | `conn.zig:913` | `connection/pn_space.zig` | 5 |
| `expandPnApp` | `conn.zig:918` | `connection/pn_space.zig` | 5 |
| `trackRecvPnInitial` | `conn.zig:926` | `connection/pn_space.zig` | 5 |
| `trackRecvPnHandshake` | `conn.zig:931` | `connection/pn_space.zig` | 5 |
| `trackRecvPnApp` | `conn.zig:936` | `connection/pn_space.zig` | 5 |
| `buildAckInitial` | `conn.zig:941` | `connection/recovery.zig` | 5 |
| `buildAckHandshake` | `conn.zig:946` | `connection/recovery.zig` | 5 |
| `buildAckApp` | `conn.zig:951` | `connection/recovery.zig` | 5 |
| `onEcnMark` | `conn.zig:1594` | `connection/recovery.zig` | 5 |
| `getAckEcn` | `conn.zig:1616` | `connection/recovery.zig` | 5 |
| `onNewConnectionId` | `conn.zig:1402` | `connection/connection_id.zig` (existing 30 LOC stub grows) | 5 |
| `activePeerCid` | `conn.zig:1506` | `connection/connection_id.zig` | 5 |
| `installInitialLocalCid` | `conn.zig:1524` | `connection/connection_id.zig` | 5 |
| `localDcidMatchLen` | `conn.zig:1544` | `connection/connection_id.zig` | 5 |
| `looksLikeStatelessReset` | `conn.zig:1580` | `connection/connection_id.zig` (uses reset_token state) | 5 |
| `canIssueNewConnectionId` | `methods_c.zig:528` | `connection/connection_id.zig` | 5 |
| `onIssuedNewConnectionId` | `methods_c.zig:534` | `connection/connection_id.zig` | 5 |
| `ensureLocalConnectionIdSupply` | `methods_c.zig:555` | `connection/connection_id.zig` | 5 |
| `issueNewConnectionId` | `methods_c.zig:571` | `connection/connection_id.zig` | 5 |
| `flushPendingNewConnectionIds` | `methods_c.zig:582` | `connection/connection_id.zig` | 5 |
| `markPendingNewCid` | `methods_c.zig:598` | `connection/connection_id.zig` | 5 |
| `writePendingNewConnectionIds` | `methods_c.zig:604` | `connection/connection_id.zig` | 5 |
| `onRetireConnectionId` | `methods_c.zig:631` | `connection/connection_id.zig` | 5 |
| `acquireLocalCid` | `methods_c.zig:688` | `connection/connection_id.zig` | 5 |
| `issueNewConnectionIdRotating` | `methods_c.zig:711` | `connection/connection_id.zig` | 5 |
| `setSender` | `conn.zig:1629` | stays in `conn.zig` (orchestration / glue) | — |
| `setAeadUsageLimits` | `conn.zig:1635` | stays in `conn.zig` | — |
| `setServerName` | `conn.zig:1238` | `connection/handshake.zig` | 5 |
| `init` | `conn.zig:1009` | stays in `conn.zig` (struct lifecycle) | — |
| `deinit` | `conn.zig:1252` | stays in `conn.zig` (struct lifecycle) | — |

After Stage 5: every method that survived migration sits in a domain module; `methods_a/b/c.zig` are deleted (or reduced to deprecated re-export shims emitting `@compileLog` warnings if direct callers exist outside the repo); `conn.zig` shrinks to the `Connection` struct + lifecycle + the re-export table.

---

## Stage Plan

Each stage is one mergeable MR. Each ends green (perf gate + interop + full test graph) before the next begins. Reviewers can pause indefinitely between stages.

### Stage 1: Extract `connection/recovery.zig`

**Why first:** Lowest coupling. Recovery / PTO / ACK / CC bookkeeping touches `recovery.PacketNumberSpace` and a handful of `Connection` fields (PTO timer handles, recovery state) but does not call into stream, handshake, or path code. Most failures here surface as numeric drift in ACK-eliciting counters or PTO arming — easy to detect with the existing recovery tests.

**Scope:**

- New file: `src/quic/connection/recovery.zig` with the `pub fn bind(comptime Connection: type) type` shape mirroring `methods_*.zig`.
- Move 24 functions per the Stage 1 mapping table above.
- Bring along any `methods_a/b/c.zig`-private helpers used exclusively by the moved set (they become file-private in `recovery.zig`).

**Files touched:**

- Add: `src/quic/connection/recovery.zig`
- Modify: `src/quic/connection/methods_a.zig` (remove 4 methods), `methods_b.zig` (remove 14 methods), `methods_c.zig` (remove 2 methods)
- Modify: `src/quic/conn.zig` (re-export table at lines 1758+: add `const recovery_methods = @import("connection/recovery.zig").bind(@This());` and re-point `pub const onAckReceived = recovery_methods.onAckReceived;` etc.; remove the corresponding `methods_a/b/c` re-exports)

**Tests to run:**

- `zig build -Dfull-test-graph=true test` — must match pre-stage pass/fail count exactly (modulo the known `test_transport_geode_compat.zig:246` pre-existing fail)
- `zig build test --summary all 2>&1 | grep -E "tests/.*recovery|tests/.*ack|tests/.*loss|tests/.*pto"` — direct verification that recovery-named tests still pass
- `make interop-full` — must remain 105/0/50

**Perf gate suite required:**

- `scripts/perf-gate.sh --suite=integration` (covers `handshake_e2e`, `stream_throughput`, `flush_cadence`, `poll_overhead` — recovery code is on every of these hot paths)
- `scripts/perf-gate.sh --suite=micro` (covers `loss_detection_scan` micro-benchmark which sits directly on top of the moved code)

**Rollback procedure:** `git revert <stage-1-commit>`. Because the public API is preserved, no caller had to be updated and the revert is a single-commit no-op for downstream. Re-run `zig build test` and `make interop-full` to confirm restoration; the prior baseline state is the test-graph state recorded before Stage 1.

---

### Stage 2: Extract `connection/streams.zig`

**Why second:** Streams own the largest LOC chunk after recovery (estimated ~1100 LOC of `methods_b.zig` body). Doing this after recovery means the recovery extraction has stabilized and any "the Connection struct is fragile under method refactors" risks have already surfaced once. Streams also benefit from being separated from handshake/path code.

**Scope:**

- New file: `src/quic/connection/streams.zig` (note: pluralized — distinct from existing `connection/stream.zig`, which holds the `StreamRx`/`StreamTx` type definitions).
- Move 28 functions per the Stage 2 mapping table.
- Datagram methods (`pushDatagram`, `popDatagram`, `sendDatagram`) are moved into `streams.zig` as a sub-region for this stage; if `streams.zig` exceeds 800 LOC, split into `streams.zig` + `datagram.zig` in a Stage-2.5 follow-up before Stage 3 begins.
- Move the three flow-control orchestrator methods (`isStreamFinished`, `markStreamFlowControlDirty`, `appendDirtyMaxStreamDataFrames`) from `conn.zig` into `streams.zig`. They are pure stream-state bookkeeping that only happens to live in `conn.zig` today.

**Files touched:**

- Add: `src/quic/connection/streams.zig`
- Modify: `src/quic/connection/methods_a.zig` (remove 2 methods: `pushStreamFrame`, `pushDatagram`, `popDatagram`, `advertiseInitialFlowControl`), `methods_b.zig` (remove 11 methods), `methods_c.zig` (remove 11 methods)
- Modify: `src/quic/conn.zig` (re-export table; remove the three relocated public methods from the `Connection` struct body)

**Tests to run:**

- `zig build -Dfull-test-graph=true test`
- `zig build test --summary all 2>&1 | grep -E "stream|datagram|flow_control|max_stream_data"` — direct stream-test sweep
- `make interop-full` — 105/0/50 confirms wire-format and stream-state-machine compatibility unchanged

**Perf gate suite required:**

- `scripts/perf-gate.sh --suite=integration` (`stream_throughput`, `datagram_batch`, `flush_cadence` are the load-bearing scenarios)
- `scripts/perf-gate.sh --suite=micro` (`frame_serialization`, `connection_lookup`)

**Rollback procedure:** `git revert <stage-2-commit>`. Re-run the same verification matrix. Stage 1 remains in place — Stage 2's revert is independent.

---

### Stage 3: Extract `connection/path.zig`

**Why third:** Path validation, PMTUD, peer-rotation, and amplification limiting form a tight cluster that cross-cuts both recovery (PMTUD-on-ack-progress) and handshake (path challenge before keys finalize). Doing this after Stages 1 and 2 means both of those neighbors are already isolated, so any cross-coupling that surfaces here is bounded.

**Scope:**

- Grow the existing `src/quic/connection/path.zig` (currently 19 LOC, only `PathValidation` state struct) by adding the `bind` shape and 16 methods per Stage 3 mapping.
- Existing `PathValidation` struct stays at the top of the file; the new `bind` block goes below.
- Move six `Connection`-method orchestrators (`setPeer`, `canSendUnderAmplification`, `isLocalhost`, `overAmplification`, `addRxUnvalidated`, `addTxUnvalidated`) from `conn.zig` into `path.zig` as part of the `bind` block.

**Files touched:**

- Modify: `src/quic/connection/path.zig` (grow from 19 LOC to ~400 LOC)
- Modify: `src/quic/connection/methods_a.zig` (remove 4 path-challenge methods), `methods_b.zig` (remove 4 PMTUD methods), `methods_c.zig` (remove 2 methods: `sendPmtudProbe`, `onIcmpPacketTooBig`)
- Modify: `src/quic/conn.zig` (remove the six relocated `Connection` methods; update re-export table)

**Tests to run:**

- `zig build -Dfull-test-graph=true test`
- `zig build test --summary all 2>&1 | grep -E "path|pmtud|migration|amplif|icmp"` — path-test sweep
- `make interop-full` — 105/0/50 (path validation is exercised by the migration interop scenarios)

**Perf gate suite required:**

- `scripts/perf-gate.sh --suite=integration` (path validation and PMTUD probing show up in `handshake_e2e` and `stream_throughput`; amplification-limit math is on the inbound packet path)
- `scripts/perf-gate.sh --suite=micro` (`connection_lookup`)

**Rollback procedure:** `git revert <stage-3-commit>`. Verify path tests + interop. Stages 1 and 2 unchanged.

---

### Stage 4: Extract `connection/handshake.zig`

**Why fourth:** Handshake is the largest remaining domain (45 functions per Stage 4 mapping) and the one most entangled with TLS state, key schedule, and cross-cutting orchestrators (`send`, `sendControlFrames`, `sendConnectionClose`). Doing it after Stages 1–3 means recovery/streams/path are all isolated, leaving the handshake extraction with the cleanest possible neighbor surface.

**Scope:**

- Grow the existing `src/quic/connection/handshake.zig` (currently 32 LOC, only `HandshakeState` struct) by adding the `bind` shape and 45 methods per Stage 4 mapping.
- Existing `HandshakeState` struct stays at the top.
- The existing tiny `connection/key_update.zig` (28 LOC, RFC 9001 §6 derivation) stays as-is — it is already cleanly factored. The Stage 4 `handshake.zig` `bind` block calls into it for the three key-update methods (`maybeTriggerKeyUpdateOnSend`, `maybeFinalizeKeyUpdateOnAck`, `syncTxKeysAfterRxUpdate`) just as `methods_b.zig` does today.
- Move `setServerName` from `conn.zig` into `handshake.zig`.

**Files touched:**

- Modify: `src/quic/connection/handshake.zig` (grow from 32 LOC to ~1500 LOC — note: this will be the largest single domain module; consider a Stage-4.5 follow-up to sub-split into `handshake.zig` + `crypto_tx.zig` + `key_update.zig` if reviewers find 1500 LOC unwieldy)
- Modify: `src/quic/connection/methods_a.zig` (remove ~33 methods), `methods_b.zig` (remove ~9 methods), `methods_c.zig` (remove `applyPeerTransportParameters`, `onAeadAuthFailure`)
- Modify: `src/quic/conn.zig` (relocate `setServerName`; update re-export table)

**Tests to run:**

- `zig build -Dfull-test-graph=true test`
- `zig build test --summary all 2>&1 | grep -E "handshake|tls|alpn|transport_param|0rtt|key_update|crypto"` — handshake-test sweep
- `make interop-full` — 105/0/50 (handshake correctness is what most interop scenarios exist to verify; this is the single most regression-prone stage)

**Perf gate suite required:**

- `scripts/perf-gate.sh --suite=integration` (`handshake_e2e` is the dedicated scenario; also `stream_throughput` and `flush_cadence` because they include the full handshake before bytes flow)
- `scripts/perf-gate.sh --suite=micro` (`tls_keygen`, `aead`, `hp` micros sit beneath the moved code)

**Rollback procedure:** `git revert <stage-4-commit>`. Verify handshake tests + interop. Stages 1–3 unchanged. Because handshake is so wire-format-sensitive, schedule at least 24h of soak (e.g., a downstream `geode` integration run) before declaring Stage 4 complete and proceeding to Stage 5.

---

### Stage 5: Slim `conn.zig` forwarding table; delete or shim `methods_a/b/c.zig`

**Why last:** Stages 1–4 have moved every domain method out of `methods_a/b/c.zig`. Whatever remains in those three files at this point is either (a) dead code, (b) cross-domain glue that should live in `conn.zig`, or (c) an oversight to migrate to a domain module. Stage 5 audits the residual content and resolves each item by deletion, relocation, or a deliberate decision to leave it in `conn.zig`.

**Scope:**

- Audit `methods_a.zig`, `methods_b.zig`, `methods_c.zig`. Each surviving function is one of:
  1. **Dead** (no caller) → delete; verify with `rg` that no `methods_x.fooBar` re-export exists in `conn.zig`.
  2. **Cross-domain glue** (e.g., `send` routes between handshake-state-gated paths and stream-tx paths) → relocate to `conn.zig` as a private helper or to the most appropriate domain module.
  3. **Forgotten** → migrate to the matching domain module per the same `bind` pattern.
- Delete `methods_a.zig`, `methods_b.zig`, `methods_c.zig` if empty of public methods. If a few hold-outs remain that justify a longer migration, reduce each to a deprecated re-export shim with a top-of-file `// DEPRECATED: this file will be removed in <next-MR>; new methods must live in connection/<domain>.zig` and a tracking comment in `docs/QUALITY_GAP_ANALYSIS.md`.
- Move the residual relocatable methods on `Connection` (per the Stage 5 mapping table) into `connection/recovery.zig`, `connection/connection_id.zig`, `connection/handshake.zig`, and the new `connection/pn_space.zig`.
- Create `connection/pn_space.zig` (new) by promoting the existing `packet_number.zig` `PnWindow` struct + `expandTruncatedPn` helper into the `bind`-style module home for the six relocating PN-space methods.
- Slim `conn.zig`: target shape after Stage 5 is `Connection` struct + `init`/`deinit`/`setSender`/`setAeadUsageLimits` + a flat re-export table.

**Files touched:**

- Modify: `src/quic/conn.zig` (final slim — should drop below 1000 LOC)
- Modify or delete: `src/quic/connection/methods_a.zig`, `methods_b.zig`, `methods_c.zig`
- Add: `src/quic/connection/pn_space.zig` (new)
- Modify: `src/quic/connection/connection_id.zig` (grow from 30 LOC by absorbing the 14 connection-ID methods)
- Modify: `src/quic/connection/recovery.zig`, `connection/handshake.zig` (absorb the residual `Connection` methods per Stage 5 mapping)

**Tests to run:**

- `zig build -Dfull-test-graph=true test` — match pre-stage state
- `zig build test --summary all` — full sweep
- `make interop-full` — 105/0/50
- `wc -l src/quic/conn.zig` — verify < 1000 LOC acceptance criterion

**Perf gate suite required:**

- `scripts/perf-gate.sh --suite=integration` (final stage — full integration tier)
- `scripts/perf-gate.sh --suite=micro` (`connection_lookup` and `frame_serialization` are particularly load-bearing at this final state)
- `scripts/perf-gate.sh --suite=external` (only at this final stage, against the pinned cross-impl baseline — Stage 5 is the right point to confirm no cross-impl regression has accumulated across Stages 1–4)

**Rollback procedure:** `git revert <stage-5-commit>`. Stage 5 is a structural cleanup with the highest call-site re-routing density (the re-export table in `conn.zig` changes substantially). If revert is needed, the pre-Stage-5 state is itself a healthy intermediate (Stages 1–4 still landed) and remains a viable shipping point — the ownership clarity from those four stages is the bulk of the value.

---

## Risk & Mitigation

The risks below are listed per stage; each row is a concrete failure mode plus the specific signal that catches it and the mitigation if caught.

### Stage 1 (recovery)

- **Risk: PTO timer arming order changes.** `methods_b.zig` interleaves `computeAndMaybeArmPto` with private helpers that may be inlined by the Zig compiler today; pulling them into a separate module could change inlining behavior and shift PTO arming by a few microseconds. **Signal:** `loss_detection_scan` micro-benchmark stddev gate trips. **Mitigation:** keep all `methods_b.zig` private helpers used only by the recovery set co-located in `connection/recovery.zig`; do not split helpers across files within a stage.
- **Risk: ACK frame builder ordering.** `buildAckInitial`/`buildAckHandshake`/`buildAckApp` (Stage 5 candidates) are called from `methods_b.onAckReceived` paths. Stage 1 only moves `onAckReceived`, leaving `buildAck*` in `conn.zig` until Stage 5. **Signal:** integration tests for ACK frame layout fail. **Mitigation:** Stage 1 explicitly does not touch `buildAck*`; the Connection-method-on-self call (`self.buildAckInitial()`) works identically whether the caller lives in `conn.zig` or `recovery.zig`.
- **Risk: Hidden mutual recursion.** `methods_b.computeAndMaybeArmPto` may call into `methods_a.scheduleConnPto` (both move in Stage 1, so OK), but also into a `methods_a` private helper. **Signal:** Zig compile error on missing symbol. **Mitigation:** before committing Stage 1, run `rg -n 'methods_a\.|methods_b\.|methods_c\.' src/quic/connection/recovery.zig` to confirm zero cross-file references; fold any helper into `recovery.zig`'s file-private scope.

### Stage 2 (streams)

- **Risk: Flow-control state ordering.** `appendDirtyMaxStreamDataFrames` (relocated from `conn.zig`) reads `Connection.streams_rx` and writes a `frame.Writer`. If the new module declares `StreamRxMap = @FieldType(Connection, "streams_rx")` differently from `methods_b.zig`'s declaration, the type alias may diverge silently. **Signal:** test fails with a wrong-type-of-stream-id error. **Mitigation:** copy the `methods_b.zig` `StreamTxMap`/`StreamRxMap`/`StreamTx`/`StreamRx` aliases verbatim into `streams.zig`; do not "improve" them during the move.
- **Risk: Datagram methods cross-couple with stream tx queues.** `pushDatagram`, `popDatagram`, `sendDatagram` share the unreliable-datagram queue with stream tx scheduling. Moving them into `streams.zig` is fine; splitting them into a separate `datagram.zig` mid-stage is not. **Mitigation:** treat the datagram trio as part of the stream stage, with the documented escape hatch that if `streams.zig` exceeds 800 LOC, split out `datagram.zig` in a Stage-2.5 follow-up MR before Stage 3 begins. Do not split mid-stage.
- **Risk: Lifetime/ownership of pool buffers.** `pushStreamFrame` calls into the connection's frame pool; `writeStream` owns the data slice's lifetime until the frame is acked. Moving these methods does not change ownership, but a refactor that accidentally changes a `*Connection` argument to `Connection` (value) would silently drop the mutation. **Signal:** test fails because a stream's send offset did not advance. **Mitigation:** every moved method keeps the exact `*Connection` (or `*const Connection`) receiver type from its source location; review the move with `git diff --word-diff` to make this explicit.

### Stage 3 (path)

- **Risk: PMTUD timer arming reaches into recovery state.** `pmtudOnAckProgress` may call `recovery_methods.computeAndMaybeArmPto` indirectly. **Signal:** Zig compile error or runtime PMTUD test failure. **Mitigation:** Stage 3 runs after Stage 1; the recovery module is already a stable target. Use `recovery_methods` re-exports on `Connection`, not direct cross-file imports between `path.zig` and `recovery.zig`.
- **Risk: Amplification limit interacts with both inbound packet handling and connection-state-machine transitions.** `addRxUnvalidated`/`addTxUnvalidated` are called from multiple sites — moving them to `path.zig` is correct (they belong with peer-validation), but every caller must keep working unchanged via the re-export table. **Signal:** integration test with a pre-handshake amplification scenario fails. **Mitigation:** review the re-export table addition and confirm `pub const addRxUnvalidated = path_methods.addRxUnvalidated;` is in place before deleting the body from `conn.zig`.
- **Risk: Migration is interop-sensitive.** The interop suite has migration scenarios (path validation under address change). **Signal:** `make interop-full` flips a SKIP→FAIL or drops a PASS. **Mitigation:** run interop-full as a hard gate before commit.

### Stage 4 (handshake)

- **Risk: Highest regression surface in the entire plan.** Forty-five methods, key-derivation paths, transport-parameter parsing, 0-RTT acceptance, and the cross-cutting `send` entry point all move at once. **Signal:** any of: handshake unit tests fail; `make interop-full` drops PASS count; perf gate `handshake_e2e` regresses; an external interop client fails the handshake. **Mitigation:** (a) plan to split Stage 4 into Stage 4a (key derivation + transport params + ALPN — ~20 methods) and Stage 4b (everything else — ~25 methods) if pre-stage review estimates Stage 4 will exceed a single MR's reviewable size; (b) require 24h soak with a downstream `geode` integration run before declaring Stage 4 complete; (c) hold the `handshake.zig` file-size escape hatch — if it grows past 1500 LOC, defer a Stage-4.5 sub-split into `handshake.zig` + `crypto_tx.zig` + a `bind`-style `key_update_methods.zig` (separate from the existing pure-function `key_update.zig`).
- **Risk: 0-RTT secret material lifetime.** `enable0RTT` takes a `[32]u8` secret by value and stores it; if the move accidentally turns this into a slice copy, the secret could be over-written. **Signal:** 0-RTT test fails or logs a wrong key. **Mitigation:** preserve the value-vs-pointer signature of every moved method exactly; the move is text-level relocation, not a redesign.
- **Risk: Key update timing interaction with Stage 1's recovery extraction.** `maybeFinalizeKeyUpdateOnAck` is called from the ACK reception path. After Stage 1 the ACK path lives in `recovery.zig`, but the key-update finalize lives in `methods_b.zig` until Stage 4. **Signal:** Stages 1 and 4 both pass tests; the cross-stage interaction breaks under perf gate. **Mitigation:** the call goes through `self.maybeFinalizeKeyUpdateOnAck()` (re-exported on `Connection`), so it works identically whether the callee lives in `methods_b.zig` (pre-Stage-4) or `handshake.zig` (post-Stage-4). The re-export table is the load-bearing decoupling.

### Stage 5 (slim + retire)

- **Risk: Hidden direct callers of `methods_a/b/c.zig` outside `conn.zig`.** A test, benchmark, or downstream `cmd/` binary may import `connection/methods_a.zig` directly rather than going through the `Connection` re-exports. **Signal:** `rg -n '@import.*methods_[abc]' src/ tests/ benchmarks/ cmd/` returns hits, or compile breaks. **Mitigation:** before deleting any `methods_*.zig` file, run that `rg` check; if hits exist, route each through the `Connection`-method re-export instead, then delete. If a hit must remain (e.g., a debug helper that genuinely wants the inner-struct access), reduce the file to a deprecated re-export shim and document the timeline in `docs/QUALITY_GAP_ANALYSIS.md` row 14.
- **Risk: Field ordering of `Connection` struct affects perf via cache layout.** Stage 5 does not change struct fields per the non-goals, but `init`/`deinit` does touch every field. **Signal:** `connection_lookup` micro-benchmark stddev gate trips. **Mitigation:** Stage 5 explicitly leaves `init`/`deinit` in `conn.zig` and does not reorder any fields; perf gate `--suite=micro` catches accidental cache-layout drift.
- **Risk: Re-export table becomes the bottleneck.** A flat list of ~120 `pub const x = domain_methods.x;` lines is readable but hard to keep in alphabetical or domain-grouped order. **Signal:** code review fatigue on Stage 5. **Mitigation:** group the re-export block by domain with comments (`// --- recovery ---`, `// --- streams ---`, etc.); commit the table as its own atomic step within Stage 5.

### Cross-stage / global

- **Risk: Stages land out-of-order.** A reviewer merges Stage 3 before Stage 1 because Stage 1's MR has unrelated review feedback. **Signal:** Stage 3's `path.zig` references `recovery_methods` symbols that do not yet exist. **Mitigation:** in the MR description for each stage, list its prerequisites by stage number and link to the merged commit SHA of the prior stage. Refuse to merge Stage N+1 until Stage N is in main.
- **Risk: Atomic stage assumption violated by accidental scope creep.** A reviewer suggests "while you're moving these, also rename `pushStreamFrame` to `streams.pushFrame`." **Signal:** the diff for the stage exceeds the function-list it was scoped to. **Mitigation:** non-goals §1 ("No public API changes") is explicit. Renames go in a separate later MR.
- **Risk: Perf gate baseline drifts during the multi-week plan.** The `benchmarks/results/baseline.json` may be refreshed for an unrelated reason between Stage 1 and Stage 5, causing a stage to compare against a different baseline than its predecessors. **Signal:** a stage's perf gate passes against a fresher baseline but the cumulative drift across all stages is masked. **Mitigation:** capture and pin a `methods-refactor-baseline.json` once at the start of Stage 1; every stage's `--suite=integration` and `--suite=micro` gate compares against that pinned snapshot in addition to the rolling baseline. Document the snapshot path in the Stage 1 MR description.
- **Risk: The "block before next stage" rule is interpreted as "land in same release."** It is not — each stage is independently shippable and should sit in production for at least one release cycle before its successor. **Mitigation:** this plan explicitly does not require all five stages to land in the same release. The acceptance criteria below are the post-Stage-5 target; intermediate states (post-Stage-1, post-Stage-2, etc.) are valid release points.

---

## Acceptance Criteria

The refactor is complete when **all** of the following are true. Each can be checked with a one-line command after Stage 5 is merged.

1. `wc -l src/quic/conn.zig` reports **< 1000 LOC** (down from 1895).
2. `ls src/quic/connection/methods_*.zig 2>&1 | wc -l` reports **0** (or, if deprecation shims are kept per Stage 5 escape hatch, each `methods_*.zig` file is < 50 LOC and contains only re-exports + a deprecation header — captured by `wc -l src/quic/connection/methods_*.zig`).
3. `ls src/quic/connection/` shows the canonical domain set: `recovery.zig`, `streams.zig`, `path.zig`, `handshake.zig`, `key_update.zig`, `pn_space.zig`, `connection_id.zig`, `flow_control.zig`, plus any of the existing supporting files (`stream.zig`, `crypto_buffer.zig`, `error.zig`, `idle.zig`, `limits.zig`, `reset_token.zig`, `pmtud.zig`, `crypto_utils.zig`, `connection.zig`, `types.zig`, `amplification.zig`, `ack.zig`).
4. `make interop-full` reports **105 PASS / 0 FAIL / 50 SKIP** (matches pre-refactor baseline exactly).
5. `zig build -Dfull-test-graph=true test` is green (modulo the documented pre-existing `tests/test_transport_geode_compat.zig:246` CA-cert assertion fail tracked in `CLAUDE.md` Known Pre-existing Issues #1).
6. `scripts/perf-gate.sh --suite=integration` and `scripts/perf-gate.sh --suite=micro` and `scripts/perf-gate.sh --suite=external` all pass against the Stage-1 pinned snapshot.
7. `rg -n '^pub fn |^        pub fn ' src/quic/conn.zig` count is approximately the orchestration set: `init`, `deinit`, `setSender`, `setAeadUsageLimits` (plus the re-export table). All other public methods have moved to a domain module.
8. Every method in the §Inventory function-to-module mapping table is in its target module — verified by `rg -n '^        pub fn <name>' src/quic/connection/<target>.zig` returning a hit for each row.
9. `docs/GAP_ANALYSIS.md` GAP-0060 status is updated from **Blocked / Deferred** to **Closed**, with a back-reference to the merged Stage 5 commit SHA.
10. `docs/QUALITY_GAP_ANALYSIS.md` row 14 (#115/#177) status is updated from **Blocked / Deferred** to **Closed**, with the same back-reference.

---

## References

- `docs/GAP_ANALYSIS.md` GAP-0060 — "Non-domain method module naming obscures ownership" (lines 108+)
- `docs/QUALITY_GAP_ANALYSIS.md` row 14 — "Connection struct 1711 LOC, 160 fields + non-domain-aligned method split" (lines 42, 96, 133, 145)
- `.claude/skills/quic-performance-gating/SKILL.md` — Iron Law for paired same-session A/B perf gating
- `docs/PERFORMANCE_TARGETS.md` — tier thresholds the gate enforces
- `docs/PERFORMANCE_TRACKING.md` — A/B protocol + MR checklist + decision log
- `docs/BENCHMARKS.md` — operator manual for the benchmark suite
- `scripts/perf-gate.sh` — unified tiered A/B gate
- `docs/superpowers/plans/2026-04-20-perf-bench-suite-and-gating.md` — plan style + Phase 0 baseline (Zig 0.16.0)
- `docs/superpowers/plans/2026-04-22-quic-system-tuning.md` — sibling plan structure reference
- `src/quic/connection/key_update.zig` — existing canonical example of a domain-named extraction (RFC 9001 §6 traffic-secret derivation)
- `CLAUDE.md` "Known Pre-existing Issues" — pre-refactor test/build state to compare against

---

## Plan self-review

**Goal coverage:**

- Goal 1 (split `methods_*` → domain modules) → Stages 1–4 each extract one domain; Stage 5 retires the residuals.
- Goal 2 (`conn.zig` < 1000 LOC) → Acceptance Criterion 1.
- Goal 3 (preserve API) → Non-goals §1 + the `bind`-and-re-export pattern preserved in every stage.
- Goal 4 (perf flat per stage) → Constraint 1 + per-stage perf-gate suite specification.
- Goal 5 (ownership readable) → Acceptance Criterion 3 (canonical domain file set).

**Non-goal enforcement:**

- §1 (no API changes) → Stage 5 §Risk row "scope creep."
- §2 (no perf optimizations) → Constraint 1 (gate must be flat, not faster).
- §3 (no test churn) → Stages 1–5 "Files touched" exclude `tests/`.
- §4 (no struct changes) → Stage 5 §Risk row "field ordering of Connection struct."
- §5 (preserve `bind` pattern) → architecture paragraph + every stage's "Scope."

**Constraint enforcement:**

- C1 (perf gate per stage) → each stage's "Perf gate suite required" section.
- C2 (interop 105/0/50) → each stage's "Tests to run" + Acceptance Criterion 4.
- C3 (full test graph) → each stage + Acceptance Criterion 5.
- C4 (no edits outside `src/quic/conn.zig` and `connection/*`) → "Files touched" of every stage.
- C5 (atomic stages) → §Risk cross-stage row "stages land out-of-order."
- C6 (Zig 0.16.0) → tech-stack header + reference to Phase 0 plan.

**Placeholder scan:** None. Every function name in the mapping tables was verified with `rg -n '^        pub fn |^    pub fn |^pub fn ' src/quic/connection/methods_*.zig src/quic/conn.zig` on 2026-04-26. Every LOC number is from `wc -l` on the same date. No invented APIs.

**Type consistency:** Stage numbers (1–5) used identically in Inventory mapping tables, Stage Plan sections, and Risk & Mitigation. File paths (`src/quic/connection/<name>.zig`) consistent. Re-export pattern (`pub const x = domain_methods.x;`) named identically in Stage 1, 2, 3, 4, and 5.

**Ordering self-check:** The suggested ordering (recovery → streams → path → handshake → slim) was retained. The strongest argument for reordering would be moving handshake before streams because handshake has higher regression risk and a smaller surface relative to the overall complexity — but doing handshake earlier means the recovery and stream modules cannot yet absorb their cleanest neighbors, and the cross-coupling between key-update-on-ack (handshake) and ACK reception (recovery) gets resolved later than necessary. The chosen ordering minimizes Stage 4's neighbor surface by isolating recovery, streams, and path first.
