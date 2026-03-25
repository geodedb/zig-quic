# Quality Gap Analysis

Last updated: 2026-03-25

Repository: `gitlab.com/devnw/zig/quic`
Scope: Full codebase quality review (Phase 1-3)
PriorityScore formula: `Impact(1-5) * Likelihood(1-5) * 4`

## Summary

- Total findings: 31
- Status counts: `Open=1`, `Closed/Implemented=30`
- Severity totals:
  - Critical: 2 (`Open=0`, `Closed=2`)
  - High: 9 (`Open=0`, `Closed=9`)
  - Medium: 14 (`Open=0`, `Closed=14`)
  - Low: 6 (`Open=1`, `Closed=5`)

### Top Active Risks

1. **#115 (Low, PriorityScore 24)** -- Connection struct 1711 LOC, 160 fields + non-domain-aligned method split

---

## Stack-Ranked Findings -- Phase 3 (Open)

| Rank | ID | Severity | PriorityScore | Category | Finding | Component | Evidence | GitLab Issue | Fix Summary | Owner | Effort | Status |
|---:|:---|:---|---:|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| 1 | A1 | Critical | 100 | maintainability | `unreachable` on peer-controlled CID length -- server crash/UB | Transport | `connection/reset_token.zig:10`, `connection_id.zig:38`, `methods_c.zig:619` | [#87](https://gitlab.com/devnw/zig/quic/-/issues/87) | Replaced `unreachable` with `error.InvalidCidLength` | Core QUIC | S (15 min) | Closed / Implemented |
| 2 | E1 | High | 80 | perf | `page_allocator` syscall per packet in decrypt AAD | Transport | `packet.zig:699-703` | [#89](https://gitlab.com/devnw/zig/quic/-/issues/89) | Replaced with stack-allocated buffer | Core QUIC | S (30 min) | Closed / Implemented |
| 3 | E4+R4 | High | 80 | perf, maintainability | `dumpBytes` production leak + duplication | Crypto | `crypto_quic.zig:669-680`, `packet.zig` | [#93](https://gitlab.com/devnw/zig/quic/-/issues/93) | Restored `is_test` guard so production builds skip entirely | Core QUIC | S (10 min) | Closed / Implemented |
| 4 | A3 | High | 64 | maintainability | Silent `catch {}` on connection registration -- ghost connections | Transport | `endpoint.zig:500,473,561,1037` | [#96](https://gitlab.com/devnw/zig/quic/-/issues/96) | Proper cleanup on map put failure | Core QUIC | M (1h) | Closed / Implemented |
| 5 | A7 | High | 64 | api-contract | `handshakeComplete == isHandshakeConfirmed` -- incorrect RFC 9000 semantics | Transport | `api.zig:157-167` | [#98](https://gitlab.com/devnw/zig/quic/-/issues/98) | Changed `handshakeComplete` to return `peer_finished_verified` per RFC 9000 S4.1.1 | Core QUIC | S (30 min) | Closed / Implemented |
| 6 | R1-R3 | Medium | 48 | maintainability | Triplicated `deriveStatelessResetToken` + `hashForSecret` + `maybeTriggerKeyUpdateOnSend` | Transport | `reset_token.zig`, `connection_id.zig`, `methods_c.zig`, `methods_b.zig` | [#99](https://gitlab.com/devnw/zig/quic/-/issues/99) | Extract each into single canonical location | Core QUIC | M (1h) | Closed |
| 7 | E5 | Medium | 40 | perf | `getenv` on every packet send for debug config | Transport | `conn.zig:1534`, `methods_c.zig:45`, `methods_b.zig:1454` | [#106](https://gitlab.com/devnw/zig/quic/-/issues/106) | Env var removed entirely; config field used instead | Core QUIC | S (15 min) | Closed / Implemented |
| 8 | E6 | Medium | 40 | ci-cd | No Zig build cache in CI | CI | `.gitlab-ci.yml` (no cache directive for zig-cache) | [#112](https://gitlab.com/devnw/zig/quic/-/issues/112) | Added cache blocks with key `zig-cache-${ZIG_VERSION}` to CI jobs | CI | S (15 min) | Closed / Implemented |
| 9 | E7 | Medium | 36 | ci-cd | macOS/Windows CI downloads Zig without SHA-256 verification | CI / Platform | `.gitlab-ci.yml:503-524` | [#102](https://gitlab.com/devnw/zig/quic/-/issues/102) | Added SHA-256 verification for macOS/Windows CI jobs | CI | S (30 min) | Closed / Implemented |
| 10 | R5-R6 | Medium | 36 | architecture | Parallel monolithic + modular frame/recovery modules | Transport | `endpoint/frame_handler.zig` vs `incoming/module_b*.zig` | [#103](https://gitlab.com/devnw/zig/quic/-/issues/103) | Documented: deprecated monolithic files with doc comments; build wires modular versions | Core QUIC | M-L (2-4h) | Closed / Implemented |
| 11 | R9 | Medium | 36 | api-contract | Heuristic endpoint role detection by port number | Transport | `endpoint.zig:270-274` | [#107](https://gitlab.com/devnw/zig/quic/-/issues/107) | Replaced port heuristic with cert_path-based detection | Core QUIC | S (20 min) | Closed / Implemented |
| 12 | E3 | Medium | 36 | maintainability | 40+ state-corrupting `catch {}` patterns in core modules | Transport | 287 occurrences across 63 files | [#110](https://gitlab.com/devnw/zig/quic/-/issues/110) | All 75 `catch {}` patterns in `src/quic/` eliminated (phases 1+2). Phase 1 fixed ~15 critical patterns; phase 2 fixed remaining 60 with proper logging. Commit bf8cf7f audited remaining catch sites. | Core QUIC | L (4-8h) | Closed / Implemented |
| 13 | D1-D5 | Low | 24 | docs | Documentation gaps -- no architecture doc, sparse doc comments | Docs | No `docs/ARCHITECTURE.md`; many public fns undocumented | [#113](https://gitlab.com/devnw/zig/quic/-/issues/113) | Created `docs/ARCHITECTURE.md` covering module layout, mixin pattern, migration status, threading model, data flows | Docs | Ongoing | Closed / Implemented |
| 14 | R7-R8 | Low | 24 | architecture | Connection struct 1711 LOC, 160 fields + non-domain-aligned method split | Transport | `conn.zig` (1711 lines), `methods_a/b/c.zig` | [#115](https://gitlab.com/devnw/zig/quic/-/issues/115) | Re-split by domain concern | Core QUIC | L | Open |
| 15 | E9 | Low | 16 | cleanup | Global mutable debug state -- data race, debug scaffolding | Core | Module-level mutable `var` for debug control | [#117](https://gitlab.com/devnw/zig/quic/-/issues/117) | Gated phase57 vars behind `builtin.is_test`; no-ops in production | Core QUIC | S (5 min) | Closed / Implemented |

---

## Stack-Ranked Findings -- Phase 1-2 (Closed)

| Rank | Severity | PriorityScore | Category | Finding | Component | Evidence | GitLab Issue | Fix Summary | Owner | ETA/SLA | Status |
|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 1 | Critical | 100 | perf | Heap allocations per packet in encode/decode + send path | QUIC core | `src/quic/packet.zig:148`, `src/quic/conn.zig:494`, `bench/main.zig:372` | [#62](https://gitlab.com/devnw/zig/quic/-/issues/62) | Added `...Into` packet APIs, connection buffer pool, incoming scratch decode, and allocation regression gate in bench | Core QUIC | 2026-02-16 | Closed |
| 2 | High | 80 | cleanup | Large committed artifacts bloated repo + contexts | Repo hygiene | `.gitignore:86`, `.gitignore:87`, deleted `docs/sources.tar`, deleted `quic-test/quicgo-server` | [#66](https://gitlab.com/devnw/zig/quic/-/issues/66) | Removed tracked artifacts and added prevent-reintroduction ignore rules | Build/Infra | 2026-02-16 | Closed |
| 3 | High | 64 | maintainability | Exported `transport` module parse failure | Transport API | `src/quic/transport.zig:4`, `build.zig:623` | [#63](https://gitlab.com/devnw/zig/quic/-/issues/63) | Fixed parse/import issues; examples compile again | Core QUIC | 2026-02-16 | Closed |
| 4 | High | 64 | ci-cd | Missing CI quality gates for fmt/examples | CI pipeline | `.gitlab-ci.yml:345`, `.gitlab-ci.yml:363`, `.gitlab-ci.yml:364` | [#64](https://gitlab.com/devnw/zig/quic/-/issues/64) | Added dedicated quality gate job for fmt checks and examples build | CI | 2026-02-16 | Closed |
| 5 | High | 64 | perf | `zig build test` overhead from high artifact count | Build system | `build.zig:142`, `build.zig:1606`, `tests/smoke.zig:1` | [#70](https://gitlab.com/devnw/zig/quic/-/issues/70) | Added grouped smoke entrypoint for default test run; retained full graph via `-Dfull-test-graph=true` | Build owners | 2026-02-16 | Closed |
| 6 | High | 64 | architecture | Monolithic core files concentrate responsibilities | QUIC core | `src/quic/conn.zig:1380`, `src/quic/endpoint/incoming.zig:56` | [#75](https://gitlab.com/devnw/zig/quic/-/issues/75) | Completed staged extraction into focused modules (<1500 LOC) | Core QUIC | 2026-02-16 | Closed |
| 7 | Medium | 48 | ci-cd | Missing `.dockerignore` led to oversized Docker contexts | CI + Docker | `.dockerignore:1`, `.gitlab-ci.yml:296` | [#65](https://gitlab.com/devnw/zig/quic/-/issues/65) | Added strict allowlist-style `.dockerignore` | CI/Interop | 2026-02-16 | Closed |
| 8 | Medium | 48 | cleanup | Stale legacy/backup sources + parse debt | Repo hygiene | `src/quic/conn.zig.legacy` (deleted) | [#67](https://gitlab.com/devnw/zig/quic/-/issues/67) | Removed legacy/backup tracked files | Core QUIC | 2026-02-16 | Closed |
| 9 | Medium | 48 | readability | Full-tree formatting drift | Code style | `zig fmt --check` output | [#68](https://gitlab.com/devnw/zig/quic/-/issues/68) | Applied full-tree `zig fmt` | Core QUIC | 2026-02-16 | Closed |
| 10 | Medium | 48 | tests | Tests were chatty by default | Test harness | `tests/helpers/testlog.zig:1` | [#69](https://gitlab.com/devnw/zig/quic/-/issues/69) | Added `QUIC_TEST_VERBOSE` gate | Test owners | 2026-02-16 | Closed |
| 11 | Medium | 48 | maintainability | Makefile hazards (destructive defaults + masked failures) | Tooling | `Makefile:34`, `Makefile:53` | [#72](https://gitlab.com/devnw/zig/quic/-/issues/72) | Made `build` incremental, narrowed kill behavior | Tooling | 2026-02-16 | Closed |
| 12 | Medium | 48 | ci-cd | E2E jobs lacked pinning/caching | CI pipeline | `.gitlab-ci.yml:89`, `.gitlab-ci.yml:97` | [#74](https://gitlab.com/devnw/zig/quic/-/issues/74) | Added pip/go caches and pinned Python install path | CI | 2026-02-16 | Closed |
| 13 | Medium | 36 | cleanup | Duplicate test harness directory structure | Tests + tooling | `.gitlab-ci.yml:395`, `Makefile:188` | [#73](https://gitlab.com/devnw/zig/quic/-/issues/73) | Consolidated under canonical `test-clients/` | QA/Interop | 2026-02-16 | Closed |
| 14 | Medium | 36 | maintainability | `flake.nix` shellHook was heavyweight and side-effectful | Dev env | `flake.nix:78` | [#76](https://gitlab.com/devnw/zig/quic/-/issues/76) | Made shellHook side-effect free | Platform | 2026-02-16 | Closed |
| 15 | Low | 32 | docs | README drift (broken link + CI mismatch) | Documentation | `README.md:91`, `README.md:249` | [#71](https://gitlab.com/devnw/zig/quic/-/issues/71) | Updated docs link and CI description | Docs | 2026-02-16 | Closed |
| 16 | Low | 24 | maintainability | ShellCheck warnings in scripts | Scripts | `examples/interop/debug_interop.sh:46` | [#77](https://gitlab.com/devnw/zig/quic/-/issues/77) | Completed warning-level ShellCheck remediation | Tooling | 2026-02-16 | Closed |

---

## Findings By Category

### perf
- [#62](https://gitlab.com/devnw/zig/quic/-/issues/62) Closed -- per-packet heap allocations in encode/decode.
- [#70](https://gitlab.com/devnw/zig/quic/-/issues/70) Closed -- `zig build test` overhead.
- [#89](https://gitlab.com/devnw/zig/quic/-/issues/89) **Closed** -- page_allocator syscall per packet (AAD). Fixed in Batch A (stack buffer).
- [#93](https://gitlab.com/devnw/zig/quic/-/issues/93) **Closed** -- dumpBytes production leak + duplication. Fixed in Batch A (is_test guard).
- [#106](https://gitlab.com/devnw/zig/quic/-/issues/106) **Closed** -- getenv per packet send. Fixed in Batch A (env var removed entirely).

### maintainability
- [#63](https://gitlab.com/devnw/zig/quic/-/issues/63) Closed.
- [#72](https://gitlab.com/devnw/zig/quic/-/issues/72) Closed.
- [#76](https://gitlab.com/devnw/zig/quic/-/issues/76) Closed.
- [#77](https://gitlab.com/devnw/zig/quic/-/issues/77) Closed.
- [#87](https://gitlab.com/devnw/zig/quic/-/issues/87) **Closed** -- unreachable on peer CID (Critical). Fixed in Batch A (error.InvalidCidLength).
- [#96](https://gitlab.com/devnw/zig/quic/-/issues/96) **Closed** -- ghost connections from silent catch {}. Fixed in Batch B (proper cleanup on map put failure).
- [#99](https://gitlab.com/devnw/zig/quic/-/issues/99) **Closed** -- triplicated crypto functions deduplicated into canonical locations.
- [#110](https://gitlab.com/devnw/zig/quic/-/issues/110) **Closed / Implemented** -- All 75 `catch {}` patterns in `src/quic/` eliminated across phases 1+2. Phase 1 fixed ~15 critical patterns; phase 2 fixed remaining 60 with proper logging (commits c7e8d6d, bf8cf7f).

### api-contract
- [#98](https://gitlab.com/devnw/zig/quic/-/issues/98) **Closed** -- handshakeComplete == isHandshakeConfirmed. Fixed in Batch A (returns peer_finished_verified).
- [#107](https://gitlab.com/devnw/zig/quic/-/issues/107) **Closed** -- port-based role detection heuristic. Fixed in Batch A (cert_path detection).

### architecture
- [#75](https://gitlab.com/devnw/zig/quic/-/issues/75) Closed.
- [#103](https://gitlab.com/devnw/zig/quic/-/issues/103) **Closed** -- documented monolithic files as deprecated; build wires modular versions.
- [#115](https://gitlab.com/devnw/zig/quic/-/issues/115) **Open** -- Connection struct 1711 LOC.

### ci-cd
- [#64](https://gitlab.com/devnw/zig/quic/-/issues/64) Closed.
- [#65](https://gitlab.com/devnw/zig/quic/-/issues/65) Closed.
- [#74](https://gitlab.com/devnw/zig/quic/-/issues/74) Closed.
- [#102](https://gitlab.com/devnw/zig/quic/-/issues/102) **Closed** -- macOS/Windows CI SHA-256 hash verification. Fixed in Batch A.
- [#112](https://gitlab.com/devnw/zig/quic/-/issues/112) **Closed** -- Zig build cache in CI. Fixed in Batch A (cache blocks added).

### docs
- [#71](https://gitlab.com/devnw/zig/quic/-/issues/71) Closed.
- [#113](https://gitlab.com/devnw/zig/quic/-/issues/113) **Closed** -- created `docs/ARCHITECTURE.md`.

### cleanup
- [#66](https://gitlab.com/devnw/zig/quic/-/issues/66) Closed.
- [#67](https://gitlab.com/devnw/zig/quic/-/issues/67) Closed.
- [#73](https://gitlab.com/devnw/zig/quic/-/issues/73) Closed.
- [#117](https://gitlab.com/devnw/zig/quic/-/issues/117) **Closed** -- global mutable debug state. Fixed in Batch A (phase57 behind is_test).

### readability
- [#68](https://gitlab.com/devnw/zig/quic/-/issues/68) Closed.

### tests
- [#69](https://gitlab.com/devnw/zig/quic/-/issues/69) Closed.

---

## Roadmap

### Quick Wins (< 1 day)
- Completed: #63, #64, #65, #66, #71, #72, #74, #87, #89, #93, #98, #102, #106, #107, #112, #117.

### Medium (1-5 days)
- Completed: #67, #68, #69, #73, #76, #77, #96, #99, #103.

### Strategic (> 5 days)
- **Closed**: #110 (all 75 patterns eliminated across phases 1+2)
- **Open**: #115 (Large, deferred -- connection struct refactor)
- Completed: #62, #70, #75, #113.

---

## Future-Agent Notes

1. CI/CD hash/toolchain pinning and Docker tag digest pinning are intentionally tracked as **won't do** at repo level (see security issues #54 and #55); controls are external. Note: #102 specifically addresses platform-specific (macOS/Windows) hash verification gaps that were not covered by the external controls.
2. Pre-commit hook pinning/enforcement is also externalized; do not create repo-local gaps for that unless governance ownership changes.
3. The `catch {}` audit (#110) is complete -- all 75 patterns in `src/quic/` eliminated. #96 (ghost connections) was fixed in Batch B with proper cleanup on map put failure.
4. Code deduplication (#99) and the CID unreachable fix (#87) are both closed.
5. The `dumpBytes` fix (#93) overlaps with the closed security issue #56 (debug logging leaks secrets). The #56 fix addressed the logger level; #93 addresses the separately-guarded `dumpBytes` function that bypasses the logger gate.

---

## Phase 4 Gap Closure -- 2026-03-25

### Closed Items
- **QF-E6:** `canSendUnderAmplification` duplicate computation -- Closed. Consolidated with `overAmplification()` to check `exempt_localhost` consistently.
- **QF-R6:** 7 duplicate doc comments removed across `conn.zig`, `methods_a.zig`, `methods_b.zig`.
- **QF-D6:** `trace_enabled` documented with purpose and usage context.
- **QF-A4:** `alpn` field documented with RFC 7301 reference.
- **GAP-0047 (#155):** frame_handler comment corrected -- Closed. Replaced catch-all `else => .{}` with explicit match arms; Zig compiler now flags unhandled variants.
