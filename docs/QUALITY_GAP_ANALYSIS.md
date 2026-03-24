# Quality Gap Analysis

Last updated: 2026-03-24

Repository: `gitlab.com/devnw/zig/quic`
Scope: Full codebase quality review (Phase 1-3)
PriorityScore formula: `Impact(1-5) * Likelihood(1-5) * 4`

## Summary

- Total findings: 31
- Status counts: `Open=15`, `Closed/Implemented=16`
- Severity totals:
  - Critical: 2 (`Open=1`, `Closed=1`)
  - High: 9 (`Open=4`, `Closed=5`)
  - Medium: 14 (`Open=6`, `Closed=8`)
  - Low: 6 (`Open=4`, `Closed=2`)

### Top 5 Active Risks

1. **#87 (Critical, PriorityScore 100)** -- `unreachable` on peer-controlled CID length crashes server from a single unauthenticated packet
2. **#89 (High, PriorityScore 80)** -- `page_allocator` syscall on every packet decrypt (AAD assembly)
3. **#93 (High, PriorityScore 80)** -- `dumpBytes` production leak: debug hex dump active in all builds + allocates per call
4. **#96 (High, PriorityScore 64)** -- Silent `catch {}` on connection registration creates ghost connections under OOM
5. **#98 (High, PriorityScore 64)** -- `handshakeComplete == isHandshakeConfirmed` conflates two distinct RFC 9000 states

---

## Stack-Ranked Findings -- Phase 3 (Open)

| Rank | ID | Severity | PriorityScore | Category | Finding | Component | Evidence | GitLab Issue | Fix Summary | Owner | Effort | Status |
|---:|:---|:---|---:|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| 1 | A1 | Critical | 100 | maintainability | `unreachable` on peer-controlled CID length -- server crash/UB | Transport | `connection/reset_token.zig:10`, `connection_id.zig:38`, `methods_c.zig:619` | [#87](https://gitlab.com/devnw/zig/quic/-/issues/87) | Replace `unreachable` with error return; add test for CID > 20 | Core QUIC | S (15 min) | Open |
| 2 | E1 | High | 80 | perf | `page_allocator` syscall per packet in decrypt AAD | Transport | `packet.zig:699-703` | [#89](https://gitlab.com/devnw/zig/quic/-/issues/89) | Replace ArrayList+page_allocator with stack buffer (AAD is max ~25 bytes) | Core QUIC | S (30 min) | Open |
| 3 | E4+R4 | High | 80 | perf, maintainability | `dumpBytes` production leak + duplication | Crypto | `crypto_quic.zig:669-680`, `packet.zig` | [#93](https://gitlab.com/devnw/zig/quic/-/issues/93) | Restore `is_test` guard; consolidate to single utility; remove page_allocator | Core QUIC | S (10 min) | Open |
| 4 | A3 | High | 64 | maintainability | Silent `catch {}` on connection registration -- ghost connections | Transport | `endpoint.zig:500,473,561,1037` | [#96](https://gitlab.com/devnw/zig/quic/-/issues/96) | Propagate errors or cleanup on failure; log error context | Core QUIC | M (1h) | Open |
| 5 | A7 | High | 64 | api-contract | `handshakeComplete == isHandshakeConfirmed` -- incorrect RFC 9000 semantics | Transport | `api.zig:157-167` | [#98](https://gitlab.com/devnw/zig/quic/-/issues/98) | Track completion and confirmation separately per RFC 9000 s4.1 | Core QUIC | S (30 min) | Open |
| 6 | R1-R3 | Medium | 48 | maintainability | Triplicated `deriveStatelessResetToken` + `hashForSecret` + `maybeTriggerKeyUpdateOnSend` | Transport | `reset_token.zig`, `connection_id.zig`, `methods_c.zig`, `methods_b.zig` | [#99](https://gitlab.com/devnw/zig/quic/-/issues/99) | Extract each into single canonical location | Core QUIC | M (1h) | Open |
| 7 | E5 | Medium | 40 | perf | `getenv` on every packet send for debug config | Transport | `conn.zig:1534`, `methods_c.zig:45`, `methods_b.zig:1454` | [#106](https://gitlab.com/devnw/zig/quic/-/issues/106) | Cache env lookup at init time | Core QUIC | S (15 min) | Open |
| 8 | E6 | Medium | 40 | ci-cd | No Zig build cache in CI | CI | `.gitlab-ci.yml` (no cache directive for zig-cache) | [#112](https://gitlab.com/devnw/zig/quic/-/issues/112) | Add cache key for zig-cache directories | CI | S (15 min) | Open |
| 9 | E7 | Medium | 36 | ci-cd | macOS/Windows CI downloads Zig without SHA-256 verification | CI / Platform | `.gitlab-ci.yml:503-524` | [#102](https://gitlab.com/devnw/zig/quic/-/issues/102) | Add hash verification matching Linux job pattern | CI | S (30 min) | Open |
| 10 | R5-R6 | Medium | 36 | architecture | Parallel monolithic + modular frame/recovery modules | Transport | `endpoint/frame_handler.zig` vs `incoming/module_b*.zig` | [#103](https://gitlab.com/devnw/zig/quic/-/issues/103) | Remove non-canonical version; consolidate | Core QUIC | M-L (2-4h) | Open |
| 11 | R9 | Medium | 36 | api-contract | Heuristic endpoint role detection by port number | Transport | `endpoint.zig:270-274` | [#107](https://gitlab.com/devnw/zig/quic/-/issues/107) | Make role an explicit config parameter | Core QUIC | S (20 min) | Open |
| 12 | E3 | Medium | 36 | maintainability | 40+ state-corrupting `catch {}` patterns in core modules | Transport | 287 occurrences across 63 files | [#110](https://gitlab.com/devnw/zig/quic/-/issues/110) | Phased audit: propagate or document each | Core QUIC | L (4-8h) | Open |
| 13 | D1-D5 | Low | 24 | docs | Documentation gaps -- no architecture doc, sparse doc comments | Docs | No `docs/ARCHITECTURE.md`; many public fns undocumented | [#113](https://gitlab.com/devnw/zig/quic/-/issues/113) | Create architecture doc; add doc comments to public API | Docs | Ongoing | Open |
| 14 | R7-R8 | Low | 24 | architecture | Connection struct 1711 LOC, 160 fields + non-domain-aligned method split | Transport | `conn.zig` (1711 lines), `methods_a/b/c.zig` | [#115](https://gitlab.com/devnw/zig/quic/-/issues/115) | Re-split by domain concern | Core QUIC | L | Open |
| 15 | E9 | Low | 16 | cleanup | Global mutable debug state -- data race, debug scaffolding | Core | Module-level mutable `var` for debug control | [#117](https://gitlab.com/devnw/zig/quic/-/issues/117) | Replace with comptime flags or per-instance config | Core QUIC | S (5 min) | Open |

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
- [#89](https://gitlab.com/devnw/zig/quic/-/issues/89) **Open** -- page_allocator syscall per packet (AAD).
- [#93](https://gitlab.com/devnw/zig/quic/-/issues/93) **Open** -- dumpBytes production leak + duplication.
- [#106](https://gitlab.com/devnw/zig/quic/-/issues/106) **Open** -- getenv per packet send.

### maintainability
- [#63](https://gitlab.com/devnw/zig/quic/-/issues/63) Closed.
- [#72](https://gitlab.com/devnw/zig/quic/-/issues/72) Closed.
- [#76](https://gitlab.com/devnw/zig/quic/-/issues/76) Closed.
- [#77](https://gitlab.com/devnw/zig/quic/-/issues/77) Closed.
- [#87](https://gitlab.com/devnw/zig/quic/-/issues/87) **Open** -- unreachable on peer CID (Critical).
- [#96](https://gitlab.com/devnw/zig/quic/-/issues/96) **Open** -- ghost connections from silent catch {}.
- [#99](https://gitlab.com/devnw/zig/quic/-/issues/99) **Open** -- triplicated crypto functions.
- [#110](https://gitlab.com/devnw/zig/quic/-/issues/110) **Open** -- 287 catch {} patterns.

### api-contract
- [#98](https://gitlab.com/devnw/zig/quic/-/issues/98) **Open** -- handshakeComplete == isHandshakeConfirmed.
- [#107](https://gitlab.com/devnw/zig/quic/-/issues/107) **Open** -- port-based role detection heuristic.

### architecture
- [#75](https://gitlab.com/devnw/zig/quic/-/issues/75) Closed.
- [#103](https://gitlab.com/devnw/zig/quic/-/issues/103) **Open** -- parallel monolithic/modular modules.
- [#115](https://gitlab.com/devnw/zig/quic/-/issues/115) **Open** -- Connection struct 1711 LOC.

### ci-cd
- [#64](https://gitlab.com/devnw/zig/quic/-/issues/64) Closed.
- [#65](https://gitlab.com/devnw/zig/quic/-/issues/65) Closed.
- [#74](https://gitlab.com/devnw/zig/quic/-/issues/74) Closed.
- [#102](https://gitlab.com/devnw/zig/quic/-/issues/102) **Open** -- macOS/Windows CI missing SHA-256 hash verification.
- [#112](https://gitlab.com/devnw/zig/quic/-/issues/112) **Open** -- no Zig build cache in CI.

### docs
- [#71](https://gitlab.com/devnw/zig/quic/-/issues/71) Closed.
- [#113](https://gitlab.com/devnw/zig/quic/-/issues/113) **Open** -- architecture doc + doc comments.

### cleanup
- [#66](https://gitlab.com/devnw/zig/quic/-/issues/66) Closed.
- [#67](https://gitlab.com/devnw/zig/quic/-/issues/67) Closed.
- [#73](https://gitlab.com/devnw/zig/quic/-/issues/73) Closed.
- [#117](https://gitlab.com/devnw/zig/quic/-/issues/117) **Open** -- global mutable debug state.

### readability
- [#68](https://gitlab.com/devnw/zig/quic/-/issues/68) Closed.

### tests
- [#69](https://gitlab.com/devnw/zig/quic/-/issues/69) Closed.

---

## Roadmap

### Quick Wins (< 1 day)
- **Open**: #87 (15 min), #93 (10 min), #89 (30 min), #106 (15 min), #98 (30 min), #107 (20 min), #102 (30 min), #112 (15 min), #117 (5 min)
- Completed: #63, #64, #65, #66, #71, #72, #74.

### Medium (1-5 days)
- **Open**: #96 (1h), #99 (1h), #103 (2-4h)
- Completed: #67, #68, #69, #73, #76, #77.

### Strategic (> 5 days)
- **Open**: #110 (4-8h), #115 (Large), #113 (Ongoing)
- Completed: #62, #70, #75.

---

## Future-Agent Notes

1. CI/CD hash/toolchain pinning and Docker tag digest pinning are intentionally tracked as **won't do** at repo level (see security issues #54 and #55); controls are external. Note: #102 specifically addresses platform-specific (macOS/Windows) hash verification gaps that were not covered by the external controls.
2. Pre-commit hook pinning/enforcement is also externalized; do not create repo-local gaps for that unless governance ownership changes.
3. The `catch {}` audit (#110) should be coordinated with #96 (ghost connections) -- #96 covers the critical endpoint paths while #110 covers the broader codebase.
4. Code deduplication (#99) should be done before or alongside the CID unreachable fix (#87) to avoid fixing the same bug in 3 places.
5. The `dumpBytes` fix (#93) overlaps with the closed security issue #56 (debug logging leaks secrets). The #56 fix addressed the logger level; #93 addresses the separately-guarded `dumpBytes` function that bypasses the logger gate.
