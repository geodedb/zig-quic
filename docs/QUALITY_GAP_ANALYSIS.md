# Quality Gap Analysis

Last updated: 2026-02-16

PriorityScore: `Impact(1-5) * Likelihood(1-5) * 4`

## Summary

- Total findings: 16
- Final status counts: `Closed/Implemented=16`, `Blocked=0`, `Open=0`
- Severity totals:
  - Critical: 1 (`Closed=1`)
  - High: 5 (`Closed=5`)
  - Medium: 8 (`Closed=8`)
  - Low: 2 (`Closed=2`)

### Top 5 Active Risks (Blocked)

1. None.
2. None.
3. None.
4. None.
5. None.

## Stack-Ranked Findings (Final)

| Rank | Severity | PriorityScore | Category | Finding | Component | Evidence | GitLab Issue | Fix Summary | Owner | ETA/SLA | Status |
|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 1 | Critical | 100 | perf | Heap allocations per packet in encode/decode + send path | QUIC core | `src/quic/packet.zig:148`, `src/quic/conn.zig:494`, `bench/main.zig:372` | https://gitlab.com/devnw/zig/quic/-/issues/62 | Added `...Into` packet APIs, connection buffer pool, incoming scratch decode, and allocation regression gate in bench | Core QUIC | 2026-02-16 | Closed / Implemented |
| 2 | High | 80 | cleanup | Large committed artifacts bloated repo + contexts | Repo hygiene | `.gitignore:86`, `.gitignore:87`, deleted `docs/sources.tar`, deleted `quic-test/quicgo-server` | https://gitlab.com/devnw/zig/quic/-/issues/66 | Removed tracked artifacts and added prevent-reintroduction ignore rules | Build/Infra | 2026-02-16 | Closed / Implemented |
| 3 | High | 64 | maintainability | Exported `transport` module parse failure | Transport API | `src/quic/transport.zig:4`, `build.zig:623` | https://gitlab.com/devnw/zig/quic/-/issues/63 | Fixed parse/import issues; examples compile again | Core QUIC | 2026-02-16 | Closed / Implemented |
| 4 | High | 64 | ci-cd | Missing CI quality gates for fmt/examples | CI pipeline | `.gitlab-ci.yml:345`, `.gitlab-ci.yml:363`, `.gitlab-ci.yml:364` | https://gitlab.com/devnw/zig/quic/-/issues/64 | Added dedicated quality gate job for fmt checks and examples build | CI | 2026-02-16 | Closed / Implemented |
| 5 | High | 64 | perf | `zig build test` overhead from high artifact count | Build system | `build.zig:142`, `build.zig:1606`, `tests/smoke.zig:1` | https://gitlab.com/devnw/zig/quic/-/issues/70 | Added grouped smoke entrypoint for default test run; retained full graph via `-Dfull-test-graph=true` | Build owners | 2026-02-16 | Closed / Implemented |
| 6 | High | 64 | architecture | Monolithic core files concentrate responsibilities | QUIC core | `src/quic/conn.zig:1380`, `src/quic/endpoint/incoming.zig:56`, `src/quic/connection/methods_a.zig:1`, `src/quic/endpoint/incoming/module_b.zig:1`, `src/quic/connection/methods_b.zig:211` | https://gitlab.com/devnw/zig/quic/-/issues/75 | Completed staged extraction: connection/incoming pipelines split into focused modules (<1500 LOC), aliases preserved, and post-extraction stream-0 TX-state typing regression fixed; build/examples/test/bench/fmt gates green | Core QUIC | 2026-02-16 | Closed / Implemented |
| 7 | Medium | 48 | ci-cd | Missing `.dockerignore` led to oversized Docker contexts | CI + Docker | `.dockerignore:1`, `.dockerignore:3`, `.gitlab-ci.yml:296` | https://gitlab.com/devnw/zig/quic/-/issues/65 | Added strict allowlist-style `.dockerignore` | CI/Interop | 2026-02-16 | Closed / Implemented |
| 8 | Medium | 48 | cleanup | Stale legacy/backup sources + parse debt | Repo hygiene | `src/quic/conn.zig.legacy` (deleted), `src/quic/endpoint.zig.legacy` (deleted), `quic.zig:544` | https://gitlab.com/devnw/zig/quic/-/issues/67 | Removed legacy/backup tracked files and fixed remaining parse blockers | Core QUIC | 2026-02-16 | Closed / Implemented |
| 9 | Medium | 48 | readability | Full-tree formatting drift | Code style | `git ls-files '*.zig' | xargs -r zig fmt --check` | https://gitlab.com/devnw/zig/quic/-/issues/68 | Applied full-tree `zig fmt` and verified clean check | Core QUIC | 2026-02-16 | Closed / Implemented |
| 10 | Medium | 48 | tests | Tests were chatty by default | Test harness | `tests/helpers/testlog.zig:1`, `build.zig:27`, `tests/integration/connection_pair.zig:11` | https://gitlab.com/devnw/zig/quic/-/issues/69 | Added shared `QUIC_TEST_VERBOSE` gate and refactored test logging through shared helper | Test owners | 2026-02-16 | Closed / Implemented |
| 11 | Medium | 48 | maintainability | Makefile hazards (destructive defaults + masked failures) | Tooling | `Makefile:34`, `Makefile:53`, `Makefile:87` | https://gitlab.com/devnw/zig/quic/-/issues/72 | Made `build` incremental, removed `tail -1`, narrowed process kill behavior | Tooling | 2026-02-16 | Closed / Implemented |
| 12 | Medium | 48 | ci-cd | E2E jobs lacked pinning/caching | CI pipeline | `.gitlab-ci.yml:89`, `.gitlab-ci.yml:97`, `.gitlab-ci.yml:133` | https://gitlab.com/devnw/zig/quic/-/issues/74 | Added pip/go caches and pinned Python dependency install path | CI | 2026-02-16 | Closed / Implemented |
| 13 | Medium | 36 | cleanup | Duplicate test harness directory structure | Tests + tooling | `.gitlab-ci.yml:395`, `Makefile:188`, `.gitignore:80` | https://gitlab.com/devnw/zig/quic/-/issues/73 | Consolidated under canonical `test-clients/` with legacy content moved to explicit subpaths | QA/Interop | 2026-02-16 | Closed / Implemented |
| 14 | Medium | 36 | maintainability | `flake.nix` shellHook was heavyweight and side-effectful | Dev env | `flake.nix:78`, `flake.nix:107`, `scripts/devshell_auth.sh:1` | https://gitlab.com/devnw/zig/quic/-/issues/76 | Made shellHook side-effect free and moved auth/secret actions to explicit opt-in script | Platform | 2026-02-16 | Closed / Implemented |
| 15 | Low | 32 | docs | README drift (broken link + CI mismatch) | Documentation | `README.md:91`, `README.md:249` | https://gitlab.com/devnw/zig/quic/-/issues/71 | Updated docs link and CI description | Docs | 2026-02-16 | Closed / Implemented |
| 16 | Low | 24 | maintainability | ShellCheck warnings in scripts | Scripts | `examples/interop/debug_interop.sh:46`, `scripts/install_pkgs.sh:115`, `shellcheck --severity=warning` clean run | https://gitlab.com/devnw/zig/quic/-/issues/77 | Completed warning-level ShellCheck remediation and validated clean lint output | Tooling | 2026-02-16 | Closed / Implemented |

## Findings By Category

### perf
- #62 Closed.
- #70 Closed.

### architecture
- #75 Closed.

### ci-cd
- #64 Closed.
- #65 Closed.
- #74 Closed.

### tests
- #69 Closed.

### readability
- #68 Closed.

### maintainability
- #72 Closed.
- #76 Closed.
- #77 Closed.

### docs
- #71 Closed.

### cleanup
- #66 Closed.
- #67 Closed.
- #73 Closed.

## Roadmap Status

### Quick Wins
- Completed: #63, #64, #65, #66, #71, #72, #74.

### Medium
- Completed: #67, #68, #69, #73, #76, #77.

### Strategic
- Completed: #62, #70, #75.

## Future-Agent Notes

1. CI/CD hash/toolchain pinning and Docker tag digest pinning are intentionally tracked as **won't do** at repo level (see security issues #54 and #55); controls are external.
2. Pre-commit hook pinning/enforcement is also externalized; do not create repo-local gaps for that unless governance ownership changes.
