# Security GAP Analysis

Last updated: 2026-02-16

Repository: `gitlab.com/devnw/zig/quic`  
Risk scoring: `Risk (0-100) = Impact(1-5) * Likelihood(1-5) * 4`

## Summary

| Severity | Found | Closed/Implemented | Closed/Won't do | Blocked | Open |
|----------|------:|-------------------:|----------------:|--------:|-----:|
| High | 8 | 5 | 3 | 0 | 0 |
| Medium | 2 | 2 | 0 | 0 | 0 |
| Low | 1 | 1 | 0 | 0 | 0 |
| **Total** | **11** | **8** | **3** | **0** | **0** |

### Top 5 Residual Risks

1. Historical private key material remains recoverable from Git history as accepted external-control risk (`#36`, won't do).
2. Mutable image/tag pinning remains accepted as external-control risk (`#55`, won't do).
3. CI hash/toolchain integrity controls are managed externally (`#54`, won't do).
4. None.
5. None.

## Stack-Ranked Findings

| Rank | Sev | Risk | Finding | Component | CWE/OWASP | Evidence(file:line) | Issue URL | Fix | Owner | Due | Status |
|------|-----|------|---------|-----------|-----------|----------------------|----------|-----|-------|-----|--------|
| 1 | High | 60 | Mutable container tags in CI/interop are accepted risk (`confidence::confirmed`) | CI/CD | OWASP A08:2021 | `.gitlab-ci.yml:78`, `.gitlab-ci.yml:240`, `examples/interop/docker-compose.full.yml:172` | https://gitlab.com/devnw/zig/quic/-/issues/55 | Managed by external controls (repo-level won't-do) | Platform | N/A | Closed / Won't do |
| 2 | High | 60 | CI installs pinned Python deps and gates this path (`confidence::confirmed`) | CI/CD | CWE-494 | `.gitlab-ci.yml:97`, `test-clients/aioquic-client/requirements.txt:1` | https://gitlab.com/devnw/zig/quic/-/issues/57 | Keep pinned requirements + scan updates | CI | 2026-02-16 | Closed / Implemented |
| 3 | High | 48 | Private keys still discoverable in repository history (`confidence::confirmed`) | Supply chain | CWE-321, CWE-798 | `certs/server.key:1 (historical commit e3117889)`, `certs/key.pem:4 (historical commit e3117889)` | https://gitlab.com/devnw/zig/quic/-/issues/36 | Managed by external governance controls (repo-level won't-do) | Security | N/A | Closed / Won't do |
| 4 | High | 48 | CI hash/toolchain integrity pinning is externally governed (`confidence::confirmed`) | CI/CD | CWE-494 | `.gitlab-ci.yml:358`, `.gitlab-ci.yml:359` | https://gitlab.com/devnw/zig/quic/-/issues/54 | Managed by external controls (repo-level won't-do) | Platform | N/A | Closed / Won't do |
| 5 | High | 48 | Legacy Go module vulnerability + scan coverage blind spot (`confidence::confirmed`) | Supply chain | OWASP A06:2021 | `test-clients/quic-test-legacy/go.mod:3`, `.gitlab-ci.yml:395` | https://gitlab.com/devnw/zig/quic/-/issues/59 | Upgraded module to `toolchain go1.25.7` and added binary-mode govulncheck coverage for legacy standalone mains | Go owners | 2026-02-16 | Closed / Implemented |
| 6 | High | 48 | Debug logging secret leakage remediated (`confidence::confirmed`) | Application | CWE-532 | `src/quic/logger.zig:15`, `src/quic/conn.zig:3084`, `src/quic/packet.zig:708` | https://gitlab.com/devnw/zig/quic/-/issues/56 | Keep secret-redaction policy enforced | Core QUIC | 2026-02-16 | Closed / Implemented |
| 7 | High | 48 | Client secure connect fail-closed remediated (`confidence::confirmed`) | Application | CWE-295 | `src/quic/transport.zig:674`, `src/quic/transport.zig:678` | https://gitlab.com/devnw/zig/quic/-/issues/51 | Keep strict CA requirement in secure path | Core QUIC | 2026-02-16 | Closed / Implemented |
| 8 | High | 48 | Secret scanner bypass config remediated (`confidence::confirmed`) | CI/CD | CWE-693 | `.gitlab-secret-detection.yml:15`, `.gitleaks.toml:19` | https://gitlab.com/devnw/zig/quic/-/issues/53 | Keep allowlists narrow and path exclusions disabled | Security | 2026-02-16 | Closed / Implemented |
| 9 | Medium | 36 | Rust advisory suppression for unmaintained crate (`confidence::confirmed`) | Supply chain | CWE-1104 / OWASP A06:2021 | `clients/rust/Cargo.toml:20`, `.gitlab-ci.yml:378` | https://gitlab.com/devnw/zig/quic/-/issues/58 | Removed `rustls-pemfile` and dropped `cargo audit --ignore RUSTSEC-2025-0134` from CI | Rust owners | 2026-02-16 | Closed / Implemented |
| 10 | Medium | 36 | SBOM scan is gating in CI (`confidence::confirmed`) | CI/CD | OWASP A08:2021 | `.gitlab-ci.yml:45` | https://gitlab.com/devnw/zig/quic/-/issues/61 | Keep `allow_failure: false` for SBOM scan | CI | 2026-02-16 | Closed / Implemented |
| 11 | Low | 24 | Interop Docker hardening baseline implemented (`confidence::confirmed`) | Containers | CWE-250 | `interop/Dockerfile:15`, `interop/Dockerfile:31`, `examples/interop/zig-qns/Dockerfile:12`, `interop/run_endpoint.sh:65` | https://gitlab.com/devnw/zig/quic/-/issues/60 | Maintain non-root execution path and health checks | Interop | 2026-02-16 | Closed / Implemented |

## Findings By Area

### Application
- #51: Closed / Implemented.
- #56: Closed / Implemented.

### CI/CD
- #53: Closed / Implemented.
- #54: Closed / Won't do (external controls).
- #55: Closed / Won't do.
- #57: Closed / Implemented.
- #61: Closed / Implemented.

### Supply Chain
- #36: Closed / Won't do (external governance controls).
- #58: Closed / Implemented.
- #59: Closed / Implemented.

### Containers
- #60: Closed / Implemented.

## Delivery Plan Status

### Quick Wins (<=30 days)
- Completed: #51, #53, #56, #57, #58, #59, #60, #61.

### Medium (<=90 days)
- None.

### Strategic
- Accepted risk (external controls): #36, #54, #55.

## Blocked Items

- None.

## Future-Agent Notes

1. CI/CD hash/toolchain pinning and Docker tag digest pinning are intentionally tracked as **won't do** in this repo (`#54`, `#55`) because control is managed outside the repository.
2. Historical secret-remediation item `#36` is intentionally tracked as **won't do** in this repo because lifecycle controls are handled via external governance process.
3. Pre-commit hook pinning/enforcement is also handled via external controls; do not re-open as a repo-local gap unless governance ownership changes.

## Geode Bootstrap Backport Traceability (Non-Security)

Source usage reviewed in `~/src/devnw/codepros/geode/geode`. The items below track bootstrap behaviors geode carried in `src/transport/quic.zig` and related call sites that now exist in this library.

| # | Backported gap | Geode evidence (file:line) | Library implementation (file:line) | Status |
|---|----------------|----------------------------|------------------------------------|--------|
| 1 | Endpoint poll vs concurrent I/O synchronization (`PollSync`) | `src/transport/quic.zig:39`, `src/transport/quic.zig:51`, `src/server/quic_connection_handler.zig:375` | `src/quic/transport.zig:45`, `src/quic/transport.zig:482`, `src/quic/transport.zig:534`, `src/quic/transport.zig:668` | Closed / Implemented |
| 2 | Deferred connection destruction path for safe async cleanup (`destroyConnection` + `drainPendingDestroy`) | `src/transport/quic.zig:170`, `src/transport/quic.zig:411`, `src/server/main.zig:523`, `src/server/quic_connection_handler.zig:371` | `src/quic/transport.zig:365`, `src/quic/transport.zig:450`, `src/quic/transport.zig:135` | Closed / Implemented |
| 3 | Non-blocking accept surface (`tryAccept`) and `WouldBlock` accept semantics | `src/transport/quic.zig:370`, `src/transport/quic.zig:375`, `src/security/kms_remote.zig:184` | `src/quic/transport.zig:431`, `src/quic/transport.zig:437` | Closed / Implemented |
| 4 | Accept-loop stream-readiness gating before returning connection | `src/transport/quic.zig:334`, `src/server/quic_connection_handler.zig:387` | `src/quic/transport.zig:422` | Closed / Implemented |
| 5 | Connection helper APIs needed by server/mTLS flows (`inner`, `hasIncomingStreams`, `isDrained`, `isHandshakeConfirmed`, `getPeerCertificateDer`, `destroyStream`) | `src/server/quic_connection_handler.zig:387`, `src/server/quic_connection_handler.zig:497`, `src/transport/quic.zig:537`, `src/transport/quic.zig:548`, `src/transport/quic.zig:559` | `src/quic/transport.zig:494`, `src/quic/transport.zig:594`, `src/quic/transport.zig:599`, `src/quic/transport.zig:604`, `src/quic/transport.zig:609`, `src/quic/transport.zig:617` | Closed / Implemented |
| 6 | Stream I/O semantics parity (`write` returns `usize`, partial-write handling, `WouldBlock` propagation, retrying line reads, `finish`) | `src/transport/quic.zig:597`, `src/transport/quic.zig:614`, `src/transport/quic.zig:623`, `src/transport/quic.zig:634`, `src/transport/quic.zig:683`, `tests/test_quic_regression.zig:53`, `tests/test_quic_regression.zig:87` | `src/quic/transport.zig:667`, `src/quic/transport.zig:681`, `src/quic/transport.zig:691`, `src/quic/transport.zig:716`, `src/quic/transport.zig:751` | Closed / Implemented |
| 7 | Client API parity (`waitForHandshake(timeout_secs)`, `openStream(bidirectional)`, explicit `poll`) | `src/transport/quic.zig:818`, `src/transport/quic.zig:838`, `src/transport/quic.zig:857`, `src/dist/rpc.zig:431`, `src/dist/rpc.zig:434`, `src/distributed/twophase.zig:184`, `src/distributed/twophase.zig:213` | `src/quic/transport.zig:916`, `src/quic/transport.zig:931`, `src/quic/transport.zig:951` | Closed / Implemented |
| 8 | Client stream behavior parity (`WouldBlock` + poll and `readLineWithInterrupt`) | `src/transport/quic.zig:883`, `src/transport/quic.zig:917`, `src/transport/quic.zig:935` | `src/quic/transport.zig:986`, `src/quic/transport.zig:1006`, `src/quic/transport.zig:1024` | Closed / Implemented |
| 9 | Localhost normalization and insecure-SNI compatibility behavior | `src/transport/quic.zig:724`, `src/transport/quic.zig:767`, `src/transport/quic.zig:774` | `src/quic/transport.zig:810`, `src/quic/transport.zig:849`, `src/quic/transport.zig:860` | Closed / Implemented |
| 10 | Client idle-timeout parity for longer-running streams (300s) | `src/transport/quic.zig:746`, `src/transport/quic.zig:794` | `src/quic/transport.zig:832`, `src/quic/transport.zig:891` | Closed / Implemented |
| 11 | Self-signed certificate generation alignment (ECDSA P-256) | `src/transport/quic.zig:459`, `src/transport/quic.zig:470` | `src/quic/transport.zig:321`, `src/quic/transport.zig:331` | Closed / Implemented |
