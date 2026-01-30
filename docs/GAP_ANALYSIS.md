# GAP Analysis

**Project:** QUIC Protocol Implementation (Zig)
**Repository:** gitlab.com/devnw/zig/quic
**Last Updated:** 2026-01-30
**Review Commit:** edb8461 (main branch)
**Status:** **ALL GAPS CLOSED**

## Summary

| Severity | Found | Closed | Open |
|----------|-------|--------|------|
| Critical | 1 | 1 | 0 |
| High | 8 | 8 | 0 |
| Medium | 9 | 9 | 0 |
| Low | 2 | 2 | 0 |
| Info | 1 | 1 | 0 |
| **Total** | **21** | **21** | **0** |

### Open Issues (as of 2026-01-30)

None - all tracked gaps are closed.

### Top 5 Risks (Resolved)

1. **Private Keys Committed to Repository** (#36) - High (Risk 64) - **Resolved**
2. **QuicClient.connect Defaults to Insecure TLS** (#51) - High (Risk 64) - **Resolved**
3. **TLS Hostname/SNI Validation Missing** (#50) - High (Risk 48) - **Resolved**
4. **QuicTransport Fails Open to Insecure / Test Cert Defaults** (#52) - High (Risk 48) - **Resolved**
5. **GitLab Secret Detection Allowlist Bypass** (#53) - High (Risk 48) - **Resolved**

---

## Stack-Ranked Findings

| Rank | Severity | Risk Score | Finding | Component | CWE/OWASP | Evidence | GitLab Issue | Fix Summary | Status |
|------|----------|------------|---------|-----------|-----------|----------|--------------|-------------|--------|
| 1 | Critical | 80 | Overly Permissive Gitleaks Configuration | CI/CD | CWE-798, CWE-200 | `.gitleaks.toml:9-28` | [#35](https://gitlab.com/devnw/zig/quic/-/issues/35) | Removed blanket allowlists, use specific test paths only | **Closed** |
| 2 | High | 64 | Private Keys Committed to Repository | Supply Chain | CWE-321, CWE-798 | `create_test_certs.sh:8-23`, `tests/integration/tls_helpers.zig:69` | [#36](https://gitlab.com/devnw/zig/quic/-/issues/36) | Removed committed keys; generate certs on demand and document local generation | **Closed** |
| 3 | High | 64 | QuicClient.connect Defaults to Insecure TLS | Application | CWE-295 | `src/quic/transport.zig:538-583` | [#51](https://gitlab.com/devnw/zig/quic/-/issues/51) | Require CA file; `allow_insecure=false`; docs/examples updated | **Closed** |
| 4 | High | 56 | Connection Limit Not Enforced | Application | CWE-400 | `endpoint.zig`, `transport.zig:50` | [#44](https://gitlab.com/devnw/zig/quic/-/issues/44) | Added `max_connections` check in `processInitial()` | **Closed** |
| 5 | High | 49 | Stream Map Memory Exhaustion | Application | CWE-400 | `conn.zig:636-665` | [#45](https://gitlab.com/devnw/zig/quic/-/issues/45) | Added `validatePeerStreamLimit()` in `pushStreamFrame()` | **Closed** |
| 6 | High | 48 | Outdated Go Dependencies | Supply Chain | CWE-1395 | `test-clients/quic-go-client/go.mod` | [#37](https://gitlab.com/devnw/zig/quic/-/issues/37) | Updated x/crypto to v0.47.0, quic-go to v0.59.0 | **Closed** |
| 7 | High | 48 | TLS Hostname/SNI Validation Missing | Application | CWE-297 | `src/quic/conn.zig:1064-1074`, `tests/test_connection_server_name.zig:1-23` | [#50](https://gitlab.com/devnw/zig/quic/-/issues/50) | Set TLS context server_name; added unit test | **Closed** |
| 8 | High | 48 | QuicTransport Fails Open to Insecure / Test Cert Defaults | Application | CWE-295 | `src/quic/transport.zig:117-215`, `docs/TRANSPORT_LAYER.md:232-260` | [#52](https://gitlab.com/devnw/zig/quic/-/issues/52) | Require explicit cert/key; optional auto-generate; no insecure fallback | **Closed** |
| 9 | High | 48 | GitLab Secret Detection Allowlist Bypass | CI/CD | CWE-200 | `.gitlab-secret-detection.yml:14-18` | [#53](https://gitlab.com/devnw/zig/quic/-/issues/53) | Narrowed exclusions to test-only directories | **Closed** |
| 10 | Medium | 40 | Install Script Executes Remote Code | Supply Chain | CWE-829, CWE-494 | `scripts/install_pkgs.sh:120` | [#40](https://gitlab.com/devnw/zig/quic/-/issues/40) | Added installer verification (shebang + nix-store markers) | **Closed** |
| 11 | Medium | 36 | Debug Tools Default to Insecure Mode | Application | CWE-295 | `cmd/quic-debug-client.zig:13` | [#38](https://gitlab.com/devnw/zig/quic/-/issues/38) | All debug tools now default to secure mode | **Closed** |
| 12 | Medium | 36 | Idle Timeout Clock Skew Vulnerability | Application | CWE-191 | `connection/idle.zig:85-88` | [#47](https://gitlab.com/devnw/zig/quic/-/issues/47) | Added clock skew detection and fallback timeout | **Closed** |
| 13 | Medium | 36 | Padding Frame Lacks Bounds Check | Application | CWE-770 | `frame/misc.zig:15-25` | [#48](https://gitlab.com/devnw/zig/quic/-/issues/48) | Added `MAX_PACKET_SIZE` constant and `writePaddingBounded()` | **Closed** |
| 14 | Medium | 36 | CI Downloads External Tools Without Integrity Verification | CI/CD | CWE-494 | `.gitlab-ci.yml:248-273` | [#54](https://gitlab.com/devnw/zig/quic/-/issues/54) | Added SHA256 verification and pinned interop-runner commit | **Closed** |
| 15 | Medium | 36 | Floating Container Tags (latest) | Supply Chain | CWE-829 | `.gitlab-ci.yml:283-319`, `interop/Dockerfile:5-8`, `examples/interop/zig-qns/Dockerfile:1` | [#55](https://gitlab.com/devnw/zig/quic/-/issues/55) | Pinned interop images to digests (CI/compose/Dockerfiles) | **Closed** |
| 16 | Medium | 35 | Thread Safety - Stream Maps Unprotected | Application | CWE-366 | `conn.zig:636-640`, `endpoint.zig:57-58` | [#49](https://gitlab.com/devnw/zig/quic/-/issues/49) | Added mutex lock to `pushStreamFrame()`, documented threading model | **Closed** |
| 17 | Medium | 32 | Unsafe eval Usage in Shell Scripts | CI/CD | CWE-78 | `test-clients/run-tests.sh:46` | [#39](https://gitlab.com/devnw/zig/quic/-/issues/39) | Replaced eval with direct command execution | **Closed** |
| 18 | Medium | 30 | DCID Length Casting Without Validation | Application | CWE-195 | `packet.zig:70,491,750,897` | [#46](https://gitlab.com/devnw/zig/quic/-/issues/46) | Added `validateCidLength()` and `MAX_CID_LENGTH` constant | **Closed** |
| 19 | Low | 16 | No OCSP/CRL Support | Crypto | CWE-299 | `docs/IMPLEMENTATION_STATUS.md` | [#41](https://gitlab.com/devnw/zig/quic/-/issues/41) | Documented in SECURITY.md Known Limitations section | **Closed** |
| 20 | Low | 12 | Token Secret Not Required | Application | CWE-330 | `src/quic/config.zig:31` | [#42](https://gitlab.com/devnw/zig/quic/-/issues/42) | Auto-generate cryptographic secret at endpoint init | **Closed** |
| 21 | Info | 8 | Environment Variable Exposure | Infrastructure | CWE-526 | `flake.nix:113` | [#43](https://gitlab.com/devnw/zig/quic/-/issues/43) | Added security_notice() warnings for sensitive tokens | **Closed** |

---

## Findings by Area

### Application Security - CLOSED

#### TLS Hostname/SNI Validation Missing (#50) - **CLOSED**
- **Severity:** High | **Risk Score:** 48
- **Files:** `src/quic/conn.zig`, `tests/test_connection_server_name.zig`
- **Issue:** `setServerName()` is a no-op and TLS Context lacks hostname verification, allowing certs for other hosts.
- **Resolution:**
  - `setServerName()` now sets `tls_ctx.config.server_name` to enable SNI + hostname validation
  - Added unit test `tests/test_connection_server_name.zig`

#### QuicClient.connect Defaults to Insecure TLS (#51) - **CLOSED**
- **Severity:** High | **Risk Score:** 64
- **Files:** `src/quic/transport.zig`, `docs/TRANSPORT_LAYER.md`, `README.md`
- **Issue:** Missing `certs/ca.crt` causes `allow_insecure = true` by default.
- **Resolution:**
  - `QuicClient.connect()` now requires a CA file and sets `allow_insecure = false`
  - Updated docs/examples to use `connectEx()` with explicit CA or explicit `--insecure`

#### QuicTransport Fails Open to Insecure / Test Cert Defaults (#52) - **CLOSED**
- **Severity:** High | **Risk Score:** 48
- **Files:** `src/quic/transport.zig`, `docs/TRANSPORT_LAYER.md`
- **Issue:** Defaults point to test certs and TLS failures fall back to insecure mode.
- **Resolution:**
  - Removed test-cert defaults and require explicit `cert_path`/`key_path`
  - Added opt-in `auto_generate_certs` and eliminated insecure fallback

#### Connection Limit Not Enforced (#44) - **CLOSED**
- **Severity:** High | **Risk Score:** 56
- **Files:** `src/quic/config.zig`, `src/quic/endpoint.zig`, `src/quic/endpoint/incoming.zig`
- **Issue:** The `max_connections` config option existed but was never enforced.
- **Resolution:**
  - Added `max_connections: usize = 10000` to `QuicConfig` struct
  - Added `max_connections` field to `RxContext`
  - Added check in `processInitial()` before creating new connections:
    ```zig
    if (ctx.max_connections > 0 and ctx.conns.count() >= ctx.max_connections) {
        return; // Drop packet - do not create connection
    }
    ```

#### Stream Map Memory Exhaustion (#45) - **CLOSED**
- **Severity:** High | **Risk Score:** 49
- **Files:** `src/quic/conn.zig`
- **Issue:** Streams stored without enforcing `peer_max_streams_bidi`/`peer_max_streams_uni` limits.
- **Resolution:**
  - Added `validatePeerStreamLimit()` function that checks peer-initiated streams against `local_max_streams_bidi`/`local_max_streams_uni`
  - Called in `pushStreamFrame()` before `ensureStreamRx()`
  - Returns `error.StreamLimitExceeded` if peer violates limits

#### DCID Length Casting (#46) - **CLOSED**
- **Severity:** Medium | **Risk Score:** 30
- **Files:** `src/quic/packet.zig`
- **Issue:** DCID length cast from `usize` to `u8` without RFC 9000 §5.1 validation.
- **Resolution:**
  - Added `MAX_CID_LENGTH: usize = 20` constant
  - Added `validateCidLength()` function that returns `error.InvalidCidLength` if length > 20
  - Updated all 6 locations casting DCID/SCID length to use `validateCidLength()`

#### Idle Timeout Clock Skew (#47) - **CLOSED**
- **Severity:** Medium | **Risk Score:** 36
- **Files:** `src/quic/connection/idle.zig`
- **Issue:** Clock going backward prevented idle timeout expiry.
- **Resolution:**
  - Added `MAX_CLOCK_SKEW_NS` constant (5 seconds)
  - Added `clock_skew_count` field to `IdleTimer`
  - Modified `isExpired()` to detect significant backward clock skew
  - After 3 clock skew events, force timeout to prevent keepalive attacks
  - Reset counter on legitimate activity

#### Padding Frame Lacks Bounds Check (#48) - **CLOSED**
- **Severity:** Medium | **Risk Score:** 36
- **Files:** `src/quic/frame/misc.zig`
- **Issue:** PADDING frame encoder allowed arbitrary padding without max packet size check.
- **Resolution:**
  - Added `MIN_INITIAL_PACKET_SIZE`, `MAX_SAFE_PACKET_SIZE`, `MAX_PACKET_SIZE` constants
  - Added sanity check to `writePadding()` rejecting counts > 65535
  - Added `writePaddingBounded()` for callers who want explicit bounds checking

#### Thread Safety - Stream Maps (#49) - **CLOSED**
- **Severity:** Medium | **Risk Score:** 35
- **Files:** `src/quic/conn.zig`, `src/quic/endpoint.zig`
- **Issue:** Stream maps lacked mutex protection in `pushStreamFrame()`.
- **Resolution:**
  - Added mutex lock to `pushStreamFrame()`:
    ```zig
    self.mu.lock();
    defer self.mu.unlock();
    ```
  - Updated module documentation with comprehensive threading model description
  - Documented lock ordering (endpoint -> connection) to prevent deadlocks

#### Debug Tools Default to Insecure Mode (#38) - **CLOSED**
- **Severity:** Medium | **Risk Score:** 36
- **Files:** `cmd/quic-debug-client.zig`, `cmd/quic-debug-dgram-client.zig`, `cmd/quic-client-comprehensive.zig`, `cmd/qns-endpoint.zig`
- **Resolution:** All debug tools now default to `insecure = false`. Users must explicitly pass `--insecure` flag.

#### Token Secret Not Required (#42) - **CLOSED**
- **Severity:** Low | **Risk Score:** 12
- **Files:** `src/quic/config.zig`, `src/quic/endpoint.zig`, `src/quic/endpoint/incoming.zig`
- **Resolution:** Added `generated_token_secret: [32]u8` field populated with `std.crypto.random.bytes` at endpoint init.

### CI/CD Security - CLOSED

#### GitLab Secret Detection Allowlist Bypass (#53) - **CLOSED**
- **Severity:** High | **Risk Score:** 48
- **Files:** `.gitlab-secret-detection.yml`
- **Issue:** Blanket exclusions for `*.key`, `*.pem`, `*.crt`, `*.der` disable scanning for real secrets.
- **Resolution:** Removed wildcard exclusions and limited allowlist to test cert directories only.

#### CI Downloads External Tools Without Integrity Verification (#54) - **CLOSED**
- **Severity:** Medium | **Risk Score:** 36
- **Files:** `.gitlab-ci.yml`
- **Issue:** docker-compose binary download and interop-runner clone are not checksum/commit pinned.
- **Resolution:** Added SHA256 verification for docker-compose and pinned quic-interop-runner commit.

#### Gitleaks Configuration Bypass (#35) - **CLOSED**
- **Severity:** Critical | **Risk Score:** 80
- **Resolution:** Rewrote configuration to use only specific path allowlists.

#### Unsafe Shell Patterns (#39) - **CLOSED**
- **Severity:** Medium | **Risk Score:** 32
- **Resolution:** Replaced `eval` with direct command execution in `run-tests.sh`.

### Supply Chain Security - CLOSED

#### Committed Private Keys (#36) - **CLOSED**
- **Severity:** High | **Risk Score:** 64
- **Files:** `certs/`, `data/`, `clients/python/examples/interop/certs/`, `examples/interop/certs/`
- **Issue:** Private keys remain tracked in repo; requires removal/rotation.
- **Resolution:**
  - Removed committed key material and updated docs to clarify local generation
  - Added/extended `create_test_certs.sh` + test harness generation for local/dev usage
  - If any removed keys were reused outside tests, rotate them immediately

#### Floating Container Tags (latest) (#55) - **CLOSED**
- **Severity:** Medium | **Risk Score:** 36
- **Files:** `.gitlab-ci.yml`, `interop/Dockerfile`, `examples/interop/zig-qns/Dockerfile`, `examples/interop/docker-compose.*.yml`
- **Issue:** Mutable tags in CI and Dockerfiles allow unexpected upstream changes.
- **Resolution:** Pinned interop images to immutable digests across CI, Dockerfiles, and compose files.

#### Outdated Dependencies (#37) - **CLOSED**
- **Severity:** High | **Risk Score:** 48
- **Resolution:** Updated Go dependencies to latest versions.

#### Remote Code Execution in Install Script (#40) - **CLOSED**
- **Severity:** Medium | **Risk Score:** 40
- **Resolution:** Added installer verification with shebang and nix-store markers check.

### Cryptographic Security - ALL CLOSED

#### No OCSP/CRL Support (#41) - **CLOSED**
- **Severity:** Low | **Risk Score:** 16
- **Resolution:** Documented as known limitation in `SECURITY.md` with mitigation recommendations.

### Infrastructure Security - ALL CLOSED

#### Environment Variable Exposure (#43) - **CLOSED**
- **Severity:** Info | **Risk Score:** 8
- **Resolution:** Added `security_notice()` warnings for sensitive token exports.

---

## Quick wins / Medium / Strategic

### Quick wins
- All quick wins completed (#53, #54, #55).

### Medium
- All medium items completed (#50, #51, #52).

### Strategic
No remaining strategic gaps.

---

## Implementation Summary

### Code Changes Made

1. **Removed committed key material and added local generation**: Deleted tracked cert/key files; expanded `create_test_certs.sh` and test helpers; updated `SECURITY.md` and cert README files.
2. **SNI/hostname validation wiring**: `Connection.setServerName()` now sets `tls_ctx.config.server_name` and added `tests/test_connection_server_name.zig`.
3. **Secure client defaults**: `QuicClient.connect()` now requires a CA file and keeps `allow_insecure = false`; docs/examples updated to use `connectEx()` or explicit insecure mode.
4. **Secure server defaults**: `QuicTransport` now requires explicit cert/key, adds `auto_generate_certs` opt-in, and removes fail-open fallback; docs/examples updated.
5. **CI/CD supply-chain hardening**: Verified docker-compose SHA256, pinned quic-interop-runner commit, pinned interop images to digests, and narrowed secret detection allowlist.

### Tests Executed

```bash
zig build test
# Result: pass
```

### Security Notes

- TLS hostname validation now wired through SNI in the QUIC connection layer
- Server/client defaults fail closed unless explicit insecure options are chosen
- CI downloads and container images are pinned/verified to reduce supply-chain drift

---

## Methodology

### Scope
- Application code (Zig)
- Test clients (Go, Python, Rust)
- CI/CD configuration (GitLab CI)
- Build system (Nix, Makefile)
- Scripts and tooling

### Tools Used
- Manual code review
- Pattern-based grep searches
- Dependency manifest analysis
- CI configuration review
- Automated exploration agent

### Review Areas
- Resource exhaustion (CWE-400)
- Integer handling (CWE-191, CWE-195)
- Race conditions (CWE-366)
- Memory allocation limits (CWE-770)
- RFC 9000/9001/9002 compliance

---

## References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [RFC 9000 - QUIC Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 - QUIC TLS](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9002 - QUIC Loss Detection](https://www.rfc-editor.org/rfc/rfc9002)

---

*This document was updated on 2026-01-30 to reflect closed gaps and remediation work.*
