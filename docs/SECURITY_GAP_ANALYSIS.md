# Security Gap Analysis -- QUIC Implementation

| Field | Value |
|-------|-------|
| **Repository** | `gitlab.com/devnw/zig/quic` |
| **Scope** | Phase 3 security review of core QUIC transport, TLS integration, frame parsing, and CI/CD |
| **Reviewer** | security-reviewer agent (Phase 3) |
| **Last updated** | 2026-06-11 |
| **Status** | Phase 3 findings (1--14) all Closed / Implemented or closed as repo-level Won't Do boundaries; 2026-06-11 AppSec Audit Round (QC-series) appended -- 10 Fixed, 2 Partial, 5 Open |

---

## Summary

| Severity | Open | Partially Fixed | Closed / Implemented | Total |
|----------|------|-----------------|----------------------|-------|
| Critical | 0 | 0 | 0 | 0 |
| High | 0 | 0 | 4 | 4 |
| Medium | 0 | 0 | 7 | 7 |
| Low | 0 | 0 | 3 | 3 |
| **Total** | **0** | **0** | **14** | **14** |

The summary table above covers the original Phase 3 findings (1--14). The 2026-06-11 AppSec Audit Round (QC-series) adds a fresh batch of findings; its counts are tracked separately below and detailed in the appended `## 2026-06-11 AppSec Audit Round (QC-series)` section.

### 2026-06-11 AppSec Audit Round (QC-series) Summary

| Severity | Open | Partial | Fixed | Total |
|----------|------|---------|-------|-------|
| Critical | 0 | 0 | 1 | 1 |
| High | 0 | 1 | 2 | 3 |
| Medium | 2 | 1 | 4 | 7 |
| Low | 3 | 0 | 3 | 6 |
| **Total** | **5** | **2** | **10** | **17** |

Notes: #111 (High, frame alloc caps) is closed; `frame.decode()` now applies frame allocation caps and rejects oversized frame payloads. #114 (High, allow_insecure) closed -- audit confirmed flag only controls TLS certificate validation; Retry integrity, CID matching, and amplification protection are unconditionally enforced. #118 (High, mTLS wiring) closed in commit bf8cf7f. Phase 4 closure (2026-03-25): SF-015 anti-replay wired, SF-016 catch unreachable replaced, SF-017 Go binary removed, SF-018 secureZero, SF-019 unknown frames, SF-020 amplification consolidation, SF-021 ct_empty data race, SF-022 CID validation, GAP-0018 timing-safe Retry tag. 2026-04-25 closure: thread-local debug counters confirmed, Retry tag temporary ciphertext buffer is function-local, static interop Docker cert copies removed in favor of runtime-generated ephemeral fallback certs, and CI/Docker/pre-commit governance boundaries documented as repo-level Won't Do.

### Top Residual Risks

No open residual risks remain in this tracking file. Security gaps still open in the repository-wide `docs/GAP_ANALYSIS.md` remain tracked separately by their GitLab issues.

---

## Stack-Ranked Findings

| Rank | Severity | Risk Score | Finding | Component | CWE / OWASP | Evidence (file:line) | Issue | Fix | Owner | Due | Status |
|------|----------|------------|---------|-----------|-------------|----------------------|-------|-----|-------|-----|--------|
| 1 | High | 80 | Unbounded heap alloc from wire varint -- OOM DoS | frame parser | CWE-770 / A06:2021 | `frame/frame.zig:367,380,422,435,487,529` | [#111](https://gitlab.com/devnw/zig/quic/-/issues/111) CONFIDENTIAL | Allocation caps added to frame/frame.zig; GitLab issue closed after verification | TBD | 2026-04-23 | Closed / Implemented |
| 2 | High | 64 | `allow_insecure` bypasses Retry integrity + CID match -- connection hijack | endpoint | CWE-287 / A07:2021 | `endpoint.zig:1007-1020` | [#114](https://gitlab.com/devnw/zig/quic/-/issues/114) CONFIDENTIAL | Batch B removed `allow_insecure` from Retry/CID paths; flag now controls TLS cert validation only. Full audit confirmed scope (2026-03-24). Doc comments added to all 4 declaration sites. | Core QUIC | 2026-03-24 | Closed / Implemented |
| 3 | High | 60 | Env var disables amplification limit -- DDoS reflector | conn | CWE-1188 / A05:2021 | `conn.zig:1534` | [#116](https://gitlab.com/devnw/zig/quic/-/issues/116) CONFIDENTIAL | Env var removed entirely; config field used instead (Batch A, commit 7034861) | Core QUIC | 2026-03-24 | Closed / Implemented |
| 4 | High | 48 | mTLS `request_client_cert` silently ignored | handshake | CWE-295 / A07:2021 | `handshake_integration.zig:334-336` | [#118](https://gitlab.com/devnw/zig/quic/-/issues/118) | Removed `_ = ...` discards; wired `request_client_cert`, `client_cert_der`, `client_key_der` into `tls13.Config` struct literal (commit bf8cf7f) | Core QUIC | 2026-03-24 | Closed / Implemented |
| 5 | Medium | 48 | `unreachable` on CID > 20 bytes -- server crash | connection | CWE-617 / A06:2021 | `reset_token.zig:10`, `connection_id.zig:38`, `methods_c.zig:619` | [#119](https://gitlab.com/devnw/zig/quic/-/issues/119) | Replaced `unreachable` with `error.InvalidCidLength` (Batch A, commit 7034861) | Core QUIC | 2026-03-24 | Closed / Implemented |
| 6 | Medium | 48 | Retry integrity tag function signature mismatch -- broken retry | server | CWE-628 / A06:2021 | `server.zig:196` | [#120](https://gitlab.com/devnw/zig/quic/-/issues/120) | Fixed to 3-arg call (Batch A, commit 7034861) | Core QUIC | 2026-03-24 | Closed / Implemented |
| 7 | Medium | 36 | No 0-RTT anti-replay detection | connection | CWE-294 / A08:2021 | `methods_a.zig:971-973` | [#121](https://gitlab.com/devnw/zig/quic/-/issues/121) | AntiReplayCache wired from Endpoint.init() to connections via RxContext. accept0RTT() rejects replay when cache present. 5 endpoint-level tests. | Core QUIC | 2026-03-25 | Closed / Implemented |
| 8 | Medium | 36 | Key material not zeroed on connection teardown | conn | CWE-244 / A02:2021 | `conn.zig:1227-1283` | [#122](https://gitlab.com/devnw/zig/quic/-/issues/122) | Added `@memset` before free (Batch B, commit f470ea5) | Core QUIC | 2026-03-24 | Closed / Implemented |
| 9 | Medium | 32 | ACK range count silently truncated to 16 -- CPU exhaustion | frame/ack | CWE-130 / A06:2021 | `frame/ack.zig:137-144` | [#123](https://gitlab.com/devnw/zig/quic/-/issues/123) | Buffer increased from 16 to 64 ranges; hard ceiling at 256; returns error.TooManyAckRanges instead of silent truncation | TBD | 2026-06-22 | Closed / Implemented |
| 10 | Medium | 32 | Localhost exemption from amplification protection | conn / incoming | CWE-290 / A05:2021 | `conn.zig:1542`, `incoming.zig:544-558` | [#124](https://gitlab.com/devnw/zig/quic/-/issues/124) | Added `exempt_localhost` config flag (default true); `overAmplification()` and `processInitial()` now check the flag | Core QUIC | 2026-03-24 | Closed / Implemented |
| 11 | Medium | 24 | Retry not enabled by default | config | CWE-1188 / A05:2021 | `config.zig:30` | [#125](https://gitlab.com/devnw/zig/quic/-/issues/125) | Defaulted `enable_retry` to `true` (Batch A, commit 7034861) | Core QUIC | 2026-03-24 | Closed / Implemented |
| 12 | Low | 16 | Global mutable state in crypto/debug code | packet / crypto | CWE-362 / A04:2021 | `packet.zig:14-18`, `crypto_quic.zig:179` | [#194](https://gitlab.com/devnw/zig/quic/-/issues/194) | `phase57_*` debug state is `threadlocal` and test-only; Retry tag temporary ciphertext buffer is function-local | Core QUIC | 2026-04-25 | Closed / Implemented |
| 13 | Low | 12 | Test certificates baked into Docker image | interop | CWE-798 / A07:2021 | `interop/Dockerfile:25-26` | [#193](https://gitlab.com/devnw/zig/quic/-/issues/193) | Removed static cert/key COPY; `run_endpoint.sh` generates ephemeral fallback TLS material at startup | Interop | 2026-04-25 | Closed / Implemented |
| 14 | Low | 8 | macOS/Windows CI downloads without hash verification | CI | CWE-494 / A08:2021 | `.gitlab-ci.yml:618-659` | [#102](https://gitlab.com/devnw/zig/quic/-/issues/102) | Platform-specific Zig download SHA-256 verification added; generic CI/toolchain hash pinning remains [#54](https://gitlab.com/devnw/zig/quic/-/issues/54) repo-level won't-do under external controls | CI | N/A | Closed / Implemented + Won't Do boundary documented |

---

## Detailed Findings

### 1. HIGH -- Unbounded Heap Allocation from Wire Varint (OOM DoS)

- **ID**: 2.1
- **Risk Score**: 80 (Impact 4 x Likelihood 5 x 4)
- **CWE**: [CWE-770](https://cwe.mitre.org/data/definitions/770.html) -- Allocation of Resources Without Limits or Throttling
- **OWASP**: A06:2021 Vulnerable and Outdated Components (resource management)
- **Exploit surface**: Internet-facing, pre-auth, trivially exploitable
- **Confidence**: `confirmed`

**Summary**: The reader-based `frame.decode()` path in `frame/frame.zig` uses `alloc.alloc(u8, @intCast(len))` where `len` comes directly from a wire varint. A varint can encode values up to 2^62, allowing a single crafted QUIC packet to request a multi-gigabyte heap allocation.

**Evidence** (file paths and lines):

- `src/quic/frame/frame.zig:367` -- CRYPTO frame: `const data = try alloc.alloc(u8, @intCast(len));`
- `src/quic/frame/frame.zig:380` -- ACK ranges: `const ranges = try alloc.alloc(AckRange, @intCast(range_count));`
- `src/quic/frame/frame.zig:422,435` -- STREAM frame data allocation
- `src/quic/frame/frame.zig:487,529` -- NEW_CONNECTION_ID, DATAGRAM frame allocations

**Attack scenario**: An unauthenticated remote attacker sends a single UDP datagram containing a CRYPTO frame with a length varint set to 0x3FFFFFFFFFFFFFFF (2^62 - 1). The server's frame parser calls `alloc.alloc(u8, ...)` with this value, triggering OOM and process termination.

**Fix guidance**: Cap all wire-derived allocation sizes to `max_datagram_size` (or a protocol-appropriate upper bound). Validate `len <= remaining_packet_bytes` before allocation.

**How to verify**: Send a crafted QUIC Initial packet with a CRYPTO frame whose length varint exceeds 1500. Confirm the server rejects it without allocating.

---

### 2. HIGH -- `allow_insecure` Bypasses Retry Integrity and CID Matching

- **ID**: 1.1
- **Risk Score**: 64 (Impact 4 x Likelihood 4 x 4)
- **CWE**: [CWE-287](https://cwe.mitre.org/data/definitions/287.html) -- Improper Authentication
- **OWASP**: A07:2021 Identification and Authentication Failures
- **Exploit surface**: Internet-facing when `allow_insecure` is active
- **Confidence**: `confirmed`

**Summary**: When `allow_insecure` is true, `endpoint.zig:1007-1020` skips CID matching for Retry packets and returns the first client connection found. Lines 1020-1023 also skip Retry integrity tag verification. An attacker can forge a Retry packet that redirects a victim's connection to an attacker-controlled CID.

**Evidence**:

- `src/quic/endpoint.zig:1007-1015` -- Falls back to iterating all connections and returning the first client
- `src/quic/endpoint.zig:1020` -- Skips integrity verification when `allow_insecure` is set

**Attack scenario**: Attacker on the same network path sends a spoofed Retry packet with an attacker-chosen SCID. With `allow_insecure` active, the endpoint skips CID matching and integrity verification, accepting the forged Retry and redirecting the client to the attacker's connection ID.

**Fix guidance**: Remove the `allow_insecure` fallback in the Retry processing path entirely. Retry integrity MUST always be verified per RFC 9000 section 17.2.5. If `allow_insecure` is needed for development, restrict it to non-Retry code paths.

**How to verify**: With `allow_insecure=true`, send a Retry packet with an invalid integrity tag. Confirm it is rejected.

**Resolution (2026-03-24)**: Batch B removed `allow_insecure` from the Retry processing path and CID matching logic. Full audit of all 18 `allow_insecure` references in `src/quic/` confirmed the flag now only controls TLS certificate validation via `tls13.Config.allow_insecure`. The Retry integrity enforcement at `endpoint.zig:1011-1017` is unconditional (explicit security comment present). Doc comments added to all 4 declaration sites (`config.zig:46`, `transport.zig:122`, `server.zig:268`, `handshake_integration.zig:316`) stating scope limits. Status: **Closed / Implemented**.

---

### 3. HIGH -- Env Var Disables Amplification Protection (DDoS Reflector)

- **ID**: 4.1
- **Risk Score**: 60 (Impact 3 x Likelihood 5 x 4)
- **CWE**: [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) -- Initialization with an Insecure Default
- **OWASP**: A05:2021 Security Misconfiguration
- **Exploit surface**: Internet-facing (any co-tenant or supply-chain compromise that sets env var)
- **Confidence**: `confirmed`

**Summary**: `conn.zig:1534` reads `QUIC_DISABLE_AMPLIFICATION_LIMIT` from the process environment. If set to any non-"0" value (including empty string), `overAmplification()` always returns `false`, completely disabling RFC 9000 section 8.1 amplification protection. The server becomes a DDoS amplification reflector.

**Evidence**:

- `src/quic/conn.zig:1534-1536`:

  ```zig
  if (std.posix.getenv("QUIC_DISABLE_AMPLIFICATION_LIMIT")) |v| {
      if (v.len == 0 or !std.mem.eql(u8, v, "0")) return false;
  }
  ```

**Attack scenario**: (1) A co-tenant on the same host, a compromised CI pipeline, or a container escape sets `QUIC_DISABLE_AMPLIFICATION_LIMIT=1`. (2) Attacker spoofs victim's source IP and sends minimal Initial packets to the QUIC server. (3) Server responds with full Initial + Handshake flights (potentially 10-100x amplification) because the limit is disabled.

**Fix guidance**: Remove the environment variable check entirely. If a disable mechanism is needed for testing, use a compile-time flag (`@import("builtin").mode == .Debug`) or a config struct field that requires explicit code-level opt-in with audit logging.

**How to verify**: Set `QUIC_DISABLE_AMPLIFICATION_LIMIT=1`, send a minimal Initial packet, and measure the response size ratio. It should still be capped at 3x.

---

### 4. HIGH -- mTLS `request_client_cert` Silently Ignored

- **ID**: 1.2
- **Risk Score**: 48 (Impact 4 x Likelihood 3 x 4)
- **CWE**: [CWE-295](https://cwe.mitre.org/data/definitions/295.html) -- Improper Certificate Validation
- **OWASP**: A07:2021 Identification and Authentication Failures
- **Exploit surface**: Internet-facing (any server configured for mTLS)
- **Confidence**: `confirmed`

**Summary**: `handshake_integration.zig:334-336` discards the `request_client_cert`, `client_cert_der`, and `client_key_der` parameters with `_ = request_client_cert`. Operators who configure mTLS believe client certificates are required, but the server accepts all connections regardless of client certificate status.

**Evidence**:

```zig
_ = request_client_cert; // mTLS: deferred to TLS library support
_ = client_cert_der; // mTLS: deferred to TLS library support
_ = client_key_der; // mTLS: deferred to TLS library support
```

**Attack scenario**: An operator deploys a QUIC server with `request_client_cert = true` expecting mutual TLS. The parameter is silently discarded. An attacker connects without presenting a client certificate and gains full access to services that should require mTLS authentication.

**Fix guidance**: Either (a) wire the mTLS parameters through to the TLS context when TLS library support is available, or (b) return an explicit error or emit a warning log when `request_client_cert` is set but the feature is not yet implemented, so operators are not silently misled.

**How to verify**: Configure server with `request_client_cert = true`. Attempt connection without a client certificate. Connection should be rejected (or at minimum, a warning should be logged).

**Resolution (2026-03-24, commit bf8cf7f):** Removed three `_ = ...` discard lines and added `.request_client_cert`, `.client_cert_der`, `.client_key_der` fields to the `tls13.Config` struct literal in `handshake_integration.zig`. mTLS parameters are now wired through to the TLS context. **Status: Closed / Implemented.**

---

### 5. MEDIUM -- `unreachable` on CID > 20 Bytes (Server Crash)

- **ID**: 6.1
- **Risk Score**: 48 (Impact 3 x Likelihood 4 x 4)
- **CWE**: [CWE-617](https://cwe.mitre.org/data/definitions/617.html) -- Reachable Assertion
- **OWASP**: A06:2021 Vulnerable and Outdated Components
- **Exploit surface**: Internet-facing, pre-auth
- **Confidence**: `confirmed`

**Summary**: Three locations use `unreachable` when CID length exceeds 20 bytes. In safe builds, `unreachable` triggers a panic. A crafted NEW_CONNECTION_ID frame with `cid_len > 20` reaches this code and crashes the server process.

**Evidence**:

- `src/quic/connection/reset_token.zig:10`: `if (cid_len > 20) unreachable;`
- `src/quic/connection/connection_id.zig:38`: `if (cid_len > 20) unreachable;`
- `src/quic/connection/methods_c.zig:619`: `if (cid_len > 20) unreachable;`

**Fix guidance**: Replace `unreachable` with `return error.InvalidCidLength` and handle the error at the call site. Validate CID length during frame parsing before it reaches these functions.

**How to verify**: Send a NEW_CONNECTION_ID frame with a 21-byte CID. Confirm the server returns a PROTOCOL_VIOLATION error rather than crashing.

---

### 6. MEDIUM -- Retry Integrity Tag Function Signature Mismatch

- **ID**: 3.3
- **Risk Score**: 48 (Impact 3 x Likelihood 4 x 4)
- **CWE**: [CWE-628](https://cwe.mitre.org/data/definitions/628.html) -- Function Call with Incorrectly Specified Arguments
- **OWASP**: A06:2021 Vulnerable and Outdated Components
- **Exploit surface**: Server-side (retry path completely broken)
- **Confidence**: `confirmed`

**Summary**: `server.zig:196` calls `computeRetryIntegrityTag(config.version, pseudo_buf[0..p])` with 2 arguments, but the function at `crypto_quic.zig:182` requires 3 arguments: `(version_v2: bool, odcid: []const u8, retry_without_tag: []const u8)`. This is a compile-time error that breaks the entire Retry packet generation path.

**Evidence**:

- Call site: `src/quic/endpoint/server.zig:196`
- Function: `src/quic/crypto_quic.zig:182`

**Fix guidance**: Update the call to pass all three required arguments: `computeRetryIntegrityTag(config.version_v2, config.odcid, retry_without_tag_slice)`.

**How to verify**: Enable retry (`enable_retry = true`), connect a client. The server should successfully generate and send a Retry packet.

---

### 7. MEDIUM -- No 0-RTT Anti-Replay Detection

- **ID**: 3.2
- **Risk Score**: 36 (Impact 3 x Likelihood 3 x 4)
- **CWE**: [CWE-294](https://cwe.mitre.org/data/definitions/294.html) -- Authentication Bypass by Capture-replay
- **OWASP**: A08:2021 Software and Data Integrity Failures
- **Exploit surface**: Internet-facing (requires captured 0-RTT data)
- **Confidence**: `confirmed`

**Summary**: `accept0RTT()` at `methods_a.zig:971-973` simply sets `self.zero_rtt_accepted = true` without any replay detection. RFC 8446 section 8 and RFC 9001 section 9.2 require servers to implement anti-replay mechanisms for 0-RTT data.

**Evidence**:

```zig
pub fn accept0RTT(self: *Connection) void {
    self.zero_rtt_accepted = true;
}
```

**Fix guidance**: Implement at least one anti-replay mechanism: (a) single-use ticket cache, (b) client hello recording with bloom filter or strike register, or (c) time-window based freshness check with ticket age validation.

**How to verify**: Capture a 0-RTT handshake. Replay the captured Client Hello + 0-RTT data. The server should reject the replayed attempt.

---

### 8. MEDIUM -- Key Material Not Zeroed on Connection Teardown

- **ID**: 3.1
- **Risk Score**: 36 (Impact 3 x Likelihood 3 x 4)
- **CWE**: [CWE-244](https://cwe.mitre.org/data/definitions/244.html) -- Improper Clearing of Heap Data Before Release
- **OWASP**: A02:2021 Cryptographic Failures
- **Exploit surface**: Local (memory reuse, core dumps, swap)
- **Confidence**: `confirmed`

**Summary**: `conn.zig:1227-1283` (`Connection.deinit`) frees TLS context, crypto buffers, and key material without zeroing the underlying memory. Freed memory retains cryptographic secrets that could be recovered via heap reuse, core dumps, or swap file analysis.

**Evidence**: The `deinit` function calls `self.allocator.free(...)` and `tls_ctx.deinit()` without any prior `@memset(..., 0)` on key-bearing buffers.

**Fix guidance**: Before each `free()` call for security-sensitive buffers (TLS context, crypto retransmit buffers, key material), zero the memory: `@memset(buf, 0)`. Consider a `secureZero` wrapper that prevents compiler dead-store elimination.

**How to verify**: In a test, allocate a connection with known keys, call `deinit`, then inspect the freed memory region (via a custom allocator) to confirm it contains zeros.

---

### 9. MEDIUM -- ACK Range Count Silently Truncated to 16

- **ID**: 2.2
- **Risk Score**: 32 (Impact 2 x Likelihood 4 x 4)
- **CWE**: [CWE-130](https://cwe.mitre.org/data/definitions/130.html) -- Improper Handling of Length Parameter Inconsistency
- **OWASP**: A06:2021 Vulnerable and Outdated Components
- **Exploit surface**: Internet-facing, post-handshake
- **Confidence**: `confirmed`

**Summary**: `ack.zig:137-144` stores ACK ranges into a fixed-size buffer (`ranges_buf.len` = 16) but still reads all remaining varint pairs from the wire. A packet claiming thousands of ranges forces thousands of varint decodes (CPU exhaustion) while silently discarding all but 16 ranges, causing incorrect loss recovery.

**Evidence**:

```zig
if (out_len < ranges_buf.len) {
    ranges_buf[out_len] = .{ .gap = gap.value, .len = lenv.value };
    out_len += 1;
}
```

**Fix guidance**: Reject ACK frames with `range_count > MAX_ACK_RANGES` (e.g., 256) at parse time. Return a FRAME_ENCODING_ERROR for excessive range counts.

**How to verify**: Send an ACK frame with `range_count = 10000`. Confirm the server rejects it instead of spending CPU on varint decoding.

---

### 10. MEDIUM -- Localhost Exemption from Amplification Protection

- **ID**: 4.2
- **Risk Score**: 32 (Impact 3 x Likelihood 2.67 x 4)
- **CWE**: [CWE-290](https://cwe.mitre.org/data/definitions/290.html) -- Authentication Bypass by Spoofing
- **OWASP**: A05:2021 Security Misconfiguration
- **Exploit surface**: Internal (co-tenant, container network)
- **Confidence**: `confirmed`

**Summary**: `conn.zig:1542` (`self.isLocalhost()`) and `incoming.zig:544-558` auto-validate localhost addresses and bypass amplification limits. In containerized or multi-tenant environments, a co-tenant can spoof `127.0.0.1` source to bypass the 3x amplification limit.

**Evidence**:

- `src/quic/conn.zig:1542`: `if (self.isLocalhost()) return false;`
- `src/quic/endpoint/incoming.zig:544-558`: Auto-validates localhost and resets byte counters

**Fix guidance**: Remove the automatic localhost exemption. If needed for development, gate behind an explicit config flag (`allow_localhost_bypass = false` by default) and log when activated.

**How to verify**: From a container, send a UDP packet with source IP `127.0.0.1` to the QUIC server. Confirm the 3x amplification limit is still enforced.

---

### 11. MEDIUM -- Retry Not Enabled by Default

- **ID**: 4.4
- **Risk Score**: 24 (Impact 2 x Likelihood 3 x 4)
- **CWE**: [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) -- Initialization with an Insecure Default
- **OWASP**: A05:2021 Security Misconfiguration
- **Exploit surface**: Internet-facing
- **Confidence**: `confirmed`

**Summary**: `config.zig:30` sets `enable_retry: bool = false`. Without Retry, the server allows 3x amplification out of the box for any spoofed-source Initial packet.

**Evidence**: `src/quic/config.zig:30`: `enable_retry: bool = false,`

**Fix guidance**: Default `enable_retry` to `true`. Document the performance trade-off and provide explicit opt-out instructions.

**How to verify**: Instantiate a default `QuicConfig`. Confirm `enable_retry` is `true`.

---

### 12. LOW -- Global Mutable State in Crypto/Debug Code

- **ID**: 4.3
- **GitLab issue**: [#194](https://gitlab.com/devnw/zig/quic/-/issues/194)
- **Risk Score**: 16 (Impact 2 x Likelihood 2 x 4)
- **CWE**: [CWE-362](https://cwe.mitre.org/data/definitions/362.html) -- Concurrent Execution Using Shared Resource with Improper Synchronization
- **OWASP**: A04:2021 Insecure Design
- **Evidence**:
  - `src/quic/packet.zig:14-18`: `phase57_dump_count` and `phase57_attempt_label` are `threadlocal` and `phase57SetAttemptLabel()` is test-only via `if (!builtin.is_test) return`.
  - `src/quic/crypto_quic.zig:179`: Retry tag helper uses function-local `ct_local`; no shared mutable ciphertext buffer remains.
- **Status**: Closed / Implemented.
- **Fix evidence**: Thread-local debug state prevents cross-thread races in tests, production builds return before mutating debug labels, and Retry tag temporary storage is stack-local.

---

### 13. LOW -- Test Certificates in Docker Image

- **ID**: 5.1
- **Risk Score**: 12 (Impact 2 x Likelihood 1.5 x 4)
- **CWE**: [CWE-798](https://cwe.mitre.org/data/definitions/798.html) -- Use of Hard-coded Credentials
- **OWASP**: A07:2021 Identification and Authentication Failures
- **GitLab issue**: [#193](https://gitlab.com/devnw/zig/quic/-/issues/193)
- **Evidence**:
  - `interop/Dockerfile:21-24`: copies the endpoint binary and run script only; no `tests/certs/*.pem` COPY remains.
  - `interop/run_endpoint.sh:47-93`: `ensure_fallback_tls_materials()` generates an ephemeral ECDSA P-256 certificate/key at startup with key mode `0600`.
  - `interop/README.md:152-163`: documents `QNS_FALLBACK_CERT_DAYS` and states static test keys are not baked into the image.
- **Status**: Closed / Implemented.

---

### 14. LOW -- macOS/Windows CI Downloads Without Hash Verification

- **ID**: 5.2
- **Risk Score**: 8 (Impact 2 x Likelihood 1 x 4)
- **CWE**: [CWE-494](https://cwe.mitre.org/data/definitions/494.html) -- Download of Code Without Integrity Check
- **OWASP**: A08:2021 Software and Data Integrity Failures
- **Evidence**: `.gitlab-ci.yml:618-659`
- **Resolution**: Closed / Implemented for project-owned platform-specific Zig downloads. macOS uses `shasum -a 256 --check`; Windows uses `Get-FileHash -Algorithm SHA256`.
- **Governance boundary**: Generic CI/CD external-tool hash/toolchain pinning is closed as repo-level won't-do in GitLab issue #54 because external controls own that risk. Do not reopen this as a local repository gap unless governance ownership changes.

---

## Findings by Area

### Authentication and TLS Integration

| # | Finding | Severity | Risk |
|---|---------|----------|------|
| 1.1 | `allow_insecure` bypasses Retry integrity | High | 64 |
| 1.2 | mTLS `request_client_cert` silently ignored | High | 48 |
| 3.2 | No 0-RTT anti-replay detection | Medium | 36 |

### Input Validation and Frame Parsing

| # | Finding | Severity | Risk |
|---|---------|----------|------|
| 2.1 | Unbounded heap allocation from wire varint | High | 80 |
| 2.2 | ACK range count silently truncated to 16 | Medium | 32 |
| 6.1 | `unreachable` on CID > 20 bytes | Medium | 48 |

### Cryptographic Operations

| # | Finding | Severity | Risk |
|---|---------|----------|------|
| 3.1 | Key material not zeroed on teardown | Medium | 36 |
| 3.3 | Retry integrity tag signature mismatch | Medium | 48 |
| 4.3 | Global mutable state in crypto/debug | Low | 16 |

### Network and Amplification Protection

| # | Finding | Severity | Risk |
|---|---------|----------|------|
| 4.1 | Env var disables amplification limit | High | 60 |
| 4.2 | Localhost exemption from amplification | Medium | 32 |
| 4.4 | Retry not enabled by default | Medium | 24 |

### Infrastructure and Supply Chain

| # | Finding | Severity | Risk |
|---|---------|----------|------|
| 5.1 | Test certificates in Docker image | Low | 12 |
| 5.2 | macOS/Windows CI downloads without hash verification | Low | 8 |

---

## Future-Agent Governance Notes

1. CI/CD external-tool hash/toolchain pinning is closed as **Won't Do** at the repository level. GitLab issue #54 is the authoritative record; external controls own that risk.
2. Docker tag/digest pinning is closed as **Won't Do** at the repository level. GitLab issue #55 is the authoritative record; external controls own that risk.
3. Pre-commit hook pinning/enforcement is also externalized. Do not create or reopen a repo-local pre-commit governance gap unless ownership changes.
4. Platform-specific Zig download verification in this repository is separate from the generic external-control boundary and is closed as implemented by #102.

## Remediation Roadmap

### Quick Wins (< 1 day)

| Finding | Effort | Impact | Status |
|---------|--------|--------|--------|
| 3.3 -- Fix `computeRetryIntegrityTag` call signature | 30 min | Unblocks entire Retry path | **Closed** (Batch A) |
| 4.4 -- Default `enable_retry` to `true` | 15 min | Enables amplification protection out of box | **Closed** (Batch A) |
| 6.1 -- Replace `unreachable` with error return | 1 hr | Prevents crash from crafted CID | **Closed** (Batch A) |
| 4.1 -- Remove `QUIC_DISABLE_AMPLIFICATION_LIMIT` env var | 30 min | Removes DDoS reflector vector | **Closed** (Batch A) |
| 4.3 -- Annotate globals with `@threadlocal` or make const | 30 min | Thread safety | **Closed** (thread-local/test-only state confirmed) |

### Medium Effort (1--5 days)

| Finding | Effort | Impact | Status |
|---------|--------|--------|--------|
| 2.1 -- Add allocation caps to frame parser | 2 days | Eliminates OOM DoS | **Closed** (#111) |
| 2.2 -- Validate ACK range count at parse time | 1 day | Prevents CPU exhaustion | **Closed** (previously) |
| 1.1 -- Remove `allow_insecure` from Retry path | 1 day | Prevents connection hijack | **Closed** (#114) |
| 3.1 -- Zero key material before free | 1 day | Protects against memory forensics | **Closed** (Batch B) |
| 4.2 -- Remove localhost amplification exemption | 1 day | Prevents co-tenant spoofing | **Closed** (previously) |

### Strategic (> 5 days)

| Finding | Effort | Impact | Status |
|---------|--------|--------|--------|
| 1.2 -- Complete mTLS integration | 5--10 days | Enables mutual TLS enforcement | **Closed** (commit bf8cf7f) |
| 3.2 -- Implement 0-RTT anti-replay | 5--10 days | RFC compliance, prevents replay attacks | **Closed** (#121) |

---

## Positive Findings (What Is Done Well)

1. **Amplification protection core logic**: The 3x limit calculation in `overAmplification()` correctly implements RFC 9000 section 8.1 when the env var and localhost exemptions are not in effect.
2. **Retry token framework**: Token generation and verification infrastructure exists and follows RFC 9000 section 8.1.4 patterns, though the integrity tag call has a signature mismatch.
3. **Connection ID management**: CID rotation and stateless reset token derivation use HKDF-based key derivation following RFC 9000 section 10.3 guidance.
4. **Structured error handling**: The codebase consistently uses Zig's error union pattern rather than panicking, with the notable exception of the `unreachable` findings documented above.
5. **Security issue tracking**: Previous security reviews (Phase 1, Phase 2) have already identified and tracked 30+ security findings, demonstrating an active security posture.
6. **Supply chain awareness**: SBOM scanning, dependency pinning, and secret detection are configured in the CI pipeline (though some have gaps noted in prior findings).
7. **Separation of concerns**: TLS integration is cleanly separated via `handshake_integration.zig`, making it possible to audit the TLS boundary independently.

---

## Phase 4 Gap Closure -- 2026-03-25

### Closed Items

- **SF-015 (#145):** Anti-replay cache wired from Endpoint.init() to connections -- Closed. `AntiReplayCache` heap-allocated when `role == Server && zero_rtt_anti_replay == true`; cache passed through `RxContext`; `accept0RTT()` rejects replays. 5 tests added.
- **SF-016 (#153):** `catch unreachable` on page_allocator in crypto_quic.zig -- Closed. Replaced with 2048-byte stack buffer in `computeRetryIntegrityTag`. No more remote DoS vector.
- **SF-017 (#157):** Go interop binary with Critical CVEs -- Closed. Binary removed from repository. Added to `.gitignore`.
- **SF-018:** Key material `@memset` replaced with `std.crypto.secureZero` -- Closed. 36 call sites across `conn.zig`, `methods_b.zig`, `module_b.zig` use volatile-store `secureZero` preventing compiler dead-store elimination.
- **SF-019:** Unknown frames now signal CONNECTION_CLOSE with FRAME_ENCODING_ERROR (0x07) -- Closed. `module_b2.zig:processFrames` sends FRAME_ENCODING_ERROR instead of silently breaking, per RFC 9000 S12.4.
- **SF-020:** `canSendUnderAmplification` now checks `exempt_localhost` -- Closed. Consolidated with `overAmplification()` behavior. `amplification.zig` documented as deprecated/unused.
- **SF-021 (#117):** `ct_empty` global mutable data race -- Closed. Replaced with function-local variable in `crypto_quic.zig`.
- **SF-022:** CID >20 byte validation at parse boundary -- Closed. Validation occurs at frame decode before reaching connection state.
- **GAP-0018 (#149):** Retry integrity tag timing-safe comparison -- Closed. Changed to `std.crypto.timing_safe.eql` in `packet.zig`.
- **GAP-0047 (#155):** frame_handler comment corrected -- Closed. Replaced `else => .{}` with explicit `.padding => .{}` and `.crypto => .{}` arms.
- **#121:** 0-RTT anti-replay detection -- Closed. `AntiReplayCache` wired end-to-end; `accept0RTT()` rejects replayed 0-RTT data.

---

## 2026-06-11 AppSec Audit Round (QC-series)

A fresh OWASP-aligned application-security code review (2026-06-11) of the QUIC transport, flow control, migration, token, key-update, and supporting tooling paths. Full per-finding analysis, attack scenarios, and fix evidence live in [`docs/APPSEC_REVIEW_2026-06-11.md`](APPSEC_REVIEW_2026-06-11.md).

**Status legend:** `Fixed` = closed in code with tests; `Partial` = partially addressed, residual open; `Open` = tracked, not yet implemented.

### Findings

| ID | Severity | Title | Location | Status | Fix Commit |
|----|----------|-------|----------|--------|------------|
| QC-01 | Critical | Receive-side flow control not enforced (unbounded buffering DoS) | `src/quic/connection/methods_a.zig` (`pushStreamFrame`), `stream.zig` | Fixed | `2047925` |
| QC-02 | High (residual Medium) | Connection migration committed before AEAD authentication | `src/quic/endpoint.zig` (`onPathAddressChanged`) | Partial | -- |
| QC-03 | High | Anti-amplification RX budget credited with unauthenticated bytes (short-header path) | `src/quic/endpoint/incoming/module_c.zig` | Fixed | `2047925` |
| QC-04 | High | Connection IDs / reset tokens from non-CSPRNG; all `getrandom()` returns discarded | `src/quic/connection/methods_c.zig` + 10 sites | Fixed | `e7762c8` |
| QC-05 | Medium | Unbounded `stream_txs` map growth from peer MAX_STREAM_DATA | `src/quic/endpoint/frame_handler.zig` | Fixed | `75a597a` |
| QC-06 | Medium | Retry/NEW_TOKEN tokens replayable; no type discriminator | `src/quic/token.zig`, `src/quic/endpoint/incoming.zig` | Open | -- |
| QC-07 | Medium | Unbounded received-DATAGRAM queue | `src/quic/connection/methods_a.zig` (`pushDatagram`) | Fixed | `75a597a` |
| QC-08 | Medium | Peer MAX_STREAMS accepted without 2^60 bound / monotonic check | `src/quic/endpoint/frame_handler.zig` | Fixed | `75a597a` |
| QC-09 | Medium | 0-RTT encoder emits unprotected header on short ciphertext; swallows HP errors | `src/quic/packet.zig` (`encode0RTTProtected`) | Fixed | `3edadae` |
| QC-10 | Medium | PATH_RESPONSE accepted from any address; non-constant-time compare; predictable challenge fallback | `src/quic/connection/methods_a.zig` | Partial | `e7762c8` |
| QC-11 | Medium | RX-triggered key update has no rate limit / prior-update-confirmed gate | `src/quic/endpoint/incoming/module_b.zig`, `src/quic/connection/methods_b.zig` | Open | -- |
| QC-12 | Low | Server-side path traversal in qns interop endpoint | `cmd/qns-endpoint.zig` | Fixed | `3edadae` |
| QC-13 | Low | Anti-replay cache keyed on 64-bit Wyhash (fixed seed) -> targeted false-reject | `src/quic/anti_replay.zig` | Open | -- |
| QC-14 | Low | TLS keylog file created world-readable (`0o644`) | `src/quic/connection/methods_a.zig` | Fixed | `fcd28ce` |
| QC-15 | Low | Interop/test cert scripts install private keys world-readable | `create_test_certs.sh` (umask 077) | Fixed (interop part reverted) | `fcd28ce` |
| QC-16 | Low | `stateless_reset_base` derived from per-connection secret, not endpoint-static key | `src/quic/connection/methods_c.zig` | Open | -- |
| QC-17 | Low | Nix dev-bootstrap installer executed without hash/signature verification | `scripts/install_pkgs.sh` | Open | -- |

### Residual / Open Detail

- **QC-01 (Critical) -- Fixed (`2047925`):** Enforces per-stream window, out-of-order buffer caps, and connection-level `MAX_DATA`; violations raise `FLOW_CONTROL_ERROR`.
- **QC-02 (High, residual Medium) -- Partial:** The High-severity amplification/reflection portion is closed by QC-03 (a spoofed non-decrypting packet now credits 0 anti-amplification bytes). The residual pre-auth `setPeer` redirect (transient response misrouting until a legitimate packet flaps it back) remains **Open**. Full fix needs authenticate-before-migrate: defer `setPeer` / counter-reset / `PATH_CHALLENGE` to the post-decrypt path, which requires wiring an endpoint reference into `RxContext` (`endpoint_ctx` is currently unset) plus concurrency validation.
- **QC-03 (High) -- Fixed (`2047925`):** `addRxUnvalidated` moved to after successful decrypt.
- **QC-04 (High) -- Fixed (`e7762c8`):** `compat.secureRandomBytes` (checked `getrandom`) replaces all sites; the Xoshiro CID generator was removed and all sites now fail closed.
- **QC-05 (Medium) -- Fixed (`75a597a`):** `STREAM_STATE_ERROR` for peer-initiated uni streams; 16384-entry pre-creation cap.
- **QC-06 (Medium) -- Open:** Needs a token-type byte (RETRY vs NEW_TOKEN) and a single-use/strike cache for Retry tokens.
- **QC-07 (Medium) -- Fixed (`75a597a`):** `dgram_inbox` capped at 1024, drops oldest.
- **QC-08 (Medium) -- Fixed (`75a597a`):** `FRAME_ENCODING_ERROR` above 2^60; monotonic updates.
- **QC-09 (Medium) -- Fixed (`3edadae`):** Fails closed (returns error) instead of emitting an unprotected header.
- **QC-10 (Medium) -- Partial (`e7762c8`):** The predictable `PATH_CHALLENGE` fallback was removed and seeding now fails closed via CSPRNG. The source-address binding of `PATH_RESPONSE` and constant-time compare remain **Open** (tied to the QC-02 authenticate-before-migrate work).
- **QC-11 (Medium) -- Open:** Needs to gate forced TX rotation on prior-update confirmation and rate-limit to ~1/RTT.
- **QC-12 (Low) -- Fixed (`3edadae`):** Rejects `..`, NUL, and non-leading-`/` paths.
- **QC-13 (Low) -- Open:** Use a >=128-bit cryptographic digest or randomly-seeded SipHash.
- **QC-14 (Low) -- Fixed (`fcd28ce`):** Keylog file now created `0o600`.
- **QC-15 (Low) -- Fixed partially (`fcd28ce`):** `create_test_certs.sh` now sets `umask 077`. The `scripts/interop_*.sh` `0600` key installs were **reverted to `0644`** afterward: those ephemeral, per-run keys are mounted read-only into QUIC-interop Docker containers whose unprivileged `quic` uid differs from the host's, so `0600` caused `server: AccessDenied` and broke the entire interop matrix. World-readable is required for that container-mount case (keys are throwaway, localhost-only); the scripts carry comments warning against re-hardening.
- **QC-16 (Low) -- Open:** Low because no outbound stateless-reset send path exists yet; derive from a long-lived endpoint key per RFC 9000 section 10.3.1 when reset emission is added.
- **QC-17 (Low) -- Open:** Dev tooling; pin and verify a SHA-256, use `mktemp`.

### Second-pass additions

The 2026-06-11 SECOND-PASS review surfaced two further findings, both now Fixed.

| ID | Severity | Title | Location | RFC | Status | Fix Commit |
|----|----------|-------|----------|-----|--------|------------|
| NEW-SEC-01 | Low | Path traversal in HTTP/3 server `respondFile` (`/www{path}` with no `..`/NUL rejection) | `src/h3/server.zig` (`respondFile`) | -- | Fixed | `ad34e76` |
| NEW-SEC-02 | Medium | RESET_STREAM final size not validated -> missing FINAL_SIZE_ERROR | `src/quic/connection/stream.zig` (`recordReset`), `connection/methods_b.zig` (`handleResetStream`), `endpoint/frame_handler.zig` | RFC 9000 §4.5 | Fixed | `ad34e76` |

- **NEW-SEC-01 (Low) -- Fixed (`ad34e76`):** Rejects `..` and NUL paths. `H3Server` is a public library export, so the guard lives here, not only in the qns binary (QC-12).
- **NEW-SEC-02 (Medium) -- Fixed (`ad34e76`):** `recordReset` rejects an inconsistent or below-`recv_off` final size with `error.FinalSizeError`; `handleResetStream` is fallible; the dispatcher closes with FINAL_SIZE_ERROR (0x06); a regression test was added.

### Third-pass additions

The 2026-06-11 THIRD-PASS review surfaced one further finding, now Fixed.

| ID | Severity | Title | Location | RFC | Status | Fix Commit |
|----|----------|-------|----------|-----|--------|------------|
| TP3-01 | Low | Client advertised `active_connection_id_limit` default (2) but `onNewConnectionId` enforced against `peer_cids` capacity (8) -- advertise-vs-enforce mismatch | `src/quic/endpoint/handshake_integration.zig` (`setupClientTransportParams`) | RFC 9000 §5.1.1 | Fixed | `ddb3e1a` |

- **TP3-01 (Low) -- Fixed (`ddb3e1a`):** Client now advertises `active_connection_id_limit = 8`, matching enforcement and the server.
