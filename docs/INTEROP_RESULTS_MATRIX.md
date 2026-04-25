# Interop Results Matrix

Last validated run set: 2026-02-18
Last updated: 2026-02-18

These results are from clean batch executions of `scripts/interop_full.sh full` with `SKIP_BUILD=1 INTEROP_SKIP_EXTRAS=1`.

Focused revalidation on 2026-02-18:
- `INTEROP_IMPLS=msquic,xquic,s2n-quic INTEROP_TESTCASES=handshake,transfer,retry,http3,keyupdate`
- Log: `/tmp/interop_targeted_triplet_20260218_postfix.log`
- Summary: `Passed: 26`, `Failed: 0`, `Skipped: 4`
- `INTEROP_FORCE_RUN_SKIPS=1 INTEROP_IMPLS=msquic,s2n-quic,quinn INTEROP_TESTCASES=http3,keyupdate`
- Log: `/tmp/interop_forced_skips_20260218.log`
- Summary: `Passed: 8`, `Failed: 0`, `Skipped: 4`
- `INTEROP_IMPLS=quinn INTEROP_TESTCASES=http3`
- Log: `/tmp/interop_quinn_http3_unskipped_20260218.log`
- Summary: `Passed: 2`, `Failed: 0`, `Skipped: 0`

## Batch Summary

| Batch | Implementations | Log | Passed | Failed | Skipped |
|---|---|---|---:|---:|---:|
| Core | `quic-go,ngtcp2,quiche` | `/tmp/interop_batch0_core_20260217_214249.log` | 27 | 0 | 3 |
| Batch A | `mvfst,kwik,picoquic,aioquic,neqo` | `/tmp/interop_batch1_clean_20260217_211818.log` | 39 | 0 | 11 |
| Batch B | `msquic,xquic,lsquic` | `/tmp/interop_batch2_clean_20260217_205435.log` | 17 | 0 | 13 |
| Batch C | `quinn,s2n-quic,go-x-net` | `/tmp/interop_batch3_clean_20260217_210533.log` | 19 | 0 | 11 |

Historical aggregate across these four batch logs:
- Passed: **102**
- Failed: **0**
- Skipped: **38**

Focused revalidation on 2026-02-18 supersedes the prior `msquic/xquic/s2n-quic` entries in the matrix below.

## Status Legend

- `PASS`: testcase passed for that direction.
- `SKIP`: policy/harness skip (expected).
- `FAIL`: testcase failed (none in this run set).

## Implementation/Testcase Matrix

| Implementation | Testcase | zig -> impl | impl -> zig |
|---|---|---|---|
| quic-go | handshake | PASS | PASS |
| quic-go | transfer | PASS | PASS |
| quic-go | retry | PASS | PASS |
| quic-go | http3 | PASS | PASS |
| quic-go | keyupdate | PASS | SKIP |
| ngtcp2 | handshake | PASS | PASS |
| ngtcp2 | transfer | PASS | PASS |
| ngtcp2 | retry | PASS | PASS |
| ngtcp2 | http3 | PASS | PASS |
| ngtcp2 | keyupdate | PASS | PASS |
| quiche | handshake | PASS | PASS |
| quiche | transfer | PASS | PASS |
| quiche | retry | PASS | PASS |
| quiche | http3 | PASS | PASS |
| quiche | keyupdate | SKIP | SKIP |
| mvfst | handshake | PASS | PASS |
| mvfst | transfer | PASS | PASS |
| mvfst | retry | SKIP | SKIP |
| mvfst | http3 | PASS | PASS |
| mvfst | keyupdate | SKIP | SKIP |
| kwik | handshake | SKIP | PASS |
| kwik | transfer | SKIP | SKIP |
| kwik | retry | SKIP | PASS |
| kwik | http3 | SKIP | PASS |
| kwik | keyupdate | SKIP | SKIP |
| picoquic | handshake | SKIP | PASS |
| picoquic | transfer | SKIP | PASS |
| picoquic | retry | SKIP | PASS |
| picoquic | http3 | SKIP | PASS |
| picoquic | keyupdate | SKIP | PASS |
| aioquic | handshake | PASS | PASS |
| aioquic | transfer | PASS | PASS |
| aioquic | retry | PASS | PASS |
| aioquic | http3 | PASS | PASS |
| aioquic | keyupdate | PASS | PASS |
| neqo | handshake | PASS | PASS |
| neqo | transfer | PASS | PASS |
| neqo | retry | PASS | PASS |
| neqo | http3 | PASS | PASS |
| neqo | keyupdate | PASS | SKIP |
| msquic | handshake | PASS | PASS |
| msquic | transfer | PASS | PASS |
| msquic | retry | PASS | PASS |
| msquic | http3 | SKIP | SKIP |
| msquic | keyupdate | PASS | PASS |
| xquic | handshake | SKIP | SKIP |
| xquic | transfer | SKIP | SKIP |
| xquic | retry | SKIP | SKIP |
| xquic | http3 | SKIP | SKIP |
| xquic | keyupdate | SKIP | SKIP |
| lsquic | handshake | PASS | PASS |
| lsquic | transfer | PASS | PASS |
| lsquic | retry | PASS | PASS |
| lsquic | http3 | PASS | PASS |
| lsquic | keyupdate | SKIP | SKIP |
| quinn | handshake | PASS | PASS |
| quinn | transfer | PASS | PASS |
| quinn | retry | PASS | PASS |
| quinn | http3 | PASS | PASS |
| quinn | keyupdate | PASS | PASS |
| s2n-quic | handshake | PASS | PASS |
| s2n-quic | transfer | PASS | PASS |
| s2n-quic | retry | PASS | PASS |
| s2n-quic | http3 | PASS | PASS |
| s2n-quic | keyupdate | SKIP | SKIP |
| go-x-net | handshake | PASS | PASS |
| go-x-net | transfer | PASS | PASS |
| go-x-net | retry | SKIP | SKIP |
| go-x-net | http3 | SKIP | SKIP |
| go-x-net | keyupdate | PASS | PASS |

## Notes on Skips

Skips are expected and policy-driven for known incompatibilities in this harness environment. See `scripts/interop_full.sh:162` for current skip policy and reason text.

Key examples from this run set:
- `zig -> kwik` all major testcases: skipped due to missing TLS key_share in kwik client path.
- `kwik -> zig` transfer is skipped because the kwik server throws `java.lang.NullPointerException` after the first response in this harness, then the Zig client reaches a per-stream response idle timeout. Current evidence: `/tmp/interop_release_kwik_current_20260425.log`.
- `kwik -> zig` keyupdate is skipped because the kwik server blocks on a `keytool` overwrite prompt. Current evidence: `/tmp/interop_release_kwik_current_20260425.log` records `Existing entry alias servercert exists, overwrite? [no]:` before the Zig client handshake timeout.
- `zig -> picoquic` all major testcases: skipped because the picoquic client path does not expose an X25519 TLS key_share to the current pinned TLS dependency. Current evidence: `/tmp/interop_zig_picoquic_handshake.log` debug traces show repeated server-side `MissingKeyShare`, `/tmp/interop_release_picoquic_handshake_current_20260425.log` records repeated Zig server handshake timeouts, and the reverse `picoquic -> zig` handshake passes.
- `neqo -> zig` keyupdate is skipped because the neqo server path blocks on an NSS certificate DB prompt in this harness. Current evidence: `/tmp/interop_release_neqo_current_20260425.log` records `Enter Password or Pin for "NSS Certificate DB":` before the Zig client handshake timeout; the reverse `zig -> neqo` keyupdate passes.
- `zig -> xquic` and `xquic -> zig` are skipped for the current xquic image. Current evidence: `/tmp/interop_full_current_20260425.log` shows `zig -> xquic` handshake/transfer stalling with `socket idle timeout, task failed` and `recv_bytes:0`; the reverse `xquic -> zig` path logs `server_read_handler: packet process err, ret: -636` and `conn_err:336` before the Zig client handshake timeout.
- `zig -> msquic` transfer/retry/keyupdate now pass; `http3` remains unsupported.
- `zig -> s2n-quic` handshake/transfer/retry/http3 now pass; `keyupdate` remains skipped by policy (unsupported testcase in s2n-quic image).
- `quinn -> zig` http3 now passes in the current harness (`/tmp/interop_quinn_http3_unskipped_20260218.log`).
- Select `keyupdate` cases are skipped when the runner cannot verify key update progression in a testcase path.
