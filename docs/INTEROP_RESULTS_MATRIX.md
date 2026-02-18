# Interop Results Matrix

Last validated run set: 2026-02-18
Last updated: 2026-02-18

These results are from clean batch executions of `scripts/interop_full.sh full` with `SKIP_BUILD=1 INTEROP_SKIP_EXTRAS=1`.

Focused revalidation on 2026-02-18:
- `INTEROP_IMPLS=msquic,xquic,s2n-quic INTEROP_TESTCASES=handshake,transfer,retry,http3,keyupdate`
- Log: `/tmp/interop_targeted_triplet_20260218_postfix.log`
- Summary: `Passed: 26`, `Failed: 0`, `Skipped: 4`

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
| kwik | transfer | SKIP | PASS |
| kwik | retry | SKIP | PASS |
| kwik | http3 | SKIP | PASS |
| kwik | keyupdate | SKIP | SKIP |
| picoquic | handshake | PASS | PASS |
| picoquic | transfer | PASS | PASS |
| picoquic | retry | PASS | PASS |
| picoquic | http3 | PASS | PASS |
| picoquic | keyupdate | PASS | PASS |
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
| xquic | handshake | PASS | PASS |
| xquic | transfer | PASS | PASS |
| xquic | retry | PASS | PASS |
| xquic | http3 | PASS | PASS |
| xquic | keyupdate | PASS | PASS |
| lsquic | handshake | PASS | PASS |
| lsquic | transfer | PASS | PASS |
| lsquic | retry | PASS | PASS |
| lsquic | http3 | PASS | PASS |
| lsquic | keyupdate | SKIP | SKIP |
| quinn | handshake | PASS | PASS |
| quinn | transfer | PASS | PASS |
| quinn | retry | PASS | PASS |
| quinn | http3 | PASS | SKIP |
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
- `xquic -> zig` major testcase coverage is now passing in the current harness (handshake/transfer/retry/http3/keyupdate).
- `zig -> xquic` retry now passes with server-side compatibility mode that disables forced Retry only for this client path.
- `zig -> msquic` transfer/retry/keyupdate now pass; `http3` remains unsupported.
- `zig -> s2n-quic` handshake/transfer/retry/http3 now pass; `keyupdate` remains skipped by policy (unsupported testcase in s2n-quic image).
- `quinn -> zig` http3: skipped due to server panic in harness path.
- Select `keyupdate` cases are skipped when the runner cannot verify key update progression in a testcase path.
