# Skipped Test Inventory

Last updated: 2026-04-26

Source issue: https://gitlab.com/devnw/zig/quic/-/issues/88

This inventory records every source file that still contains `return error.SkipZigTest`. It does not close GAP-0004 by itself; it is the required baseline for deciding whether each skipped scenario should be implemented or explicitly de-scoped.

## Command

```sh
rg --hidden --glob '!.git/**' --glob '!.claude/worktrees/**' --glob '*.zig' -n 'return error\.SkipZigTest' tests src | cut -d: -f1 | sort | uniq -c | sort -nr
```

Total matches: 529.

## Inventory

| Count | File |
|---:|---|
| 62 | `tests/integration/zero_rtt.zig` |
| 58 | `tests/integration/flow_control.zig` |
| 56 | `tests/integration/fault/fault.zig` |
| 52 | `tests/integration/key_update.zig` |
| 46 | `tests/integration/migration.zig` |
| 40 | `tests/integration/interop/interop.zig` |
| 37 | `tests/integration/stress/stress.zig` |
| 30 | `tests/integration/rfc9000_packets.zig` |
| 27 | `tests/integration/rfc9001_advanced.zig` |
| 24 | `tests/integration/rfc9000_section8.zig` |
| 18 | `tests/integration/rfc9000_medium.zig` |
| 16 | `tests/integration/rfc9000_advanced.zig` |
| 16 | `tests/integration/real_endpoint.zig` |
| 14 | `tests/integration/rfc9000_section7.zig` |
| 7 | `tests/test_tls_harness_layout.zig` |
| 4 | `tests/test_transport_geode_compat.zig` |
| 3 | `tests/test_transcript_hash.zig` |
| 2 | `tests/test_tls_server_handshake_flight.zig` |
| 2 | `tests/test_resumption.zig` |
| 2 | `tests/test_hp_aead_kats.zig` |
| 2 | `tests/test_endpoint_pto_handshake_uaf_regression.zig` |
| 2 | `tests/integration/tls_helpers.zig` |
| 1 | `tests/test_tls_handshake_secrets.zig` |
| 1 | `tests/test_tls_handshake_context.zig` |
| 1 | `tests/test_shortrtt_roundtrip.zig` |
| 1 | `tests/test_rx_key_update_accept.zig` |
| 1 | `tests/test_public_quic_exports.zig` |
| 1 | `tests/test_initial_protect.zig` |
| 1 | `tests/test_initial_handshake_loop.zig` |
| 1 | `tests/test_conn_init_mutex.zig` |
| 1 | `tests/integration/harness.zig` |

## Required Triage

- Implement executable tests for required RFC/protocol behavior.
- Explicitly de-scope non-required scenarios with a GitLab issue link, owner, and rationale.
- Keep this inventory current whenever skips are removed or added.
