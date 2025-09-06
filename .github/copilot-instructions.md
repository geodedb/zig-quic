# QUIC — Copilot Instructions (Zig 0.15.1, std‑only)

## T — Task & Role

You are a senior **Zig** engineer. Build a **production‑grade QUIC v1** transport + **TLS 1.3 binding** + tools **using only Zig std**. If std lacks a primitive, implement it in‑repo. **Authoritative specs:** RFC 9000 (transport), RFC 9001 (QUIC‑TLS), RFC 9002 (loss & CC). :contentReference[oaicite:2]{index=2} :contentReference[oaicite:3]{index=3} :contentReference[oaicite:4]{index=4} :contentReference[oaicite:5]{index=5}

## A — Action Steps

- Implement and maintain:
  - **Library:** `src/` (transport, crypto/tls, recovery/cc, event loop).
  - **Tools/CLI:** `cmd/quic-{client,server}.zig`, `tools/varint_tool.zig`.
  - **Build & CI:** `build.zig`, `.github/workflows/ci.yml`.
  - **Quality assets:** `tests/`, `fuzz/`, `bench/`, `docs/` (incl. GAP & NEXT). :contentReference[oaicite:7]{index=7}
- **Strict deps:** std‑only (`std.crypto` for AEAD/HP; in‑repo TLS 1.3 subset). QUIC v1 wire rules (frames, PN encode/expand, header protection) must follow RFC text and examples (e.g., header‑protection sample offset, PN mask).:contentReference[oaicite:9]{index=9} :contentReference[oaicite:10]{index=10} :contentReference[oaicite:11]{index=11}
- **Transport coverage:**
  - **Frames & ACK ranges/ECN** per §19.3 (multiple ranges + ECN counts). :contentReference[oaicite:13]{index=13}
  - **CONNECTION_CLOSE** semantics and error mapping per §11.1, §19.19. :contentReference[oaicite:16]{index=16} :contentReference[oaicite:17]{index=17}
  - **PMTUD/DPLPMTUD**: probe sizing & ICMP validation per §14.2–§14.4.:contentReference[oaicite:19]{index=19} :contentReference[oaicite:20]{index=20} :contentReference[oaicite:21]{index=21}
  - **Path validation/migration**: PATH_CHALLENGE/RESPONSE + preferred address rules.§19.17–§19.18; §9.6.:contentReference[oaicite:22]{index=22} :contentReference[oaicite:24]{index=24} :contentReference[oaicite:25]{index=25}
- **TLS/crypto coverage:**
  - HKDF labels; Initial/Handshake/1‑RTT keys; **Key Update** rules (§6.1–§6.5), AEAD usage limits (§6.6). :contentReference[oaicite:28]{index=28} :contentReference[oaicite:29]{index=29}
  - **Side‑channel constraints** for header protection timing (§9.5). :contentReference[oaicite:31]{index=31}
- **Recovery/CC:** RFC 9002 PTO, persistent congestion, NewReno + **CUBIC** option (`-Dcc=cubic`). :contentReference[oaicite:34]{index=34} :contentReference[oaicite:35]{index=35}

## Files & Layout (target)

```

zig
tools/varint\_tool.zig
tests/{test\_varint.zig,test\_frames.zig,test\_tp.zig,test\_tls\_key\_schedule.zig}
bench/main.zig
fuzz/{fuzz\_packet\_parse.zig,fuzz\_frame\_parse.zig,fuzz\_varint.zig}
docs/{README.md,DESIGN.md,GAP.md,GAP\_ANALYSIS.md,NEXT.md,requirements.md}
.github/workflows/ci.yml
specs/  examples/

```

Keep this tree valid and green in CI. :contentReference[oaicite:37]{index=37}

## Process Gates (every slice)

1. Finish a coherent slice → 2) Update `docs/GAP.md` + `docs/GAP_ANALYSIS.md` → 3) Update `docs/DESIGN.md` APIs → 4) `zig build`, `zig build test`, build fuzz/bench → 5) fix all failures → 6) commit with `docs:`/`tests:` scopes. :contentReference[oaicite:39]{index=39}

- CI rehearsal: Before pushing, run GitHub Actions locally with `act` to validate workflows (e.g., `act -W .github/workflows/ci.yml`). Ensure all jobs pass locally to keep main green.

## Acceptance (must pass, exact)

- **Varint tool:** Cmds + outputs exactly as specified (encode/decode/underflow). :contentReference[oaicite:41]{index=41}
- **TLS KAT:** `zig build test --test-filter "tls_key_schedule_kat"` prints `PASSED tls_key_schedule_kat`. :contentReference[oaicite:43]{index=43}
- **New coverage:**
  - ACK ranges/ECN unit tests per §19.3. :contentReference[oaicite:44]{index=44}
  - PMTUD probe tests (PADDING/PING only) per §14.3–§14.4. :contentReference[oaicite:45]{index=45}
  - Key Update RX/TX tests: confirm phase toggling and retention window per §6.2–§6.5. :contentReference[oaicite:46]{index=46}

## Out of Scope

Non‑std libraries, non‑QUIC transports, features contradicting v1 invariants. Follow QUIC v1; defer v2/compat toggles behind flags.
