# GAP Analysis — QUIC v1 (updated)

Date: 2025-09-07

## Latest interop observations (zig server vs quic-go/ngtcp2 clients)
- Compose/network orchestration stabilized (unique project names; sim up first; longer timeouts).
- Implemented minimal HTTP/3 path: control stream + SETTINGS; HEADERS (QPACK static only) + DATA response. Server responds with /www/index.html (200) when any bidi request bytes are seen.
- ALPN negotiation prefers "h3"; real TLS is enabled when /certs are mounted by runner.

Status of previously observed issues:
- "no recent network activity" timeouts traced to lack of HTTP/3; addressed by minimal h3.

Remaining gaps impacting full interop:
1) HTTP/3 request decode is minimal. We do not parse request HEADERS; path is fixed to /www/index.html. For "handshake" and "transfer" this is sufficient, but not for full http3 suite or parallel transfers.
2) QPACK dynamic table not used; only static and literal allowed in responses. That is acceptable for baseline tests; add decoder/encoder streams later if needed.
3) Retry/key update/v2 testcases: transport code supports toggles; will validate once h3 path is green.

## Action Plan
- Harden minimal HTTP/3 server:
  - Keep unidirectional control stream with SETTINGS; optionally open empty QPACK encoder/decoder streams later.
  - Parse request HEADERS minimally to extract :path; keep fallback to /www/index.html for runner handshake/transfer.
  - Continue without dynamic table initially; add when parallel/pipelined tests demand it.
  - Maintain ALPN preference for "h3"; keep HQ fallback only when ALPN != h3.
- Iterate with interop runner quick matrix and capture logs.

## Status Summary
- Transport (RFC 9000): good coverage; Retry/VN/Stateless reset working.
- TLS (RFC 9001): key schedule / HP / Key Update OK; interop certs wired.
- HTTP/3: Minimal server implemented (control stream + SETTINGS, HEADERS(:status 200) + DATA for /www/index.html). No request HEADERS parsing yet.

## Next Steps
- Run scripts/interop_full.sh quick to validate handshake/transfer against quic-go and ngtcp2 (both dirs).
- Ensure runner logs show successful transfers (no "no recent network activity").
- If needed, add empty QPACK encoder/decoder streams for stricter peers.
- Implement minimal request HEADERS parser to honor :path for broader http3 scenarios.
- Iterate on retry/v2/keyupdate once HTTP/3 path is green; update docs accordingly.
