# Zig Client Comprehensive Testing Log

## 2025-11-19 – Handshake parse failure (client side)

- **Scenario:** `make e2e-test-zig-comprehensive` (Zig client ↔ Zig server, ALPN `hq-interop`).
- **Result:** ❌ Handshake fails with `TLS: Unknown handshake type byte=0xD8` while processing Handshake CRYPTO after EncryptedExtensions. Failure happens on the client side; server completes its flight.
- **Observation:** Added client-side TLS debug logging in `pushCrypto`:
  - Handshake head bytes: `{08 00 00 53 00 81 00 10 00 13 00 11 0a 68 71 2d}` (EncryptedExtensions + transport params, ALPN `hq-interop`).
  - Middle bytes (~80..112) show certificate header: `0x0b 00 01 8a 00 01 81 30 82 01 7d 30 82 01 23 ...` (certificate total length 0x018a).
  - Parser later sees an unexpected handshake type byte (`0xD8` in latest run) when advancing past the certificate, indicating stream misalignment or length accounting bug during Handshake CRYPTO reassembly/parsing on the client.
- **Other clients:** Go, aioquic (Python), and Quinn (Rust) comprehensive suites all pass; issue confined to Zig client TLS parsing path.
- **Next steps:**
  1. Inspect handshake CRYPTO buffering on the client: ensure CRYPTO fragments are concatenated in order and not double-applied. Compare offsets/lengths delivered to TLS context.
  2. Instrument TLS handshake parser to dump handshake message boundaries (type/len) before consuming; verify certificate length (0x018a) and remaining bytes for CertVerify/Finished.
  3. If lengths are correct, verify AEAD decrypt for the second Handshake packet (payload_len=620) to rule out corruption before parsing.

