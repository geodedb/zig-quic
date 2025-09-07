# Minimal HTTP/3 Shim (Server)

This module provides a minimal, non‑compliant shim to satisfy interop runner expectations while the full HTTP/3 implementation is being built. It is deliberately isolated under `src/h3/` and kept separate from QUIC transport.

What it does now:
- Detect negotiated ALPN `h3` in qns-endpoint
- Emit a placeholder SETTINGS frame on stream 0 and drive a few polls
- Documented as a shim; not spec‑correct (HTTP/3 control streams are unidirectional)

Planned next slices:
- Proper control stream (unidirectional) with SETTINGS
- Minimal request handling on bidi streams (pseudo‑headers, DATA framing)
- Static table / literal headers only; no QPACK dynamic table
- Simple 200 responses serving `/www/<path>`

Rationale for isolation:
- Keeps transport RFC 9000/9001 code independent from application (HTTP/3)
- Enables iterative bring‑up without risking regression in core QUIC
