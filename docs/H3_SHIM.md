# HTTP/3 Implementation

This module provides a basic HTTP/3 implementation under `src/h3/`, kept separate from the QUIC transport layer for clean architecture.

## Current Implementation Status

### Server ([`src/h3/server.zig`](../src/h3/server.zig))
- ✅ Control stream with SETTINGS frame
- ✅ QPACK encoder/decoder streams 
- ✅ Static table encoding/decoding (no dynamic table)
- ✅ HEADERS frame parsing with pseudo-headers
- ✅ DATA frame handling
- ✅ Static file serving from `/www/`
- ✅ Basic request/response flow

### Client ([`src/h3/client.zig`](../src/h3/client.zig))
- ✅ QPACK static table encoding
- ✅ GET request generation
- ✅ Response parsing
- ✅ Varint encoding/decoding

### Limitations
- ⚠️ Static QPACK only (no dynamic table)
- ⚠️ No server push support
- ⚠️ No prioritization
- ⚠️ Basic error handling

Rationale for isolation:
- Keeps transport RFC 9000/9001 code independent from application (HTTP/3)
- Enables iterative bring‑up without risking regression in core QUIC
