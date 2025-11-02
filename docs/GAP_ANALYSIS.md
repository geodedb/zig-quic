# GAP Analysis — QUIC v1 (updated)

Date: 2025-09-20 (Current Implementation Status)

## Current Status

- **Unit tests**: Targeted TLS handshake and record-layer suites passing; additional transport and interop tests are gated behind ongoing TLS work.
- **Implementation**: QUIC v1 transport/recovery stack is largely in place; TLS 1.3 integration is mid-flight with server-side handshake flights, metadata callbacks, and Finished verification complete.
- **Interop testing**: Local loopback harnesses only; external interop pending once TLS handshake stabilises.
- **Features**: Stream/data path, ACK/ECN, loss recovery, and DPLPMTUD implemented; TLS certificates, resumption, and 0-RTT remain on the roadmap.
- **Platform support**: Linux primary; macOS/Windows backends tracked but not yet feature-parity tested during this phase.

## Implementation Completeness

### Implemented

- **QUIC v1 Transport** (RFC 9000): Initial/Handshake/Short header processing, frame encode/decode, connection ID lifecycle, amplification guard, path validation, preferred address scaffolding.
- **Loss Recovery** (RFC 9002): Separate packet number spaces, RTT estimation, loss detection, PTO, persistent congestion, NewReno and optional CUBIC.
- **Connection ID Management**: Rotation, retirement, stateless reset tokens with HKDF derivation.
- **Path Sizing**: PMTUD/DPLPMTUD with ICMP validation hooks.

### In Progress

- **HTTP/3**: Minimal HTTP/0.9 compatibility remains; full H3/QPACK integration deferred.
- **Certificate Handling**: X.509 parsing and validation planned; current TLS handshake stops before Certificate/CertificateVerify.
- **TLS 1.3 Record Layer**: Plaintext/inner-plaintext framing with AEAD suites and usage-limit enforcement implemented; dedicated fuzz harness pending.
- **TLS 1.3 Handshake Integration**: Server-side flights, handshake secret installation, metadata exposure (`HandshakeMetadata`, `on_handshake_metadata`, `on_peer_finished`), ClientHello PSK offer capture, and application secret derivation complete. Outstanding: wiring metadata callbacks into the outer QUIC connection, client-role Finished handling, certificate authentication, alert mapping, and the remaining session resumption/0-RTT work (ticket issuance, binder validation, resumption secrets).
- **Platform Backends**: kqueue/IOCP backends need parity testing and tuning once TLS work settles.

### Platform Specific

- **Linux**: Full support including ECN, PMTUD via ICMP
- **macOS**: Full support with kqueue
- **Windows**: Basic support (IOCP event loop is stub only)

## Test Coverage

- **Unit tests**: Record layer, TLS handshake context, transport parameters, and recovery suites run under `zig build test` with selective filters during TLS development.
- **Interop tests**: Deferred; internal harnesses simulate loopback handshakes with synthetic Finished messages.
- **Planned additions**: certificate negative tests, client-role Finished tampering cases, QUIC/TLS integration fuzzers, and broader regression coverage once TLS milestones land.

## Minimal HTTP/3 status (in-repo)

- Implemented minimal HTTP/3 server path: control stream + SETTINGS; HEADERS (QPACK static-only) + DATA (/www/index.html)
- Parser captures :path and decodes static-indexed :method
- H3 loopback test passes in-process

## Architecture Decisions

### Memory Management

- Arena allocators for connection state
- Zero-copy packet processing where possible
- Efficient buffer management with minimal allocations

### Modularity

- Clean separation between transport, crypto, and application layers
- Modules registered in build.zig to avoid duplicate compilation
- Platform-specific I/O backends (epoll/kqueue/IOCP)

### Security

- Constant-time crypto operations
- Side-channel resistant header protection
- Proper key zeroization when retired
- Vendored Ed25519 for production-grade signatures

## Summary

The project delivers a robust QUIC transport foundation while actively expanding its TLS 1.3 integration. Server-side handshake flights, metadata callbacks, and Finished verification are now in place, enabling the next slices: certificate handling, client-role paths, and QUIC wiring. Additional testing, fuzzing, and interop validation remain before declaring production readiness.
