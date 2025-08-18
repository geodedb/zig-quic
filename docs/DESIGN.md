# Design Overview

This project targets a production-grade QUIC (RFC 9000/9001/9002) library and CLI tools in Zig 0.13.0 using only the Zig standard library.

Key principles:

- std-only cryptography via std.crypto; implement TLS 1.3 subset in-repo.
- Strict parsing, constant-time crypto, zeroization of secrets.
- Event loop abstraction over epoll/kqueue/IOCP using std.os.
- Separation of transport, crypto, recovery, and congestion control.
- Deterministic tests/fuzz seeds for reproducibility.

Initial slices build bottom-up: varint, frames, key schedule KATs, then handshake and transport machinery.
