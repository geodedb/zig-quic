# Design Overview

This project targets a production-grade QUIC (RFC 9000/9001/9002) library and CLI tools in Zig 0.14.1 using only the Zig standard library.

Key principles:

- std-only cryptography via std.crypto; implement TLS 1.3 subset in-repo.
- Strict parsing, constant-time crypto, zeroization of secrets.
- Event loop abstraction over epoll/kqueue/IOCP using std.os.
- Separation of transport, crypto, recovery, and congestion control.
- Deterministic tests/fuzz seeds for reproducibility.

Initial slices build bottom-up: varint, frames, key schedule KATs, then handshake and transport machinery.

## Runtime Key Update (TLS 1.3 + QUIC binding)

- TX direction:
  - Maintain app_tx_secret and app_tx_keys. Trigger update after thresholds (packets/bytes).
  - Derive next secret via HKDF-Expand-Label("traffic upd"); derive key/iv/hp per QUIC v1/v2.
  - Toggle tx_key_phase bit for short headers; retain previous tx keys until any packet number in new phase is ACKed, then zeroize.
- RX direction:
  - Attempt decrypt with current app_rx_keys. On failure, derive next from app_rx_secret and attempt; on success, promote: move current to rx_prev_keys, set rx_prev_allow to a bounded window, set app_rx_keys/app_rx_secret to next, toggle rx_key_phase.
  - If next fails but rx_prev_keys exist, accept with previous and decrement rx_prev_allow. When allowance reaches zero, zeroize and clear rx_prev_keys.
- Security:
  - All key material is zeroized when retired. No secrets are logged.
  - Promotion occurs only on successful decryption/authentication of a short packet using derived-next keys.
