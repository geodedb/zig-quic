# Design Overview

This project targets a production-grade QUIC (RFC 9000/9001/9002) library and CLI tools in Zig 0.14.1 using only the Zig standard library.

Key principles:

- std-only cryptography via std.crypto; implement TLS 1.3 subset in-repo.
- Strict parsing, constant-time crypto, zeroization of secrets.
- Event loop abstraction over epoll/kqueue/IOCP using std.os.
- Separation of transport, crypto, recovery, and congestion control.
- Deterministic tests/fuzz seeds for reproducibility.

Initial slices build bottom-up: varint, frames, key schedule KATs, then handshake and transport machinery.

## ACK handling and ECN propagation

- Frames:
  - ACK (0x02) supports multiple ranges; ACK_ECN (0x03) additionally carries ECN counters {ECT(0), ECT(1), CE} per RFC 9000 §19.3.2.
- Endpoint → Connection → Recovery:
  - On RX, decoded ACK/ACK_ECN frames are forwarded with ranges and optional ECN counts.
  - Connection.onAckReceivedSpace(space, largest, first_range, ranges, ecn: ?EcnCounts) builds the acked PN list and calls Recovery.onAckReceivedWithEcn(..., ecn).
  - Recovery.onAckReceivedWithEcn updates RTT, detects loss (packet/time threshold), and adjusts congestion window; on CE counter increase, cwnd is reduced similar to a loss event with a floor at 2\*max_datagram_size.
  - Recovery.onAckReceived(...) remains as a compatibility wrapper calling the ECN-aware variant with ecn = null for existing tests.
- Outgoing ACKs:
  - Endpoint emits ACK_ECN when the connection reports non-empty ECN counters for the corresponding PN space via Connection.getAckEcn(space).
  - Connection maintains per-space counters (ECT(0), ECT(1), CE) and exposes onEcnMark(space, ecn_bits) for the endpoint to call on packet reception. Until socket ancillary reception is implemented, counters remain zero and ACKs encode as plain ACK (0x02).

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

## AEAD usage limits (RFC 9001 §6.6)

- Counters and limits:
  - Each connection tracks the total number of encrypted application packets sent (confidentiality usage) and the total number of packets that failed authentication on receive (integrity failures).
  - Defaults follow RFC 9001 guidance (e.g., AES-GCM): confidentiality ~2^23 packets; integrity ~2^52 failures. Config overrides allow lowering these for tests.
- Enforcement:
  - RX: On any AEAD authentication failure (Initial/Handshake/1-RTT), the endpoint calls `Connection.onAeadAuthFailure()`, incrementing the integrity counter. When exceeding the integrity limit, the connection is marked closed and the endpoint emits a CONNECTION_CLOSE with AEAD_LIMIT_REACHED (0x0f) and a short reason.
  - TX: Short-header send path increments the encrypted-packet counter. Approaching the confidentiality limit biases an immediate Key Update; if updating is not feasible in future, closing is preferable to exceeding limits.
- Safety:
  - Counters are monotonic per connection. All enforcement and state changes occur without logging secrets, and retired keys are zeroized.

## Address validation & anti-amplification (3x limit)

- Policy:
  - Before a path is validated, a server must not send more than 3x the bytes it has received from that address (RFC 9000 §8.1). Validation is achieved by a Retry/Token, or by PATH_CHALLENGE/PATH_RESPONSE at 1-RTT.
- Implementation:
  - `Connection.canSendUnderAmplification()` and `Connection.overAmplification()` are the only gates used by both the connection and endpoint. They compare using `(tx/3) <= rx` to avoid 64-bit overflow.
  - Counters are updated via saturating helpers `addRxUnvalidated(n)` and `addTxUnvalidated(n)` to avoid wrap. When the address is validated, both counters are reset to 0.
  - Endpoint centralizes path-change transitions in `Endpoint.onPathAddressChanged(...)` and successful validation in `Endpoint.onPathValidated(...)`. These helpers update the peer address, reset counters and flags, refresh the map key for the new peer hash, and trigger/complete PATH validation.
- Notes:
  - The division-based compare has a floor bias of at most 2 bytes relative to the exact `tx > 3*rx` inequality. This bias is acceptable and intentional to prevent overflow when counters approach `u64::MAX`.

## PMTUD and DPLPMTUD

- Probing: Connection can generate MTU probes as exact-size UDP payloads using PING + PADDING. A pending probe records PN and size.
- Validation:
  - ACK-driven: when the probe PN is ACKed in Application space, path_mtu is raised to the probe size.
  - ICMP-driven: Endpoint drains the Linux error queue for IPv4 Frag Needed / IPv6 Packet Too Big. Quoted packets are parsed and spoof-checked (short header DCID must match a known connection) before calling `Connection.onIcmpPacketTooBig(mtu)` to clamp path_mtu.
- State machine: A basic DPLPMTUD state machine (ProbeStart/ProbeSearch) runs via endpoint timers (TimerKind.Pmtud). ACK progression hooks drive searches forward.
- Safety: ICMP processing is optional and guarded; spoof checks prevent off-path PTB from affecting path_mtu. Minimum QUIC datagram size (1200 bytes) is enforced.

## Connection ID Lifecycle & Rotation

Goals: Support migration, stateless reset robustness, and linkability reduction while respecting the peer's `active_connection_id_limit`.

Data structures:

- `local_cids`: fixed-size array of CID slots `{ sequence, cid_bytes, stateless_reset_token, in_use }`.
- `pending_new_cid`: bitset marking which slot indices must be (re)advertised as NEW_CONNECTION_ID.
- Counters: `issued_cids` (number of currently active issued CIDs), `next_cid_sequence` (monotonic sequence allocator), and `retired_prior_to` (inclusive lower bound the peer may retire without further notification).

Issuance:

- `issueNewConnectionId()`: allocate a new slot if under limit; derive CID bytes (random) & stateless reset token (currently SHA-256(base||seq||cid) truncated 16B placeholder); mark pending.
- `issueNewConnectionIdRotating()`: if at limit, select oldest non-zero sequence CID, retire it (mark not in_use, decrement `issued_cids`), advance `retired_prior_to` if all lower sequences retired, then issue a fresh CID as above.

Advertisement:

- `writePendingNewConnectionIds()`: iterates pending bitset, writing one NEW_CONNECTION_ID frame per set bit, each including current `retired_prior_to`.
- Piggyback: ACK send path calls the writer before finalizing packet framing so NEW_CONNECTION_ID frames share packets with ACK / ACK_ECN.
- `flushPendingNewConnectionIds()`: forces emission (e.g., for tests) even without other ack-eliciting frames.

Retirement handling:

- On RETIRE_CONNECTION_ID(frame.sequence), we mark the matching local CID retired, decrement `issued_cids` (except sequence 0 if policy differs), and recompute the minimal contiguous retired prefix to advance `retired_prior_to`.
- Advancement only occurs when all sequences below the new threshold are fully retired to maintain RFC 9000 invariants.

Security considerations:

- Placeholder stateless reset token derivation will be replaced by HKDF using a per-endpoint secret + sequence + CID to avoid direct hash oracle concerns and enable secret rotation.
- Rotation heuristics (time / traffic volume) are pluggable; current implementation performs explicit rotation when invoked by higher-level policy or tests.

Testing:

- Unit tests cover: limit enforcement, pending flush emission, retirement frees slot for reuse, rotation advancing `retired_prior_to` and advertising new CIDs.

Future work:

- Integrate with path migration triggers (issue new CID on validated new path, retire old after stable period).
- HKDF-based token derivation & secret rotation on key update or timer.
- Frame packing optimization (batch multiple NEW_CONNECTION_ID frames while respecting path MTU & congestion window).
