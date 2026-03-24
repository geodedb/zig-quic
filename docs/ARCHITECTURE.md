# Architecture Overview

Last updated: 2026-03-24

This document describes the high-level structure of the QUIC implementation
for new contributors.  For RFC mapping details see `IMPLEMENTATION_STATUS.md`;
for security posture see `GAP_ANALYSIS.md`.

## Repository Layout

```
src/quic/
  config.zig            QuicConfig (shared knobs, no dependency cycles)
  conn.zig              Connection struct (state + monolithic helpers)
  connection/           Modular Connection methods (mixin pattern, see below)
  endpoint.zig          Endpoint (UDP listener, connection map, timer loop)
  endpoint/             Modular Endpoint sub-modules
    client.zig          Client-side connection creation
    server.zig          Server-side connection creation
    incoming.zig        Initial/Handshake packet processing pipeline
    handshake_integration.zig  TLS <-> QUIC transport-parameter glue
    pto.zig             PTO probe construction
    frame_handler.zig   Frame dispatch after decryption
    timer.zig           Timer queue management
    transport.zig       UDP transport abstraction
  transport.zig         High-level QuicTransport / QuicClient API
  api.zig               Public API surface (re-exports)
  frame.zig             DEPRECATED monolithic frame codec (see frame/)
  frame/                Modular frame codec (production)
    frame.zig           Root re-export
    types.zig           FrameType enum, AckRange, etc.
    ack.zig             ACK frame encode/decode
    crypto.zig          CRYPTO frame
    stream.zig          STREAM frame
    flow_control.zig    MAX_DATA / MAX_STREAM_DATA / *_BLOCKED
    connection_mgmt.zig NEW_CONNECTION_ID / RETIRE_CONNECTION_ID
    path.zig            PATH_CHALLENGE / PATH_RESPONSE
    misc.zig            PING, PADDING, CONNECTION_CLOSE
    datagram.zig        DATAGRAM (RFC 9221)
  recovery.zig          DEPRECATED monolithic recovery (see recovery/)
  recovery/             Modular recovery (production)
    recovery.zig        Root: Recovery struct, timer integration
    types.zig           SentPacket, CongestionState
    rtt.zig             RTT estimator (RFC 9002 S5)
    loss_detection.zig  Loss detection (RFC 9002 S6)
    congestion.zig      NewReno + CUBIC congestion control
  packet.zig            Monolithic packet codec (Initial, Handshake, 1-RTT)
  packet/               Modular packet codec (in progress)
  crypto_quic.zig       QUIC-specific AEAD wrappers (Initial/HP protect)
  token.zig             Retry / NEW_TOKEN token generation & verification
  transport_params.zig  Transport parameter encoding/decoding (RFC 9000 S18)
  varint.zig            QUIC variable-length integer codec (RFC 9000 S16)
  logger.zig            Debug-only logger with secret redaction
  algorithms/           Standalone algorithm modules (Geode extraction)
    congestion_newreno.zig  NewReno (standalone, not yet wired to prod)
    loss_recovery.zig       Loss detection (standalone)
    timer_heap.zig          Bounded timer heap
    sharding.zig            Seeded Wyhash connection sharding
    drr.zig                 Deficit Round Robin scheduler
  io/                   Platform I/O backends
    loop_epoll.zig      Linux epoll event loop
    loop_kqueue.zig     macOS kqueue event loop
    loop_iocp.zig       Windows IOCP event loop
```

## The Mixin Pattern

`conn.zig` defines the `Connection` struct with all state fields.  Method
implementations live in `connection/methods_a.zig`, `methods_b.zig`, and
`methods_c.zig`.  Each file exports a `bind(comptime Connection: type) type`
function that returns a struct of methods operating on `*Connection`.  The
monolithic `conn.zig` then re-exports each method:

```zig
// conn.zig (inside pub const Connection = struct { ... })
const methods_a = @import("connection/methods_a.zig").bind(@This());
pub const send = methods_a.send;
pub const openStream = methods_b.openStream;
// ...
```

This avoids Zig's file-size compilation limits while keeping `Connection` a
single type.  New methods should be added to the smallest methods file or a
new `methods_d.zig` following the same pattern.

## Monolithic vs Modular Migration

Several subsystems exist in both monolithic (`src/quic/X.zig`) and modular
(`src/quic/X/`) forms.  The **build system** (`build.zig`) wires the modular
versions as the `quic_frame` and `quic_recovery` build modules -- those are
what production and test code imports.  The monolithic files are retained for
reference but are deprecated.

| Subsystem | Monolithic       | Modular (active)       | Status       |
|-----------|------------------|------------------------|--------------|
| Frame     | `frame.zig`      | `frame/frame.zig`      | Migrated     |
| Recovery  | `recovery.zig`   | `recovery/recovery.zig`| Migrated     |
| Packet    | `packet.zig`     | `packet/packet.zig`    | In progress  |

The `algorithms/` directory contains standalone, independently-tested modules
extracted for potential reuse.  They are **not yet wired** to production code
paths and may diverge from the active `recovery/` implementations.

## Thread Safety Model (3-Tier Locking)

```
Tier 1: Endpoint.mu          (coarsest -- protects connection map, accepted queue)
Tier 2: Endpoint.timer_mu    (protects timer queue and next_timer_id)
Tier 3: Connection.mu        (per-connection -- protects streams, keys, flow control)
```

**Lock ordering rule:** `Endpoint.mu` -> `Connection.mu`.  Never acquire
`Endpoint.mu` while holding `Connection.mu`.  `timer_mu` is independent and
must not be held across callbacks that may re-enter timer scheduling.

Public API methods (e.g., `writeStream`, `readStream`) acquire `Connection.mu`
internally.  Endpoint methods that iterate the connection map hold
`Endpoint.mu` and may then acquire `Connection.mu` on individual connections.

## Key Data Flows

### Packet RX (server)

```
UDP recv -> Endpoint.processIncomingDatagram()
  -> parse long header (version, type)
  -> Initial?  -> incoming.processInitial()
       -> lookup/create Connection
       -> decrypt with Initial keys
       -> extract CRYPTO frames -> feed TLS engine
       -> derive Handshake keys on ServerHello
       -> send ACK + server flight
  -> Handshake? -> incoming.processHandshake()
       -> decrypt with Handshake keys
       -> extract CRYPTO frames -> complete TLS handshake
       -> derive 1-RTT keys
  -> 1-RTT (short header)?
       -> decrypt with app keys (current or next phase)
       -> frame_handler dispatches STREAM / ACK / FC / etc.
       -> push data to Connection.streams_rx
```

### Packet TX (application write)

```
Application -> Connection.writeStream(id, data, fin)
  -> flow-control check (stream + connection level)
  -> if pn_app.have_any: prepend ACK frame (piggyback)
  -> encode STREAM frame after ACK in same buffer
  -> encrypt coalesced frames with current TX keys
  -> UDP sendTo (direct or paced via sender callback)
  -> track SentPacket for loss detection / retransmission
```

### Loss Recovery / PTO

```
Endpoint.fireExpiredTimers()
  -> PTO timer fires
  -> sendPtoProbe() -> re-send PING or oldest unacked CRYPTO
  -> reschedule PTO with exponential back-off
ACK received -> Recovery.onAck()
  -> update RTT estimates
  -> detect lost packets (time + reordering threshold)
  -> retransmit lost STREAM/CRYPTO frames
  -> update congestion window (NewReno or CUBIC)
```

## Frame Coalescing

RFC 9000 Section 13.2.1 recommends that endpoints include an ACK frame in
every ACK-eliciting packet.  STREAM frames are ACK-eliciting, so every
STREAM packet is an opportunity to piggyback acknowledgment information.

### Current Implementation: ACK Piggybacking in STREAM Packets

`writeStreamUnlocked` (methods_b.zig) prepends an ACK frame before the
STREAM frame in every 1-RTT packet when `pn_app.have_any` is true (i.e.,
when the connection has received at least one app-space packet to
acknowledge).  The ACK frame is built from the same `buildAckApp()` and
`getAckDelayEncoded()` helpers used by the standalone ACK path in
`generateAndSendAck()`.

This provides two benefits without changing the standalone ACK send path:

1. **Redundant acknowledgment** -- if a standalone ACK packet is lost, the
   piggybacked ACK in the next STREAM packet ensures the peer still
   receives timely acknowledgment.  This speeds loss recovery at the peer.
2. **Reduced ACK-only datagrams** -- once the peer receives the piggybacked
   ACK, it may suppress its own redundant ACK-only sends, reducing overall
   UDP datagram count.

The ACK frame is written first in the frame buffer because non-ack-eliciting
frames (ACK) should precede ack-eliciting frames (STREAM) by convention.
Both frames share the 2048-byte `frame_storage` stack buffer; a typical ACK
frame is 5-20 bytes, leaving ample room for the STREAM payload.

### Future Coalescing Opportunities

Additional frame types can be piggybacked into STREAM packets using the
same pattern (write into `frame_stream` before the STREAM frame):

| Frame Type         | Trigger Condition                          | Insertion Point          |
|--------------------|--------------------------------------------|--------------------------|
| MAX_DATA           | `local_max_data > last_sent_max_data`      | Before STREAM            |
| MAX_STREAM_DATA    | Dirty per-stream FC via `pending_fc_streams`| Before STREAM            |
| MAX_STREAMS_BIDI   | `local_max_streams_bidi` bumped            | Before STREAM            |
| NEW_CONNECTION_ID  | `pending_new_cid` bitset has entries       | Before STREAM            |

These follow the same approach used in `generateAndSendAck` (module_b2.zig)
where MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, and NEW_CONNECTION_ID are
already piggybacked into ACK packets.  Extending this to STREAM packets
would further reduce standalone control datagrams.

**Not planned:** Full PacketBuilder abstraction or GSO (Generic Segmentation
Offload).  The per-frame piggybacking approach is sufficient for the current
single-stream-per-packet architecture.

## Configuration

`QuicConfig` in `config.zig` is the single entry point for all tunable knobs.
Fields are documented with their RFC section.  Key fields:

- `version`: Wire version (v1 / v2)
- `alpn`: Required ALPN list
- `cc`: Congestion control algorithm (newreno / cubic)
- `enable_retry`: Server-side Retry token validation
- `exempt_localhost`: Loopback anti-amplification bypass (default true)
- `allow_insecure`: Skip certificate verification (testing only)
- `require_client_cert`: mTLS mode

Configuration values are copied into `Connection` fields at creation time
(see `client.zig`, `server.zig`, `incoming.zig`) so that per-connection
behavior is immutable after setup.
