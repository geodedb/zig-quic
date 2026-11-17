# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.54] - 2026-11-16

### Fixed

- Lost NEW_CONNECTION_ID frames are sent again (RFC 9000 §13.3; SONNY-6655, NEWGAP-21). The server advertises its first connection IDs in the packet that carries HANDSHAKE_DONE, which was not recorded for control-frame retransmission, and NEW_CONNECTION_ID was resent from no lost packet: when that packet was lost the client held 3 of the server's 7 connection IDs for good. Packets carrying NEW_CONNECTION_ID (the HANDSHAKE_DONE packet, ACK packets) are now recorded like the flow-control frames of SONNY-6486, and a lost one is sent again while the connection ID is not retired; such an ACK packet now counts as ack-eliciting, which it is.
- Connection IDs the peer retires are retired with RETIRE_CONNECTION_ID (RFC 9000 §5.1.2; SONNY-6655, NEWGAP-02). An increased Retire Prior To removed the peer's connection IDs below it locally, but the peer was never told and short headers kept going to the peer's initial connection ID. The retired sequence numbers, the initial one included, are now sent in RETIRE_CONNECTION_ID frames, sent again when lost (§13.3), short headers use the peer's newest connection ID once its initial one is retired (`shortHeaderDcid`, now also used by the ACK paths), and a NEW_CONNECTION_ID below a Retire Prior To already received is retired at once. More than 16 retirements waiting to be sent is a CONNECTION_ID_LIMIT_ERROR. A NEW_CONNECTION_ID whose Retire Prior To is greater than its sequence number is a FRAME_ENCODING_ERROR (RFC 9000 §19.15). NEW_CONNECTION_ID and RETIRE_CONNECTION_ID are handled under `Connection.mu`. `activePeerCid` returned a slice into a copy of the connection ID on its own stack frame; with short headers now using it, release builds sent packets to garbage connection IDs. It now points into the connection.
- `flush_cadence` and `datagram_batch` no longer return placeholder numbers when they cannot measure (SONNY-6656, NEWGAP-24). A client that did not start, a connect or handshake that failed or timed out, a run with no sample (a starved server) and a non-Linux host gave one iteration in 1 ms with latency 0, which passed the perf gate against the same placeholder; they now return a not-measured row (`ClientStartFailed`, `ConnectFailed`, `HandshakeTimeout`, `NoSamples`, `UnsupportedPlatform`), which `bench-compare` fails (SONNY-4381).
- The client issues connection IDs (RFC 9000 §5.1.1; SONNY-6668). Only the server did, when it sent HANDSHAKE_DONE; a client never gave the server a connection ID beyond its initial one, so the server could not switch to another (for migration, or to retire the initial one). The client now issues them up to the server's active_connection_id_limit when the handshake is confirmed and sends them at once; they are resent if lost (SONNY-6655).
- `quic-client` exits 1 when its request/response stream does not complete (no handshake confirmation, request not written, or no response), and waits about 20 s for the handshake and the write and 10 s for the response instead of up to 50 s each (SONNY-6668).
- The remaining benchmarks no longer return placeholder numbers on a platform they cannot measure on (SONNY-6668): `stream_throughput`, `handshake_e2e`, `poll_overhead`, `conn_scale`, `udp_batch`, `micro/connection_lookup` and the external tier (quic-go, quinn, aioquic) return a not-measured `UnsupportedPlatform` row off Linux (`common.requireLinux`), like `flush_cadence` and `datagram_batch`. The external tier's `-SKIP` rows for a missing toolchain are unchanged.
- The bench suite compiles for macOS and Windows again (SONNY-6669). `benchmarks/common.zig` used `std.time.Timer` and `benchmarks/integration/_helpers.zig` `std.Thread.sleep`, both removed in Zig 0.16; nothing noticed, because the suite was only ever built for Linux. They now use the `std.Io` clock and sleep.

### Security

- No two packets share a packet number, and so an AEAD nonce, while the handshake completes (RFC 9000 §12.3, RFC 9001 §5.3; SONNY-6654, NEWGAP-23). v0.1.53 put every steady-state 1-RTT sender under `Connection.mu` (SONNY-4379), but the step that completes the handshake still sent without it: the server's HANDSHAKE_DONE packet (`sendHandshakeDoneControl`, from `pushCrypto`) and `deriveAppKeys`, which replaces the 1-RTT keys and sends flow-control credit and HANDSHAKE_DONE. A server application writing the moment its keys are usable (a connection is accepted on its first Initial) sent concurrently with that packet: over 40 handshakes, 67 server packet numbers were used twice, in every connection. Both now take `Connection.mu` (lock order `endpoint_rx_serial_mu` -> `tls_context_mu` -> `Connection.mu`), as do the CONNECTION_CLOSE for a malformed Initial frame (a 1-RTT packet once the keys exist), the unused `handshake_integration.sendHandshakeDone`, and the qns interop client's keep-alive probe. Initial and Handshake packets are numbered on the receive path under `endpoint_rx_serial_mu`, and the Initial/Handshake PTO probes now take it too (without waiting: when the receive path has the connection the probe is re-armed), so a probe can no longer take the packet number of a packet the receive path is sending.

### CI

- The interop-test job starts a fresh network simulator for every case, as the quic-interop-runner does, and is required again (SONNY-6656, NEWGAP-20). It started the simulator once for all four cases; reused with new endpoint containers on the same addresses, the simulator forwarded nothing, and every case after the first failed whichever implementations ran (quic-go against quic-go failed the same way). The three failures blamed on the Zig client and server in v0.1.53 were this: with a fresh simulator per case, v0.1.53 and this release pass all four cases (Zig and quic-go, server and client, handshake and transfer).
- e2e-test-zig drives one request/response stream between the Zig client and server and fails unless the client receives the echo (`scripts/e2e_zig.sh`; SONNY-6668). It passed `--addr`, which `quic-client` ignores (it dialled the default 127.0.0.1:4433), offered ALPN h3 to a server serving hq-interop, and passed whenever the server logged a connection: no handshake ever completed.
- quality-zig-gates runs `zig build test-bench-common` (SONNY-6668).
- A new bench-cross-compile job runs `scripts/bench_cross_compile.sh`: `zig build bench-build` (every bench executable, compiled, not run) for x86_64 and aarch64 Linux, macOS and Windows (SONNY-6669). The macOS and Windows runtime smoke jobs run the `poll_overhead` scenario and require every row to be not measured (`UnsupportedPlatform`); the macOS job also runs when `benchmarks/` change.

### Tests

- `zig build test-sonny6655-cid-retransmission` (SONNY-6655): the relay drops the server's 1-RTT datagrams until it has sent HANDSHAKE_DONE (before: the client learned 3 of 7 connection IDs; after: 7), and, after the client asks the server to retire its connection IDs below its newest one, opens server packets with the server's keys and drops the first carrying RETIRE_CONNECTION_ID (before: none was ever sent; after: it is sent again, the client retires the connection ID and the server sends to the newest one).
- `zig build test-key-update-ooo-pn-gap` and `zig build test-key-update-stress` (SONNY-6656): the two key update tests that were never compiled, rewritten for the three-PTO previous-key window (RFC 9001 §6.5) and the send-side update rule of SONNY-6522, through a real client endpoint's receive path. `test_key_update_lifecycle.zig` (full test graph) confirms the handshake before expecting a key update (NEWGAP-16).
- `zig build test-sonny6654-handshake-pn` (SONNY-6654): 40 handshakes through the loopback relay while the server application writes from the moment it accepts the connection; the relay records every 1-RTT datagram (`ShortLog`) and the test reads the server's packet numbers afterwards. Before: 67 duplicates. After: none.
- `zig build test-sonny6668-client-new-cid` (SONNY-6668): the relay drops the client's 1-RTT datagrams until it has confirmed the handshake. Before: the client issued no connection ID. After: it issues them, and the server holds them once the path recovers. `zig build test-bench-common` covers `common.requireLinux`.
- `zig build bench-build` and `scripts/bench_cross_compile.sh` (SONNY-6669): before, all four macOS and Windows targets failed to compile; after, all six targets compile.

## [0.1.53] - 2026-11-16

### Fixed

- 1-RTT packet numbers are long enough for the packets in flight (SONNY-6649, NEWGAP-14). Every 1-RTT packet used a 2-byte packet number, which the receiver decodes relative to the largest it received (RFC 9000 Appendix A.3). After more than 2^15 consecutive lost packets the next one decoded 65536 too low, its AEAD nonce was wrong, and so was every later packet's: the connection was dead. The loopback congestion-window exemption lets a sender have that many packets in flight. The length now follows RFC 9000 §17.1 and Appendix A.2 against the largest acknowledged packet number (at least 2 bytes, so the common case is unchanged); the encoder takes the packet number as u64.
- Lost STREAM data is retransmitted a full packet at a time (RFC 9000 §13.3; SONNY-6649). Each lost packet's STREAM frame went out again alone, at most two per ACK, so a sender of small frames needed one packet per lost frame: after the 33000-packet blackout of the packet-number test, a client that wrote faster than it read its own ACKs retransmitted 63000 16-byte frames in 63000 packets, which on a 2-vCPU runner did not finish within a minute (main pipeline 3073168754). Lost packets whose data continues on the same stream are now sent together, up to the size of a new STREAM packet: 693 packets, and about 2 s of recovery instead of 17 s on a quiet host. The coalesced packet replaces them in the retransmission tracking; an ACK for one of the original packets no longer releases it, since it acknowledges only part of its data.
- A stream retransmission is protected with the keys its key phase says (SONNY-6649, NEWGAP-15). Up to two lost packets are retransmitted per ACK with keys copied once; when the first started a key update, the second carried the new key phase and the old keys, and the peer could not decrypt it. Under the receive path of v0.1.52 such a packet, opened by the current keys despite its other phase bit, also promoted the receiver's keys to a generation the sender had not reached.
- No key update is initiated before the handshake is confirmed (RFC 9001 §6.1; SONNY-6649, NEWGAP-16). A client can send 1-RTT data before HANDSHAKE_DONE confirms the handshake, and initiated a key update after 512 such packets.
- HANDSHAKE_DONE is sent again until acknowledged (RFC 9000 §13.3; SONNY-6649, NEWGAP-17). It was sent once: when that packet was lost the client never confirmed the handshake.
- The previous receive keys are kept for three PTOs after the key update (RFC 9001 §6.5; SONNY-6649, NEWGAP-18). They were kept until 16 packets had been opened with them: packets reordered behind more than 16 of the new generation were dropped however soon they came, and without reordering the old keys stayed for the life of the generation.
- Small STREAM frames behind a lost packet are no longer a flow control error (RFC 9000 §4.1; SONNY-6649, NEWGAP-19). The receiver allowed 16384 buffered out-of-order segments per stream, one per frame, and closed the connection with FLOW_CONTROL_ERROR beyond that: with 16-byte frames, after 256 KiB of a 16 MiB window. Contiguous out-of-order data is now one segment, so the limit counts the gaps in the received data, and a flood of tiny gapped segments is still refused. Bytes a buffered run already holds are not buffered again: a spurious retransmission into a stream window filled behind a hole would otherwise have been counted twice and closed the connection with FLOW_CONTROL_ERROR.

- A benchmark scenario that cannot measure says so and fails the perf gate (SONNY-4381). Without `tests/certs` (or with certificates that do not parse) `handshake_e2e`, `stream_throughput`, `flush_cadence` and `datagram_batch` returned placeholder numbers (one iteration in 1 ms, latency 0), which passed the gate against the same placeholder. They now return a not-measured row (`ResultRow.not_measured`: `CredentialsMissing`, `CredentialsInvalid` or `ServerStartFailed`), and `bench-compare` reports `NOT-MEASURED` and exits 1 for such a row on either side.

### Security

- No two 1-RTT packets share a packet number, and so an AEAD nonce (RFC 9000 §12.3, RFC 9001 §5.3; SONNY-4379). Packets are numbered from `pn_app_tx` under `Connection.mu`, but some senders did not take it, and a packet they sent could get the number of one an application thread was sending: a geode server sent a FIN and another packet both numbered 189, quic-go dropped the second as a duplicate, and response pages were lost. Now under `Connection.mu`: PATH_RESPONSE, the MAX_DATA answer to DATA_BLOCKED, the DATAGRAM echo and every CONNECTION_CLOSE sent by the receive path; the HANDSHAKE_DONE resent for a late Handshake packet; the PATH_CHALLENGE sent on a peer address change; `openStream` (STREAMS_BLOCKED; `openStreamUnlocked` for callers holding the mutex), `sendDatagram`, `api.close`/`closeConnection`; the endpoint's stale- and dead-connection closes; the PMTUD probe (NEWGAP-22). With a server closing 600 streams while PATH_CHALLENGEs arrive, 74 server packet numbers were used twice; now none.
- An undecryptable 1-RTT packet costs one header protection removal and at most one AEAD open (SONNY-6649, NEWGAP-13). The receive path tried every DCID length 0..20 with the current, next and previous keys and a "hybrid" of them, then 21 forced next-key attempts: about 85 decryption attempts per packet for anyone who knows a connection ID and its peer's address. The DCID length is known from the connection lookup (RFC 9000 §17.3.1) and the header protection key does not change with a key update (RFC 9001 §6), so the key phase bit now selects the keys (RFC 9001 §6.3, §6.5). This also ends the key promotion of a packet that the current keys opened with the other key phase bit.

### CI

- `.install-zig` installs ca-certificates when the CA bundle is missing, so a job with Zig cached but dependencies not yet fetched no longer fails with TlsInitializationFailed (SONNY-6650).
- `stress-integration-20x` creates the test certificate pair and rejects not-measured rows (SONNY-4381); it used to pass on placeholder rows.
- The interop-test job generates the certificate the servers load and fails when a case fails (SONNY-6649). It reported success whatever happened, and no case got as far as a handshake: the quic-go server found no certificate, and the Zig server could not read its fallback key, which `run_endpoint.sh` generated as root before running the endpoint as the `quic` user (fixed). A case now passes when the client exits 0 and every requested file arrived intact. Three of the four cases fail, on v0.1.52 as well (NEWGAP-20); the job stays `allow_failure`.

### Tests

- `zig build test-rx-packet-protection` (SONNY-6649): real endpoints over the loopback UDP relay of SONNY-6522 (now `tests/udp_relay.zig`, which can also capture, inject, hold back and filter datagrams). Covers forged packets on a live connection's path, a 33000-packet blackout (recovered with at most one retransmission packet per 500 bytes sent), key updates while the server's 1-RTT packets are dropped, packets reordered across a key update and released within or after the server's retention period, 22000 16-byte frames behind a held-open hole, and server packet numbers while FINs race PATH_CHALLENGE answers (SONNY-4379).
- `zig build test-bench-compare` (SONNY-4381): a not-measured row on either side makes `bench-compare` exit 1.

## [0.1.52] - 2026-11-15

### Changed

- thread-pool v0.2.11 and tls v0.1.28 (SONNY-6630, the thread-pool diamond cascade). tls v0.1.28 pins the same thread-pool. Only the lazy otel v0.1.28 dependency still pins tls v0.1.24 and thread-pool v0.2.9; it is re-pinned in a later release.

### Fixed

- A long transfer no longer dies after a burst loss right after a key update (SONNY-6522, NEWGAP-12). Two defects let one endpoint's send keys get two generations ahead of the peer's receive keys, after which the peer could decrypt nothing it sent: the receiver kept polling, the sender kept probing, and no packet was ever acknowledged again. The stalls of the 16/64 MiB loopback transfers under CPU starvation ("key-phase desync" with the key phase bits different, and "PTO probes that never reach the connection" with them equal) were both this.
  - A key update counted as acknowledged when the packet that triggered it, still protected with the old keys, was acknowledged: `onShortHeaderPacketSent` ran the update check before advancing the packet number, so the update's first packet number was the old-key packet's. The next update then needed no acknowledgement at all and came 512 packets later, even if every one of them was lost. RFC 9001 §6.1 forbids a subsequent update until a packet sent with the current keys is acknowledged; the update now starts at the next packet number. The duplicate copy of `maybeTriggerKeyUpdateOnSend` in `methods_c.zig` was removed.
  - Responding to the peer's key update compared key phase bits, so when our own update was already ahead of what we received the response moved the send keys once more, to a generation the peer had never seen. The connection now counts send and receive key generations (`tx_key_gen`, `rx_key_gen`) and moves the send keys only when they are behind the receive keys (RFC 9001 §6.2).
- A server endpoint's port can no longer be taken over by a second socket (SONNY-6522, NEWGAP-12). The UDP socket was bound with SO_REUSEADDR, which on Linux lets another socket that sets it bind the same address and port while the first is open; unicast datagrams then go to the newer socket only. A second endpoint on a live server's port (a concurrent run of the same tests, a restarted process overlapping the old one) took over its clients: they completed the handshake and every packet was acknowledged, but the first server's `tryAccept` never returned the connection. This was the "accepted connection never reaches `tryAccept`" stall. SO_REUSEADDR is no longer set (UDP has no TIME_WAIT, so a closed port rebinds without it); binding a port in use now fails with `error.BindFailed`.
- The client takes an RTT sample from the handshake (SONNY-6522, NEWGAP-11). The server acknowledged the client's Initial after sending its ServerHello flight, which gave the client Handshake keys and made it drop its Initial keys, so the acknowledgement was discarded unread and the client confirmed the handshake without an RTT sample. Its first application PTO then used the 333 ms initial RTT, about 1 s (RFC 9002 §6.2.2): on loopback a request lost right after the handshake was resent after ~1 s. The server now acknowledges the client's Initial before sending its flight (RFC 9002 §5.1, RFC 9000 §13.2.1); the lost request is resent in ~0.1 s.

### Security

- Another local user could take over a QUIC server's traffic by binding its UDP port (SONNY-6522). With SO_REUSEADDR on the server socket, Linux let any process that also set it bind the same address and port, with no user check, and delivered the server's unicast datagrams to that process instead. Binds are now exclusive (see Fixed).

### Tests

- `zig build test-long-transfer-liveness` (SONNY-6522): real endpoints over a loopback UDP relay that removes header protection to see each packet's key phase and drops chosen datagrams. It drops the first 2000 packets of the first updated key generation, uploading and downloading 4 MiB, and checks that no second update is sent before the first is acknowledged; checks the client's handshake RTT sample; and checks that a second endpoint cannot bind a live server's port.

## [0.1.51] - 2026-11-13

### Fixed

- Long-lived connections no longer slow down with every request or keep sending when idle. On v0.1.49, 1100 sequential request/response streams on one loopback connection went from ~14 ms to ~490 ms per exchange and timed out at the 262nd, and the idle connection sent ~4500 packets/s in each direction. Three defects (SONNY-6478):
  - Every received datagram with an ECN mark, which is nearly all of them, owed an ACK, including datagrams carrying only an ACK, so two endpoints exchanged ACK-only packets forever, one more exchange per request. An ECN mark now only updates the counts reported in the next ACK; RFC 9000 §13.2.1 forbids answering a non-ack-eliciting packet with one.
  - The Application PTO timer is armed once and not moved on each send or ACK, and on expiry it always sent a probe, even with everything acknowledged. Each probe re-armed it, so an idle connection sent a PING (or the oldest tracked STREAM data) every PTO forever. On expiry the PTO is now checked against its RFC 9002 §6.2.1 deadline, the send time of the most recent ack-eliciting packet plus the backed-off PTO (`Recovery.ptoDeadlineNs`); a timer that is early is re-armed and one with nothing in flight is dropped. Lost STREAM data waiting for retransmission is still probed for. A peer that does not send `max_ack_delay` now gets the RFC 9000 §18.2 default of 25 ms in the PTO, so a request whose ACK the server delays is no longer resent.
  - Stream state was never released. A stream is now retired once both directions are finished (RFC 9000 §3: all data and the FIN acknowledged or the stream reset, and everything read or the stream reset); `closeStream`'s FIN is tracked and retransmitted like data. A retired peer-initiated stream returns stream-count credit (RFC 9000 §4.6), so a connection is no longer limited to 1000 streams in its lifetime: MAX_STREAMS is sent once half of the initial limit has been returned and immediately on STREAMS_BLOCKED. Late frames for a retired stream are ignored, `readStream` returns 0 and `isStreamFinished` true for it, and writes fail with `StreamStopped`. Applications need not call `teardownStream`.
- A stream carrying more than its receive window no longer slows to a crawl (SONNY-6475). Out-of-order data was appended to a list that was sorted and walked in full for every received packet, so after one early loss in a 16 MiB window each packet cost a sort of up to ~12,000 buffered segments: the receiver fell behind, its socket overflowed, and every new hole made it worse. On loopback in a Debug build 64 MiB on one stream ran at about 1 MiB/s and did not finish in 34 s; it now runs at about 4 MiB/s, the same rate as 16 MiB. Segments are now kept sorted by offset (binary-search insertion) and draining touches only the contiguous prefix. A retransmission that overlaps data already received is trimmed instead of dropped whole, which lost its new bytes when a peer resent with different frame boundaries.
- Loss detection follows RFC 9002 more closely (SONNY-6454). The time threshold has the 1 ms kGranularity floor (§6.1.2): with a sub-millisecond RTT, packets whose ACK was still on its way were declared lost, resent and the window cut. Only packets sent before an acknowledged packet can be lost (§6.1), by packet or time threshold, on an ACK or on the loss timer; packets above the largest acknowledged, or sent before anything was acknowledged, wait for the PTO instead. Acknowledging only packet 0 now sets the largest acknowledged and takes an RTT sample. Persistent congestion (§7.6.2) needs a run of lost packets spanning the period with no packet between them acknowledged; it used to be declared over any two lost packets, even across acknowledged ones, collapsing the window to two packets. The Application PTO honours its exponential backoff (§6.2.1, see the SONNY-6478 entry): the 100 ms cap now only bounds how often the timer wakes.
- Lost MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS and RESET_STREAM frames are sent again (RFC 9000 §13.3; SONNY-6486). They used to be sent once: a lost MAX_STREAMS could leave a long-lived connection stuck at its stream limit, and a lost MAX_STREAM_DATA a transfer larger than the stream window (the lossy-loopback test stalled at exactly 16 MiB). Each 1-RTT packet carrying them is recorded until acknowledged; when lost (by the rule used for STREAM data) the flow-control frames are resent with their current value and RESET_STREAM as is. ACK packets that carry MAX_* frames are now counted as ack-eliciting, which they are.
- STREAM_DATA_BLOCKED is acknowledged (it is ack-eliciting, RFC 9002 §2) and answered with the current MAX_STREAM_DATA when the peer has not seen all the credit (RFC 9000 §4.1); on a stream we cannot receive on it is STREAM_STATE_ERROR (SONNY-6486). It used to be ignored: a sender blocked on flow control whose last data packets were lost got no ACK that could reveal the loss, and with each STREAM_DATA_BLOCKED restarting its PTO the transfer stalled.
- The ACK Delay field is encoded with this endpoint's own exponent (RFC 9000 §18.2, §19.3); it used the peer's, so a peer advertising a non-default exponent read our ACK delays wrong. `Connection.local_ack_delay_exponent` and `local_max_ack_delay_ms` (defaults 3 and 25 ms) are advertised when changed, and the delayed-ACK timer uses our own maximum (SONNY-6486).
- STREAM data that a PTO re-sent is no longer sent again after the peer acknowledges the original packet (SONNY-6478 follow-up). The ACK for the original packet number did not find the data, which was tracked under the new one, so if that copy was lost the delivered data went out a third time. Earlier packet numbers of re-sent data are now remembered until the data is acknowledged under any of them; the work per ACK stays bounded by the smaller of the packet numbers it covers and the re-sent packets in flight. `Connection.retx_diag` (off by default) counts retransmissions of already-acknowledged data for tests.
- `connect` reports why a host name did not resolve. The client resolver reads only /etc/hosts (there is no DNS resolution) and does not support IPv6 zone ids; both cases failed as `error.InvalidAddress`, the error for malformed input. A well-formed name that is not in /etc/hosts now fails with `error.HostNotFound`, a zone id (`[fe80::1%eth0]:443`) with `error.UnsupportedZoneId`, and a host containing characters not allowed in a host name with `error.InvalidAddress`. The limitation is documented on `api.connect`; resolve names yourself and pass a numeric address when DNS is needed. DNS and zone-id support remain open.
- A connection whose handshake was slow no longer stops probing for lost data (RFC 9002 §6.4, A.11). Initial and Handshake packets stayed in flight after their keys were discarded, and the PTO backoff their probes raised, shared with application data, was never reset. On a CPU-starved runner a slow handshake left hundreds of them in flight with the backoff above 300, so the application PTO deadline was effectively infinite and a lost request or reply was never sent again (27 of 32 high-parallel clients timed out in the v0.1.51 MR pipeline). This was latent before this release, because the application PTO fired every 100 ms whatever its deadline; the RFC 9002 deadline introduced above exposed it. Discarding a space now removes its packets from bytes in flight and resets the backoff.
- Initial and Handshake PTO probes are sent at the RFC 9002 §6.2.1 deadline (NEWGAP-10). Their timers wake at least every 100 ms and used to probe on every wake-up: a client with no reachable server sent 29 Initial packets in 1.5 s instead of 3, and each wake-up raised the PTO backoff shared with application data. This, more than the stale in-flight packets, is what left the application PTO deadline effectively infinite on the starved runner: there the clients had not yet dropped their handshake keys, so discarding the spaces alone did not reset the backoff.

### Security

- A peer could make the library free memory with the wrong length (SONNY-6486). A RESET_STREAM whose final size cut through buffered out-of-order data was accepted; the buffered segment was shortened in place and later freed with the shortened length. RFC 9000 §4.5 now applies on every path: a RESET_STREAM or FIN whose final size is below data already received or differs from a known final size, and STREAM data past a known final size (also after a reset or once the stream was read), close the connection with FINAL_SIZE_ERROR. The final size of a RESET_STREAM counts against flow control (FLOW_CONTROL_ERROR past the limit), a RESET_STREAM for a peer stream beyond our stream limit is STREAM_LIMIT_ERROR, and one for a send-only or unopened local stream, like STOP_SENDING for a receive-only stream, is STREAM_STATE_ERROR. A FINAL_SIZE_ERROR or STREAM_LIMIT_ERROR found in a STREAM frame used to drop the packet without an ACK or a close; it now closes the connection. Buffered segments are always freed with their allocated length. STOP_SENDING on a stream with nothing sent answers with final size 0 instead of stream 0's offset.
- A failed `connect` no longer leaves a freed connection registered with the endpoint (found by geode-client-zig on v0.1.50). When a step after registration failed, for example dialling an IPv6 address from an IPv4-bound endpoint, the connection was freed but stayed in the endpoint's connection map and PTO-dirty set, so the next poll or endpoint deinit used it after free (or freed it twice). It is now torn down through the endpoint like `api.destroy`, and `createClientConnection` no longer leaks the connection when CID generation fails.
- PEM parsing (`api.pem`) no longer leaks the output buffer when the base64 does not decode, and wipes every buffer that held private-key material (the base64 scratch copy, reserved up front so it never reallocates, and a partly decoded key) with `std.crypto.secureZero` before freeing it.

### CI

- The paired perf gate copies the locally generated `tests/certs/*.pem` into the baseline worktree, so its TLS integration rows measure the baseline instead of comparing against a placeholder (SONNY-6454).

## [0.1.50] - 2026-11-13

### Changed

- tls v0.1.27 (client chain completion from configured CAs; a double free on a failed client CertificateVerify is fixed; RFC 8446 exporter and HkdfLabel sizes) (SONNY-6457).

### Added

- `QuicConfig.inline_client_ca_der`: the DER CA certificates a server trusts for client certificates (mTLS). Every server connection hands them to its TLS context as `trusted_ca_der`, so only those CAs are trusted for client certificates and, with a tls release that completes client chains, a client that sends only its leaf is verified against them. The server used to pass no anchors, leaving client-certificate validation to the process-global trust store (SONNY-6457).

## [0.1.49] - 2026-11-12

### Fixed

- ACK processing no longer does work proportional to the packets in flight, which stalled bulk transfers of more than about 11 MB (Geode remote `backup create` stopped at about 46%, with the server's network thread down to about 80 packets/s). Every application-space ACK walked the whole STREAM retransmit map, and for every entry recovery no longer tracked, `Recovery.getPacketDeliveryState` scanned every sent packet: millions of steps per ACK once thousands of packets were in flight. The retransmit map now keeps its packet numbers in ascending order, so an ACK visits only the entries its ranges cover plus at most the two it retransmits, oldest first, below the largest acknowledged (RFC 9002 §6.1). `getPacketDeliveryState` uses its index only. Recovery takes the ACK frame's ranges (`Recovery.onAckRangesReceivedWithEcn`) instead of at most 256 enumerated packet numbers, so an ACK covering more packets no longer leaves the rest to be declared lost and cut the congestion window. A retransmission whose send fails now stops that ACK's retransmit pass instead of re-encoding every remaining lost packet; the data stays tracked for the next ACK or PTO (SONNY-6434).
- Recovery no longer does work proportional to the tracked packets on every send and every ACK. Once 4096 packets were tracked, recording each packet compacted the list and rebuilt its packet-number hash index twice while the writer held the connection lock (about 0.9 ms per packet in a Debug build), and every ACK rescanned and re-indexed the whole set, so the server's receive path fell behind and Geode's acceptor watchdog restarted it mid-backup. Tracked packets are now kept sorted by packet number and looked up by binary search; the cap drops the oldest eighth at once; and for packets recorded in send order loss detection walks only the lost prefix (both RFC 9002 §6.1 thresholds select a prefix), with the full scan kept for out-of-order input. Loss-detection results are unchanged (SONNY-6434).

## [0.1.48] - 2026-10-28

### Fixed

- Fix a use-after-free in the server's pending-handshake retry (`pollWithStats` Phase 4.5). The retry snapshotted connection pointers from `pending_hs_send_set` and used them after dropping the set's lock, without `Endpoint.mu` or an endpoint RX pin, so a concurrent `api.destroy` / `api.destroyBatch` could free a connection mid-retry, and a `NoHandshakeKeys` retry re-inserted the freed pointer for the next poll. The retry now pins each connection while it is still in the set; destroy waits for the pin exactly as for an RX poll worker, and connections already being destroyed are dropped from the set instead of retried.
- Keep the client's Finished when its UDP submission returns `WouldBlock` (EAGAIN on a full socket send buffer). TLS hands the Finished to QUIC once, and the client used to free it on any send failure, before a retransmit copy existed, so nothing could resend it: the server never verified the client and the connection stalled until the idle timeout. The client now holds the bytes in `pending_hs_messages`, queues the connection on the endpoint's bounded pending-handshake retry (previously server-only), and marks the Finished sent only after a submission succeeds (SONNY-4791, carried over from !56).
- Serialize `closeStream`, `resetStream` and the STOP_SENDING response with stream writes. They emitted a packet without holding the connection lock, so a concurrent writer could take the same packet number, which also reuses the AEAD nonce (SONNY-4776).
- macOS/BSD: put the UDP socket into non-blocking mode with `O_NONBLOCK`. The old code passed `SOCK_NONBLOCK` (a socket-creation flag, a Zig-only shim on Darwin) to `F_SETFL`, which could leave `recvfrom` blocked after a batch was drained; `fcntl` failures are now reported. Timestamps and sleeps go through the portable `compat` helpers instead of Linux syscalls, and the self-signed certificate helper no longer uses the global single-threaded `Io`, whose allocator always fails.

### CI

- The paired perf gate builds each micro benchmark suite as its own executable (`zig build bench-isolated`) once both compared commits support it. Changes to unrelated code no longer move a micro suite's hot loops in the shared `bench` binary, which had failed `micro/aead chacha20_poly1305` on an endpoint-only change (!80). Thresholds and rows are unchanged.

## [0.1.47] - 2026-10-24

### Fixed

- Stop freeing lost STREAM data before it is retransmitted. Recovery forgets a packet as soon as it declares it lost, so a lost packet and an acknowledged one looked the same to the "prune below largest ACK" pass, which then freed the lost data. A burst of losses bigger than the two-packets-per-ACK retransmit budget left a permanent hole in the stream, and the transfer stalled. This happened on hosts whose kernel caps the UDP receive buffer at about 212 KB (the Docker/AWS `net.core.rmem_max` default), where Geode `backup create` hung at 0%. Acknowledged STREAM packets are now released by ACK range membership, which also covers ACKs that span more than the 256 packet numbers passed to recovery.

### Security

- Rust clients: tokio 1.53.3 (RUSTSEC-2026-0386, `AsyncFd::new` I/O-safety unsoundness).

### CI

- Drop the GitLab enterprise SAST, dependency-scanning, and secrets scanner components. Gitleaks, SBOM scanning, cargo-audit, govulncheck, and safety still run, and the remaining CI catalog components are pinned to a commit.

## [0.1.46] - 2026-10-20

### Fixed

- Keep the client's Handshake keys and its Finished retransmission data until the handshake is confirmed (HANDSHAKE_DONE), per RFC 9001 §4.9.2. The client used to drop them as soon as it installed 1-RTT keys, so a lost client Finished could never be retransmitted: the server never got 1-RTT keys and dropped every request the client sent. The Handshake PTO probe now resends the Finished.

### Security

- Rust clients: rustls-webpki 0.103.16 (RUSTSEC-2026-0382) and webpki-root-certs 1.0.10 (RUSTSEC-2026-0383).

### CI

- `create-release` authenticates with the CI job token instead of `GITLAB_TOKEN`, so tag pipelines create the GitLab release.

## [0.1.45] - 2026-10-13

### Changed

- Update dependencies: tls v0.1.24, thread_pool v0.2.9, otel v0.1.28 (lazy) and fips v0.1.3 (lazy). These are the versions the rest of the devnw/zig ecosystem's newest tags pin, so downstream graphs converge without diamonds. The Python test clients move to aioquic 1.6.1.
- The micro performance gate (`quality-zig-gates`) is now noise-tolerant. A regression must exceed absolute floors (p95 by more than 3 ns, per-op time by more than 1 ns), and with `PERF_GATE_ROUNDS > 1` it must reproduce: rounds are captured in alternating order, and every HEAD round must be worse than every baseline round. See `docs/PERFORMANCE_TARGETS.md#noise-tolerance`.

### Fixed

- Fix a deadlock between connection teardown and endpoint poll workers. `Endpoint.destroyConnections` (`api.destroy` / `api.destroyBatch`) waited for a connection's in-flight RX refs while the caller held `Endpoint.mu`, and a poll worker holding such a ref needed `Endpoint.mu` (`maybeQueueDeferredAccepted`) before releasing it. Teardown now detaches the connection under `mu`, releases `mu` while waiting for the ref to drain, then re-acquires it to free the connection. A doomed connection is never published to the accept queue, and destroy now also clears the closed / PTO-dirty / pending-handshake side sets. The lock order is documented on `Endpoint.mu`.
- Preserve every received datagram of a mixed receive batch within the existing processing quotas (receive-tail accounting).
- `fips-deps`: fetch pinned OpenSSL release keys from keyserver.ubuntu.com when keys.openpgp.org serves them without user IDs.

### Notes

- v0.1.41 to v0.1.44 were tagged from a side branch (GAP-0838 grpc_zig convergence) whose only dependency change, otel v0.1.24, is superseded here. v0.1.45 is the first tag since v0.1.40 that is cut from `main`.

## [0.1.40] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5, config v0.1.13 (GAP-0838 diamond sync).

## [0.1.39] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5 (GAP-0838 diamond sync).

## [0.1.29]

### Fixed

- **Acceptor-wedge RC-A iteration 2: actually BOUND the kernel rx-queue under a
  reconnect storm.** v0.1.28 decoupled a larger socket-drain cap from the
  processing budget, but on the `v0.6.27-30` k8s gate the rx_queue still reached
  ~11.4 MB (above the 8 MiB watchdog → `exit(70)`) — because draining was still
  gated behind the **256-Initial, ep.mu-serialized processing budget**: with 16
  poll workers each grinding 256 new-connection Initials under the global
  endpoint mutex before reaching the cheap lock-free shed phase, almost none were
  draining the socket. Two changes:
  - **Decouple the Initial PROCESSING budget** from `server_max_packets_per_poll_cycle`
    and drop it to **one UDP batch (64)** (`maxInitialPacketsPerPollCycleForRole`,
    new runtime knob `setServerInitialProcessingBudget` / geode
    `GEODE_QUIC_INITIAL_BUDGET`). A worker now processes ≤64 new Initials per
    cycle then SHEDS the rest (lock-free read-and-discard; client PTO
    retransmits), so the lock-free shed-drain engages almost immediately and the
    socket actually drains. This is load-shedding backpressure: under a reconnect
    storm new connections are admitted at a steady bounded rate while the kernel
    buffer stays drained. Normal load is unaffected (the budget is only hit when
    Initials exceed one batch/cycle).
  - **Raise the socket-drain cap** to `UdpBatchCap*256` = 16384 so a single poll
    cycle can empty a full 16 MiB `SO_RCVBUF` rather than leaving a tail.
  - Regression assertions added to `tests/test_acceptor_drain_budget.zig`
    (Initial budget ≤ one batch; drain cap ≥ 16× it; setter round-trip). RED on
    the old 256-Initial budget.

## [0.1.28]

### Fixed

- **Acceptor-wedge RC-A: decouple the per-poll socket-DRAIN cap from the
  per-class PROCESSING budgets so the kernel UDP rx_queue stays bounded under a
  connection-kill / reconnect storm.** `pollWithStats` used a single master cap
  (`maxPacketsPerPollCycleForRole`) for both how many datagrams it *read* from
  the socket and how many Initials it *processed*. Because the Initial-processing
  budget equalled the master cap, the loop stopped reading at the exact point it
  stopped processing, so the "shed surplus Initials" fast path never ran — a
  reconnect storm let the listener `:PORT` UDP rx_queue back up to the geode
  acceptor-watchdog 8 MiB threshold and the pod self-restarted (`exit(70)`),
  which under churn cascaded into a no-leader cluster livelock (geode
  `docs/bugs/2026-06-03-acceptor-wedge-connection-burst-new-conns-refused.md`,
  `docs/bugs/2026-06-04-cluster-raft-no-stable-quorum-writes-time-out.md`).
  A new server socket-drain cap (`maxSocketDrainPacketsForRole`, default
  `UdpBatchCap * 64` = 4096, enough to drain a full 16 MiB `SO_RCVBUF` in a
  couple of cycles) is now the master read cap; the Initial/short-header
  PROCESSING budgets are unchanged, so surplus Initials beyond the processing
  budget are cheaply shed (client PTO retransmits) and the kernel buffer drains
  independent of how much expensive work the cycle can afford. Client behaviour
  is unchanged (one-batch fairness budget). Runtime-tunable for k8s churn
  validation without a rebuild via `setServerSocketDrainPackets`
  (geode `GEODE_QUIC_DRAIN_PACKETS`).
  - New public API: `setServerSocketDrainPackets`, `serverSocketDrainPackets`,
    `serverInitialProcessingBudget` (exported through `api.zig` + `lib.zig`).
  - Regression test `tests/test_acceptor_drain_budget.zig`
    (`zig build test -Dtest-filter=acceptor_drain_budget`).

## [0.1.0] - 2026-01-24

### Added

#### 0-RTT Implementation
- Complete 0-RTT data transmission and reception
- `encode0RTTProtected` and `decode0RTTProtected` functions in `packet.zig`
- 0-RTT keys derivation from resumption secret
- Support for variable packet number lengths (1-4 bytes)
- Comprehensive test coverage in `test_0rtt.zig`

#### Session Resumption
- Full PSK (Pre-Shared Key) support in TLS 1.3 engine
- Session ticket storage and retrieval mechanism
- Resumption secret derivation from master secret
- PSK binder computation for ClientHello
- Ticket age obfuscation support
- Tests in `test_resumption.zig`

#### Connection Migration
- Complete connection migration state machine
- PATH_CHALLENGE and PATH_RESPONSE frame handling
- NAT rebinding detection and handling
- Multiple path management support
- Migration state transitions (None -> Probing -> Validated/Failed)
- Comprehensive tests in `test_connection_migration.zig`

#### Preferred Address
- `PreferredAddress` structure per RFC 9000
- `parsePreferredAddress` function for transport parameters
- Support for both IPv4 and IPv6 addresses
- Connection ID and stateless reset token extraction
- Tests in `test_preferred_address.zig`

#### Test Infrastructure
- 4 new comprehensive test files added
- All 63 tests now passing
- Full integration with build system
- Regression test coverage for new features

#### Documentation
- Comprehensive IMPLEMENTATION_STATUS.md
- Updated GAP.md with complete feature matrix
- Enhanced README with implementation highlights
- Detailed interop testing documentation

#### Interoperability
- Interoperability test infrastructure
- Docker compose configuration for 18 QUIC implementations
- GitHub Actions workflows for automated testing
- QUIC v2 support
- ChaCha20-Poly1305 cipher suite
- Multiconnect test case support

#### Core Implementation
- Core QUIC v1 implementation
- Basic TLS 1.3 integration
- Initial packet types (Initial, Handshake, Short)
- Frame parsing and serialization
- Loss recovery and congestion control
- Stream management
- Flow control
- Varint encoding/decoding
- CLI tools (quic-client, quic-server, quic-varint)
- Initial test suite
- RFC 9000 transport protocol basics
- RFC 9001 TLS integration
- RFC 9002 loss recovery
- AES-128-GCM encryption
- X25519 key exchange
- NewReno congestion control
- Basic ECN support

### Changed
- Updated `cmd/qns-endpoint.zig` to support all test cases
- Enhanced `build.zig` with new test integrations
- Improved error handling in packet processing
- Optimized memory allocation patterns
- Enhanced transport parameter negotiation
- Improved connection ID rotation
- Updated ALPN handling

### Fixed
- Connection ID management in short headers
- Key update retention window
- ECN counter tracking
- Path validation timing

[Unreleased]: https://gitlab.com/devnw/quic/-/compare/v0.1.0...HEAD
[0.1.0]: https://gitlab.com/devnw/quic/-/releases/v0.1.0
