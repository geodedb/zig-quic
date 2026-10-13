# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Fix a use-after-free in the server's pending-handshake retry (`pollWithStats` Phase 4.5). The retry snapshotted connection pointers from `pending_hs_send_set` and used them after dropping the set's lock, without `Endpoint.mu` or an endpoint RX pin, so a concurrent `api.destroy` / `api.destroyBatch` could free a connection mid-retry, and a `NoHandshakeKeys` retry re-inserted the freed pointer for the next poll. The retry now pins each connection while it is still in the set; destroy waits for the pin exactly as for an RX poll worker, and connections already being destroyed are dropped from the set instead of retried.

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
