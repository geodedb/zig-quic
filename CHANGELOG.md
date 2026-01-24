# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
