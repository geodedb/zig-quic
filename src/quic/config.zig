// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Shared QUIC configuration types (no dependencies on api/endpoint to avoid cycles)
//!
//! Unless otherwise noted, field level comments cite the RFC section that
//! motivated the exposed knob so integrators can reconcile behaviour with the
//! transport (RFC 9000), TLS binding (RFC 9001), or recovery (RFC 9002) text.
const std = @import("std");

/// Configuration for a QUIC endpoint and connections.
///
/// The defaults follow RFC 9000 §7 and §10 for handshake/path timeouts, RFC 9001
/// §4 for TLS, and RFC 9002 §7 for congestion-control specific parameters.
pub const QuicConfig = struct {
    // Wire version selection (RFC 9000 §6: version negotiation)
    version: enum { v1, v2 } = .v1,
    /// Required. Application-Layer Protocol Negotiation identifiers sent in the
    /// TLS ClientHello/ServerHello (RFC 9001 §4.2). At least one ALPN must be
    /// provided; the QUIC handshake will fail without it.
    ///
    /// Examples: `&.{"h3"}` for HTTP/3, `&.{"hq-interop"}` for interop testing.
    alpn: []const []const u8,
    // Congestion control selection (RFC 9002 §3)
    cc: enum { newreno, cubic } = .newreno,
    // Feature toggles (RFC 9221 §4 for DATAGRAM, RFC 9000 §17.4 for spin bit)
    enable_datagram: bool = false,
    enable_spin_bit: bool = false,
    // RFC 8701: GREASE compliance for transport parameters
    grease: bool = true,
    // RFC 9368 Compatible Version Negotiation toggle
    compatible_vn: bool = false,
    // Retry configuration (server) (RFC 9000 §8.1: stateless retry)
    enable_retry: bool = true,
    // MAC secret for Retry/NEW_TOKEN tokens (RFC 9000 §8.1.4)
    token_secret: ?[]const u8 = null,
    token_expiry_ms: u32 = 60000,
    // Optional pacing (RFC 9002 §6.7 suggests pacing to reduce bursts)
    enable_pacing: bool = false,
    // Congestion-control max_datagram_size per RFC 9002 §7.3. Default 1200.
    max_datagram_size: u16 = 1200,
    // Transport idle timeout (RFC 9000 §10.1) and UDP payload limit (RFC 9000 §14.1)
    max_idle_timeout_ms: u32 = 30000,
    max_udp_payload: u16 = 1350,
    // TLS certificate chain/key (server) and trust anchors (client) (RFC 9001 §4.4)
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
    ca_path: ?[]const u8 = null,
    /// Controls TLS certificate validation only. When true, self-signed and
    /// expired certificates are accepted. Does NOT affect Retry integrity
    /// verification, connection ID matching, or amplification protection.
    /// For development and testing only — never enable in production.
    /// (RFC 9001 §4.4)
    allow_insecure: bool = false,
    // AEAD usage limit overrides (tests/dev). RFC 9001 §6.6 supplies defaults.
    aead_confidentiality_limit_override: ?u64 = null,
    aead_integrity_limit_override: ?u64 = null,
    // Maximum concurrent connections (RFC 9000 §8.1 rate-limiting recommendation).
    // Protects against DoS via unbounded connection creation. 0 = unlimited.
    max_connections: usize = 10000,
    // Inline test/server certificate and raw P-256 private key (DER cert, 32-byte scalar) (RFC 9001 §4.4)
    inline_server_cert_der: ?[]const u8 = null,
    inline_server_priv_p256: ?[]const u8 = null,
    // mTLS: Server requests client certificate (RFC 8446 §4.3.2, RFC 9001 initial handshake only)
    require_client_cert: bool = false,
    // mTLS: Client certificate and private key (DER-encoded) for mutual authentication
    inline_client_cert_der: ?[]const u8 = null,
    inline_client_priv_key: ?[]const u8 = null,
    // Exempt localhost (127.0.0.1 / ::1) from anti-amplification and address validation.
    // Default true preserves existing behaviour; set false to enforce strict RFC 9000 §8.1
    // amplification limits even on loopback (useful for conformance testing). (#124)
    exempt_localhost: bool = true,
    // RFC 8446 §8 / RFC 9001 §9.2: enable server-side 0-RTT anti-replay cache.
    // When true the server maintains a bounded ticket-hash cache and rejects
    // replayed 0-RTT data. Default true for production safety; set false only
    // for testing or when the application layer handles replay protection.
    zero_rtt_anti_replay: bool = true,
};
