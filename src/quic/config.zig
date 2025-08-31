//! Shared QUIC configuration types (no dependencies on api/endpoint to avoid cycles)
const std = @import("std");

/// Configuration for a QUIC endpoint and connections.
pub const QuicConfig = struct {
    // Wire version selection
    version: enum { v1, v2 } = .v1,
    // Allowed ALPN protocol IDs
    alpn: []const []const u8,
    // Congestion control selection
    cc: enum { newreno, cubic } = .newreno,
    // Feature toggles
    enable_datagram: bool = false,
    enable_spin_bit: bool = false,
    grease: bool = true,
    // RFC 9368 Compatible Version Negotiation toggle
    compatible_vn: bool = false,
    // Retry configuration (server)
    enable_retry: bool = false,
    token_secret: ?[]const u8 = null, // MAC secret for Retry/NEW_TOKEN
    token_expiry_ms: u32 = 60000,
    // Optional pacing
    enable_pacing: bool = false,
    // Congestion-control max_datagram_size used for initial cwnd and min window (RFC 9002). Default 1200.
    max_datagram_size: u16 = 1200,
    // Transport timeouts and UDP payload limits
    max_idle_timeout_ms: u32 = 30000,
    max_udp_payload: u16 = 1350,
    // TLS paths (server), client trust store
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
    ca_path: ?[]const u8 = null,
    // Allow insecure (skip cert verify) — tests only
    allow_insecure: bool = false,
};
