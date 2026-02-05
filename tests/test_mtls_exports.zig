// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! mTLS Export Verification Tests
//!
//! Verifies that the public QUIC module (`lib.zig`) exports all types needed by
//! geode and geode-client-zig consumers for mTLS configuration and usage.
//!
//! ## Consumers
//!
//! - **geode**: Server-side QUIC endpoint — needs QuicConfig with require_client_cert
//! - **geode-client-zig**: Client-side QUIC — needs inline_client_cert_der/inline_client_priv_key

const std = @import("std");
const testing = std.testing;
const quic = @import("quic");

// ============================================================================
// Test 1: quic.QuicConfig is accessible and constructible with mTLS fields
// ============================================================================

test "mTLS exports: QuicConfig accessible with mTLS fields" {
    const cfg = quic.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .require_client_cert = true,
        .inline_client_cert_der = &[_]u8{ 0x30, 0x82 },
        .inline_client_priv_key = &[_]u8{0x01},
    };

    try testing.expectEqual(true, cfg.require_client_cert);
    try testing.expect(cfg.inline_client_cert_der != null);
    try testing.expect(cfg.inline_client_priv_key != null);
}

// ============================================================================
// Test 2: quic.TlsConfig is accessible (geode uses for TLS configuration)
// ============================================================================

test "mTLS exports: TlsConfig type is accessible" {
    // Just verify the type exists and is accessible through the public module
    const T = quic.TlsConfig;
    try testing.expect(@sizeOf(T) > 0);
}

// ============================================================================
// Test 3: quic.pem module is accessible (parseCertificate, parsePrivateKey)
// ============================================================================

test "mTLS exports: pem module is accessible" {
    // Verify the pem module is re-exported
    const P = @TypeOf(quic.pem);
    try testing.expect(@sizeOf(P) >= 0); // Type exists
}

// ============================================================================
// Test 4: quic.DetailedQuicConfig has mTLS fields
// ============================================================================

test "mTLS exports: DetailedQuicConfig has mTLS fields" {
    const cfg = quic.DetailedQuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .require_client_cert = true,
        .inline_client_cert_der = &[_]u8{ 0x30, 0x82 },
        .inline_client_priv_key = &[_]u8{0x01},
    };

    try testing.expectEqual(true, cfg.require_client_cert);
    try testing.expect(cfg.inline_client_cert_der != null);
    try testing.expect(cfg.inline_client_priv_key != null);
}

// ============================================================================
// Test 5: quic.SignatureScheme is accessible (needed for CertificateRequest)
// ============================================================================

test "mTLS exports: SignatureScheme is accessible" {
    // Verify the enum is exported and has expected values
    const ed25519 = quic.SignatureScheme.ed25519;
    try testing.expectEqual(@as(u16, 0x0807), @intFromEnum(ed25519));

    const ecdsa = quic.SignatureScheme.ecdsa_secp256r1_sha256;
    try testing.expectEqual(@as(u16, 0x0403), @intFromEnum(ecdsa));
}
