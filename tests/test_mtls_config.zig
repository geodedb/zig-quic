// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! mTLS Configuration Tests
//!
//! Verifies that mTLS config fields exist on QuicConfig and propagate correctly.
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.3.2: CertificateRequest (require_client_cert)
//! - RFC 9001 §4.4: TLS certificate/key for QUIC (inline_client_cert_der, inline_client_priv_key)

const std = @import("std");
const testing = std.testing;
const config = @import("config");

// ============================================================================
// Test 1: QuicConfig has require_client_cert field, defaults to false
// ============================================================================

test "mTLS config: require_client_cert defaults to false" {
    const cfg = config.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
    };
    try testing.expectEqual(false, cfg.require_client_cert);
}

// ============================================================================
// Test 2: QuicConfig has inline_client_cert_der field, defaults to null
// ============================================================================

test "mTLS config: inline_client_cert_der defaults to null" {
    const cfg = config.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
    };
    try testing.expectEqual(@as(?[]const u8, null), cfg.inline_client_cert_der);
}

// ============================================================================
// Test 3: QuicConfig has inline_client_priv_key field, defaults to null
// ============================================================================

test "mTLS config: inline_client_priv_key defaults to null" {
    const cfg = config.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
    };
    try testing.expectEqual(@as(?[]const u8, null), cfg.inline_client_priv_key);
}

// ============================================================================
// Test 4: Config fields can be set to non-default values and read back
// ============================================================================

test "mTLS config: fields set to non-default values" {
    const mock_cert = [_]u8{ 0x30, 0x82, 0x01, 0x00 };
    const mock_key = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    const cfg = config.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .require_client_cert = true,
        .inline_client_cert_der = &mock_cert,
        .inline_client_priv_key = &mock_key,
    };

    try testing.expectEqual(true, cfg.require_client_cert);
    try testing.expectEqualSlices(u8, &mock_cert, cfg.inline_client_cert_der.?);
    try testing.expectEqualSlices(u8, &mock_key, cfg.inline_client_priv_key.?);
}

// ============================================================================
// Test 5: Default config is non-mTLS (all mTLS fields at zero/null)
// ============================================================================

test "mTLS config: default config is non-mTLS" {
    const cfg = config.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
    };

    // All mTLS fields should be at their zero/null defaults
    try testing.expectEqual(false, cfg.require_client_cert);
    try testing.expectEqual(@as(?[]const u8, null), cfg.inline_client_cert_der);
    try testing.expectEqual(@as(?[]const u8, null), cfg.inline_client_priv_key);

    // Server cert fields also default to null (non-mTLS server won't have inline certs either by default)
    try testing.expectEqual(@as(?[]const u8, null), cfg.inline_server_cert_der);
    try testing.expectEqual(@as(?[]const u8, null), cfg.inline_server_priv_p256);
}
