//! QUIC Address Validation Token Module (RFC 9000 §8.1)
//!
//! This module implements address validation tokens used for:
//! - Retry packets (RFC 9000 §8.1.2)
//! - NEW_TOKEN frames (RFC 9000 §8.1.3)
//!
//! Token Format:
//! - Timestamp (8 bytes, big-endian milliseconds since epoch)
//! - Client IP address (4 or 16 bytes)
//! - Connection ID (variable length)
//! - HMAC-SHA256 (32 bytes) over all previous fields

const std = @import("std");

/// Encode a token for address validation.
/// Returns allocated buffer containing the token.
///
/// RFC 9000 §8.1.2: "To protect against handshake replay, the token SHOULD include information
/// that allows the server to verify that the token was recently generated."
///
/// Parameters:
/// - allocator: Memory allocator
/// - client_ip: Client IP address bytes (4 for IPv4, 16 for IPv6)
/// - dcid: Destination Connection ID
/// - secret: Secret key for HMAC
/// - validity_ms: Token validity period in milliseconds
///
/// Returns: Allocated token bytes (caller must free)
pub fn encode(
    allocator: std.mem.Allocator,
    client_ip: []const u8,
    dcid: []const u8,
    secret: []const u8,
    validity_ms: u64,
) ![]u8 {
    const now_ms = @as(u64, @intCast(std.time.milliTimestamp()));
    const expiry_ms = now_ms + validity_ms;

    // Token layout: timestamp(8) + ip_len(1) + ip + dcid_len(1) + dcid + hmac(32)
    const token_size = 8 + 1 + client_ip.len + 1 + dcid.len + 32;
    const token = try allocator.alloc(u8, token_size);
    errdefer allocator.free(token);

    var pos: usize = 0;

    // Write expiry timestamp (8 bytes, big-endian)
    std.mem.writeInt(u64, token[pos..][0..8], expiry_ms, .big);
    pos += 8;

    // Write IP length and bytes
    token[pos] = @intCast(client_ip.len);
    pos += 1;
    @memcpy(token[pos .. pos + client_ip.len], client_ip);
    pos += client_ip.len;

    // Write DCID length and bytes
    token[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(token[pos .. pos + dcid.len], dcid);
    pos += dcid.len;

    // Compute HMAC-SHA256 over timestamp + ip + dcid
    const data_to_sign = token[0..pos];
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    var hmac_out: [32]u8 = undefined;
    Hmac.create(&hmac_out, data_to_sign, secret);
    @memcpy(token[pos .. pos + 32], &hmac_out);

    return token;
}

/// Verify a token for address validation.
/// Returns true if the token is valid and not expired.
///
/// RFC 9000 §8.1.4: "A server validates a client address using a token by checking
/// that the token signature is valid and that the token is not expired."
///
/// Parameters:
/// - token: Token bytes to verify
/// - client_ip: Client IP address bytes (4 for IPv4, 16 for IPv6)
/// - secret: Secret key for HMAC
/// - now_ms: Current time in milliseconds since epoch
///
/// Returns: true if token is valid, false otherwise
pub fn verify(
    token: []const u8,
    client_ip: []const u8,
    secret: []const u8,
    now_ms: u64,
) bool {
    // Minimum token size: timestamp(8) + ip_len(1) + ip(>=4) + dcid_len(1) + dcid(>=0) + hmac(32)
    if (token.len < 8 + 1 + 4 + 1 + 0 + 32) return false;

    var pos: usize = 0;

    // Read expiry timestamp
    const expiry_ms = std.mem.readInt(u64, token[pos..][0..8], .big);
    pos += 8;

    // Check expiration
    if (now_ms > expiry_ms) return false;

    // Read and verify IP address
    const ip_len = token[pos];
    pos += 1;
    if (pos + ip_len > token.len - 1 - 32) return false; // Ensure space for dcid_len + hmac
    if (ip_len != client_ip.len) return false;
    if (!std.mem.eql(u8, token[pos .. pos + ip_len], client_ip)) return false;
    pos += ip_len;

    // Read DCID length
    const dcid_len = token[pos];
    pos += 1;
    if (pos + dcid_len + 32 != token.len) return false; // Exact size check
    pos += dcid_len; // Skip DCID (we don't validate it, just include in HMAC)

    // Verify HMAC
    const data_to_sign = token[0 .. pos]; // Everything before HMAC
    const expected_hmac = token[pos .. pos + 32];

    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    var computed_hmac: [32]u8 = undefined;
    Hmac.create(&computed_hmac, data_to_sign, secret);

    // Constant-time comparison
    return std.crypto.timing_safe.eql([32]u8, computed_hmac, expected_hmac[0..32].*);
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;
const test_allocator = testing.allocator;

test "encode and verify valid token" {
    const secret = "test-secret-key-for-tokens";
    const client_ip = [_]u8{ 192, 168, 1, 100 };
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const validity_ms = 60000; // 60 seconds

    const token = try encode(test_allocator, &client_ip, &dcid, secret, validity_ms);
    defer test_allocator.free(token);

    const now_ms = @as(u64, @intCast(std.time.milliTimestamp()));
    try testing.expect(verify(token, &client_ip, secret, now_ms));
}

test "verify rejects expired token" {
    const secret = "test-secret-key-for-tokens";
    const client_ip = [_]u8{ 192, 168, 1, 100 };
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const validity_ms = 1; // 1 millisecond

    const token = try encode(test_allocator, &client_ip, &dcid, secret, validity_ms);
    defer test_allocator.free(token);

    // Wait for token to expire
    std.time.sleep(2 * std.time.ns_per_ms);

    const now_ms = @as(u64, @intCast(std.time.milliTimestamp()));
    try testing.expect(!verify(token, &client_ip, secret, now_ms));
}

test "verify rejects wrong IP address" {
    const secret = "test-secret-key-for-tokens";
    const client_ip = [_]u8{ 192, 168, 1, 100 };
    const wrong_ip = [_]u8{ 192, 168, 1, 101 };
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const validity_ms = 60000;

    const token = try encode(test_allocator, &client_ip, &dcid, secret, validity_ms);
    defer test_allocator.free(token);

    const now_ms = @as(u64, @intCast(std.time.milliTimestamp()));
    try testing.expect(!verify(token, &wrong_ip, secret, now_ms));
}

test "verify rejects wrong secret" {
    const secret = "test-secret-key-for-tokens";
    const wrong_secret = "wrong-secret-key-for-tokens";
    const client_ip = [_]u8{ 192, 168, 1, 100 };
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const validity_ms = 60000;

    const token = try encode(test_allocator, &client_ip, &dcid, secret, validity_ms);
    defer test_allocator.free(token);

    const now_ms = @as(u64, @intCast(std.time.milliTimestamp()));
    try testing.expect(!verify(token, &client_ip, wrong_secret, now_ms));
}

test "verify rejects truncated token" {
    const secret = "test-secret-key-for-tokens";
    const client_ip = [_]u8{ 192, 168, 1, 100 };
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const validity_ms = 60000;

    const token = try encode(test_allocator, &client_ip, &dcid, secret, validity_ms);
    defer test_allocator.free(token);

    const now_ms = @as(u64, @intCast(std.time.milliTimestamp()));
    // Try to verify truncated token
    try testing.expect(!verify(token[0 .. token.len - 1], &client_ip, secret, now_ms));
}
