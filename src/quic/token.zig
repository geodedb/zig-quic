// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

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
    const data_to_sign = token[0..pos]; // Everything before HMAC
    const expected_hmac = token[pos .. pos + 32];

    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    var computed_hmac: [32]u8 = undefined;
    Hmac.create(&computed_hmac, data_to_sign, secret);

    // Constant-time comparison
    return std.crypto.timing_safe.eql([32]u8, computed_hmac, expected_hmac[0..32].*);
}

// =============================================================================
// Phase 4b.5 Session 5: Initial Packet Token Validation Helpers
// =============================================================================

/// Extract IP address bytes from socket address for token validation.
/// RFC 9000 §8.1.2: "The token MUST allow the server to validate that the client address is correct."
///
/// Parameters:
/// - addr: Socket address structure
///
/// Returns:
/// - Slice containing IP address bytes (4 for IPv4, 16 for IPv6)
pub fn extractIpBytes(addr: std.posix.sockaddr) []const u8 {
    if (addr.family == std.posix.AF.INET) {
        const sin: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&addr));
        const ip_bytes = std.mem.asBytes(&sin.addr);
        return ip_bytes[0..4];
    } else if (addr.family == std.posix.AF.INET6) {
        const sin6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(&addr));
        const ip_bytes = std.mem.asBytes(&sin6.addr);
        return ip_bytes[0..16];
    } else {
        return &[_]u8{}; // Unknown address family
    }
}

/// Validate a token from an Initial packet.
/// RFC 9000 §8.1.4: "A server validates a client address using a token."
///
/// This is a convenience wrapper around verify() that extracts the client IP
/// from a socket address and uses the current time.
///
/// Parameters:
/// - token: Token bytes from Initial packet
/// - client_addr: Client socket address
/// - secret: Secret key for HMAC
///
/// Returns:
/// - true if token is valid and not expired, false otherwise
pub fn validateInitialToken(
    token: []const u8,
    client_addr: std.posix.sockaddr,
    secret: []const u8,
) bool {
    const client_ip = extractIpBytes(client_addr);
    if (client_ip.len == 0) return false; // Unknown address family

    const now_ms = @as(u64, @intCast(std.time.milliTimestamp()));
    return verify(token, client_ip, secret, now_ms);
}

/// Check if server should send Retry based on token presence and validity.
/// RFC 9000 §8.1.2: "Servers SHOULD use address validation by sending a Retry
/// packet or by sending data to a validated address."
///
/// Returns true if the server should send a Retry packet to validate the client address.
///
/// Parameters:
/// - has_token: Whether the Initial packet contains a token
/// - token: Token bytes (if has_token is true)
/// - client_addr: Client socket address
/// - secret: Secret key for HMAC
/// - require_retry: Server policy: always require Retry for new connections
///
/// Returns:
/// - true if server should send Retry, false if address is validated
pub fn shouldSendRetry(
    has_token: bool,
    token: []const u8,
    client_addr: std.posix.sockaddr,
    secret: []const u8,
    require_retry: bool,
) bool {
    // If no token, decide based on policy
    if (!has_token) {
        return require_retry;
    }

    // Token present: validate it
    const is_valid = validateInitialToken(token, client_addr, secret);

    // Send Retry if token is invalid
    return !is_valid;
}

/// Generate a Retry token for a client.
/// RFC 9000 §8.1.2: "A Retry packet includes a Retry token that can be
/// validated by the server."
///
/// This is a convenience wrapper around encode() for generating Retry tokens.
///
/// Parameters:
/// - allocator: Memory allocator
/// - client_addr: Client socket address
/// - dcid: Original Destination Connection ID from client's first Initial
/// - secret: Secret key for HMAC
/// - validity_ms: Token validity period (typically 60000-180000 ms)
///
/// Returns:
/// - Allocated token bytes (caller must free), or error
pub fn generateRetryToken(
    allocator: std.mem.Allocator,
    client_addr: std.posix.sockaddr,
    dcid: []const u8,
    secret: []const u8,
    validity_ms: u64,
) ![]u8 {
    const client_ip = extractIpBytes(client_addr);
    if (client_ip.len == 0) return error.UnsupportedAddressFamily;

    return try encode(allocator, client_ip, dcid, secret, validity_ms);
}

/// Module marker for Phase 4b.5 Session 5 token validation.
pub const session_5_token_validation = true;

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

// =============================================================================
// Phase 4b.5 Session 5: Token Validation Helper Tests
// =============================================================================

test "RFC 9000 §8.1.2 - extractIpBytes extracts IPv4 address" {
    var addr: std.posix.sockaddr = undefined;
    addr.family = std.posix.AF.INET;
    const sin: *std.posix.sockaddr.in = @ptrCast(@alignCast(&addr));
    sin.addr = @bitCast([4]u8{ 192, 168, 1, 100 });

    const ip_bytes = extractIpBytes(addr);
    try testing.expectEqual(@as(usize, 4), ip_bytes.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 100 }, ip_bytes);
}

test "RFC 9000 §8.1.2 - validateInitialToken validates correct token" {
    const secret = "test-secret-for-initial-validation";
    const dcid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    // Create IPv4 address
    var addr: std.posix.sockaddr = undefined;
    addr.family = std.posix.AF.INET;
    const sin: *std.posix.sockaddr.in = @ptrCast(@alignCast(&addr));
    sin.addr = @bitCast([4]u8{ 10, 0, 0, 1 });

    const client_ip = extractIpBytes(addr);
    const validity_ms = 60000;

    // Generate token for this client
    const token = try encode(test_allocator, client_ip, &dcid, secret, validity_ms);
    defer test_allocator.free(token);

    // Validate token
    try testing.expect(validateInitialToken(token, addr, secret));
}

test "RFC 9000 §8.1.2 - validateInitialToken rejects token from different IP" {
    const secret = "test-secret-for-initial-validation";
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };

    // Create token for one IP
    var addr1: std.posix.sockaddr = undefined;
    addr1.family = std.posix.AF.INET;
    const sin1: *std.posix.sockaddr.in = @ptrCast(@alignCast(&addr1));
    sin1.addr = @bitCast([4]u8{ 192, 168, 1, 1 });

    const client_ip1 = extractIpBytes(addr1);
    const validity_ms = 60000;
    const token = try encode(test_allocator, client_ip1, &dcid, secret, validity_ms);
    defer test_allocator.free(token);

    // Try to validate from different IP
    var addr2: std.posix.sockaddr = undefined;
    addr2.family = std.posix.AF.INET;
    const sin2: *std.posix.sockaddr.in = @ptrCast(@alignCast(&addr2));
    sin2.addr = @bitCast([4]u8{ 192, 168, 1, 2 });

    try testing.expect(!validateInitialToken(token, addr2, secret));
}

test "RFC 9000 §8.1.2 - shouldSendRetry returns true when no token and policy requires it" {
    const secret = "test-secret";
    var addr: std.posix.sockaddr = undefined;
    addr.family = std.posix.AF.INET;

    const empty_token: []const u8 = &[_]u8{};
    const require_retry = true;

    try testing.expect(shouldSendRetry(false, empty_token, addr, secret, require_retry));
}

test "RFC 9000 §8.1.2 - shouldSendRetry returns false when no token and policy allows it" {
    const secret = "test-secret";
    var addr: std.posix.sockaddr = undefined;
    addr.family = std.posix.AF.INET;

    const empty_token: []const u8 = &[_]u8{};
    const require_retry = false;

    try testing.expect(!shouldSendRetry(false, empty_token, addr, secret, require_retry));
}

test "RFC 9000 §8.1.2 - shouldSendRetry returns false when valid token present" {
    const secret = "test-secret-for-retry-check";
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    var addr: std.posix.sockaddr = undefined;
    addr.family = std.posix.AF.INET;
    const sin: *std.posix.sockaddr.in = @ptrCast(@alignCast(&addr));
    sin.addr = @bitCast([4]u8{ 172, 16, 0, 1 });

    const client_ip = extractIpBytes(addr);
    const validity_ms = 60000;

    // Generate valid token
    const token = try encode(test_allocator, client_ip, &dcid, secret, validity_ms);
    defer test_allocator.free(token);

    // With valid token, should not send Retry regardless of policy
    try testing.expect(!shouldSendRetry(true, token, addr, secret, true));
    try testing.expect(!shouldSendRetry(true, token, addr, secret, false));
}

test "RFC 9000 §8.1.2 - shouldSendRetry returns true when invalid token present" {
    const secret = "test-secret-for-retry-check";
    const wrong_secret = "wrong-secret";
    const dcid = [_]u8{ 0x05, 0x06, 0x07, 0x08 };

    var addr: std.posix.sockaddr = undefined;
    addr.family = std.posix.AF.INET;
    const sin: *std.posix.sockaddr.in = @ptrCast(@alignCast(&addr));
    sin.addr = @bitCast([4]u8{ 10, 1, 2, 3 });

    const client_ip = extractIpBytes(addr);
    const validity_ms = 60000;

    // Generate token with wrong secret
    const token = try encode(test_allocator, client_ip, &dcid, wrong_secret, validity_ms);
    defer test_allocator.free(token);

    // Invalid token should trigger Retry
    try testing.expect(shouldSendRetry(true, token, addr, secret, true));
    try testing.expect(shouldSendRetry(true, token, addr, secret, false));
}

test "RFC 9000 §8.1.2 - generateRetryToken creates valid token" {
    const secret = "test-secret-for-retry-generation";
    const dcid = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const validity_ms = 120000; // 2 minutes

    var addr: std.posix.sockaddr = undefined;
    addr.family = std.posix.AF.INET;
    const sin: *std.posix.sockaddr.in = @ptrCast(@alignCast(&addr));
    sin.addr = @bitCast([4]u8{ 203, 0, 113, 42 });

    const token = try generateRetryToken(test_allocator, addr, &dcid, secret, validity_ms);
    defer test_allocator.free(token);

    // Verify the generated token is valid
    try testing.expect(validateInitialToken(token, addr, secret));
}

test "RFC 9000 §8.1.2 - generateRetryToken fails for unsupported address family" {
    const secret = "test-secret";
    const dcid = [_]u8{ 0x01, 0x02 };
    const validity_ms = 60000;

    var addr: std.posix.sockaddr = undefined;
    addr.family = 999; // Invalid address family

    const result = generateRetryToken(test_allocator, addr, &dcid, secret, validity_ms);
    try testing.expectError(error.UnsupportedAddressFamily, result);
}
