// MIT License
// Stateless Retry token encode/verify (stub)
const std = @import("std");

/// Stateless Retry token view (opaque bytes in this stub).
pub const Token = struct {
    // Opaque bytes; in real impl include MAC over client IP/DCID and expiration.
    bytes: []const u8,
};

/// Encode a Retry token bound to client_ip and dcid with a secret and expiry. Stub returns empty.
pub fn encode(alloc: std.mem.Allocator, client_ip: []const u8, dcid: []const u8, secret: []const u8, expiry_ms: u64) ![]u8 {
    _ = client_ip;
    _ = dcid;
    _ = secret;
    _ = expiry_ms;
    // TODO: HMAC + expiry; for now return empty token
    return try alloc.alloc(u8, 0);
}

/// Verify a Retry token using client_ip, dcid and secret at time now_ms. Stub always returns true.
pub fn verify(token: []const u8, client_ip: []const u8, dcid: []const u8, secret: []const u8, now_ms: u64) bool {
    _ = token;
    _ = client_ip;
    _ = dcid;
    _ = secret;
    _ = now_ms;
    // TODO: verify HMAC and expiry
    return true;
}
