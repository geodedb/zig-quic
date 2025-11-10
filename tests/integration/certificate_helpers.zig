//! Certificate Loading Utilities for Integration Tests
//!
//! This module provides utilities for loading test certificates from vendor/ztls/tests/test_certs/.
//! These certificates are used for TLS 1.3 handshake testing in the QUIC integration test suite.
//!
//! ## Certificate Infrastructure
//!
//! The test PKI consists of:
//! - **Root CA**: Self-signed certificate authority (root_cert.pem / root_key.pem)
//! - **Intermediate CA**: Signed by root CA (intermediate_cert.pem / intermediate_key.pem)
//! - **Leaf Certificates**: End-entity certs signed by intermediate CA
//!   - leaf_cert.pem / leaf_key.pem: RSA-2048 certificate for localhost testing
//!   - p256_cert.pem / p256_key.pem: ECDSA P-256 certificate
//!   - ed25519_cert.pem / ed25519_key.pem: Ed25519 certificate
//!
//! ## Usage
//!
//! ```zig
//! const certs = @import("certificate_helpers.zig");
//!
//! // Load server certificate chain for TLS handshake
//! var server_chain = try certs.loadServerCertificateChain(allocator);
//! defer server_chain.deinit(allocator);
//!
//! // Load private key for server
//! const private_key = try certs.loadServerPrivateKey(allocator);
//! defer allocator.free(private_key);
//! ```
//!
//! ## PEM Format
//!
//! Certificates are stored in PEM format (Base64-encoded DER with headers/footers).
//! This module converts PEM to DER format as needed for ztls integration.

const std = @import("std");
const base64 = std.base64;

/// Certificate chain containing leaf and intermediate certificates
pub const CertificateChain = struct {
    /// Leaf certificate (end-entity, server or client)
    leaf: []const u8,

    /// Intermediate CA certificates (chain from leaf to root, excluding root)
    intermediates: []const []const u8,

    /// Deinitialize and free all allocated memory
    pub fn deinit(self: *CertificateChain, allocator: std.mem.Allocator) void {
        allocator.free(self.leaf);
        for (self.intermediates) |cert| {
            allocator.free(cert);
        }
        allocator.free(self.intermediates);
    }
};

/// Base path to test certificates
const cert_base_path = "vendor/ztls/tests/test_certs/";

/// Certificate file paths
const leaf_cert_path = cert_base_path ++ "leaf_cert.pem";
const leaf_key_path = cert_base_path ++ "leaf_key.pem";
const intermediate_cert_path = cert_base_path ++ "intermediate_cert.pem";
const intermediate_key_path = cert_base_path ++ "intermediate_key.pem";
const root_cert_path = cert_base_path ++ "root_cert.pem";
const root_key_path = cert_base_path ++ "root_key.pem";
const p256_cert_path = cert_base_path ++ "p256_cert.pem";
const p256_key_path = cert_base_path ++ "p256_key.pem";
const ed25519_cert_path = cert_base_path ++ "ed25519_cert.pem";
const ed25519_key_path = cert_base_path ++ "ed25519_key.pem";

/// Read certificate file from disk
fn readCertFile(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    const contents = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(contents);

    const bytes_read = try file.readAll(contents);
    if (bytes_read != stat.size) return error.IncompleteRead;

    return contents;
}

/// Convert PEM-encoded certificate to DER format
///
/// PEM format: Base64-encoded DER with -----BEGIN/END----- headers
/// DER format: Raw binary ASN.1 encoding
///
/// Caller owns returned memory and must free it.
pub fn pemToDer(allocator: std.mem.Allocator, pem_data: []const u8) ![]const u8 {
    // Find certificate content between headers
    const begin_marker = "-----BEGIN";
    const end_marker = "-----END";

    const begin_idx = std.mem.indexOf(u8, pem_data, begin_marker) orelse return error.InvalidPem;
    const begin_line_end = std.mem.indexOfScalarPos(u8, pem_data, begin_idx, '\n') orelse return error.InvalidPem;

    const end_idx = std.mem.indexOf(u8, pem_data, end_marker) orelse return error.InvalidPem;

    // Extract Base64 content (between headers, excluding newlines)
    const base64_content = pem_data[begin_line_end + 1 .. end_idx];

    // Remove newlines from Base64 content
    var base64_clean = try std.ArrayList(u8).initCapacity(allocator, base64_content.len);
    defer base64_clean.deinit(allocator);

    for (base64_content) |byte| {
        if (byte != '\n' and byte != '\r' and byte != ' ' and byte != '\t') {
            try base64_clean.append(allocator, byte);
        }
    }

    // Decode Base64 to DER
    const decoder = base64.standard.Decoder;
    const der_size = try decoder.calcSizeForSlice(base64_clean.items);
    const der_data = try allocator.alloc(u8, der_size);
    errdefer allocator.free(der_data);

    try decoder.decode(der_data, base64_clean.items);

    return der_data;
}

/// Load server certificate chain (leaf + intermediate)
///
/// Returns a certificate chain suitable for server-side TLS handshake.
/// The chain includes the leaf certificate (server identity) and intermediate CA.
/// The root CA is typically not included in the chain (client must have it in trust store).
///
/// Caller owns returned CertificateChain and must call deinit().
pub fn loadServerCertificateChain(allocator: std.mem.Allocator) !CertificateChain {
    const leaf_pem = try readCertFile(allocator, leaf_cert_path);
    defer allocator.free(leaf_pem);
    const leaf_der = try pemToDer(allocator, leaf_pem);
    errdefer allocator.free(leaf_der);

    const intermediate_pem = try readCertFile(allocator, intermediate_cert_path);
    defer allocator.free(intermediate_pem);
    const intermediate_der = try pemToDer(allocator, intermediate_pem);
    errdefer allocator.free(intermediate_der);

    // Allocate array for intermediate certificates
    const intermediates = try allocator.alloc([]const u8, 1);
    errdefer allocator.free(intermediates);
    intermediates[0] = intermediate_der;

    return CertificateChain{
        .leaf = leaf_der,
        .intermediates = intermediates,
    };
}

/// Load server private key (leaf certificate private key)
///
/// Returns the private key in DER format for the leaf certificate.
/// This key is used by the server to prove ownership of the certificate during handshake.
///
/// Caller owns returned memory and must free it.
pub fn loadServerPrivateKey(allocator: std.mem.Allocator) ![]const u8 {
    const key_pem = try readCertFile(allocator, leaf_key_path);
    defer allocator.free(key_pem);
    return pemToDer(allocator, key_pem);
}

/// Load client certificate chain (same as server for testing)
///
/// For testing purposes, we use the same leaf certificate for both client and server.
/// In production, client certificates would have different identities and may be optional.
///
/// Caller owns returned CertificateChain and must call deinit().
pub fn loadClientCertificateChain(allocator: std.mem.Allocator) !CertificateChain {
    // For testing, use same cert as server
    return loadServerCertificateChain(allocator);
}

/// Load client private key (same as server for testing)
///
/// Caller owns returned memory and must free it.
pub fn loadClientPrivateKey(allocator: std.mem.Allocator) ![]const u8 {
    // For testing, use same key as server
    return loadServerPrivateKey(allocator);
}

/// Load root CA certificate for trust store
///
/// Returns the root CA certificate in DER format.
/// This is used by clients to verify server certificates during handshake.
///
/// Caller owns returned memory and must free it.
pub fn loadRootCaCertificate(allocator: std.mem.Allocator) ![]const u8 {
    const root_pem = try readCertFile(allocator, root_cert_path);
    defer allocator.free(root_pem);
    return pemToDer(allocator, root_pem);
}

/// Load alternative certificate chain (P-256 ECDSA)
///
/// Provides P-256 ECDSA certificate for testing different signature algorithms.
///
/// Caller owns returned CertificateChain and must call deinit().
pub fn loadP256CertificateChain(allocator: std.mem.Allocator) !CertificateChain {
    const cert_pem = try readCertFile(allocator, p256_cert_path);
    defer allocator.free(cert_pem);
    const leaf_der = try pemToDer(allocator, cert_pem);
    errdefer allocator.free(leaf_der);

    // P-256 cert is self-signed for testing, no intermediate
    const intermediates = try allocator.alloc([]const u8, 0);

    return CertificateChain{
        .leaf = leaf_der,
        .intermediates = intermediates,
    };
}

/// Load P-256 private key
///
/// Caller owns returned memory and must free it.
pub fn loadP256PrivateKey(allocator: std.mem.Allocator) ![]const u8 {
    const key_pem = try readCertFile(allocator, p256_key_path);
    defer allocator.free(key_pem);
    return pemToDer(allocator, key_pem);
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "pemToDer converts PEM certificate to DER" {
    const cert_pem = try readCertFile(testing.allocator, leaf_cert_path);
    defer testing.allocator.free(cert_pem);

    const der_data = try pemToDer(testing.allocator, cert_pem);
    defer testing.allocator.free(der_data);

    // DER certificates start with 0x30 (SEQUENCE tag)
    try testing.expect(der_data.len > 0);
    try testing.expectEqual(@as(u8, 0x30), der_data[0]);

    // Verify reasonable size (certificates are typically 500-2000 bytes)
    try testing.expect(der_data.len > 100);
    try testing.expect(der_data.len < 5000);
}

test "pemToDer converts PEM private key to DER" {
    const key_pem = try readCertFile(testing.allocator, leaf_key_path);
    defer testing.allocator.free(key_pem);

    const der_data = try pemToDer(testing.allocator, key_pem);
    defer testing.allocator.free(der_data);

    // DER private keys start with 0x30 (SEQUENCE tag)
    try testing.expect(der_data.len > 0);
    try testing.expectEqual(@as(u8, 0x30), der_data[0]);

    // Private keys are typically larger (1000-3000 bytes for RSA-2048)
    try testing.expect(der_data.len > 500);
    try testing.expect(der_data.len < 10000);
}

test "loadServerCertificateChain returns valid chain" {
    var chain = try loadServerCertificateChain(testing.allocator);
    defer chain.deinit(testing.allocator);

    // Verify leaf certificate
    try testing.expect(chain.leaf.len > 0);
    try testing.expectEqual(@as(u8, 0x30), chain.leaf[0]);

    // Verify intermediate certificate
    try testing.expectEqual(@as(usize, 1), chain.intermediates.len);
    try testing.expect(chain.intermediates[0].len > 0);
    try testing.expectEqual(@as(u8, 0x30), chain.intermediates[0][0]);
}

test "loadServerPrivateKey returns valid key" {
    const key_data = try loadServerPrivateKey(testing.allocator);
    defer testing.allocator.free(key_data);

    try testing.expect(key_data.len > 0);
    try testing.expectEqual(@as(u8, 0x30), key_data[0]);
}

test "loadRootCaCertificate returns valid cert" {
    const root_cert = try loadRootCaCertificate(testing.allocator);
    defer testing.allocator.free(root_cert);

    try testing.expect(root_cert.len > 0);
    try testing.expectEqual(@as(u8, 0x30), root_cert[0]);
}

test "loadP256CertificateChain returns valid P-256 chain" {
    var chain = try loadP256CertificateChain(testing.allocator);
    defer chain.deinit(testing.allocator);

    // Verify leaf certificate
    try testing.expect(chain.leaf.len > 0);
    try testing.expectEqual(@as(u8, 0x30), chain.leaf[0]);

    // P-256 cert is self-signed, no intermediates for this test cert
    try testing.expectEqual(@as(usize, 0), chain.intermediates.len);
}

test "loadP256PrivateKey returns valid key" {
    const key_data = try loadP256PrivateKey(testing.allocator);
    defer testing.allocator.free(key_data);

    try testing.expect(key_data.len > 0);
    try testing.expectEqual(@as(u8, 0x30), key_data[0]);

    // P-256 keys are smaller than RSA-2048 (typically 100-200 bytes)
    try testing.expect(key_data.len < 500);
}
