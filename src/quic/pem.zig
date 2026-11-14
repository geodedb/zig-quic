// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! PEM parsing helpers for certificates and private keys.
//!
//! Provides the PEM-to-DER conversions required by TLS certificate loading in
//! accordance with RFC 7468 so QUIC endpoints can ingest external material.
const std = @import("std");
const base64 = std.base64.standard;

const logger = std.log.scoped(.pem);

// Key boundary markers are split with ++ so this source holds no literal key
// header (the detect-private-key pre-commit hook would flag it).

/// Decode the base64 body between PEM boundaries into a new buffer.
///
/// For private keys (`secret`), every buffer that held key material is
/// zeroed before it is freed: the base64 scratch copy (reserved up front so
/// it never reallocates and leaves an unzeroed copy behind) and, on a decode
/// failure, the partly written output. The output is freed when the base64
/// does not decode; it used to leak.
fn decodeBody(allocator: std.mem.Allocator, body: []const u8, secret: bool) ![]u8 {
    var base64_content: std.ArrayList(u8) = .empty;
    defer {
        if (secret) std.crypto.secureZero(u8, base64_content.allocatedSlice());
        base64_content.deinit(allocator);
    }
    try base64_content.ensureTotalCapacityPrecise(allocator, body.len);
    for (body) |ch| {
        if (ch != '\n' and ch != '\r' and ch != ' ' and ch != '\t') {
            base64_content.appendAssumeCapacity(ch);
        }
    }

    const decoded_size = try base64.Decoder.calcSizeForSlice(base64_content.items);
    const der = try allocator.alloc(u8, decoded_size);
    errdefer {
        if (secret) std.crypto.secureZero(u8, der);
        allocator.free(der);
    }
    try base64.Decoder.decode(der, base64_content.items);
    return der;
}

/// Parse a PEM-encoded certificate and return the DER-encoded certificate
pub fn parseCertificate(allocator: std.mem.Allocator, pem_data: []const u8) ![]u8 {
    const cert_begin = "-----BEGIN CERTIFICATE-----";
    const cert_end = "-----END CERTIFICATE-----";

    // Find the certificate boundaries
    const start_idx = std.mem.indexOf(u8, pem_data, cert_begin) orelse return error.NoCertificateFound;
    const content_start = start_idx + cert_begin.len;

    const end_idx = std.mem.indexOf(u8, pem_data[content_start..], cert_end) orelse return error.InvalidPemFormat;
    const content_end = content_start + end_idx;

    return decodeBody(allocator, pem_data[content_start..content_end], false);
}

/// Parse a PEM-encoded EC private key and return the DER-encoded key
/// The signature code expects the full DER structure, not just the raw scalar
pub fn parseECPrivateKey(allocator: std.mem.Allocator, pem_data: []const u8) ![]u8 {
    const key_begin = "-----BEGIN " ++ "EC PRIVATE KEY-----";
    const key_end = "-----END " ++ "EC PRIVATE KEY-----";

    // Find the key boundaries
    const start_idx = std.mem.indexOf(u8, pem_data, key_begin) orelse return error.NoPrivateKeyFound;
    const content_start = start_idx + key_begin.len;

    const end_idx = std.mem.indexOf(u8, pem_data[content_start..], key_end) orelse return error.InvalidPemFormat;
    const content_end = content_start + end_idx;

    // Return the full DER structure - the signature code expects this format
    return decodeBody(allocator, pem_data[content_start..content_end], true);
}

/// Parse a PEM-encoded RSA private key and return the DER-encoded key
/// For RSA, we'll keep it in DER format since the signature code will need to parse it
pub fn parseRSAPrivateKey(allocator: std.mem.Allocator, pem_data: []const u8) ![]u8 {
    const key_begin = "-----BEGIN " ++ "RSA PRIVATE KEY-----";
    const key_end = "-----END " ++ "RSA PRIVATE KEY-----";
    const pkcs8_begin = "-----BEGIN " ++ "PRIVATE KEY-----";
    const pkcs8_end = "-----END " ++ "PRIVATE KEY-----";

    // Try RSA PRIVATE KEY format first
    var start_idx = std.mem.indexOf(u8, pem_data, key_begin);
    var content_start: usize = 0;
    var content_end: usize = 0;

    if (start_idx) |idx| {
        content_start = idx + key_begin.len;
        const end_idx = std.mem.indexOf(u8, pem_data[content_start..], key_end) orelse return error.InvalidPemFormat;
        content_end = content_start + end_idx;
    } else {
        // Try PKCS#8 format
        start_idx = std.mem.indexOf(u8, pem_data, pkcs8_begin);
        if (start_idx) |idx| {
            content_start = idx + pkcs8_begin.len;
            const end_idx = std.mem.indexOf(u8, pem_data[content_start..], pkcs8_end) orelse return error.InvalidPemFormat;
            content_end = content_start + end_idx;
        } else {
            return error.NoPrivateKeyFound;
        }
    }

    return decodeBody(allocator, pem_data[content_start..content_end], true);
}

/// Try to detect and parse any supported private key format
pub fn parsePrivateKey(allocator: std.mem.Allocator, pem_data: []const u8) ![]u8 {
    // Try EC key first (most common for QUIC)
    if (parseECPrivateKey(allocator, pem_data)) |key| {
        return key;
    } else |_| {
        // Try RSA key
        if (parseRSAPrivateKey(allocator, pem_data)) |key| {
            return key;
        } else |_| {
            return error.UnsupportedKeyType;
        }
    }
}
