// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Shared cryptographic utility functions for QUIC connection management.
//!
//! Canonical location for helpers used across multiple connection method
//! modules (methods_b.zig, methods_c.zig, etc.) to avoid duplication.

const ks = @import("quic_tls");

/// Map a Secret's byte length to the corresponding TLS 1.3 hash algorithm.
/// SHA-256 secrets are 32 bytes; SHA-384 secrets are 48 bytes.
/// Returns error.InvalidSecretLength for any other length.
pub fn hashForSecret(secret: *const ks.Secret) error{InvalidSecretLength}!ks.Hash {
    return switch (secret.len) {
        32 => .sha256,
        48 => .sha384,
        else => error.InvalidSecretLength,
    };
}
