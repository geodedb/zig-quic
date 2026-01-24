// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! AEAD usage limits for key rotation.
//!
//! RFC 9001 §6.6: Limits on AEAD Usage
//! Endpoints must track AEAD usage and rotate keys before exceeding confidentiality or integrity limits.

const std = @import("std");

/// AEAD usage limit tracking.
/// RFC 9001 §6.6: Limits prevent cryptographic weaknesses from excessive AEAD usage.
pub const AeadLimits = struct {
    /// Total 1-RTT packets encrypted with current TX keys (RFC 9001 §6.6 confidentiality limit).
    aead_tx_count: u64 = 0,

    /// Confidentiality limit: max packets that can be encrypted with one key.
    aead_confidentiality_limit: ?u64 = null,

    /// Integrity limit: max failed decryption attempts before key update.
    aead_integrity_limit: ?u64 = null,
};

/// Set AEAD usage limits for key rotation.
/// RFC 9001 §6.6: Applications should configure limits based on AEAD algorithm.
pub fn setLimits(limits: *AeadLimits, conf_limit: ?u64, integ_limit: ?u64) void {
    limits.aead_confidentiality_limit = conf_limit;
    limits.aead_integrity_limit = integ_limit;
}
