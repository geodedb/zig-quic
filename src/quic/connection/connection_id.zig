// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Connection ID management and stateless reset token handling.
//!
//! RFC 9000 §5.1: Connection ID
//! RFC 9000 §5.2: Matching Packets to Connections
//! RFC 9000 §5.3: Connection ID Management
//! RFC 9000 §10.3: Stateless Reset

const std = @import("std");
const types = @import("types");
const reset_token_mod = @import("reset_token.zig");

/// Local connection ID with sequence number and stateless reset token.
/// RFC 9000 §5.3: Each endpoint maintains a set of CIDs it advertises to its peer.
pub const LocalCid = struct {
    in_use: bool = false,
    sequence: u64 = 0,
    cid: types.Cid = .{},
    reset_token: [16]u8 = [_]u8{0} ** 16,
};

/// Derive stateless reset token using HKDF.
/// Delegates to the canonical implementation in reset_token.zig.
/// RFC 9000 §10.3: Stateless Reset
pub const deriveStatelessResetToken = reset_token_mod.deriveStatelessResetToken;

/// Test helper exposing reset token derivation (used only by unit tests).
pub const testDeriveStatelessResetToken = reset_token_mod.testDeriveStatelessResetToken;
