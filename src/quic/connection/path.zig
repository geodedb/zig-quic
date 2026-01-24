// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Path validation and migration support.
//!
//! RFC 9000 §9: Connection Migration
//! RFC 9000 §9.3: Responding to Connection Migration
//! RFC 9000 §9.4: Probing a New Path

const std = @import("std");

/// Path validation state for connection migration.
/// RFC 9000 §9: Connection migration requires path validation before
/// using the new path for general traffic.
pub const PathValidation = struct {
    /// PATH_CHALLENGE validation state; true until matching PATH_RESPONSE received.
    /// RFC 9000 §9: Endpoints validate paths using PATH_CHALLENGE/PATH_RESPONSE frames.
    validated: bool = false,
};
