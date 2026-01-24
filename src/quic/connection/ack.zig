// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! ACK generation and ECN tracking for QUIC connections.
//!
//! RFC 9000 §13.2: Generating Acknowledgements
//! RFC 9000 §19.3: ACK Frames
//! RFC 3168: ECN (Explicit Congestion Notification)

const std = @import("std");
const frame = @import("quic_frame");

/// ACK descriptor containing largest PN and ranges for ACK frame generation.
pub const AckDesc = struct {
    largest: u64,
    first_range: u64,
    ranges: []const frame.AckRange,
};

/// Per-space ECN counters for ACK_ECN emission.
/// RFC 3168: Explicit Congestion Notification
pub const EcnCounter = struct {
    ect0: u64 = 0,
    ect1: u64 = 0,
    ce: u64 = 0,
    seen_any: bool = false,
};
