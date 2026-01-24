// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Common QUIC recovery types and constants.
//!
//! RFC 9002 §2: Design of the QUIC Transmission Machinery

const std = @import("std");

/// Shared CC state used by Recovery for both NewReno and CUBIC (bytes units).
/// RFC 9002 §7: Congestion Control
pub const CcState = struct {
    mds: usize = 1200,
    cwnd: usize = 10 * 1200,
    ssthresh: usize = std.math.maxInt(usize) / 2,
    bytes_in_flight: usize = 0,
};

/// CUBIC constant C (scales the cubic function), exposed for tuning/tests.
/// RFC 9002 Appendix B.2: CUBIC
pub const CUBIC_C_DEFAULT: f64 = 0.4;

/// CUBIC multiplicative decrease factor beta, exposed for tuning/tests.
/// RFC 9002 Appendix B.2: CUBIC
pub const CUBIC_BETA_DEFAULT: f64 = 0.7;

/// QUIC packet number spaces (RFC 9000): each maintains separate PN sequence and ACK logic.
/// RFC 9000 §12.1: Packet Numbers
pub const PacketNumberSpace = enum { Initial, Handshake, Application };

/// Sent packet metadata tracked for loss recovery and RTT measurement.
/// RFC 9002 §2: Design of the QUIC Transmission Machinery
pub const SentPacket = struct {
    pn: u64,
    time_ns: u64,
    size: usize,
    ack_eliciting: bool,
    acked: bool = false,
    declared_lost: bool = false,
};
