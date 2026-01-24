// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Path MTU Discovery (PMTUD) state and helpers.
//!
//! RFC 9000 §14.2: Path Maximum Transmission Unit
//! RFC 9000 §14.3: Datagram Packetization Layer PMTU Discovery (DPLPMTUD)
//! RFC 9000 §14.4: Handling of ICMP Messages by QUIC

const std = @import("std");

/// DPLPMTUD phase tracking.
/// RFC 9000 §14.3: DPLPMTUD operates in phases to discover the path MTU.
pub const DplpmtudPhase = enum {
    Disabled,
    Searching,
    SearchComplete,
};

/// PMTUD state for connection.
/// RFC 9000 §14.2: Endpoints discover the path MTU by probing with larger datagrams.
pub const PmtudState = struct {
    /// Current believed path MTU (UDP payload size), never below 1200.
    /// RFC 9000 §14: Minimum QUIC packet size is 1200 bytes.
    pmtu_current: u16 = 1200,

    /// Largest probe size we've attempted (may be unconfirmed).
    pmtu_probed: u16 = 1200,

    /// DPLPMTUD phase and timer (RFC 9000 §14.4, RFC 8899).
    dplpmtud_state: DplpmtudPhase = .Disabled,
};
