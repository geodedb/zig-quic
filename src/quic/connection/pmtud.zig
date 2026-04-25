// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Path MTU Discovery (PMTUD) state and helpers.
//!
//! RFC 9000 §14.2: Path Maximum Transmission Unit
//! RFC 9000 §14.3: Datagram Packetization Layer PMTU Discovery (DPLPMTUD)
//! RFC 9000 §14.4: Handling of ICMP Messages by QUIC

/// Connection DPLPMTUD search state.
///
/// The active connection implementation keeps the measured MTU, outstanding
/// probe packet number, and outstanding probe size on `Connection`; this enum is
/// the canonical phase model shared by production code and unit tests.
pub const PmtudState = enum {
    /// DPLPMTUD is inactive.
    Disabled,

    /// The first conservative probe should be sent when the PMTUD timer fires.
    ProbeStart,

    /// Continue probing upward from the most recently validated path MTU.
    ProbeSearch,

    pub fn active(self: PmtudState) bool {
        return self != .Disabled;
    }
};
