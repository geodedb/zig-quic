//! Unit tests for connection/pmtud.zig
//!
//! RFC References:
//! - RFC 9000 §14.2: Path Maximum Transmission Unit
//! - RFC 9000 §14.3: Datagram Packetization Layer PMTU Discovery (DPLPMTUD)
//! - RFC 8899: Packetization Layer Path MTU Discovery
//!
//! The connection object owns measured MTU values and outstanding probe
//! metadata. This module owns the shared DPLPMTUD phase enum used by production
//! code and tests.

const testing = @import("std").testing;

const pmtud = @import("pmtud");

test "RFC 9000 §14.3 - PmtudState canonical phase values" {
    try testing.expectEqual(pmtud.PmtudState.Disabled, .Disabled);
    try testing.expectEqual(pmtud.PmtudState.ProbeStart, .ProbeStart);
    try testing.expectEqual(pmtud.PmtudState.ProbeSearch, .ProbeSearch);
}

test "RFC 9000 §14.3 - PmtudState starts inactive" {
    const state: pmtud.PmtudState = .Disabled;

    try testing.expect(!state.active());
}

test "RFC 9000 §14.3 - PmtudState marks probing phases active" {
    try testing.expect(pmtud.PmtudState.ProbeStart.active());
    try testing.expect(pmtud.PmtudState.ProbeSearch.active());
}

test "RFC 9000 §14.3 - PmtudState transition order used by connection timers" {
    var state: pmtud.PmtudState = .Disabled;

    state = .ProbeStart;
    try testing.expectEqual(pmtud.PmtudState.ProbeStart, state);
    try testing.expect(state.active());

    state = .ProbeSearch;
    try testing.expectEqual(pmtud.PmtudState.ProbeSearch, state);
    try testing.expect(state.active());

    state = .Disabled;
    try testing.expect(!state.active());
}
