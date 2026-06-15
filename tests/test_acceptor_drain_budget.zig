// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Acceptor-wedge RC-A regression: the server per-poll-cycle socket-DRAIN cap
//! must stay strictly above the Initial PROCESSING budget so pollWithStats keeps
//! reading (cheaply shedding surplus Initials) instead of stalling the drain at
//! the processing budget — otherwise a connection-kill / reconnect storm backs
//! the kernel `:PORT` UDP rx_queue up to the geode acceptor-watchdog 8 MiB
//! threshold and the pod self-restarts (exit(70)).
//!
//! See geode docs/bugs/2026-06-03-acceptor-wedge-connection-burst-new-conns-refused.md
//! and docs/bugs/2026-06-04-cluster-raft-no-stable-quorum-writes-time-out.md.

const std = @import("std");
const quic = @import("quic");

test "server socket-drain cap exceeds the Initial processing budget (shed path active)" {
    // The bug was drain_cap == processing_budget, which defeats the shed path.
    try std.testing.expect(quic.serverSocketDrainPackets() > quic.serverInitialProcessingBudget());
}

test "setServerSocketDrainPackets overrides the cap and 0 restores the default" {
    const default_cap = quic.serverSocketDrainPackets();
    try std.testing.expect(default_cap > quic.serverInitialProcessingBudget());

    quic.setServerSocketDrainPackets(123456);
    try std.testing.expectEqual(@as(usize, 123456), quic.serverSocketDrainPackets());

    quic.setServerSocketDrainPackets(0);
    try std.testing.expectEqual(default_cap, quic.serverSocketDrainPackets());

    // Even an operator-chosen override must keep the shed invariant; a too-small
    // value would re-introduce the wedge. Document the floor by asserting the
    // default is comfortably above the processing budget.
    try std.testing.expect(quic.serverSocketDrainPackets() >= quic.serverInitialProcessingBudget() * 2);
}
