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

test "server Initial processing budget is small so the shed-drain engages quickly (RC-A it.2)" {
    // RC-A iteration 2: v0.1.28 left the Initial PROCESSING budget at 256
    // (== old master cap), so each poll worker ground through 256
    // ep.mu-serialized Initial processings before reaching the cheap lock-free
    // shed phase — the kernel rx_queue still wedged at k8s scale. The budget
    // must be ≤ one UDP batch (64) so shedding engages almost immediately and
    // the socket actually drains.
    try std.testing.expect(quic.serverInitialProcessingBudget() <= 64);
    // And the drain cap must dwarf it (large headroom to empty the kernel buffer).
    try std.testing.expect(quic.serverSocketDrainPackets() >= quic.serverInitialProcessingBudget() * 16);
}

test "setServerInitialProcessingBudget overrides the budget and 0 restores the default" {
    const default_budget = quic.serverInitialProcessingBudget();
    quic.setServerInitialProcessingBudget(7);
    try std.testing.expectEqual(@as(usize, 7), quic.serverInitialProcessingBudget());
    quic.setServerInitialProcessingBudget(0);
    try std.testing.expectEqual(default_budget, quic.serverInitialProcessingBudget());
    // Default must remain below the drain cap (shed invariant).
    try std.testing.expect(quic.serverInitialProcessingBudget() < quic.serverSocketDrainPackets());
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
