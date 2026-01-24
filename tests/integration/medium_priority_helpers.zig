//! Medium Priority Features Test Helpers (Phase 22)
//!
//! Provides test utilities for medium priority QUIC features:
//! - Address validation (PATH_CHALLENGE/RESPONSE)
//! - Connection migration state management
//! - Flow control window tracking
//!
//! Features:
//! - Path validation frame extraction
//! - Migration event tracking
//! - Flow control limit inspection
//! - Window update detection
//!
//! RFC References:
//! - RFC 9000 §8: Address Validation
//! - RFC 9000 §9: Connection Migration
//! - RFC 9000 §4: Flow Control
//! - RFC 9000 §19.17-19.18: PATH_CHALLENGE/RESPONSE Frames

const std = @import("std");
const harness = @import("harness");
const packet_inspector = @import("packet_inspector");

// =============================================================================
// Address Validation Types
// =============================================================================

/// PATH_CHALLENGE frame
pub const PathChallenge = struct {
    data: [8]u8,
    timestamp_ms: i64,
};

/// PATH_RESPONSE frame
pub const PathResponse = struct {
    data: [8]u8,
    timestamp_ms: i64,
};

/// Path validation result
pub const PathValidationResult = enum {
    in_progress,
    succeeded,
    failed,
    timeout,
};

// =============================================================================
// Connection Migration Types
// =============================================================================

/// Migration event type
pub const MigrationEventType = enum {
    client_initiated,
    nat_rebinding,
    path_validation_started,
    path_validation_completed,
    migration_completed,
};

/// Connection migration event
pub const MigrationEvent = struct {
    event_type: MigrationEventType,
    old_addr: []const u8,
    new_addr: []const u8,
    timestamp_ms: i64,
};

// =============================================================================
// Flow Control Types
// =============================================================================

/// Flow control window state
pub const FlowControlWindow = struct {
    /// Current data limit (MAX_DATA or MAX_STREAM_DATA)
    limit: u64,

    /// Current data sent/received
    consumed: u64,

    /// Available window
    available: u64,

    /// Whether window is blocked
    is_blocked: bool,
};

/// Flow control frame type
pub const FlowControlFrameType = enum {
    max_data,
    max_stream_data,
    data_blocked,
    stream_data_blocked,
};

/// Flow control update event
pub const FlowControlUpdate = struct {
    frame_type: FlowControlFrameType,
    stream_id: ?u64 = null,
    limit: u64,
    timestamp_ms: i64,
};

// =============================================================================
// Address Validation Helpers
// =============================================================================

/// Extract PATH_CHALLENGE frames from captured packets.
/// Returns list of challenges sent.
///
/// Note: This is a stub. Real implementation would:
/// - Parse packet payloads (requires decryption)
/// - Find PATH_CHALLENGE frames (0x1a)
/// - Extract 8-byte challenge data
pub fn extractPathChallenges(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !std.ArrayList(PathChallenge) {
    var challenges = std.ArrayList(PathChallenge){};
    errdefer challenges.deinit(allocator);

    _ = captured;

    // Stub: Real implementation would parse PATH_CHALLENGE frames
    // RFC 9000 §19.17

    return challenges;
}

/// Extract PATH_RESPONSE frames from captured packets.
/// Returns list of responses sent.
pub fn extractPathResponses(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !std.ArrayList(PathResponse) {
    var responses = std.ArrayList(PathResponse){};
    errdefer responses.deinit(allocator);

    _ = captured;

    // Stub: Real implementation would parse PATH_RESPONSE frames
    // RFC 9000 §19.18

    return responses;
}

/// Validate PATH_RESPONSE matches PATH_CHALLENGE.
/// Checks that response data equals challenge data.
///
/// RFC 9000 §8.2: Response must echo challenge data exactly
pub fn validatePathResponse(
    challenge: PathChallenge,
    response: PathResponse,
) !void {
    if (!std.mem.eql(u8, &challenge.data, &response.data)) {
        std.debug.print(
            "PATH_RESPONSE data mismatch\n",
            .{}
        );
        return error.PathResponseMismatch;
    }
}

/// Count successful path validations from capture.
/// Returns number of challenge-response pairs that matched.
pub fn countSuccessfulPathValidations(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !usize {
    var challenges = try extractPathChallenges(allocator, captured);
    defer challenges.deinit(allocator);

    var responses = try extractPathResponses(allocator, captured);
    defer responses.deinit(allocator);

    var count: usize = 0;
    for (challenges.items) |challenge| {
        for (responses.items) |response| {
            if (std.mem.eql(u8, &challenge.data, &response.data)) {
                count += 1;
                break;
            }
        }
    }

    return count;
}

// =============================================================================
// Connection Migration Helpers
// =============================================================================

/// Extract migration events from captured packets.
/// Detects migration by tracking source address changes.
///
/// RFC 9000 §9: Connection Migration
/// Note: This is a stub. Real implementation would:
/// - Track peer address changes across packets
/// - Detect PATH_CHALLENGE/RESPONSE sequences
/// - Identify NAT rebinding vs client-initiated migration
pub fn extractMigrationEvents(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !std.ArrayList(MigrationEvent) {
    var events = std.ArrayList(MigrationEvent){};
    errdefer events.deinit(allocator);

    _ = captured;

    // Stub: Real implementation would:
    // 1. Track peer address for each packet
    // 2. Detect address changes
    // 3. Correlate with PATH_CHALLENGE/RESPONSE
    // 4. Determine migration type

    return events;
}

/// Validate migration follows RFC 9000 §9 rules.
/// Checks that migration includes path validation.
pub fn validateMigration(events: []const MigrationEvent) !void {
    var migration_started = false;
    var path_validation_started = false;

    for (events) |event| {
        switch (event.event_type) {
            .client_initiated, .nat_rebinding => {
                migration_started = true;
            },
            .path_validation_started => {
                if (!migration_started) {
                    std.debug.print(
                        "Path validation started before migration\n",
                        .{}
                    );
                    return error.InvalidMigrationSequence;
                }
                path_validation_started = true;
            },
            .migration_completed => {
                if (!path_validation_started) {
                    std.debug.print(
                        "Migration completed without path validation\n",
                        .{}
                    );
                    return error.MigrationWithoutValidation;
                }
            },
            else => {},
        }
    }
}

/// Find migration event by type.
/// Returns first matching event or null if not found.
pub fn findMigrationByType(
    events: []const MigrationEvent,
    event_type: MigrationEventType,
) ?MigrationEvent {
    for (events) |event| {
        if (event.event_type == event_type) {
            return event;
        }
    }
    return null;
}

// =============================================================================
// Flow Control Helpers
// =============================================================================

/// Extract flow control updates from captured packets.
/// Returns list of MAX_DATA, MAX_STREAM_DATA, and BLOCKED frames.
///
/// Note: This is a stub. Real implementation would:
/// - Parse MAX_DATA frames (0x10)
/// - Parse MAX_STREAM_DATA frames (0x11)
/// - Parse DATA_BLOCKED frames (0x14)
/// - Parse STREAM_DATA_BLOCKED frames (0x15)
pub fn extractFlowControlUpdates(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !std.ArrayList(FlowControlUpdate) {
    var updates = std.ArrayList(FlowControlUpdate){};
    errdefer updates.deinit(allocator);

    _ = captured;

    // Stub: Real implementation would parse flow control frames
    // RFC 9000 §4, §19.10-19.14

    return updates;
}

/// Calculate flow control window state.
/// Returns current window size and availability.
pub fn calculateFlowControlWindow(
    current_limit: u64,
    consumed: u64,
) FlowControlWindow {
    const available = if (current_limit > consumed)
        current_limit - consumed
    else
        0;

    return FlowControlWindow{
        .limit = current_limit,
        .consumed = consumed,
        .available = available,
        .is_blocked = (available == 0),
    };
}

/// Validate flow control limit increases monotonically.
/// Checks that MAX_DATA/MAX_STREAM_DATA values only increase.
///
/// RFC 9000 §4.2: Receiver must not reduce limits
pub fn validateFlowControlLimits(updates: []const FlowControlUpdate) !void {
    var connection_limit: u64 = 0;
    var stream_limits = std.AutoHashMap(u64, u64).init(std.heap.page_allocator);
    defer stream_limits.deinit();

    for (updates) |update| {
        switch (update.frame_type) {
            .max_data => {
                if (update.limit < connection_limit) {
                    std.debug.print(
                        "MAX_DATA decreased: {} -> {}\n",
                        .{ connection_limit, update.limit }
                    );
                    return error.FlowControlLimitDecrease;
                }
                connection_limit = update.limit;
            },
            .max_stream_data => {
                const stream_id = update.stream_id orelse return error.MissingStreamId;
                const old_limit = stream_limits.get(stream_id) orelse 0;
                if (update.limit < old_limit) {
                    std.debug.print(
                        "MAX_STREAM_DATA decreased for stream {}: {} -> {}\n",
                        .{ stream_id, old_limit, update.limit }
                    );
                    return error.FlowControlLimitDecrease;
                }
                try stream_limits.put(stream_id, update.limit);
            },
            else => {},
        }
    }
}

/// Find flow control blocked events.
/// Returns updates where sender indicated blocked state.
pub fn findBlockedEvents(
    updates: []const FlowControlUpdate,
) []const FlowControlUpdate {
    var blocked_events = std.ArrayList(FlowControlUpdate){};

    for (updates) |update| {
        if (update.frame_type == .data_blocked or
            update.frame_type == .stream_data_blocked)
        {
            blocked_events.append(std.heap.page_allocator, update) catch break;
        }
    }

    return blocked_events.items;
}

// =============================================================================
// Test Assertion Helpers
// =============================================================================

/// Assert that path validation succeeded.
/// Validates PATH_CHALLENGE/RESPONSE exchange completed.
pub fn expectPathValidation(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
    min_validations: usize,
) !void {
    const validations = try countSuccessfulPathValidations(allocator, captured);

    if (validations < min_validations) {
        std.debug.print(
            "Expected at least {} path validations, found {}\n",
            .{ min_validations, validations }
        );
        return error.InsufficientPathValidations;
    }
}

/// Assert that connection migration succeeded.
/// Validates migration followed RFC 9000 §9 rules.
pub fn expectSuccessfulMigration(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !void {
    const events = try extractMigrationEvents(allocator, captured);
    defer events.deinit(allocator);

    if (events.items.len == 0) {
        std.debug.print("No migration events found\n", .{});
        return error.NoMigrationEvents;
    }

    try validateMigration(events.items);
}

/// Assert that flow control limits are valid.
/// Validates limits increase monotonically.
pub fn expectValidFlowControl(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !void {
    const updates = try extractFlowControlUpdates(allocator, captured);
    defer updates.deinit(allocator);

    try validateFlowControlLimits(updates.items);
}

/// Assert that sender was blocked.
/// Validates DATA_BLOCKED or STREAM_DATA_BLOCKED sent.
pub fn expectFlowControlBlocked(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
    min_blocked_events: usize,
) !void {
    const updates = try extractFlowControlUpdates(allocator, captured);
    defer updates.deinit(allocator);

    const blocked = findBlockedEvents(updates.items);

    if (blocked.len < min_blocked_events) {
        std.debug.print(
            "Expected at least {} blocked events, found {}\n",
            .{ min_blocked_events, blocked.len }
        );
        return error.InsufficientBlockedEvents;
    }
}

// =============================================================================
// Integration with ConnectionPair
// =============================================================================

/// Medium priority features metrics from connection pair test.
pub const MediumPriorityMetrics = struct {
    path_challenges: usize,
    path_responses: usize,
    successful_validations: usize,
    migration_events: usize,
    flow_control_updates: usize,
    blocked_events: usize,
};

/// Analyze medium priority features from captured packets.
pub fn analyzeMediumPriorityFeatures(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !MediumPriorityMetrics {
    const challenges = try extractPathChallenges(allocator, captured);
    defer challenges.deinit(allocator);

    const responses = try extractPathResponses(allocator, captured);
    defer responses.deinit(allocator);

    const validations = try countSuccessfulPathValidations(allocator, captured);

    const migrations = try extractMigrationEvents(allocator, captured);
    defer migrations.deinit(allocator);

    const fc_updates = try extractFlowControlUpdates(allocator, captured);
    defer fc_updates.deinit(allocator);

    const blocked = findBlockedEvents(fc_updates.items);

    return MediumPriorityMetrics{
        .path_challenges = challenges.items.len,
        .path_responses = responses.items.len,
        .successful_validations = validations,
        .migration_events = migrations.items.len,
        .flow_control_updates = fc_updates.items.len,
        .blocked_events = blocked.len,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "calculateFlowControlWindow - with available space" {
    const window = calculateFlowControlWindow(1000, 400);

    try std.testing.expectEqual(@as(u64, 1000), window.limit);
    try std.testing.expectEqual(@as(u64, 400), window.consumed);
    try std.testing.expectEqual(@as(u64, 600), window.available);
    try std.testing.expectEqual(false, window.is_blocked);
}

test "calculateFlowControlWindow - fully consumed" {
    const window = calculateFlowControlWindow(1000, 1000);

    try std.testing.expectEqual(@as(u64, 1000), window.limit);
    try std.testing.expectEqual(@as(u64, 1000), window.consumed);
    try std.testing.expectEqual(@as(u64, 0), window.available);
    try std.testing.expectEqual(true, window.is_blocked);
}

test "validatePathResponse - matching data" {
    const challenge = PathChallenge{
        .data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .timestamp_ms = 100,
    };

    const response = PathResponse{
        .data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .timestamp_ms = 200,
    };

    try validatePathResponse(challenge, response);
}

test "validatePathResponse - mismatched data" {
    const challenge = PathChallenge{
        .data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .timestamp_ms = 100,
    };

    const response = PathResponse{
        .data = [_]u8{ 9, 9, 9, 9, 9, 9, 9, 9 },
        .timestamp_ms = 200,
    };

    const result = validatePathResponse(challenge, response);
    try std.testing.expectError(error.PathResponseMismatch, result);
}

test "validateMigration - valid sequence" {
    const events = [_]MigrationEvent{
        .{
            .event_type = .client_initiated,
            .old_addr = "127.0.0.1:4433",
            .new_addr = "127.0.0.1:5544",
            .timestamp_ms = 100,
        },
        .{
            .event_type = .path_validation_started,
            .old_addr = "127.0.0.1:4433",
            .new_addr = "127.0.0.1:5544",
            .timestamp_ms = 150,
        },
        .{
            .event_type = .migration_completed,
            .old_addr = "127.0.0.1:4433",
            .new_addr = "127.0.0.1:5544",
            .timestamp_ms = 300,
        },
    };

    try validateMigration(&events);
}

test "validateFlowControlLimits - monotonic increases" {
    const updates = [_]FlowControlUpdate{
        .{ .frame_type = .max_data, .limit = 1000, .timestamp_ms = 100 },
        .{ .frame_type = .max_data, .limit = 2000, .timestamp_ms = 200 },
        .{ .frame_type = .max_data, .limit = 3000, .timestamp_ms = 300 },
    };

    try validateFlowControlLimits(&updates);
}

test "validateFlowControlLimits - limit decrease detected" {
    const updates = [_]FlowControlUpdate{
        .{ .frame_type = .max_data, .limit = 2000, .timestamp_ms = 100 },
        .{ .frame_type = .max_data, .limit = 1000, .timestamp_ms = 200 }, // Decrease!
    };

    const result = validateFlowControlLimits(&updates);
    try std.testing.expectError(error.FlowControlLimitDecrease, result);
}

test "analyzeMediumPriorityFeatures - empty capture" {
    const allocator = std.testing.allocator;

    const captured: []const harness.CapturedPacket = &[_]harness.CapturedPacket{};

    const metrics = try analyzeMediumPriorityFeatures(allocator, captured);

    try std.testing.expectEqual(@as(usize, 0), metrics.path_challenges);
    try std.testing.expectEqual(@as(usize, 0), metrics.path_responses);
    try std.testing.expectEqual(@as(usize, 0), metrics.successful_validations);
    try std.testing.expectEqual(@as(usize, 0), metrics.migration_events);
    try std.testing.expectEqual(@as(usize, 0), metrics.flow_control_updates);
    try std.testing.expectEqual(@as(usize, 0), metrics.blocked_events);
}
