# RFC Compliance Test Generation Template

## Quick Reference

Use this template to create new RFC compliance tests for any QUIC module.

## File Header Template

```zig
//! Unit tests for <module_category>/<module_name>.zig
//!
//! RFC References:
//! - RFC XXXX §Y.Z: <Brief description of relevant section>
//! - RFC XXXX §A.B: <Another relevant section>
//!
//! Coverage:
//! - Positive cases: <What normal behaviors are tested>
//! - Negative cases: <What error conditions are tested>
//! - Edge cases: <What boundary conditions are tested>
//! - RFC compliance: <What specific RFC requirements are verified>

const std = @import("std");
const testing = std.testing;

// Import the module under test
const module = @import("relative/path/to/module.zig");

// If allocator needed
var test_allocator = std.testing.allocator;
```

## Test Organization Sections

### 1. Basic Functionality Tests
```zig
// =============================================================================
// <Category Name> Tests
// =============================================================================

test "RFC XXXX §Y.Z - <Description of what is being tested>" {
    // Arrange: Set up test data
    const test_value = /* ... */;

    // Act: Execute the operation
    const result = module.function(test_value);

    // Assert: Verify expectations
    try testing.expectEqual(expected, result);
}
```

### 2. Multiple Related Tests
```zig
test "RFC XXXX §Y.Z - <Test case 1>" {
    // ...
}

test "RFC XXXX §Y.Z - <Test case 2>" {
    // ...
}

test "RFC XXXX §Y.Z - <Test case 3>" {
    // ...
}
```

### 3. Boundary Tests
```zig
// =============================================================================
// Boundary and Edge Cases
// =============================================================================

test "boundary: <Description of boundary condition>" {
    // Test minimum value
    try testing.expectEqual(expected_min, module.function(min_value));

    // Test maximum value
    try testing.expectEqual(expected_max, module.function(max_value));
}

test "boundary: <Another boundary condition>" {
    // ...
}
```

### 4. Negative Tests
```zig
// =============================================================================
// Negative Tests - Error Conditions
// =============================================================================

test "negative: <Description of error condition>" {
    // Test that error is returned for invalid input
    const result = module.function(invalid_input);
    try testing.expectError(error.ExpectedError, result);
}

test "negative: <Another error condition>" {
    // ...
}
```

### 5. RFC Compliance Tests
```zig
// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC XXXX §Y.Z - <Specific requirement from RFC>" {
    // Test that implementation follows RFC requirement
    // Include quote or summary of requirement in comment

    // "RFC XXXX states: <relevant quote>"
    // Verify this requirement is met
    try testing.expect(condition_that_proves_compliance);
}
```

## Common Test Patterns

### Pattern 1: Structure Initialization
```zig
test "RFC XXXX §Y.Z - <Struct> initial state" {
    const instance: module.StructName = .{};

    try testing.expectEqual(expected_field1, instance.field1);
    try testing.expectEqual(expected_field2, instance.field2);
}
```

### Pattern 2: Function Behavior
```zig
test "RFC XXXX §Y.Z - <Function> basic operation" {
    const input = create_test_input();
    const expected = create_expected_output();

    const result = module.function(input);

    try testing.expectEqual(expected, result);
}
```

### Pattern 3: State Transitions
```zig
test "RFC XXXX §Y.Z - State transition from A to B" {
    var state = module.State.init();

    try testing.expectEqual(.StateA, state.current);

    state.transition_to_b();

    try testing.expectEqual(.StateB, state.current);
}
```

### Pattern 4: Data Validation
```zig
test "RFC XXXX §Y.Z - Valid data accepted" {
    const valid_data = create_valid_data();

    const result = module.validate(valid_data);

    try testing.expect(result == .Valid);
}

test "RFC XXXX §Y.Z - Invalid data rejected" {
    const invalid_data = create_invalid_data();

    const result = module.validate(invalid_data);

    try testing.expect(result == .Invalid);
}
```

### Pattern 5: Allocator-based Tests
```zig
test "RFC XXXX §Y.Z - Resource allocation and cleanup" {
    var buffer = try module.allocate(test_allocator, size);
    defer module.free(test_allocator, buffer);

    // Use buffer
    module.populate(buffer, data);

    // Verification
    try testing.expectEqualSlices(u8, expected, buffer);
}
```

### Pattern 6: Ordering and Sequences
```zig
test "RFC XXXX §Y.Z - Sequential operations maintain order" {
    var sequence = module.Sequence.init();

    sequence.add(item1);
    sequence.add(item2);
    sequence.add(item3);

    try testing.expectEqual(item1, sequence.items[0]);
    try testing.expectEqual(item2, sequence.items[1]);
    try testing.expectEqual(item3, sequence.items[2]);
}
```

## RFC-Specific Testing Patterns

### QUIC Transport (RFC 9000)

#### Connection ID Testing
```zig
test "RFC 9000 §5.1 - Connection IDs up to 20 bytes" {
    var cid: types.Cid = .{ .len = 20 };
    // Fill with test data
    for (0..20) |i| {
        cid.bytes[i] = @intCast(i);
    }
    try testing.expectEqual(@as(u8, 20), cid.len);
}

test "RFC 9000 §5.1 - Zero-length Connection ID is valid" {
    const cid: types.Cid = .{ .len = 0 };
    try testing.expectEqual(@as(u8, 0), cid.len);
}
```

#### Packet Number Testing
```zig
test "RFC 9000 §12.3 - Packet number expansion" {
    const expected: u64 = 0xa82f30ea;
    const truncated: u64 = 0x9b32;

    const full = pn.expandTruncatedPn(truncated, 2, expected);

    try testing.expectEqual(@as(u64, 0xa82f9b32), full);
}
```

#### Stream Testing
```zig
test "RFC 9000 §2 - Stream data ordering" {
    var rx = stream.StreamRx.init();
    defer rx.deinit(&test_allocator);

    // Receive out of order
    rx.insert(&test_allocator, 5, "World");
    rx.insert(&test_allocator, 0, "Hello");
    rx.tryDrain(&test_allocator);

    // Should be in order
    try testing.expectEqualStrings("HelloWorld", rx.inbox.items);
}
```

#### Flow Control Testing
```zig
test "RFC 9000 §4 - Flow control window tracking" {
    var fc: module.FlowControl = .{ .limit = 1000 };

    fc.consume(500);
    try testing.expectEqual(@as(u64, 500), fc.consumed);
    try testing.expectEqual(@as(u64, 500), fc.available());
}
```

#### Frame Testing
```zig
test "RFC 9000 §19.X - <Frame> encoding/decoding" {
    const frame = module.Frame{
        .field1 = value1,
        .field2 = value2,
    };

    var buf: [100]u8 = undefined;
    const encoded_len = frame.encode(&buf);

    const decoded = try module.Frame.decode(buf[0..encoded_len]);

    try testing.expectEqual(frame.field1, decoded.field1);
    try testing.expectEqual(frame.field2, decoded.field2);
}
```

### Loss Detection and Congestion Control (RFC 9002)

#### RTT Testing
```zig
test "RFC 9002 §5 - RTT estimation" {
    var rtt_state: module.RttState = .{};

    const sample_rtt: u64 = 100; // ms
    rtt_state.update(sample_rtt);

    try testing.expect(rtt_state.smoothed_rtt > 0);
    try testing.expect(rtt_state.rttvar >= 0);
}
```

#### Loss Detection Testing
```zig
test "RFC 9002 §6.1 - Packet loss detection" {
    var detector: module.LossDetector = .{};

    detector.onPacketSent(pn, is_ack_eliciting);
    // Simulate time passage and ACK
    detector.onAckReceived(largest_acked, now);

    const lost_packets = detector.detectLostPackets(now);

    try testing.expect(lost_packets.len > 0);
}
```

## Complete Example: Connection ID Module

```zig
//! Unit tests for connection/connection_id.zig
//!
//! RFC References:
//! - RFC 9000 §5.1: Connection ID
//! - RFC 9000 §5.3: Connection ID Management
//! - RFC 9000 §10.3: Stateless Reset
//!
//! Coverage:
//! - Positive cases: LocalCid creation, reset token derivation
//! - Negative cases: Invalid sequence numbers
//! - Edge cases: Zero-length CIDs, max sequence numbers
//! - RFC compliance: Reset token cryptographic properties

const std = @import("std");
const testing = std.testing;
const cid = @import("../../../src/quic/connection/connection_id.zig");

// =============================================================================
// LocalCid Tests
// =============================================================================

test "RFC 9000 §5.3 - LocalCid initial state" {
    const local_cid: cid.LocalCid = .{};

    try testing.expect(!local_cid.in_use);
    try testing.expectEqual(@as(u64, 0), local_cid.sequence);
}

test "RFC 9000 §10.3 - Reset token derivation" {
    var base: [32]u8 = [_]u8{0x42} ** 32;
    const sequence: u64 = 1;
    const cid_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    const token = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes);

    try testing.expectEqual(@as(usize, 16), token.len);
}

// ... more tests ...
```

## Checklist for New Tests

- [ ] File header with RFC references
- [ ] Coverage summary
- [ ] Imports and allocator setup
- [ ] Section headers for test organization
- [ ] At least 5 positive tests
- [ ] At least 3 boundary/edge case tests
- [ ] At least 2 negative tests
- [ ] At least 3 RFC compliance tests
- [ ] All tests have RFC section references in names
- [ ] All assertions have clear expectations
- [ ] Tests are independent (no shared state)
- [ ] Cleanup/defer for allocated resources
- [ ] Test names describe what is tested

## Build System Integration

After creating a test file, add it to `build.zig`:

```zig
const test_your_module = addTst(b, "tests/unit/category/test_your_module.zig", target, optimize);
test_your_module.root_module.addImport("dependency1", dep1_mod);
test_your_module.root_module.addImport("dependency2", dep2_mod);
const run_test_your_module = b.addRunArtifact(test_your_module);
test_step.dependOn(&run_test_your_module.step);
```

## Running Your Tests

```bash
# Run specific test
zig build test --test-filter test_your_module

# Run all tests in a category
zig build test --test-filter connection

# Run all RFC compliance tests
./scripts/run_rfc_compliance_tests.sh
```

## Tips

1. **Start with positive cases**: Test normal operation first
2. **Add boundaries**: Test min/max values, empty inputs
3. **Test errors**: Verify error conditions are handled
4. **RFC quotes**: Include relevant RFC text as comments
5. **Deterministic**: No random values, no timing dependencies
6. **Isolated**: Each test should be independent
7. **Clear names**: Test name should describe what is verified
8. **Assertions**: Use the most specific assertion available

## Common Mistakes to Avoid

- ❌ Not using test_allocator for allocations
- ❌ Forgetting `defer` for cleanup
- ❌ Using random values (breaks determinism)
- ❌ Tests that depend on execution order
- ❌ Vague test names like "test_function_works"
- ❌ Not testing error paths
- ❌ Not referencing RFC sections
- ❌ Tests longer than 30 lines (break into multiple)

## Resources

- [CLAUDE.md](./CLAUDE.md) - Module structure reference
- [RFC_COMPLIANCE_TEST_PLAN.md](./RFC_COMPLIANCE_TEST_PLAN.md) - Overall test strategy
- [Existing unit tests](./tests/unit/) - Examples to reference
- RFC 9000: https://www.rfc-editor.org/rfc/rfc9000.html
- RFC 9001: https://www.rfc-editor.org/rfc/rfc9001.html
- RFC 9002: https://www.rfc-editor.org/rfc/rfc9002.html
