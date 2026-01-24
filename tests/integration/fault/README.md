# QUIC Fault Injection Testing

This directory contains fault injection tests for evaluating the QUIC implementation's resilience to network failures, packet corruption, and various error conditions.

## Test Categories

### Network Failure Injection
- Packet loss (random, burst, periodic)
- Packet reordering
- Packet duplication
- Packet delay and jitter
- Network partition (complete loss)
- Asymmetric failures (one-way loss)

### Packet Corruption Injection
- Random bit flips
- Header corruption
- Payload corruption
- Authentication tag corruption
- Length field corruption

### Protocol Violation Injection
- Malformed packets
- Invalid frame sequences
- Protocol state violations
- Invalid stream IDs
- Invalid connection IDs

### Resource Failure Injection
- Simulated memory allocation failures
- File descriptor exhaustion
- Buffer overflow scenarios
- CPU starvation
- Clock skew/drift

### Timing Failure Injection
- Extreme delays (seconds, minutes)
- Timeout scenarios
- Timer precision issues
- PTO edge cases
- Idle timeout edge cases

## Running Fault Injection Tests

```bash
# Run all fault injection tests
zig test tests/integration/fault/fault.zig

# Run specific fault category
zig test tests/integration/fault/fault.zig --test-filter "packet-loss"

# Run with verbose output
zig test tests/integration/fault/fault.zig -- --summary all
```

## Test Infrastructure

### Fault Injection Mechanisms

The fault injection framework provides:

1. **Packet Interceptor**: Intercepts packets and applies faults
2. **Configurable Fault Rates**: Set probabilities for each fault type
3. **Selective Faults**: Target specific packet types or flows
4. **Reproducible Faults**: Seed-based fault sequences
5. **Fault Scheduling**: Time-based or event-based fault triggers

### Loopback Transport Integration

Fault injection uses the loopback transport with extended capabilities:

```zig
var transport = try loopback.LoopbackTransport.init(allocator, .{
    .loss_rate = 0.05,        // 5% packet loss
    .corruption_rate = 0.01,  // 1% corruption
    .reordering_rate = 0.10,  // 10% reordering
    .delay_ms = 100,          // 100ms delay
    .jitter_ms = 50,          // ±50ms jitter
});
```

## Fault Scenarios

### Basic Fault Scenarios
- Single packet loss
- Burst packet loss (3+ consecutive)
- Random corruption
- Extreme delay (>1 second)

### Complex Fault Scenarios
- Loss + Corruption + Delay combined
- Asymmetric faults (client-to-server vs server-to-client)
- Time-varying faults (increase over time)
- Targeted faults (only Initial packets, only Handshake, etc.)

### Catastrophic Fault Scenarios
- Complete network partition
- Sustained 100% packet loss
- All packets corrupted
- Infinite delay
- Rapid oscillation between good and bad conditions

## Expected Behavior Under Faults

### Packet Loss
- **Low loss (<1%)**: Minimal impact, recovery via retransmission
- **Medium loss (1-10%)**: Increased latency, successful recovery
- **High loss (>10%)**: Slower recovery, possible timeout
- **Complete loss**: Connection timeout and closure

### Packet Corruption
- **Authenticated**: Corrupted packets rejected, retransmission
- **Header corruption**: Packet discarded, no side effects
- **Systematic corruption**: Connection may fail authentication

### Packet Reordering
- **Mild reordering**: Transparent to application
- **Extreme reordering**: Out-of-order processing
- **Should not**: Cause data corruption or protocol violations

### Extreme Delays
- **<RTT**: Minimal impact
- **>RTT**: Triggers retransmission, PTO
- **>>RTT**: Multiple PTOs, eventual timeout

## Debugging Fault Scenarios

### Packet Capture
```bash
# Capture packets during fault injection
tcpdump -i lo -w fault_test.pcap 'udp'
```

### Detailed Logging
Enable logging in both test framework and implementation to trace fault handling.

### Reproducing Faults
All tests use seeded random number generators for reproducibility:
```zig
test "Reproducible packet loss" {
    const seed: u64 = 12345;
    var prng = std.rand.DefaultPrng.init(seed);
    // Fault injection with deterministic RNG
}
```

## Contributing

When adding fault injection tests:
1. Use reproducible random seeds
2. Document expected recovery behavior
3. Set appropriate timeouts for fault scenarios
4. Test both transient and persistent faults
5. Verify no memory leaks on error paths
6. Ensure graceful degradation, not crashes

## Known Issues

Document any known fault handling issues:

- **Issue**: TBD
- **Fault Type**: TBD
- **Expected**: TBD
- **Actual**: TBD
- **Status**: TBD
