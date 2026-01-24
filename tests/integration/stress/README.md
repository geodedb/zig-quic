# QUIC Stress Testing

This directory contains stress tests for evaluating the QUIC implementation under high load, resource constraints, and edge conditions.

## Test Categories

### High-Load Tests
- Thousands of concurrent connections
- High packet rate (>100k packets/sec)
- Large data transfers (>1GB)
- Many concurrent streams per connection

### Resource Exhaustion Tests
- Memory pressure scenarios
- File descriptor exhaustion
- CPU saturation
- Network buffer exhaustion

### Long-Lived Connection Tests
- Connections lasting hours/days
- Idle timeout edge cases
- Key update frequency under load
- Memory leak detection

### Scalability Tests
- Connection establishment rate
- Stream creation rate
- Throughput vs connection count
- Latency under load

## Running Stress Tests

**Warning**: Stress tests consume significant system resources and may take minutes to hours to complete.

```bash
# Run all stress tests (may take a long time)
zig test tests/integration/stress/stress.zig

# Run specific stress test category
zig test tests/integration/stress/stress.zig --test-filter "high-load"

# Run with timeout
timeout 300 zig test tests/integration/stress/stress.zig
```

## System Requirements

Stress tests may require:
- **RAM**: 4GB+ available
- **File Descriptors**: Increase `ulimit -n` to 10000+
- **CPU**: Multi-core recommended
- **Time**: Allow 5-60 minutes per test

### Increasing Limits

```bash
# Increase file descriptor limit
ulimit -n 10000

# Check current limits
ulimit -a

# For permanent changes, edit /etc/security/limits.conf
```

## Monitoring

### Resource Monitoring During Tests

```bash
# Monitor memory usage
watch -n 1 'ps aux | grep zig'

# Monitor file descriptors
watch -n 1 'lsof | grep zig | wc -l'

# Monitor network stats
watch -n 1 'netstat -s | grep -E "packets|segments"'
```

### Profiling

```bash
# Run with profiling
zig test tests/integration/stress/stress.zig --release-safe

# Memory profiling (requires valgrind)
valgrind --leak-check=full zig test tests/integration/stress/stress.zig
```

## Performance Metrics

Tests track and report:
- **Throughput**: MB/s, packets/s
- **Latency**: p50, p95, p99, max
- **Resource Usage**: memory, CPU, file descriptors
- **Error Rates**: packet loss, connection failures
- **Scalability**: connections/sec, streams/sec

## Expected Performance

Target performance benchmarks:
- **Connection Rate**: 1000+ connections/sec
- **Throughput**: 1+ Gbps per connection
- **Latency**: <10ms p99 under load
- **Memory**: <10MB per 1000 connections
- **Concurrent Connections**: 10,000+ simultaneous

## Known Limitations

Document current implementation limits:
- **Max Connections**: TBD
- **Max Streams Per Connection**: TBD
- **Max Throughput**: TBD
- **Memory Per Connection**: TBD

## Debugging Performance Issues

### CPU Profiling
```bash
# Generate CPU flame graph
perf record -F 99 -g -- zig test tests/integration/stress/stress.zig
perf script | flamegraph.pl > flamegraph.svg
```

### Memory Profiling
```bash
# Track allocations
heaptrack zig test tests/integration/stress/stress.zig
heaptrack_gui heaptrack.*.gz
```

### Network Analysis
```bash
# Capture packets during stress test
tcpdump -i any -w stress_test.pcap udp
```

## Contributing

When adding stress tests:
1. Set realistic timeouts
2. Clean up resources on failure
3. Report performance metrics
4. Test in isolation (single test per run)
5. Document expected behavior under stress
