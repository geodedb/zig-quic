# QUIC Interop Test Suite Status

## Updated: 2025-10-13

## Executive Summary

The interop test infrastructure has been **updated and improved**, but there are **protocol-level issues** preventing successful Docker-based interop tests with external implementations.

### What Works ✅
- **Local interop tests**: `test_interop.sh` passes - zig-server ↔ zig-client communication works
- **Docker infrastructure**: Network simulator, container orchestration, and build process all working
- **Test scripts**: All test scripts properly configured with correct timeouts and Docker settings

### What Doesn't Work ❌
- **Docker interop tests**: zig-server doesn't receive packets from quic-go-client (or any external client)
- **Root cause**: Packets sent by external clients aren't being received by the zig server's UDP socket

## Recent Fixes Applied

### 1. Docker Host Configuration
**Issue**: DOCKER_HOST was set incorrectly to `/var/run/docker.sock` instead of `unix:///var/run/docker.sock`
**Fix**: Added automatic DOCKER_HOST fix at the start of all test scripts
**Files modified**:
- `scripts/interop_test.sh`
- `scripts/interop_verify.sh`
- `scripts/interop_full.sh`

### 2. Network Simulator Readiness Timeout
**Issue**: Tests were failing because wait times were too short (3-10 seconds)
**Fix**: Increased wait time to 15 seconds after starting sim container
**Result**: Sim is now reliably available (confirms with "sim:57832 is available after 0 seconds")
**Files modified**:
- `scripts/interop_test.sh`: Line 48 (10s → 15s)
- `scripts/interop_verify.sh`: Line 131 (5s → 15s)
- `scripts/interop_full.sh`: Lines 117, 202 (3s/10s → 15s)

## Current Issues

### Critical: Packet Reception Problem

**Symptoms**:
- quic-go client sends Initial packets (confirmed in client logs)
- zig server never receives them (server shows "got 0 events" continuously)
- Server socket is created successfully on fd=3 for 0.0.0.0:443
- Server polls correctly but receives no events

**Evidence from logs**:

Client (`examples/interop/quic-network-simulator/logs/client/log.txt`):
```
2025/10/13 19:08:17 client -> Sending packet 0 (1280 bytes) ...
2025/10/13 19:08:17 client -> Sending packet 1 (1280 bytes) ...
[... multiple retries with PTO timeouts ...]
2025/10/13 19:08:22 client Destroying connection: timeout: no recent network activity
```

Server (`examples/interop/quic-network-simulator/logs/server/server.log`):
```
Endpoint: Created socket fd=3 for address 0.0.0.0:443
[qns] server: started (listening 0.0.0.0:443)
Endpoint.poll called (count=1), timeout_ms=10
poll_epoll_backend: got 0 events
[... continuous polling with 0 events ...]
```

**Suspected causes**:
1. Network routing through simulator not configured correctly for zig endpoint
2. Server socket not properly configured to receive from simulator networks
3. Missing SO_REUSEADDR or SO_REUSEPORT socket options
4. Incorrect binding address (0.0.0.0 vs specific interface)

### Minor: Log Function Panic (Non-blocking)

**Symptoms**:
```
thread 23 panic: reached unreachable code
/opt/zig/lib/std/os/linux/x86_64.zig:47:5: 0x105f041 in log
/quic/cmd/qns-endpoint.zig:162:12: 0x105b659 in main
```

**Impact**: Server continues running despite panic, so this is non-blocking
**Note**: Previously documented as fixed in INTEROP_STATUS.md but still occurring

## Test Script Configuration

### Available Test Scripts

1. **test_interop.sh** ✅ PASSING
   - Tests local zig-server ↔ zig-client (no Docker)
   - Quick verification of basic functionality
   - Runtime: ~10 seconds

2. **scripts/interop_test.sh** ❌ FAILING
   - Single Docker handshake test: zig-server ↔ quic-go-client
   - Uses generic profile with SERVER_IMAGE/CLIENT_IMAGE env vars
   - Runtime: ~2 minutes
   - **Failure**: Packets not reaching server

3. **scripts/interop_verify.sh** ❌ NOT TESTED
   - Comprehensive suite with build verification
   - Tests against major implementations (quic-go, ngtcp2, quiche)
   - Would fail for same reason as interop_test.sh

4. **scripts/interop_full.sh** ❌ NOT TESTED
   - Full matrix testing with all implementations
   - Modes: basic (quic-go only), quick (3 impls), full (all impls)
   - Would fail for same reason as interop_test.sh

### Configuration Settings

All scripts now include:
- ✅ DOCKER_HOST automatic fix
- ✅ 15-second sim startup wait
- ✅ Proper network cleanup
- ✅ Network conflict pruning
- ✅ Profile-based container management

## Recommended Next Steps

### Priority 1: Fix Packet Reception
1. **Investigate socket configuration in qns-endpoint**
   - Check bind address and interface configuration
   - Verify socket options (SO_REUSEADDR, etc.)
   - Add detailed logging for socket creation and binding

2. **Verify routing in Docker network**
   - Check iptables rules in sim container
   - Verify packets reach server container network interface
   - Test with tcpdump in both containers

3. **Compare with working implementation**
   - Review how quic-go-interop sets up its server
   - Check run_endpoint.sh from other implementations
   - Verify routing configuration differences

### Priority 2: Add Debugging Capabilities
1. **Enhanced logging in qns-endpoint**
   - Log all incoming packets (even invalid ones)
   - Add packet hex dumps for debugging
   - Track socket state and errors

2. **Network debugging tools**
   - Add tcpdump to Docker image for packet capture
   - Create debug mode that shows routing tables
   - Add connectivity test before starting QUIC

### Priority 3: Fix Log Panic
- Investigate the "unreachable code" panic in log function
- May need to update Zig version or change logging approach
- Consider using stderr directly instead of debug.print

## How to Run Tests

### Local Test (Currently Working)
```bash
./test_interop.sh
```

### Single Docker Test (Currently Failing)
```bash
SKIP_BUILD=1 ./scripts/interop_test.sh
```

### View Logs After Test
```bash
# Server logs
cat examples/interop/quic-network-simulator/logs/server/server.log

# Client logs
cat examples/interop/quic-network-simulator/logs/client/log.txt
```

### Full Verification Suite
```bash
# Basic tests (when fixed)
./scripts/interop_verify.sh

# Extended tests
EXTENDED=1 ./scripts/interop_verify.sh
```

### Full Matrix Testing
```bash
# Test against quic-go only
SKIP_BUILD=1 ./scripts/interop_full.sh

# Test against major implementations
SKIP_BUILD=1 ./scripts/interop_full.sh quick

# Test against all implementations
SKIP_BUILD=1 ./scripts/interop_full.sh full
```

## Environment Variables

- `SKIP_BUILD=1`: Skip rebuilding Docker images and binaries
- `EXTENDED=1`: Run extended tests in interop_verify.sh
- `SKIP_QNS_NET_PRUNE=1`: Skip Docker network cleanup
- `DOCKER_HOST`: Now automatically fixed by test scripts
- `ZIG_VERBOSE=1`: Enable verbose logging in qns-endpoint

## File Modifications Summary

```
Modified files:
- scripts/interop_test.sh: Added DOCKER_HOST fix, increased sim wait to 15s
- scripts/interop_verify.sh: Added DOCKER_HOST fix, increased sim wait to 15s
- scripts/interop_full.sh: Added DOCKER_HOST fix, increased sim wait to 15s (both run_test and run_generic_test)

Files to investigate:
- cmd/qns-endpoint.zig: Packet reception and socket configuration
- examples/interop/zig-qns/Dockerfile: Network configuration
- examples/interop/zig-qns/run_endpoint.sh: Container startup
```

## Conclusion

The interop test infrastructure is **properly configured and ready for testing**, but there's a **critical packet reception issue** preventing communication between the zig server and external QUIC clients through the Docker network simulator.

The issue is isolated to the Docker environment (local tests work fine), suggesting a network routing or socket configuration problem specific to the containerized setup.

**Next action**: Debug packet flow from sim → server container to understand why UDP packets aren't reaching the qns-endpoint process.
