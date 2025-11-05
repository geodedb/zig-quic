# Client Verification Guide for TLS Error 266 Fix

This guide explains how to verify the TLS Error 266 fix works correctly with various QUIC client implementations.

## Prerequisites

1. Build the QUIC server:
   ```bash
   zig build
   ```

2. Ensure server binary is available:
   ```bash
   ./zig-out/bin/quic-server
   ```

## Test with quic-go (Go)

**Why**: quic-go uses zero-length connection IDs by default.

```bash
# Terminal 1: Start server
./zig-out/bin/quic-server --cert certs/cert.pem --key certs/key.pem --port 4433

# Terminal 2: Run quic-go client
cd test-clients/quic-go-client
go run main.go https://127.0.0.1:4433
```

**Expected**: Handshake completes successfully, no TLS alert 0x010a

**Verify in logs**:
- ✓ "accepted connection"
- ✓ No "TLS alert 0x010a" or "error 266"
- ✓ Handshake completes within 1-2 RTTs

## Test with quinn (Rust)

**Why**: quinn supports zero-length CIDs and is strict about RFC compliance.

```bash
# Terminal 1: Start server
./zig-out/bin/quic-server --cert certs/cert.pem --key certs/key.pem --port 4433

# Terminal 2: Build and run quinn client
cd clients/rust
cargo build --release
./target/release/test-client 127.0.0.1:4433
```

**Expected**: Connection established, streams working

**Verify in logs**:
- ✓ "Connection established"
- ✓ No "failed to authenticate packet"
- ✓ Stream data transfers successfully

## Test with aioquic (Python)

**Why**: aioquic can be configured for zero-length CIDs.

```bash
# Terminal 1: Start server
./zig-out/bin/quic-server --cert certs/cert.pem --key certs/key.pem --port 4433

# Terminal 2: Run aioquic client
cd clients/python
source venv/bin/activate
python3 test_client.py --host 127.0.0.1 --port 4433 --zero-length-cid
```

**Expected**: Handshake succeeds with zero-length CID

**Verify in logs**:
- ✓ "Connection established"
- ✓ No "Payload decryption failed"
- ✓ HTTP/3 requests succeed

## Stress Test: Packet Loss Simulation

To specifically test PTO probe functionality:

```bash
# Use tc (traffic control) to simulate packet loss
sudo tc qdisc add dev lo root netem loss 10%

# Run any client
cd test-clients/quic-go-client
go run main.go https://127.0.0.1:4433

# Clean up
sudo tc qdisc del dev lo root
```

**Expected**: 
- ✓ Handshake still completes despite packet loss
- ✓ PTO probes are sent (visible in debug logs)
- ✓ No early termination due to missing PTO probes

**Verify in server logs**:
```
server PTO: deriving Initial keys with odcid=...
Retransmitted Initial packet: ... bytes
```

## Automated E2E Test

Run the comprehensive end-to-end test suite:

```bash
make e2e-test-all
```

This will test with:
- quic-go client
- quinn client  
- aioquic client

**Expected output**:
```
✓ quic-go client: PASS
✓ quinn client: PASS
✓ aioquic client: PASS

All clients successfully completed handshake
```

## Regression Test Verification

Run unit tests specifically for zero-length DCID handling:

```bash
# Run all tests
zig build test

# Run specific tests
zig build test --test-filter zero_length
zig build test --test-filter pto_probe
```

**Expected**:
- ✓ `test_zero_length_scid_coalescing` - PASS
- ✓ `test_pto_probe_zero_length_dcid` - PASS

## What to Look For

### Success Indicators
- ✅ Handshake completes in 1-2 RTTs
- ✅ No TLS alerts (especially 0x010a/266)
- ✅ PTO probes sent even with zero-length DCID
- ✅ Packets coalesce correctly
- ✅ Stream data transfers work

### Failure Indicators (Fixed by this patch)
- ❌ TLS alert 0x010a (266) - **Should not appear after fix**
- ❌ "failed to authenticate packet" - Indicates DCID mismatch
- ❌ Handshake timeout - Server not retransmitting
- ❌ "Dropped packet: pn=-1, reason=3" - Header protection issue

## Logging Configuration

For detailed debugging, enable verbose logging:

```bash
# Server
RUST_LOG=trace ./zig-out/bin/quic-server --cert certs/cert.pem --key certs/key.pem --port 4433

# Or use debug build
zig build -Drelease-safe=false
./zig-out/bin/quic-server --cert certs/cert.pem --key certs/key.pem --port 4433 --verbose
```

Look for these log lines confirming the fix:
```
Server: Handshake DCID len=0 (using peer_initial_scid)
PTO Initial: Sending probe with zero-length DCID
RFC 9000 §12.2: Zero-length DCIDs are valid and must be supported
```

## Performance Verification

The fix should not impact performance:

```bash
# Benchmark before and after fix
make bench

# Measure handshake latency
./tools/measure_handshake_time.sh
```

**Expected**: No regression in handshake time (typically 20-50ms on localhost)

## Continuous Integration

Add to CI pipeline:

```yaml
- name: Test TLS Error 266 Fix
  run: |
    zig build test --test-filter zero_length
    zig build test --test-filter pto_probe
    make e2e-test-all
```

## Troubleshooting

### Issue: Client still reports TLS error 266

**Check**:
1. Server compiled with latest code? (`zig build --verbose`)
2. Running correct binary? (`which quic-server`)
3. Fix applied? (`grep "RFC 9000 §12.2" src/quic/endpoint.zig`)

### Issue: Tests fail to compile

**Solution**:
```bash
# Clean build
rm -rf zig-cache zig-out
zig build

# Verify imports
zig build test --summary all
```

### Issue: PTO probes not visible in logs

**Enable debug output**:
```zig
// In src/quic/endpoint.zig, ensure debug prints are enabled
std.debug.print("PTO probe sent: dcid_len={}\n", .{dcid.len});
```

## Contact

For issues or questions about the fix:
- See `TLS_ERROR_266_FIX_REPORT.md` for technical details
- Check `docs/DESIGN.md` for connection ID handling
- Review `docs/GAP.md` for RFC compliance notes
