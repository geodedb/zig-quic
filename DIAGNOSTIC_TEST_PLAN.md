# Zig QUIC Server: 1-RTT Bi-Directional Communication Failure - Diagnostic Test Plan

## Test Configuration

**Zig Implementation:**
- Repository: `/home/benji/src/spyder/quic`
- Branch/Commit: main (edfc9e6)
- QUIC Version: v1 (RFC 9000)
- TLS Library: BoringSSL (fork in `forks/boringssl`)
- ALPN: `hq-interop`

**Peer Implementations to Test:**
1. **quic-go** (Go) - v0.48.0+
2. **aioquic** (Python) - latest
3. **quinn** (Rust) - latest
4. **quiche** (Rust/C) - Cloudflare authoritative implementation

**Transport Parameters:**
- `max_udp_payload_size`: 1472
- `initial_max_data`: 10485760
- `initial_max_stream_data_bidi_local`: 1048576
- `initial_max_stream_data_bidi_remote`: 1048576
- `idle_timeout`: 30000ms
- `max_streams_bidi`: 128

**TLS Configuration:**
- Server cert: `certs/cert.pem` / `certs/key.pem`
- Client: `InsecureSkipVerify: true`

---

## Problem Statement

### Symptoms
1. ✅ TLS 1.3 handshake completes successfully with all peers
2. ✅ Clients send `GET /\r\n` on stream 0
3. ✅ quic-go client observes server sending two short-header packets (40 & 41 bytes)
4. ❌ Clients timeout waiting for response data (no STREAM frames received)

### Fixed Issues (context)
- Packet number expansion algorithm (RFC 9000 Appendix A.3)
- Double PN expansion bug
- `decodeShortProtected` now returns expanded PN (not truncated)
- Packet number field changed from u32 to u64
- Short header DCID uses `shortHeaderDcid()` instead of `our_scid`

### Hypothesis
Server may be:
1. Not receiving/decrypting client 1-RTT packets containing STREAM frames
2. Not processing STREAM frames correctly
3. Sending 1-RTT packets but using wrong keys/DCID/PN encoding
4. Successfully sending but clients can't decrypt responses

---

## Test Scenarios

### Test 1: Server RX Path - 1-RTT Packet Decryption

**Objective:** Verify server can decrypt incoming 1-RTT packets from client

**Steps:**
1. Start Zig server with debug logging enabled
2. Client sends `GET /\r\n` on stream 0
3. Capture server logs

**Success Criteria:**
- Log shows: `decodeShortProtected: truncated PN=X -> expanded PN=Y`
- Log shows: `Server received STREAM frame - id=0, off=0, len=8`
- Log shows: `stream0 opened rx N` where N > 0

**Evidence to Collect:**
- Server-side PN expansion trace
- STREAM frame parse success/failure
- Decrypt errors (if any): AEAD auth failure, truncated packet, etc.

**Expected vs. Actual:**
```
Expected: decodeShortProtected succeeds, payload contains STREAM{id:0, data:"GET /\r\n"}
Actual:   [TO BE DETERMINED]
```

---

### Test 2: Server Stream Processing

**Objective:** Verify server correctly processes STREAM frames into `readStream()` inbox

**Steps:**
1. After Test 1, server calls `conn.readStream(0, buf)`
2. Check if inbox contains data

**Success Criteria:**
- `readStream()` returns > 0 bytes
- Data matches `GET /\r\n`

**Evidence:**
- `readStream` debug logs
- Inbox byte count
- Stream state (FIN received, offset tracking)

---

### Test 3: Server TX Path - Response Encoding

**Objective:** Verify server can encode and send 1-RTT packets with STREAM frames

**Steps:**
1. Server calls `conn.writeStream(0, response_data)`
2. Check `sendControlFrames()` or equivalent
3. Verify `encodeShortProtected()` call

**Success Criteria:**
- Log shows: `Server: Sending control frames (N bytes)`
- `encodeShortProtected` builds packet with correct:
  - DCID (from `shortHeaderDcid()`)
  - PN (incremented `pn_app_tx`)
  - Key phase bit
  - Encrypted STREAM frame payload

**Evidence:**
- TX PN value
- DCID used (should match client's SCID)
- Packet size sent via UDP
- AEAD encryption success

---

### Test 4: Client RX Path - Response Decryption

**Objective:** Verify client can decrypt server's 1-RTT response packets

**Steps:**
1. Run quic-go client with `QUIC_GO_LOG_LEVEL=debug`
2. Capture qlog or packet-level logs
3. Check for decrypt errors

**Success Criteria:**
- Client logs: `Received 1-RTT packet: pn=X, size=Y, frames=1`
- Client logs: `STREAM id=0, offset=0, len=N`
- Client `stream.Read()` returns response data

**Evidence:**
- quic-go decrypt trace
- Packet number received
- Frame type and payload

**Common Failure Modes:**
- Wrong DCID → packet dropped (no matching connection)
- Wrong keys → AEAD auth failure
- PN too far ahead/behind → expansion fails → decrypt fails
- Key phase mismatch → decrypt with wrong key generation

---

### Test 5: PN Space Synchronization

**Objective:** Confirm PN expansion works correctly on both RX and TX

**Test Case:**
1. Server sends PN=0, 1, 2 (handshake phase)
2. Server sends 1-RTT PN=0 (first app packet)
3. Client sends 1-RTT PN=0
4. Server receives and expands client PN=0 correctly (largest_pn=0 initially)
5. Server responds with PN=1
6. Client receives and expands server PN=1

**Check:**
- `largest_pn` value passed to `decodeShortProtected`
- Expansion formula: `pn_full = pn_truncated + expected_pn - ((expected_pn + pn_half_window) % pn_window)`
- Where `pn_window = 1 << (8 * pn_len)`, `pn_half_window = pn_window / 2`

**Evidence:**
- Server: `DEBUG: Decoding 1-RTT packet, have_any=..., pn_app.max=..., largest_pn=...`
- Expanded PN values match truncated + offset

---

### Test 6: DCID Consistency

**Objective:** Verify short header DCID matches peer's SCID

**On Server (TX):**
```zig
fn shortHeaderDcid(self: *Connection) []const u8 {
    // Should return the SCID the client chose
    return if (self.peer_scid.len > 0)
        self.peer_scid.bytes[0..self.peer_scid.len]
    else
        &[_]u8{};
}
```

**On Client (RX):**
- Client expects DCID = its own SCID
- Mismatch → packet dropped silently

**Check:**
- Server's `peer_scid` is set during handshake from client's Initial SCID
- `encodeShortProtected` uses correct DCID
- Client RX logs show packet accepted (not dropped due to DCID mismatch)

---

### Test 7: Key Phase Bit

**Objective:** Ensure key_phase bit matches current encryption generation

**Initial State:**
- Both sides start with `key_phase = false` (0)
- First 1-RTT packets use `app_rx_keys` / `app_tx_keys` with phase=0

**Check:**
- Server encodes with `self.tx_key_phase` (should be 0 initially)
- Client decodes with matching phase
- If phase mismatch → client tries next/prev keys

**Evidence:**
- `encodeShortProtected(..., key_phase)` parameter
- Client logs: `Updated keys: level=Application, perspective=...`

---

## Execution Strategy

### Phase 1: Instrumentation
1. Add debug prints to:
   - `endpoint.zig:processIncomingDatagram` (short header path)
   - `packet.zig:decodeShortProtected` (RX decrypt)
   - `packet.zig:encodeShortProtected` (TX encrypt)
   - `conn.zig:readStream` / `writeStream`
   - `conn.zig:sendControlFrames`

2. Capture to structured log:
   - Timestamp (μs precision)
   - Direction (C→S / S→C)
   - Layer (TLS / QUIC / H3)
   - Event (CRYPTO, STREAM, ACK, etc.)
   - Packet number, length, DCID

### Phase 2: Minimal Reproducible Example
1. Start server: `./zig-out/bin/quic-server --bind 127.0.0.1:4433`
2. Run client: `go run test-go-client.go`
3. Client sends 8 bytes, expects echo
4. Timeout after 5 seconds
5. Collect logs from both sides

### Phase 3: Comparison with Authoritative Implementations
1. Run same test against **quiche** (Cloudflare) server
2. Run Zig server against multiple clients (quic-go, aioquic, quinn)
3. Cross-check:
   - Packet sizes match expected (header + payload + tag)
   - PN values are sequential
   - DCID/SCID are symmetric

### Phase 4: Packet Capture Analysis
1. Run with `tcpdump -i lo -w /tmp/quic.pcap port 4433`
2. Export TLS secrets: `SSLKEYLOGFILE=/tmp/keys.log`
3. Open in Wireshark with keys loaded
4. Verify:
   - Short header format correct
   - DCID matches
   - Encrypted payload decrypts to valid frames

---

## Diagnostic Outputs

### JSON Test Result Schema
```json
{
  "test_config": {
    "zig_impl": "main@edfc9e6",
    "peers": ["quic-go@v0.48.0"],
    "versions": {"zig": "main", "peer": "v0.48.0"},
    "alpn": ["hq-interop"],
    "quic_versions": ["v1"],
    "params": {
      "max_udp_payload_size": 1472,
      "initial_max_data": 10485760,
      "initial_max_stream_data_bidi_remote": 1048576
    }
  },
  "execution_summary": {
    "status": "fail",
    "metrics": {
      "handshake_rtt_ms": 12,
      "bytes_rx": 8,
      "bytes_tx": 0
    },
    "zerortt_used": false,
    "issues": ["Server receives STREAM but client gets no response"]
  },
  "failure_analysis": {
    "present": true,
    "suspected_side": "server",
    "rfc_refs": ["RFC9000 §17.3.1", "RFC9000 §A.3"],
    "root_cause": "Server TX path: incorrect DCID or key phase in short header",
    "timeline": [
      {"t_us": 0, "dir": "C→S", "layer": "QUIC", "event": "STREAM{id:0, len:8}"},
      {"t_us": 150, "dir": "S→C", "layer": "QUIC", "event": "ShortHeader{pn:1, len:40}"},
      {"t_us": 151, "dir": "S→C", "layer": "QUIC", "event": "ShortHeader{pn:2, len:41}"},
      {"t_us": 5000000, "dir": "CLIENT", "layer": "APP", "event": "Read timeout"}
    ]
  },
  "repro": {
    "commands": [
      "./zig-out/bin/quic-server --bind 127.0.0.1:4433",
      "go run test-go-client.go"
    ],
    "env": {
      "SSLKEYLOGFILE": "/tmp/keys.log"
    },
    "files": ["certs/cert.pem", "certs/key.pem"]
  },
  "compatibility_notes": [
    "quic-go: handshake OK, no data RX",
    "aioquic: same failure",
    "quinn: same failure",
    "All clients show identical symptom → server TX issue likely"
  ]
}
```

---

## Next Steps (Execution)

### Immediate Actions
1. **Enable full debug logging** in server and client
2. **Run Test 1** (Server RX path)
3. **Collect evidence**: logs showing whether `decodeShortProtected` succeeds
4. **If Test 1 fails**: Fix server RX decrypt (key derivation, PN expansion, DCID matching)
5. **If Test 1 passes**: Move to Test 3 (Server TX path)
6. **Check DCID**: Compare `shortHeaderDcid()` return value with client's SCID
7. **Check PN**: Ensure `pn_app_tx` increments and encodes correctly
8. **Packet capture**: Decrypt in Wireshark to see actual frame bytes

### Expected Outcome
- **Root cause identified** within 2-3 test iterations
- **Timeline** showing exact failure point (decrypt? parse? encode? send?)
- **Fix proposed** with specific code location and RFC reference
- **Regression test** added to prevent recurrence

---

## References

### RFC Sections (Critical)
- **RFC 9000 §17.3.1**: Short Header Packet Format
- **RFC 9000 §A.3**: Packet Number Encoding and Decoding
- **RFC 9000 §12.3**: Packet Number Spaces
- **RFC 9001 §5.1**: Packet Protection (AEAD)
- **RFC 9001 §5.4**: Header Protection
- **RFC 9001 §6**: Key Update

### Authoritative Implementations
- **forks/quiche**: Cloudflare's Rust/C impl (check `quiche/src/packet.rs`, `crypto.rs`)
- **forks/boringssl**: TLS 1.3 reference (`ssl/`, `crypto/`)

---

## Tooling

### Packet Capture
```bash
sudo tcpdump -i lo -w /tmp/quic.pcap 'udp port 4433'
# Decrypt in Wireshark with SSLKEYLOGFILE
```

### QLOG (if supported)
```bash
# Server: export QLOGDIR=/tmp/qlogs
# Client (quic-go): automatic with Tracer
# View: https://qvis.quictools.info/
```

### Network Shaping (optional)
```bash
# Add 10ms latency, 1% loss
sudo tc qdisc add dev lo root netem delay 10ms loss 1%
```

---

## Quality Gates

Before declaring test complete:
- [ ] Reproducible steps provided (run 3 times, same result)
- [ ] At least one concrete artifact (log snippet, pcap frame, PN value)
- [ ] RFC section cited for expected behavior
- [ ] Suspected code location identified
- [ ] Compatibility matrix updated (pass/fail per peer)

---

**Status:** READY FOR EXECUTION
**Estimated Time:** 2-4 hours for full diagnostic
**Blocker:** None (all tools and peers available)
