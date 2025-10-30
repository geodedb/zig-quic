// Debug patch for QUIC Initial packet handling
// This patch adds detailed logging to understand the encryption/decryption mismatch

// Key areas to investigate:
// 1. Connection ID extraction from Initial packet
// 2. Initial secret derivation
// 3. Header protection removal
// 4. AEAD decryption

// The problem flow:
// 1. Go client sends Initial packet with version 0x00000001
// 2. Server receives packet and extracts DCID/SCID
// 3. Server derives Initial secrets using DCID
// 4. Server attempts to remove header protection and decrypt
// 5. All decryption attempts fail (line 1843)
// 6. Server sends RETRY packet

// Critical code locations:
// - src/quic/endpoint.zig:1700-1880 - Initial packet processing
// - src/quic/packet.zig:250-350 - decryptInitialPacket
// - src/quic/tls/key_schedule.zig:89-100 - deriveInitialSecret

// Suspected issues:
// 1. Version handling - The server may not properly handle version negotiation
// 2. Connection ID extraction - The DCID used for key derivation may be wrong
// 3. Token handling - The Go client may send a token that confuses the server
// 4. Header protection - The sample offset calculation might be incorrect

// To fix:
// 1. Add detailed logging of DCID/SCID extraction
// 2. Log the derived Initial secrets
// 3. Compare with known test vectors from RFC 9001
// 4. Ensure version negotiation works correctly