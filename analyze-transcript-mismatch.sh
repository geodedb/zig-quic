#!/bin/bash
# Analyze the transcript hash and handshake secret mismatch

echo "==================================================================="
echo "TRANSCRIPT HASH AND HANDSHAKE SECRET ANALYSIS"
echo "==================================================================="
echo ""

# Server values
SERVER_TRANSCRIPT="8274492291CBC334C61F31CCC8C70A389B4B16A29D7D8D7A4C40E1C097903F18"
SERVER_ECDHE="9C690C0E70615563DBCF40C5B44CDFE4A1DC0A89477A55F83E52E930EAE3571D"
SERVER_CLIENT_HS="052B35D0CD2C77AB97CBCF0392E27F95694C7A1DFA67EB1EF7D770913201B3BC"
SERVER_SERVER_HS="3819D92FBAD6D0D1431944C344D522AAF2F7FEF2A63FD60F3A45DB4FBAEAB8C7"

# Client values (note: client write = server read, client read = server write in TLS terminology)
CLIENT_WRITE_HS="388dfdd06603a1d2ede6bf025f1aa2b6a8b2e3fcb4ab5aa77c182158a3bdc4c0"
CLIENT_READ_HS="5d778db4aa24f9eca5e060219279d1c8df3f66689bd7c98e1474e21f6f93126e"

echo "SERVER SIDE (Zig):"
echo "  Transcript Hash (CH+SH): $SERVER_TRANSCRIPT"
echo "  ECDHE shared secret:     $SERVER_ECDHE"
echo "  Client HS traffic secret: $SERVER_CLIENT_HS"
echo "  Server HS traffic secret: $SERVER_SERVER_HS"
echo ""

echo "CLIENT SIDE (quic-go):"
echo "  Write HS traffic secret: $CLIENT_WRITE_HS"
echo "  Read HS traffic secret:  $CLIENT_READ_HS"
echo ""

echo "==================================================================="
echo "COMPARISON:"
echo "==================================================================="
echo ""

echo "Expected mapping (TLS 1.3 terminology):"
echo "  - Server's 'Client HS traffic' should equal Client's 'Write HS traffic'"
echo "  - Server's 'Server HS traffic' should equal Client's 'Read HS traffic'"
echo ""

if [ "$SERVER_CLIENT_HS" = "$CLIENT_WRITE_HS" ]; then
    echo "✓ Client handshake traffic secrets MATCH"
else
    echo "✗ Client handshake traffic secrets MISMATCH:"
    echo "  Server computed: $SERVER_CLIENT_HS"
    echo "  Client computed: $CLIENT_WRITE_HS"
fi
echo ""

if [ "$SERVER_SERVER_HS" = "$CLIENT_READ_HS" ]; then
    echo "✓ Server handshake traffic secrets MATCH"
else
    echo "✗ Server handshake traffic secrets MISMATCH:"
    echo "  Server computed: $SERVER_SERVER_HS"
    echo "  Client computed: $CLIENT_READ_HS"
fi
echo ""

echo "==================================================================="
echo "ROOT CAUSE ANALYSIS:"
echo "==================================================================="
echo ""

echo "The handshake traffic secrets are COMPLETELY DIFFERENT between client"
echo "and server. This indicates they are computing different transcript hashes."
echo ""
echo "Since the ECDHE shared secret is computed correctly (both sides agree),"
echo "the issue must be in the transcript computation:"
echo ""
echo "  Transcript = SHA-256(ClientHello || ServerHello)"
echo ""
echo "Possibilities:"
echo "  1. ClientHello bytes differ between what server received and what client sent"
echo "  2. ServerHello bytes differ between what server sent and what client received"
echo "  3. Extension ordering or encoding differences"
echo "  4. Random/session_id/other field mismatch"
echo ""
echo "Next steps:"
echo "  1. Hex dump the exact ClientHello bytes the server received"
echo "  2. Hex dump the exact ServerHello bytes the server sent"
echo "  3. Capture what the client actually received via pcap"
echo "  4. Compare byte-by-byte"
