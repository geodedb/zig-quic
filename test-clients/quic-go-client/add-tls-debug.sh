#!/bin/bash

# Add deep TLS debugging to quic-go client
# This adds logging for:
# - Traffic secrets (handshake keys)
# - AEAD operations
# - Decryption attempts and failures

set -e

VENDOR_DIR="vendor/quic-go"

echo "Adding TLS debugging to quic-go..."

# 1. Add detailed logging to setReadKey for Handshake level
sed -i '/case tls.QUICEncryptionLevelHandshake:/,/h.handshakeOpener = newLongHeaderOpener/{
    /h.handshakeOpener = newLongHeaderOpener/a\
\t\tfmt.Printf("[TLS_DEBUG] setReadKey(Handshake): trafficSecret=%x\\n", trafficSecret)
}' "$VENDOR_DIR/internal/handshake/crypto_setup.go"

# 2. Add logging to setWriteKey for Handshake level
sed -i '/case tls.QUICEncryptionLevelHandshake:/,/h.handshakeSealer = newLongHeaderSealer/{
    /h.handshakeSealer = newLongHeaderSealer/a\
\t\tfmt.Printf("[TLS_DEBUG] setWriteKey(Handshake): trafficSecret=%x\\n", trafficSecret)
}' "$VENDOR_DIR/internal/handshake/crypto_setup.go"

# 3. Add AEAD creation logging
cat > /tmp/aead_debug.patch <<'EOF'
--- a/internal/handshake/aead.go
+++ b/internal/handshake/aead.go
@@ -1,6 +1,7 @@
 package handshake

 import (
+	"fmt"
 	"crypto/cipher"
 	"encoding/binary"

@@ -31,6 +32,7 @@ func createAEAD(suite *cipherSuite, trafficSecret []byte, v protocol.Version) c
 	keyLabel := hkdfLabel(trafficSecret, []byte{}, "quic key", suite.KeyLen)
 	key := hkdfExpandLabel(suite.Hash, trafficSecret, keyLabel, "quic key", suite.KeyLen)
 	iv := hkdfExpandLabel(suite.Hash, trafficSecret, nil, "quic iv", suite.IVLen())
+	fmt.Printf("[TLS_DEBUG] createAEAD: suite=%x, key=%x, iv=%x\n", suite.ID, key, iv)
 	return suite.AEAD(key, iv)
 }
EOF

# Check if aead.go exists and patch it
if [ -f "$VENDOR_DIR/internal/handshake/aead.go" ]; then
    # Add import if not exists
    if ! grep -q '"fmt"' "$VENDOR_DIR/internal/handshake/aead.go"; then
        sed -i '/^import ($/a\
\t"fmt"' "$VENDOR_DIR/internal/handshake/aead.go"
    fi

    # Add debug print to createAEAD function
    if ! grep -q '\[TLS_DEBUG\] createAEAD' "$VENDOR_DIR/internal/handshake/aead.go"; then
        sed -i '/iv := hkdfExpandLabel/a\
\tfmt.Printf("[TLS_DEBUG] createAEAD: suite=%x, key=%x, iv=%x\\n", suite.ID, key, iv)' "$VENDOR_DIR/internal/handshake/aead.go"
    fi
fi

# 4. Add packet unpacker decryption error logging
if ! grep -q '\[TLS_DEBUG\] Decrypt attempt' "$VENDOR_DIR/packet_unpacker.go"; then
    # Find the Handshake packet decryption section and add detailed error logging
    sed -i '/if hdr\.Type == protocol\.PacketTypeHandshake {/,/}/s/opener\.Open/\
\t\tfmt.Printf("[TLS_DEBUG] Decrypt attempt: PN=%d, header=%x, payload_len=%d\\n", hdr.PacketNumber, data[:hdr.ParsedLen()], len(data[hdr.ParsedLen():]));\
\t\topener.Open/' "$VENDOR_DIR/packet_unpacker.go"
fi

# 5. Add detailed AEAD open logging
if [ -f "$VENDOR_DIR/internal/handshake/long_header_opener.go" ]; then
    if ! grep -q '\[TLS_DEBUG\] AEAD Open' "$VENDOR_DIR/internal/handshake/long_header_opener.go"; then
        # Add import
        if ! grep -q '"fmt"' "$VENDOR_DIR/internal/handshake/long_header_opener.go"; then
            sed -i '/^import ($/a\
\t"fmt"' "$VENDOR_DIR/internal/handshake/long_header_opener.go"
        fi

        # Add logging before AEAD open
        sed -i '/data, err := opener\.aead\.Open/i\
\tfmt.Printf("[TLS_DEBUG] AEAD Open: pn=%d, nonce=%x, data_len=%d\\n", pn, nonce, len(data))' "$VENDOR_DIR/internal/handshake/long_header_opener.go"

        # Add logging after AEAD open
        sed -i '/data, err := opener\.aead\.Open/a\
\tif err != nil {\
\t\tfmt.Printf("[TLS_DEBUG] AEAD Open FAILED: %v\\n", err)\
\t} else {\
\t\tfmt.Printf("[TLS_DEBUG] AEAD Open SUCCESS: decrypted_len=%d\\n", len(data))\
\t}' "$VENDOR_DIR/internal/handshake/long_header_opener.go"
    fi
fi

# 6. Enable Go crypto/tls debug output via GODEBUG
cat > /tmp/run_debug_client.sh <<'EOF'
#!/bin/bash
# Run with maximum debugging
export QUIC_GO_LOG_LEVEL=debug
export GODEBUG=tlskyber=0
export SSLKEYLOGFILE=/tmp/sslkeylog.txt
./quic-go-test-client "$@" 2>&1 | tee /tmp/quic-go-client-debug.log
EOF

chmod +x /tmp/run_debug_client.sh

echo "TLS debugging added successfully!"
echo "Now rebuild the client: go build -o quic-go-test-client main.go"
