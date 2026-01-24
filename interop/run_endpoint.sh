#!/bin/bash
set -e

# Set up the routing needed for the simulation
/setup.sh

# Print version info
if [ -f /quic/version.txt ]; then
    echo "=== Zig QUIC Implementation ==="
    echo "Version: $(cat /quic/version.txt)"
fi

ROLE=${ROLE:-server}
TESTCASE=${TESTCASE:-handshake}

# Create log and output directories
mkdir -p /logs /downloads /www

echo "Role: $ROLE"
echo "Test case: $TESTCASE"
echo "SSLKEYLOGFILE: ${SSLKEYLOGFILE:-not set}"
echo "QLOGDIR: ${QLOGDIR:-not set}"

# Set up environment variables for the test case
export ROLE
export TESTCASE

# Export SSL key log file if specified (for Wireshark decryption)
if [ -n "${SSLKEYLOGFILE}" ]; then
    export SSLKEYLOGFILE
    echo "SSL key logging enabled: $SSLKEYLOGFILE"
fi

# Export QLOG directory if specified (for debugging)
if [ -n "${QLOGDIR}" ]; then
    export QLOGDIR
    echo "QLOG directory: $QLOGDIR"
fi

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up
    echo "Waiting for simulator to be ready..."
    for i in {1..30}; do
        if /wait-for-it.sh sim:57832 -s -t 5; then
            echo "Simulator ready!"
            break
        fi
        if [ $i -eq 30 ]; then
            echo "ERROR: Simulator failed to start after 30 attempts"
            exit 1
        fi
        echo "Retry $i/30: Simulator not ready, waiting..."
        sleep 2
    done

    # Give extra time for server to be ready
    sleep 5

    echo "=== Starting QUIC Client ==="
    echo "Test case: $TESTCASE"
    echo "Requests: $REQUESTS"
    echo "Additional params: $CLIENT_PARAMS"

    # Run client with output logging
    exec qns-endpoint 2>&1 | tee /logs/client.log
else
    echo "=== Starting QUIC Server ==="
    echo "Test case: $TESTCASE"

    # Populate www directory with test files for download tests
    if [ "$TESTCASE" == "transfer" ] || [ "$TESTCASE" == "http3" ]; then
        echo "Creating test files for download..."
        # Create various sized files for testing
        dd if=/dev/urandom of=/www/5000 bs=5000 count=1 2>/dev/null
        dd if=/dev/urandom of=/www/10000 bs=10000 count=1 2>/dev/null
        dd if=/dev/urandom of=/www/500000 bs=500000 count=1 2>/dev/null
        dd if=/dev/urandom of=/www/1000000 bs=1000000 count=1 2>/dev/null
        dd if=/dev/urandom of=/www/5000000 bs=1000000 count=5 2>/dev/null
        dd if=/dev/urandom of=/www/10000000 bs=1000000 count=10 2>/dev/null
        echo "Test files created in /www/"
        ls -lh /www/
    fi

    # Run server with output logging
    exec qns-endpoint 2>&1 | tee /logs/server.log
fi
