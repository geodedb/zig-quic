#!/bin/bash
set -e

# Set up the routing needed for the simulation.
/setup.sh

# Print version info if available
if [ -f /quic/version.txt ]; then
    echo "Using version: $(cat /quic/version.txt)"
fi

ROLE=${ROLE:-server}
TESTCASE=${TESTCASE:-}

# Create log directory
mkdir -p /logs

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    # Retry multiple times as the simulator may take a while to be ready
    for i in {1..5}; do
        if /wait-for-it.sh sim:57832 -s -t 10; then
            break
        fi
        echo "Retry $i: Simulator not ready, waiting 5 seconds..."
        sleep 5
    done
    echo "Starting QUIC client..."
    echo "Client params: $CLIENT_PARAMS"
    echo "Test case: $TESTCASE"
    echo "Requests: $REQUESTS"
    exec setpriv --reuid=quic --regid=quic --clear-groups qns-endpoint 2>&1 | tee /logs/client.log
else
    echo "Running QUIC server."
    echo "Test case: $TESTCASE"
    exec setpriv --reuid=quic --regid=quic --clear-groups qns-endpoint 2>&1 | tee /logs/server.log
fi
