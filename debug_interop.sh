#!/usr/bin/env bash
set -e

cd /home/benji/src/spyder/quic/examples/interop

PROJECT="interop_debug_test"
COMPOSE_FILE="docker-compose.full.yml"

echo "Starting Docker containers for debugging..."

# Start the containers with proper profiles
COMPOSE_PROJECT_NAME=$PROJECT \
TESTCASE=handshake \
REQUESTS="https://server4:443/index.html" \
SERVER_IMAGE=zig-qns:local \
CLIENT_IMAGE=martenseemann/quic-go-interop:latest \
docker compose -f $COMPOSE_FILE up -d --wait sim

echo "Simulator started, starting server..."

COMPOSE_PROJECT_NAME=$PROJECT \
TESTCASE=handshake \
REQUESTS="https://server4:443/index.html" \
SERVER_IMAGE=zig-qns:local \
CLIENT_IMAGE=martenseemann/quic-go-interop:latest \
docker compose -f $COMPOSE_FILE --profile zig up -d server

sleep 2
echo "Server started, checking DNS resolution in client network..."

# Create client but don't start it yet
COMPOSE_PROJECT_NAME=$PROJECT \
TESTCASE=handshake \
REQUESTS="https://server4:443/index.html" \
SERVER_IMAGE=zig-qns:local \
CLIENT_IMAGE=martenseemann/quic-go-interop:latest \
docker compose -f $COMPOSE_FILE --profile quic-go create client

echo "Client created. Now let's check DNS resolution:"
docker run --rm --network ${PROJECT}_leftnet alpine nslookup server4 || echo "nslookup failed"
docker run --rm --network ${PROJECT}_leftnet alpine ping -c 2 193.167.100.100 || echo "ping failed"

echo ""
echo "Starting client and monitoring traffic..."

# Start tcpdump on server in background
docker exec ${PROJECT}_server tcpdump -i any -n udp port 443 -w /logs/server.pcap 2>&1 &
TCPDUMP_PID=$!

# Start client
COMPOSE_PROJECT_NAME=$PROJECT \
TESTCASE=handshake \
REQUESTS="https://server4:443/index.html" \
SERVER_IMAGE=zig-qns:local \
CLIENT_IMAGE=martenseemann/quic-go-interop:latest \
docker compose -f $COMPOSE_FILE --profile quic-go up client 2>&1 | head -50

# Stop tcpdump
docker exec ${PROJECT}_server pkill tcpdump 2>/dev/null || true

echo ""
echo "Analyzing packets..."
docker exec ${PROJECT}_server tcpdump -r /logs/server.pcap -n 2>&1 || echo "No packets captured"

echo ""
echo "Cleaning up..."
COMPOSE_PROJECT_NAME=$PROJECT docker compose -f $COMPOSE_FILE down
