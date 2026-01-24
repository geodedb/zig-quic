#!/bin/bash
# Helper script to diagnose and fix Docker network issues

set -e

echo "=== Docker Network Diagnostics ==="

# Check if Docker is running
if ! docker info &>/dev/null; then
    echo "ERROR: Docker is not running or you don't have permission"
    echo "Try: sudo systemctl start docker"
    exit 1
fi

echo "✓ Docker is running"

# Check DNS configuration
echo ""
echo "=== Checking Docker DNS configuration ==="
docker run --rm alpine nslookup google.com && echo "✓ DNS resolution works" || {
    echo "✗ DNS resolution failed"
    echo ""
    echo "Suggested fixes:"
    echo "1. Configure Docker daemon DNS:"
    echo "   Edit /etc/docker/daemon.json:"
    echo '   {'
    echo '     "dns": ["8.8.8.8", "1.1.1.1"]'
    echo '   }'
    echo "   Then: sudo systemctl restart docker"
    echo ""
    echo "2. Or pass DNS when building:"
    echo "   docker build --network=host ..."
}

# Check if apt repositories are reachable
echo ""
echo "=== Checking Ubuntu repository access ==="
docker run --rm ubuntu:latest bash -c "apt-get update -qq && echo '✓ apt-get update works'" || {
    echo "✗ apt-get update failed"
    echo ""
    echo "This could be due to:"
    echo "1. Firewall blocking Docker container traffic"
    echo "2. Corporate proxy requiring configuration"
    echo "3. DNS issues (see above)"
}

# Check if we can download from ziglang.org
echo ""
echo "=== Checking Zig download site ==="
docker run --rm alpine sh -c "wget -q --spider https://ziglang.org && echo '✓ Can reach ziglang.org'" || {
    echo "✗ Cannot reach ziglang.org"
}

# Check network mode
echo ""
echo "=== Docker network driver info ==="
docker network ls

echo ""
echo "=== Recommendations ==="
echo "If you're still having issues, try building with:"
echo "  docker build --network=host -f interop/Dockerfile ..."
echo ""
echo "Or configure a proxy in /etc/docker/daemon.json:"
echo '  {'
echo '    "dns": ["8.8.8.8", "1.1.1.1"],'
echo '    "proxies": {'
echo '      "http-proxy": "http://proxy.example.com:80",'
echo '      "https-proxy": "http://proxy.example.com:80"'
echo '    }'
echo '  }'
