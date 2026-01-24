#!/usr/bin/env bash
# Setup script for Python aioquic test client

set -e

echo "=== Setting up Python aioquic test client ==="

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing dependencies..."
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

echo ""
echo "✅ Setup complete!"
echo ""
echo "To activate the environment:"
echo "  source venv/bin/activate"
echo ""
echo "To run the test client:"
echo "  python3 test_client.py --host 127.0.0.1 --port 4433 -v"
