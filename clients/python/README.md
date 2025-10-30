# Python aioquic Test Client

Simple QUIC test client using the aioquic library for testing interoperability with the Zig QUIC server implementation.

## Setup

Run the setup script to create a virtual environment and install dependencies:

```bash
./setup.sh
```

## Usage

Activate the virtual environment:

```bash
source venv/bin/activate
```

Run the test client:

```bash
python3 test_client.py --host 127.0.0.1 --port 4433 -v
```

Options:
- `--host`: Server hostname (default: 127.0.0.1)
- `--port`: Server port (default: 4433)
- `-v, --verbose`: Enable verbose logging

## Testing with Server

Start the QUIC server in one terminal:

```bash
./zig-out/bin/quic-server --bind 127.0.0.1:4433 --insecure
```

In another terminal, activate the venv and run the client:

```bash
cd clients/python
source venv/bin/activate
python3 test_client.py --host 127.0.0.1 --port 4433 -v
```

## Dependencies

- aioquic >= 0.9.0 - QUIC implementation for Python

See `requirements.txt` for full list.
