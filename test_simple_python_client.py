#!/usr/bin/env python3
"""
Simple QUIC test client to verify the server is working
"""
import socket
import struct
import random

def build_quic_initial_packet():
    """Build a minimal QUIC Initial packet with ClientHello"""

    # QUIC header (long header, Initial packet)
    header = bytearray()

    # First byte: 0xC0 = Long header, Initial packet type
    header.append(0xC0 | 0x00)  # Long header, Initial packet

    # Version (QUIC v1 = 0x00000001)
    header.extend(struct.pack('>I', 0x00000001))

    # Destination Connection ID Length (0 for initial)
    header.append(0x00)

    # Source Connection ID Length (8 bytes)
    header.append(0x08)

    # Source Connection ID (random)
    scid = bytes([random.randint(0, 255) for _ in range(8)])
    header.extend(scid)

    # Token length (0 for initial client packet)
    header.append(0x00)

    # Length field (2 bytes, will be filled later)
    length_offset = len(header)
    header.extend(b'\x00\x00')

    # Packet number (1 byte for now)
    header.append(0x00)

    # Minimal CRYPTO frame with TLS ClientHello
    # Frame type 0x06 = CRYPTO
    payload = bytearray([0x06])

    # Offset (0)
    payload.append(0x00)

    # TLS ClientHello (minimal)
    client_hello = bytearray()
    client_hello.append(0x01)  # HandshakeType: ClientHello
    client_hello.extend(b'\x00\x00\x00')  # Length placeholder
    client_hello.extend(b'\x03\x03')  # TLS 1.2 (for compatibility)
    client_hello.extend(bytes(32))  # Random (32 bytes of zeros for simplicity)
    client_hello.append(0x00)  # Session ID length
    client_hello.extend(b'\x00\x02')  # Cipher suites length
    client_hello.extend(b'\x13\x01')  # TLS_AES_128_GCM_SHA256
    client_hello.append(0x01)  # Compression methods length
    client_hello.append(0x00)  # No compression

    # Extensions
    extensions = bytearray()

    # ALPN extension
    extensions.extend(b'\x00\x10')  # ALPN extension type
    extensions.extend(b'\x00\x0b')  # Extension length
    extensions.extend(b'\x00\x09')  # ALPN list length
    extensions.append(0x08)  # Protocol name length
    extensions.extend(b'hq-interop')  # Protocol name

    # Add extensions to ClientHello
    client_hello.extend(struct.pack('>H', len(extensions)))
    client_hello.extend(extensions)

    # Fix ClientHello length
    ch_len = len(client_hello) - 4
    client_hello[1:4] = struct.pack('>I', ch_len)[1:]

    # CRYPTO frame length
    payload.append(len(client_hello))
    payload.extend(client_hello)

    # Add payload to header
    header.extend(payload)

    # Fix packet length
    packet_len = len(header) - length_offset - 2
    header[length_offset:length_offset+2] = struct.pack('>H', packet_len | 0x4000)  # Variable length encoding

    # Add AEAD tag (16 bytes of zeros for now - will be rejected but shows packet structure)
    header.extend(bytes(16))

    return bytes(header)

def test_quic_server():
    """Send a QUIC Initial packet to the server"""
    print("Testing QUIC server at localhost:7567...")

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)

    # Build and send Initial packet
    packet = build_quic_initial_packet()
    print(f"Sending {len(packet)} byte Initial packet...")

    try:
        sock.sendto(packet, ('localhost', 7567))
        print("Packet sent, waiting for response...")

        # Try to receive response
        data, addr = sock.recvfrom(4096)
        print(f"Received {len(data)} bytes from {addr}")

        # Check if it's a QUIC packet
        if len(data) > 0:
            first_byte = data[0]
            if first_byte & 0x80:
                print("Received long header QUIC packet")
                packet_type = (first_byte & 0x30) >> 4
                types = ["Initial", "0-RTT", "Handshake", "Retry"]
                print(f"Packet type: {types[packet_type] if packet_type < 4 else 'Unknown'}")
            else:
                print("Received short header QUIC packet")

            # Show first 32 bytes in hex
            print("First 32 bytes (hex):", data[:32].hex())

    except socket.timeout:
        print("No response received (timeout)")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    test_quic_server()