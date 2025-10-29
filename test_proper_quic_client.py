#!/usr/bin/env python3
"""
Proper QUIC test client with real AEAD encryption
"""
import socket
import struct
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes

# QUIC v1 Initial salt from RFC 9001
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

def hkdf_extract(salt, ikm):
    """HKDF-Extract using SHA256"""
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand_label(secret, label, context, length):
    """HKDF-Expand-Label as per TLS 1.3 / QUIC"""
    hkdf_label = struct.pack('>H', length)
    hkdf_label += bytes([6 + len(label)]) + b'tls13 ' + label.encode('ascii')
    hkdf_label += bytes([len(context)]) + context

    expander = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=hkdf_label,
        backend=default_backend()
    )
    return expander.derive(secret)

def derive_initial_secrets(dcid):
    """Derive Initial secrets from DCID"""
    initial_secret = hkdf_extract(INITIAL_SALT_V1, dcid)
    client_initial = hkdf_expand_label(initial_secret, "client in", b"", 32)
    server_initial = hkdf_expand_label(initial_secret, "server in", b"", 32)
    return client_initial, server_initial

def derive_keys(secret):
    """Derive key, IV, and HP from a secret"""
    key = hkdf_expand_label(secret, "quic key", b"", 16)
    iv = hkdf_expand_label(secret, "quic iv", b"", 12)
    hp = hkdf_expand_label(secret, "quic hp", b"", 16)
    return key, iv, hp

def apply_header_protection(hp_key, sample, packet, pn_offset):
    """Apply header protection mask"""
    cipher = Cipher(algorithms.AES(hp_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()

    # Mask the first byte (packet number length bits)
    packet[0] ^= mask[0] & 0x0f

    # Mask the packet number
    pn_len = (packet[0] & 0x03) + 1
    for i in range(pn_len):
        packet[pn_offset + i] ^= mask[1 + i]

    return packet

def build_initial_packet():
    """Build a proper QUIC Initial packet with AEAD encryption"""

    # Connection IDs
    dcid = bytes([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08])
    scid = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

    # Derive keys
    client_initial, server_initial = derive_initial_secrets(dcid)
    client_key, client_iv, client_hp = derive_keys(client_initial)

    print(f"Client key: {client_key.hex()}")
    print(f"Client IV: {client_iv.hex()}")

    # Build CRYPTO frame with ClientHello
    crypto_frame = bytearray()
    crypto_frame.append(0x06)  # CRYPTO frame type
    crypto_frame.append(0x00)  # Offset (0)

    # Build minimal TLS ClientHello
    client_hello = bytearray()
    client_hello.append(0x01)  # HandshakeType: ClientHello
    client_hello.extend(b'\x00\x00\x00')  # Length placeholder
    client_hello.extend(b'\x03\x03')  # TLS 1.2
    client_hello.extend(bytes(32))  # Random
    client_hello.append(0x00)  # Session ID length
    client_hello.extend(b'\x00\x02')  # Cipher suites length
    client_hello.extend(b'\x13\x01')  # TLS_AES_128_GCM_SHA256
    client_hello.append(0x01)  # Compression methods length
    client_hello.append(0x00)  # No compression

    # Extensions - just ALPN and minimal QUIC transport params
    extensions = bytearray()
    # ALPN
    extensions.extend(b'\x00\x10')  # ALPN extension type
    extensions.extend(b'\x00\x0e')  # Extension length
    extensions.extend(b'\x00\x0c')  # ALPN list length
    extensions.append(0x0b)  # Protocol name length (11)
    extensions.extend(b'hq-interop\x00')  # Protocol name with padding

    # QUIC transport parameters (minimal)
    extensions.extend(b'\xff\xa5')  # QUIC transport params extension
    extensions.extend(b'\x00\x06')  # Length
    extensions.extend(b'\x01\x04\x80\x00\x75\x30')  # max_idle_timeout

    # Add extensions to ClientHello
    client_hello.extend(struct.pack('>H', len(extensions)))
    client_hello.extend(extensions)

    # Fix ClientHello length
    ch_len = len(client_hello) - 4
    client_hello[1:4] = struct.pack('>I', ch_len)[1:]

    # Add ClientHello to CRYPTO frame
    crypto_frame.append(len(client_hello))
    crypto_frame.extend(client_hello)

    # Add padding to reach minimum 1200 bytes
    padding_needed = 1200 - 55 - len(crypto_frame) - 16  # Approx header + tag size
    if padding_needed > 0:
        crypto_frame.extend(bytes(padding_needed))

    # Build Initial packet header
    header = bytearray()
    header.append(0xC0)  # Long header, Initial packet, 1-byte PN length
    header.extend(struct.pack('>I', 0x00000001))  # Version (QUIC v1)
    header.append(len(dcid))
    header.extend(dcid)
    header.append(len(scid))
    header.extend(scid)
    header.append(0x00)  # Token length

    # Packet number (starting at 0)
    packet_number = 0
    pn_bytes = bytes([packet_number & 0xFF])

    # Length field (payload + PN + tag)
    packet_length = len(crypto_frame) + len(pn_bytes) + 16
    header.extend(struct.pack('>H', packet_length | 0x4000))  # 2-byte varint encoding

    # Store PN offset for header protection
    pn_offset = len(header)
    header.extend(pn_bytes)

    # Create nonce for AEAD
    nonce = bytearray(client_iv)
    # XOR packet number into last 8 bytes of nonce
    pn_full = packet_number.to_bytes(8, 'big')
    for i in range(8):
        nonce[12 - 8 + i] ^= pn_full[i]

    # AEAD encrypt
    aad = bytes(header)  # Use header as AAD
    cipher = AESGCM(client_key)
    ciphertext = cipher.encrypt(bytes(nonce), bytes(crypto_frame), aad)

    # Combine header and ciphertext
    packet = bytearray(header)
    packet.extend(ciphertext)

    # Apply header protection
    sample = ciphertext[:16]  # First 16 bytes of ciphertext
    packet = apply_header_protection(client_hp, sample, packet, pn_offset)

    return bytes(packet)

def test_quic_server():
    """Send a properly encrypted QUIC Initial packet to the server"""
    print("Testing QUIC server at localhost:7567 with proper encryption...")

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)

    # Build and send Initial packet
    packet = build_initial_packet()
    print(f"\nSending {len(packet)} byte Initial packet (with proper AEAD encryption)...")
    print(f"First 64 bytes (hex): {packet[:64].hex()}")

    try:
        sock.sendto(packet, ('localhost', 7567))
        print("Packet sent, waiting for response...")

        # Try to receive response
        data, addr = sock.recvfrom(4096)
        print(f"\nReceived {len(data)} bytes from {addr}")

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

            # Show first bytes in hex
            print(f"First 32 bytes (hex): {data[:32].hex()}")

    except socket.timeout:
        print("No response received (timeout)")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    test_quic_server()