#!/usr/bin/env python3
"""
Advanced QUIC test client that can receive and parse server responses
"""
import socket
import struct
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.backends import default_backend

# QUIC v1 Initial salt from RFC 9001
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

def hkdf_extract(salt, ikm):
    """HKDF-Extract using SHA256"""
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand_label(secret, label, context, length):
    """HKDF-Expand-Label as per TLS 1.3"""
    hkdf_label = struct.pack('>H', length)
    hkdf_label += bytes([6 + len(label)]) + b'tls13 ' + label.encode()
    hkdf_label += bytes([len(context)]) + context

    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=hkdf_label,
        backend=default_backend()
    )
    return hkdf.derive(secret)

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

def unprotect_header(hp_key, sample, header, pn_offset):
    """Remove header protection"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(hp_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()

    # Unmask packet number length from first byte
    header[0] ^= mask[0] & 0x0f
    pn_len = (header[0] & 0x03) + 1

    # Unmask packet number
    for i in range(pn_len):
        header[pn_offset + i] ^= mask[1 + i]

    return pn_len

def parse_server_response(data, dcid):
    """Parse and decrypt server's response packet"""
    if len(data) < 10:
        print(f"Response too short: {len(data)} bytes")
        return None

    first_byte = data[0]
    if not (first_byte & 0x80):
        print("Not a long header packet")
        return None

    packet_type = (first_byte & 0x30) >> 4
    types = ["Initial", "0-RTT", "Handshake", "Retry"]
    print(f"Packet type: {types[packet_type] if packet_type < 4 else 'Unknown'}")

    # Parse header
    i = 1
    version = struct.unpack('>I', data[i:i+4])[0]
    i += 4
    print(f"Version: 0x{version:08x}")

    dcid_len = data[i]
    i += 1
    resp_dcid = data[i:i+dcid_len]
    i += dcid_len
    print(f"DCID: {resp_dcid.hex()} (len={dcid_len})")

    scid_len = data[i]
    i += 1
    resp_scid = data[i:i+scid_len]
    i += scid_len
    print(f"SCID: {resp_scid.hex()} (len={scid_len})")

    if packet_type == 0:  # Initial
        # Parse token
        token_len = data[i]
        i += 1
        if token_len > 0:
            token = data[i:i+token_len]
            i += token_len
            print(f"Token: {token.hex()}")

    # Parse length
    length_byte = data[i]
    if length_byte & 0xc0 == 0x40:  # 2-byte encoding
        length = struct.unpack('>H', data[i:i+2])[0] & 0x3fff
        i += 2
    else:
        length = length_byte
        i += 1

    print(f"Payload length: {length}")

    # Derive keys
    _, server_initial = derive_initial_secrets(dcid)
    server_key, server_iv, server_hp = derive_keys(server_initial)

    # Sample for header protection (16 bytes starting 4 bytes into payload)
    sample_offset = i + 4  # Skip packet number bytes
    if sample_offset + 16 > len(data):
        print("Not enough data for sample")
        return None

    sample = data[sample_offset:sample_offset + 16]

    # Unprotect header
    header = bytearray(data[:i+4])  # Include space for max 4-byte PN
    pn_len = unprotect_header(server_hp, sample, header, i)

    # Extract packet number
    pn = 0
    for j in range(pn_len):
        pn = (pn << 8) | header[i + j]
    print(f"Packet number: {pn} (len={pn_len})")

    # Decrypt payload
    aad = bytes(header[:i+pn_len])
    ciphertext = data[i+pn_len:i+length]

    # Create nonce
    nonce = bytearray(server_iv)
    pn_bytes = pn.to_bytes(8, 'big')
    for j in range(8):
        nonce[4 + j] ^= pn_bytes[j]

    try:
        cipher = AESGCM(server_key)
        plaintext = cipher.decrypt(bytes(nonce), ciphertext, aad)
        print(f"Decrypted {len(plaintext)} bytes")

        # Parse frames
        parse_frames(plaintext)

        # Return info for further processing
        return {
            'type': packet_type,
            'scid': resp_scid,
            'plaintext': plaintext,
            'end': i + length
        }
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

def parse_frames(data):
    """Parse QUIC frames from decrypted payload"""
    i = 0
    frame_count = 0
    while i < len(data):
        frame_type = data[i]
        i += 1
        frame_count += 1

        if frame_type == 0x00:  # PADDING
            while i < len(data) and data[i] == 0x00:
                i += 1
            print(f"  Frame {frame_count}: PADDING")

        elif frame_type == 0x01:  # PING
            print(f"  Frame {frame_count}: PING")

        elif frame_type in [0x02, 0x03]:  # ACK
            print(f"  Frame {frame_count}: ACK")
            # Skip ACK parsing for brevity
            break

        elif frame_type == 0x06:  # CRYPTO
            offset = data[i]
            i += 1
            length = data[i]
            i += 1
            crypto_data = data[i:i+length]
            i += length
            print(f"  Frame {frame_count}: CRYPTO offset={offset} len={length}")

            # Parse TLS message type
            if length > 0:
                tls_type = crypto_data[0]
                tls_types = {1: "ClientHello", 2: "ServerHello", 11: "Certificate",
                            12: "ServerKeyExchange", 13: "CertificateRequest",
                            14: "ServerHelloDone", 15: "CertificateVerify",
                            16: "ClientKeyExchange", 20: "Finished"}
                print(f"    TLS: {tls_types.get(tls_type, f'Unknown({tls_type})')}")

        else:
            print(f"  Frame {frame_count}: Unknown type 0x{frame_type:02x}")
            break

def build_initial_with_crypto(dcid, scid, crypto_data):
    """Build Initial packet with CRYPTO frame"""
    # Derive keys
    client_initial, _ = derive_initial_secrets(dcid)
    client_key, client_iv, client_hp = derive_keys(client_initial)

    # Build header
    header = bytearray()
    header.append(0xC0)  # Long header, Initial, 1-byte PN
    header.extend(struct.pack('>I', 0x00000001))  # Version
    header.append(len(dcid))
    header.extend(dcid)
    header.append(len(scid))
    header.extend(scid)
    header.append(0x00)  # Token length

    # Build CRYPTO frame
    crypto_frame = bytearray()
    crypto_frame.append(0x06)  # CRYPTO frame
    crypto_frame.append(0x00)  # Offset
    crypto_frame.append(len(crypto_data))
    crypto_frame.extend(crypto_data)

    # Add padding to reach 1200 bytes minimum
    padding_needed = 1200 - len(header) - 2 - 1 - len(crypto_frame) - 16
    if padding_needed > 0:
        payload = crypto_frame + bytes(padding_needed)
    else:
        payload = crypto_frame

    # Packet number
    pn = 0
    pn_bytes = bytes([pn])

    # Length
    packet_length = len(payload) + len(pn_bytes) + 16
    header.extend(struct.pack('>H', packet_length | 0x4000))
    header.extend(pn_bytes)

    # Create AAD
    aad = bytes(header)

    # Create nonce
    nonce = bytearray(client_iv)
    for i in range(len(pn_bytes)):
        nonce[-(i+1)] ^= pn_bytes[-(i+1)]

    # Encrypt
    cipher = AESGCM(client_key)
    ciphertext = cipher.encrypt(bytes(nonce), payload, aad)

    # Combine
    packet = bytearray(header)
    packet.extend(ciphertext)

    # Apply header protection
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher_hp = Cipher(algorithms.AES(client_hp), modes.ECB(), backend=default_backend())
    encryptor = cipher_hp.encryptor()
    sample = bytes(ciphertext[:16])
    mask = encryptor.update(sample) + encryptor.finalize()

    packet[0] = (packet[0] & 0xF0) | ((packet[0] ^ mask[0]) & 0x0F)
    pn_offset = len(header) - len(pn_bytes)
    for i in range(len(pn_bytes)):
        packet[pn_offset + i] ^= mask[1 + i]

    return bytes(packet)

def test_handshake():
    """Test QUIC handshake with server"""
    print("Testing QUIC handshake at localhost:7567...")

    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)

    # Connection IDs
    dcid = bytes([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08])
    scid = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

    # Build minimal ClientHello
    client_hello = bytearray()
    client_hello.append(0x01)  # HandshakeType: ClientHello

    ch_content = bytearray()
    ch_content.extend(b'\x03\x03')  # TLS 1.2
    ch_content.extend(bytes(32))  # Random
    ch_content.append(0x00)  # Session ID length
    ch_content.extend(b'\x00\x02')  # Cipher suites length
    ch_content.extend(b'\x13\x01')  # TLS_AES_128_GCM_SHA256
    ch_content.append(0x01)  # Compression methods length
    ch_content.append(0x00)  # No compression

    # QUIC transport parameters extension
    extensions = bytearray()
    extensions.extend(b'\xff\xa5')  # QUIC transport params
    tp_data = b'\x01\x04\x80\x00\x75\x30'  # max_idle_timeout
    extensions.extend(struct.pack('>H', len(tp_data)))
    extensions.extend(tp_data)

    ch_content.extend(struct.pack('>H', len(extensions)))
    ch_content.extend(extensions)

    client_hello.extend(struct.pack('>I', len(ch_content))[1:])  # 3-byte length
    client_hello.extend(ch_content)

    # Send Initial packet
    initial_packet = build_initial_with_crypto(dcid, scid, client_hello)
    print(f"\nSending Initial packet ({len(initial_packet)} bytes)")

    try:
        sock.sendto(initial_packet, ('localhost', 7567))
        print("Packet sent, waiting for response...")

        # Receive response
        data, addr = sock.recvfrom(4096)
        print(f"\nReceived {len(data)} bytes from {addr}")

        # Parse server's response
        result = parse_server_response(data, dcid)

        if result:
            # Check if there are coalesced packets
            if result['end'] < len(data):
                print(f"\n=== Coalesced packet detected (remaining {len(data) - result['end']} bytes) ===")
                remaining = data[result['end']:]

                # Check packet type
                if len(remaining) > 0 and (remaining[0] & 0x80):
                    pkt_type = (remaining[0] & 0x30) >> 4
                    if pkt_type == 2:  # Handshake packet
                        print("Found coalesced Handshake packet!")
                        print(f"First bytes: {remaining[:32].hex()}")

                        # TODO: Decrypt Handshake packet using derived Handshake keys
                        # This requires extracting shared secret from ServerHello

            # Now we need to:
            # 1. Extract ServerHello from CRYPTO data
            # 2. Derive Handshake keys
            # 3. Send client Finished in Handshake packet
            print("\nNext steps:")
            print("1. Extract TLS shared secret from ServerHello")
            print("2. Derive Handshake traffic keys")
            print("3. Send client Finished message in Handshake packet")

    except socket.timeout:
        print("No response received (timeout)")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        sock.close()

if __name__ == "__main__":
    test_handshake()