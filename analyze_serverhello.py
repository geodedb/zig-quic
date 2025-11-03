#!/usr/bin/env python3
"""Analyze the ServerHello message structure."""

import sys

# ServerHello from the user
sh_hex = "02000056030378EAED1EFD5397603667A25F0102F33391DA0DCC0F08597FCD625558F183273700130100002E002B0002030400330024001D0020532C003061E709B3BC767B08BA8BE11297517F095DE385E4D5EFD9EDD6106932"

sh_bytes = bytes.fromhex(sh_hex)

print(f"Total ServerHello length: {len(sh_bytes)} bytes")
print(f"ServerHello hex: {sh_hex}")
print()

pos = 0

# Handshake message type (1 byte) + length (3 bytes)
msg_type = sh_bytes[pos]
pos += 1
msg_len = (sh_bytes[pos] << 16) | (sh_bytes[pos+1] << 8) | sh_bytes[pos+2]
pos += 3
print(f"Message type: 0x{msg_type:02x} (ServerHello=0x02)")
print(f"Message body length: {msg_len} bytes")
print()

# Legacy version (2 bytes)
legacy_version = (sh_bytes[pos] << 8) | sh_bytes[pos+1]
pos += 2
print(f"Legacy version: 0x{legacy_version:04x} (TLS 1.2=0x0303)")

# Random (32 bytes)
random = sh_bytes[pos:pos+32]
pos += 32
print(f"Random: {random.hex()}")

# Session ID (1 byte length + data)
sid_len = sh_bytes[pos]
pos += 1
if sid_len > 0:
    session_id = sh_bytes[pos:pos+sid_len]
    pos += sid_len
    print(f"Session ID length: {sid_len}")
    print(f"Session ID: {session_id.hex()}")
else:
    print(f"Session ID length: 0 (empty)")

# Cipher suite (2 bytes)
cipher_suite = (sh_bytes[pos] << 8) | sh_bytes[pos+1]
pos += 2
print(f"Cipher suite: 0x{cipher_suite:04x} (TLS_AES_128_GCM_SHA256=0x1301)")

# Compression method (1 byte)
compression = sh_bytes[pos]
pos += 1
print(f"Compression: 0x{compression:02x} (none=0x00)")

# Extensions length (2 bytes)
ext_len = (sh_bytes[pos] << 8) | sh_bytes[pos+1]
pos += 2
print(f"\nExtensions total length: {ext_len} bytes")

ext_end = pos + ext_len
ext_num = 0
while pos < ext_end:
    ext_type = (sh_bytes[pos] << 8) | sh_bytes[pos+1]
    pos += 2
    ext_data_len = (sh_bytes[pos] << 8) | sh_bytes[pos+1]
    pos += 2
    ext_data = sh_bytes[pos:pos+ext_data_len]
    pos += ext_data_len

    ext_num += 1
    ext_name = {
        0x002b: "supported_versions",
        0x0033: "key_share",
        0x0039: "quic_transport_parameters"
    }.get(ext_type, f"unknown(0x{ext_type:04x})")

    print(f"\nExtension {ext_num}: {ext_name}")
    print(f"  Type: 0x{ext_type:04x}")
    print(f"  Data length: {ext_data_len} bytes")
    print(f"  Data: {ext_data.hex()}")

    if ext_type == 0x002b:  # supported_versions
        version = (ext_data[0] << 8) | ext_data[1]
        print(f"  -> TLS version: 0x{version:04x} (TLS 1.3=0x0304)")
    elif ext_type == 0x0033:  # key_share
        group = (ext_data[0] << 8) | ext_data[1]
        key_len = (ext_data[2] << 8) | ext_data[3]
        key_data = ext_data[4:4+key_len]
        print(f"  -> Group: 0x{group:04x} (x25519=0x001d)")
        print(f"  -> Key exchange length: {key_len}")
        print(f"  -> Key exchange: {key_data.hex()}")

print(f"\nTotal bytes parsed: {pos}")
print(f"Expected: {len(sh_bytes)}")

# Now check extension ordering
print("\n" + "="*70)
print("EXTENSION ORDERING ANALYSIS")
print("="*70)
print("\nRFC 8446 does NOT mandate a specific extension order in ServerHello.")
print("However, BoringSSL/Quiche typically uses this order:")
print("  1. pre_shared_key (if resuming)")
print("  2. pake (if using PAKE)")
print("  3. key_share")
print("  4. supported_versions")
print("\nYour ServerHello has:")
print("  1. supported_versions (0x002b)")
print("  2. key_share (0x0033)")
print("\nThis ordering is VALID per RFC 8446.")
print("\nIMPORTANT: For QUIC (RFC 9001 §8.2), quic_transport_parameters MUST be")
print("in EncryptedExtensions, NOT ServerHello. Your ServerHello correctly omits it.")
