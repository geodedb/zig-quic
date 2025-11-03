#!/usr/bin/env python3
"""
Test whether extension order affects transcript hash.

This demonstrates that the same ServerHello with different extension orders
will produce different transcript hashes and thus different handshake keys.
"""

import hashlib

# ServerHello with extensions in order: supported_versions, key_share
sh_order1 = bytes.fromhex(
    "02000056030378EAED1EFD5397603667A25F0102F33391DA0DCC0F08597FCD625558F183273700130100002E"
    "002B0002030400330024001D0020532C003061E709B3BC767B08BA8BE11297517F095DE385E4D5EFD9EDD6106932"
)

# ServerHello with extensions in order: key_share, supported_versions
# (Same content, just extensions swapped)
# Header (4 bytes): 02000056
# Legacy version (2 bytes): 0303
# Random (32 bytes): 78EAED1EFD5397603667A25F0102F33391DA0DCC0F08597FCD625558F1832737
# Session ID length (1 byte): 00
# Cipher suite (2 bytes): 1301
# Compression (1 byte): 00
# Extensions length (2 bytes): 002E (46 bytes)
# Extension 1: key_share (0033) - 36 bytes + 4 byte header = 40 bytes
#   00330024001D0020532C003061E709B3BC767B08BA8BE11297517F095DE385E4D5EFD9EDD6106932
# Extension 2: supported_versions (002B) - 2 bytes + 4 byte header = 6 bytes
#   002B00020304

sh_order2 = bytes.fromhex(
    "02000056030378EAED1EFD5397603667A25F0102F33391DA0DCC0F08597FCD625558F183273700130100002E"
    "00330024001D0020532C003061E709B3BC767B08BA8BE11297517F095DE385E4D5EFD9EDD6106932002B00020304"
)

print("ServerHello with order: supported_versions, key_share")
print(f"Length: {len(sh_order1)} bytes")
print(f"SHA-256: {hashlib.sha256(sh_order1).hexdigest()}")
print()

print("ServerHello with order: key_share, supported_versions")
print(f"Length: {len(sh_order2)} bytes")
print(f"SHA-256: {hashlib.sha256(sh_order2).hexdigest()}")
print()

if hashlib.sha256(sh_order1).digest() == hashlib.sha256(sh_order2).digest():
    print("✓ Hashes MATCH - Extension order doesn't matter")
else:
    print("✗ Hashes DIFFER - Extension order DOES matter!")
    print()
    print("This proves that clients expecting a specific extension order will")
    print("compute a different transcript hash and derive different keys.")
    print()
    print("Since BoringSSL (used by Quiche) and likely Go's crypto/tls both")
    print("use the order: key_share, supported_versions")
    print("We must match their ordering for interoperability.")
