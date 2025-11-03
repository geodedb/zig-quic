#!/usr/bin/env python3
"""
Verify QUIC Handshake key derivation matches what quic-go expects.
Uses the actual values from our server logs.
"""

import hashlib
import hmac

# From server logs
TRANSCRIPT_HASH = bytes.fromhex("E03B2F69E6988ADFB145A6199F6F73930FB8EA83DF09F88610482CAD8D74D902")
ECDHE_SECRET = bytes.fromhex("E0DE482254C769404E74C27DDD565A71DD11C3C38ECE56444BC272A03D5C844A")

SERVER_HS_SECRET = bytes.fromhex("E5717B31C595077FDAA2A7A9F5DB1BF1082A0C0647595334F0A847E31342DF09")
CLIENT_HS_SECRET = bytes.fromhex("E0F0A2DFC4F9077F4973240BD9FA03C2D7B3CBEC8F2876CA0948E2FDA89DFAE3")

def hkdf_extract(salt, ikm):
    """HKDF-Extract per RFC 5869"""
    if not salt:
        salt = b'\x00' * 32  # Hash length for SHA-256
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk, info, length):
    """HKDF-Expand per RFC 5869"""
    t = b""
    okm = b""
    i = 0
    while len(okm) < length:
        i += 1
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def hkdf_expand_label(secret, label, context, length):
    """HKDF-Expand-Label per RFC 8446 §7.1"""
    # HkdfLabel structure:
    # - uint16 length
    # - opaque label<7..255> = "tls13 " + label
    # - opaque context<0..255>
    
    full_label = b"tls13 " + label.encode('ascii')
    hkdf_label = (
        length.to_bytes(2, 'big') +
        len(full_label).to_bytes(1, 'big') + full_label +
        len(context).to_bytes(1, 'big') + context
    )
    return hkdf_expand(secret, hkdf_label, length)

def derive_handshake_secrets(ecdhe_secret, transcript_hash):
    """Derive handshake secrets per TLS 1.3 / QUIC"""
    print("=== Deriving Handshake Secrets ===\n")
    
    # Step 1: early_secret = HKDF-Extract(0, 0)
    print("Step 1: Early Secret")
    early_secret = hkdf_extract(b"", b"")
    print(f"  early_secret: {early_secret.hex()}\n")
    
    # Step 2: derived = Derive-Secret(early_secret, "derived", "")
    print("Step 2: Derived")
    derived = hkdf_expand_label(early_secret, "derived", b"", 32)
    print(f"  derived: {derived.hex()}\n")
    
    # Step 3: handshake_secret = HKDF-Extract(derived, ecdhe_secret)
    print("Step 3: Handshake Secret")
    handshake_secret = hkdf_extract(derived, ecdhe_secret)
    print(f"  handshake_secret: {handshake_secret.hex()}\n")
    
    # Step 4: client_handshake_traffic_secret
    print("Step 4: Client Handshake Traffic Secret")
    client_hs = hkdf_expand_label(handshake_secret, "c hs traffic", transcript_hash, 32)
    print(f"  client_hs_traffic_secret: {client_hs.hex()}\n")
    
    # Step 5: server_handshake_traffic_secret
    print("Step 5: Server Handshake Traffic Secret")
    server_hs = hkdf_expand_label(handshake_secret, "s hs traffic", transcript_hash, 32)
    print(f"  server_hs_traffic_secret: {server_hs.hex()}\n")
    
    return client_hs, server_hs

def verify_quic_keys(traffic_secret):
    """Derive QUIC keys from traffic secret"""
    print("=== Deriving QUIC Keys ===\n")
    
    # QUIC uses "quic key", "quic iv", "quic hp" labels
    quic_key = hkdf_expand_label(traffic_secret, "quic key", b"", 16)
    quic_iv = hkdf_expand_label(traffic_secret, "quic iv", b"", 12)
    quic_hp = hkdf_expand_label(traffic_secret, "quic hp", b"", 16)
    
    print(f"  quic_key: {quic_key.hex()}")
    print(f"  quic_iv:  {quic_iv.hex()}")
    print(f"  quic_hp:  {quic_hp.hex()}\n")
    
    return quic_key, quic_iv, quic_hp

def main():
    print("QUIC Handshake Key Derivation Verification\n")
    print("=" * 70)
    print(f"\nInputs:")
    print(f"  Transcript Hash: {TRANSCRIPT_HASH.hex()}")
    print(f"  ECDHE Secret:    {ECDHE_SECRET.hex()}\n")
    print("=" * 70)
    print()
    
    # Derive secrets
    client_hs, server_hs = derive_handshake_secrets(ECDHE_SECRET, TRANSCRIPT_HASH)
    
    # Compare with server logs
    print("=" * 70)
    print("Verification:\n")
    
    print(f"Expected Client HS Secret: {CLIENT_HS_SECRET.hex()}")
    print(f"Computed Client HS Secret: {client_hs.hex()}")
    print(f"Match: {client_hs == CLIENT_HS_SECRET}\n")
    
    print(f"Expected Server HS Secret: {SERVER_HS_SECRET.hex()}")
    print(f"Computed Server HS Secret: {server_hs.hex()}")
    print(f"Match: {server_hs == SERVER_HS_SECRET}\n")
    
    if client_hs == CLIENT_HS_SECRET and server_hs == SERVER_HS_SECRET:
        print("✓ Server key derivation is CORRECT!\n")
        print("=" * 70)
        print("\nDeriving Server QUIC Keys (for encryption):\n")
        verify_quic_keys(server_hs)
        print("The issue must be that quic-go is computing a DIFFERENT transcript hash.")
        print("This suggests our ServerHello message is malformed or different than expected.")
    else:
        print("✗ Server key derivation is INCORRECT!")
        print("  The problem is in our HKDF-Expand-Label implementation.")

if __name__ == "__main__":
    main()
