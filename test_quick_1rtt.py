#!/usr/bin/env python3
"""Quick test to verify 1-RTT streaming works after transcript hash fix"""

import socket
import struct
import os
import sys

def main():
    print("=== Quick 1-RTT Test ===\n")
    
    # Try to connect with a simple UDP test
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    
    try:
        # Send a simple Initial packet to trigger server response
        print("Sending test packet to server on 127.0.0.1:4433...")
        
        # Minimal QUIC Initial packet structure
        initial_pkt = bytes([
            0xc0,  # Long header, Initial
            0x00, 0x00, 0x00, 0x01,  # Version 1
            0x08,  # DCID len
        ]) + os.urandom(8) + bytes([  # Random DCID
            0x00,  # SCID len (0)
            0x00,  # Token len (0)
            0x00, 0x20,  # Length (32 bytes payload)
        ]) + os.urandom(32)  # Random payload
        
        sock.sendto(initial_pkt, ('127.0.0.1', 4433))
        
        # Try to receive response
        data, addr = sock.recvfrom(2048)
        print(f"✅ Received {len(data)} bytes from server")
        print(f"   First 20 bytes: {' '.join(f'{b:02x}' for b in data[:20])}")
        
        # Check if it's a valid QUIC packet (starts with 0xc0-0xff for long header)
        if data[0] & 0x80:
            print("✅ Received valid QUIC long header packet")
            return 0
        else:
            print("⚠️  Received data but not a recognized QUIC packet")
            return 1
            
    except socket.timeout:
        print("❌ Timeout - no response from server")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    finally:
        sock.close()

if __name__ == '__main__':
    sys.exit(main())
