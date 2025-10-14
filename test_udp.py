#!/usr/bin/env python3
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 4433))
print(f"Python UDP server listening on 127.0.0.1:4433")

data, addr = sock.recvfrom(4096)
print(f"Received {len(data)} bytes from {addr}: {data}")
sock.close()