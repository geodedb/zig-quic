#!/usr/bin/env python3
import re

# Fix unused fba in packet.zig
with open('src/quic/packet.zig', 'r') as f:
    content = f.read()
content = re.sub(r'    var fba = std\.heap\.FixedBufferAllocator\.init\(&buf\);\n', '', content)
with open('src/quic/packet.zig', 'w') as f:
    f.write(content)

# Fix unused fba in crypto_quic.zig
with open('src/quic/crypto_quic.zig', 'r') as f:
    content = f.read()
content = re.sub(r'    var fba = std\.heap\.FixedBufferAllocator\.init\(&buf\);\n', '', content)
with open('src/quic/crypto_quic.zig', 'w') as f:
    f.write(content)

print("Fixed unused variables")
