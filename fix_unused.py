#!/usr/bin/env python3
import re

# Fix packet.zig
with open('src/quic/packet.zig', 'r') as f:
    content = f.read()

# Remove unused 'a' constant
content = re.sub(r'    const a = fba\.allocator\(\);\n', '', content)

# Mark unused parameters with _
content = re.sub(r'(\n    )(alloc)(: std\.mem\.Allocator,)', r'\1_\2\3', content)
content = re.sub(r'(pub fn encodeVersionNegotiation\()(alloc)(: std\.mem\.Allocator,)', r'\1_\2\3', content)
content = re.sub(r'(pub fn encodeRetry\()(alloc)(: std\.mem\.Allocator,)', r'\1_\2\3', content)

with open('src/quic/packet.zig', 'w') as f:
    f.write(content)

# Fix crypto_quic.zig
with open('src/quic/crypto_quic.zig', 'r') as f:
    content = f.read()

# Remove unused 'a' constant
content = re.sub(r'    const a = fba\.allocator\(\);\n', '', content)

with open('src/quic/crypto_quic.zig', 'w') as f:
    f.write(content)

# Fix conn.zig
with open('src/quic/conn.zig', 'r') as f:
    content = f.read()

# Mark unused parameter with _
content = re.sub(r'(fn init\()(alloc)(: \*std\.mem\.Allocator\) StreamRx)', r'\1_\2\3', content)

with open('src/quic/conn.zig', 'w') as f:
    f.write(content)

print("Fixed unused parameters and constants")
