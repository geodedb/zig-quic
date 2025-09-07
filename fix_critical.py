#!/usr/bin/env python3
import re

# Fix packet.zig toOwnedSlice calls
with open('src/quic/packet.zig', 'r') as f:
    content = f.read()
content = re.sub(r'\.toOwnedSlice\(\)', r'.toOwnedSlice(alloc)', content)
with open('src/quic/packet.zig', 'w') as f:
    f.write(content)

# Fix crypto_quic.zig writer call
with open('src/quic/crypto_quic.zig', 'r') as f:
    content = f.read()
content = re.sub(r'list\.writer\(\)', r'list.writer(a)', content)
with open('src/quic/crypto_quic.zig', 'w') as f:
    f.write(content)

# Fix test files with 'A' identifier
test_files = [
    'tests/test_connection_migration.zig',
    'tests/test_tls_kus_ekus.zig',
]

for filepath in test_files:
    with open(filepath, 'r') as f:
        content = f.read()
    # Replace .deinit(A) with .deinit(alloc)
    content = re.sub(r'\.deinit\(A\)', '.deinit(alloc)', content)
    # Replace writer(A) with writer(alloc)
    content = re.sub(r'\.writer\(A\)', '.writer(alloc)', content)
    with open(filepath, 'w') as f:
        f.write(content)

print("Fixed critical issues")
