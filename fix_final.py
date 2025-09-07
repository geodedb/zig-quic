#!/usr/bin/env python3
import os
import re

# Fix test files that use 'A' instead of 'alloc'
test_files = [
    'tests/test_amplification.zig',
    'tests/test_initial_handshake_loop.zig',
    'tests/test_retry.zig',
    'tests/test_rfc9001_a1_initial.zig',
    'tests/test_rfc9001_a3_server_initial.zig',
]

for filepath in test_files:
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            content = f.read()
        # Replace .deinit(A) with .deinit(alloc)
        content = re.sub(r'\.deinit\(A\)', '.deinit(alloc)', content)
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Fixed {filepath}")

# Fix unused variables in packet.zig and crypto_quic.zig
files = ['src/quic/packet.zig', 'src/quic/crypto_quic.zig']
for filepath in files:
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            lines = f.readlines()
        new_lines = []
        for line in lines:
            # Remove lines with unused buf variable
            if 'var buf: [' in line and ']u8 = undefined;' in line:
                continue
            new_lines.append(line)
        with open(filepath, 'w') as f:
            f.writelines(new_lines)
        print(f"Fixed {filepath}")

print("Done")
