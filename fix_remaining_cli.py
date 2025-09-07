#!/usr/bin/env python3
import re

# Fix crypto_quic.zig
with open('src/quic/crypto_quic.zig', 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if 'list.writer(a)' in line:
        # Look for the allocator definition nearby
        found_alloc = False
        for j in range(max(0, i-20), i):
            if 'const a = ' in lines[j] or 'var a = ' in lines[j]:
                found_alloc = True
                break
        if not found_alloc:
            # Replace with page allocator
            lines[i] = line.replace('list.writer(a)', 'list.writer(std.heap.page_allocator)')

with open('src/quic/crypto_quic.zig', 'w') as f:
    f.writelines(lines)

print("Fixed crypto_quic.zig")
