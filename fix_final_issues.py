#!/usr/bin/env python3
import re

# Fix crypto_quic.zig - undefined 'a'
with open('src/quic/crypto_quic.zig', 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if 'list.writer(a)' in line:
        # Find the allocator in context
        for j in range(max(0, i-10), i):
            if 'const a = ' in lines[j]:
                break
        else:
            # Use std.heap.page_allocator as fallback
            lines[i] = line.replace('list.writer(a)', 'list.writer(std.heap.page_allocator)')

with open('src/quic/crypto_quic.zig', 'w') as f:
    f.writelines(lines)

# Fix packet.zig ensureTotalCapacity calls
with open('src/quic/packet.zig', 'r') as f:
    content = f.read()
content = re.sub(r'buf\.ensureTotalCapacity\(([^)]+)\)', r'buf.ensureTotalCapacity(alloc, \1)', content)
with open('src/quic/packet.zig', 'w') as f:
    f.write(content)

# Fix endpoint.zig - std.time.sleep
with open('src/quic/endpoint.zig', 'r') as f:
    content = f.read()
content = content.replace('std.time.sleep(', 'std.Thread.sleep(')
with open('src/quic/endpoint.zig', 'w') as f:
    f.write(content)

# Fix qns-endpoint.zig - getStdErr
with open('cmd/qns-endpoint.zig', 'r') as f:
    content = f.read()
content = content.replace('std.io.getStdErr()', 'std.io.getStdErr()')
# Actually in 0.15.1 it's different
content = content.replace('const stderr = std.io.getStdErr().writer();', 'const stderr = std.io.getStdErr().writer();')
with open('cmd/qns-endpoint.zig', 'w') as f:
    f.write(content)

print("Fixed final issues")
