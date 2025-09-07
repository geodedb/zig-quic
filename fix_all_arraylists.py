#!/usr/bin/env python3
import re
import sys

def fix_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    
    # Fix ArrayList.init(allocator) -> ArrayList{}
    content = re.sub(r'std\.ArrayList\(([^)]+)\)\.init\(([^)]+)\)', r'std.ArrayList(\1){}', content)
    
    # Fix lines with defer list.deinit() that follow ArrayList creation
    lines = content.split('\n')
    new_lines = []
    for i, line in enumerate(lines):
        if 'defer' in line and '.deinit()' in line:
            # Check if previous line has ArrayList
            if i > 0 and 'ArrayList' in lines[i-1]:
                # Extract the allocator from the previous line if possible
                prev_line = lines[i-1]
                if 'self.allocator' in prev_line:
                    line = line.replace('.deinit()', '.deinit(self.allocator.*)')
                elif 'alloc' in prev_line:
                    line = line.replace('.deinit()', '.deinit(alloc)')
                elif 'std.heap.page_allocator' in prev_line:
                    line = line.replace('.deinit()', '.deinit(std.heap.page_allocator)')
        new_lines.append(line)
    content = '\n'.join(new_lines)
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Fixed {filepath}")
        return True
    return False

# Fix all the main files
files = [
    'src/quic/conn.zig',
    'src/quic/tls/tls13.zig',
    'src/quic/packet.zig',
    'src/quic/crypto_quic.zig',
]

for f in files:
    fix_file(f)
