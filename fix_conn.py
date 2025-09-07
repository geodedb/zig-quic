#!/usr/bin/env python3
import re

with open('src/quic/conn.zig', 'r') as f:
    content = f.read()

# Fix writer() calls
content = re.sub(r'(\w+)\.writer\(\)', r'\1.writer(self.allocator.*)', content)

# Fix append calls
content = re.sub(r'(\w+)\.append\(([^,])', r'\1.append(self.allocator.*, \2', content)

# Fix appendSlice calls
content = re.sub(r'(\w+)\.appendSlice\(([^,])', r'\1.appendSlice(self.allocator.*, \2', content)

# Fix deinit calls for local ArrayLists
lines = content.split('\n')
new_lines = []
for i, line in enumerate(lines):
    if 'defer' in line and '.deinit()' in line:
        # Check if it's a local ArrayList
        if 'frames' in line or 'fb' in line:
            line = line.replace('.deinit()', '.deinit(self.allocator.*)')
    new_lines.append(line)
content = '\n'.join(new_lines)

with open('src/quic/conn.zig', 'w') as f:
    f.write(content)

print("Fixed conn.zig")
