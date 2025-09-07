#!/usr/bin/env python3
import re

with open('src/quic/endpoint.zig', 'r') as f:
    content = f.read()

# Fix ArrayList.init(allocator) -> ArrayList{}
content = re.sub(r'std\.ArrayList\(([^)]+)\)\.init\(self\.allocator\.\*\)', r'std.ArrayList(\1){}', content)

# Fix defer list.deinit() -> defer list.deinit(self.allocator.*)
# But only for lines that have ArrayList on the previous line
lines = content.split('\n')
new_lines = []
for i, line in enumerate(lines):
    if 'defer' in line and '.deinit()' in line:
        # Check if previous line has ArrayList
        if i > 0 and 'ArrayList' in lines[i-1]:
            line = line.replace('.deinit()', '.deinit(self.allocator.*)')
    new_lines.append(line)
content = '\n'.join(new_lines)

# Fix list.writer() -> list.writer(self.allocator.*)
content = re.sub(r'(\w+)\.writer\(\)', r'\1.writer(self.allocator.*)', content)

# Fix list.append( -> list.append(self.allocator.*,
content = re.sub(r'(\w+)\.append\(([^)])', r'\1.append(self.allocator.*, \2', content)

# Fix list.appendSlice( -> list.appendSlice(self.allocator.*,
content = re.sub(r'(\w+)\.appendSlice\(', r'\1.appendSlice(self.allocator.*, ', content)

with open('src/quic/endpoint.zig', 'w') as f:
    f.write(content)

print("Fixed endpoint.zig")
