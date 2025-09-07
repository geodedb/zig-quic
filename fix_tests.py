#!/usr/bin/env python3
import os
import re

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
                if 'alloc' in lines[i-1]:
                    line = line.replace('.deinit()', '.deinit(alloc)')
                elif 'A' in lines[i-1] and 'std.ArrayList' in lines[i-1]:
                    line = line.replace('.deinit()', '.deinit(A)')
                elif 'std.testing.allocator' in lines[i-1]:
                    line = line.replace('.deinit()', '.deinit(std.testing.allocator)')
        new_lines.append(line)
    content = '\n'.join(new_lines)
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

# Fix all test files
test_dir = 'tests'
for filename in os.listdir(test_dir):
    if filename.endswith('.zig'):
        filepath = os.path.join(test_dir, filename)
        if fix_file(filepath):
            print(f"Fixed {filepath}")

print("Done fixing test files")
