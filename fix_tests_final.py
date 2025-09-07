#!/usr/bin/env python3
import os
import re

def fix_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    
    # Fix toOwnedSlice() -> toOwnedSlice(alloc)
    content = re.sub(r'\.toOwnedSlice\(\)', r'.toOwnedSlice(alloc)', content)
    
    # Fix ensureTotalCapacity without allocator
    content = re.sub(r'\.ensureTotalCapacity\((\d+)\)', r'.ensureTotalCapacity(alloc, \1)', content)
    
    # Fix appendSlice without allocator
    content = re.sub(r'\.appendSlice\(([^,)])', r'.appendSlice(alloc, \1', content)
    
    # Fix append without allocator (but be careful not to double-fix)
    content = re.sub(r'\.append\((?!alloc)([^,)])', r'.append(alloc, \1', content)
    
    # Fix writer() -> writer(alloc)
    content = re.sub(r'\.writer\(\)', r'.writer(alloc)', content)
    
    # Fix deinit(A) -> deinit(alloc)
    content = re.sub(r'\.deinit\(A\)', r'.deinit(alloc)', content)
    
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

# Also fix test_tls_sni.zig and test_tls_validity.zig specifically
for filepath in ['tests/test_tls_sni.zig', 'tests/test_tls_validity.zig']:
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            content = f.read()
        # Fix emitTLV calls
        content = re.sub(r'emitTLV\(&([^,]+), ([^,]+), ', r'emitTLV(&\1, alloc, \2, ', content)
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Fixed emitTLV calls in {filepath}")

print("Done")
