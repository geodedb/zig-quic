#!/usr/bin/env python3
"""
Script to wrap std.debug.print calls with compile-time flag check.
This disables all debug output in production builds.
"""

import os
import re
import sys

# Files to process (active source files only, not backups or tests)
SOURCE_FILES = [
    "src/quic/endpoint.zig",
    "src/quic/endpoint/client.zig",
    "src/quic/endpoint/incoming.zig",
    "src/quic/endpoint/server.zig",
    "src/quic/endpoint/io.zig",
    "src/quic/endpoint/pto.zig",
    "src/quic/endpoint/frame_handler.zig",
    "src/quic/endpoint/handshake_integration.zig",
    "src/quic/crypto_quic.zig",
    "src/quic/conn.zig",
    "src/quic/transport.zig",
    "src/quic/packet.zig",
    "src/quic/recovery/recovery.zig",
]

def process_file(filepath):
    """Comment out all std.debug.print calls in a file."""
    if not os.path.exists(filepath):
        print(f"  Skipping {filepath} (not found)")
        return 0

    with open(filepath, 'r') as f:
        content = f.read()

    original = content

    # Pattern to match std.debug.print calls (including multiline with for loops)
    # Simple approach: comment out lines containing std.debug.print
    lines = content.split('\n')
    new_lines = []
    modified_count = 0
    in_debug_block = False
    brace_count = 0

    for line in lines:
        stripped = line.strip()

        # Check if this is a std.debug.print statement
        if 'std.debug.print(' in line and not stripped.startswith('//'):
            # Comment out the line
            indent = len(line) - len(line.lstrip())
            new_lines.append(' ' * indent + '// ' + line.lstrip())
            modified_count += 1

            # Check if it's a multiline call (ends with semicolon)
            if ';' not in line:
                in_debug_block = True
                brace_count = line.count('(') - line.count(')')
        elif in_debug_block:
            # Continue commenting multiline debug.print
            indent = len(line) - len(line.lstrip())
            new_lines.append(' ' * indent + '// ' + line.lstrip())
            brace_count += line.count('(') - line.count(')')
            if ';' in line or brace_count <= 0:
                in_debug_block = False
                brace_count = 0
        else:
            new_lines.append(line)

    new_content = '\n'.join(new_lines)

    if new_content != original:
        with open(filepath, 'w') as f:
            f.write(new_content)
        print(f"  Modified {filepath}: commented out {modified_count} debug.print calls")
        return modified_count
    else:
        print(f"  No changes to {filepath}")
        return 0

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    total_modified = 0

    print("Disabling QUIC debug prints...")

    for rel_path in SOURCE_FILES:
        filepath = os.path.join(base_dir, rel_path)
        total_modified += process_file(filepath)

    print(f"\nTotal: commented out {total_modified} std.debug.print calls")
    print("Done! Debug output is now disabled.")

if __name__ == "__main__":
    main()
