#!/bin/bash

set -e

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor/quic-go"
PATCHES_DIR="${SCRIPT_DIR}/patches"
SOURCE_DIR="/home/benji/src/spyder/quic/forks/quic-go"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}QUIC-Go Patch Generator${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Check if vendor directory exists
if [ ! -d "$VENDOR_DIR" ]; then
    echo -e "${RED}ERROR: Vendor directory not found: $VENDOR_DIR${NC}"
    echo -e "${YELLOW}Run ./apply-patches.sh first to create modified vendor files${NC}"
    exit 1
fi

# Check if source directory exists
if [ ! -d "$SOURCE_DIR" ]; then
    echo -e "${RED}ERROR: Source directory not found: $SOURCE_DIR${NC}"
    exit 1
fi

# Create patches directory
mkdir -p "$PATCHES_DIR"

# List of files to generate patches for
FILES=(
    "connection.go"
    "crypto_stream_manager.go"
    "packet_unpacker.go"
    "packet_packer.go"
    "transport.go"
)

PATCH_NAMES=(
    "01-connection-debug-logging"
    "02-crypto-stream-manager-debug-logging"
    "03-packet-unpacker-debug-logging"
    "04-packet-packer-debug-logging"
    "05-transport-debug-logging"
)

echo -e "${BLUE}Generating patches from modified vendor files...${NC}"
echo

GENERATED=0

# Generate patches
for i in "${!FILES[@]}"; do
    file="${FILES[$i]}"
    patch_name="${PATCH_NAMES[$i]}"

    if [ ! -f "$VENDOR_DIR/$file" ]; then
        echo -e "${YELLOW}Warning: $VENDOR_DIR/$file not found, skipping${NC}"
        continue
    fi

    if [ ! -f "$SOURCE_DIR/$file" ]; then
        echo -e "${YELLOW}Warning: $SOURCE_DIR/$file not found, skipping${NC}"
        continue
    fi

    echo -e "${YELLOW}Generating patch for $file...${NC}"

    # Generate diff (unified format with 3 lines of context)
    diff -u "$SOURCE_DIR/$file" "$VENDOR_DIR/$file" > "$PATCHES_DIR/${patch_name}.patch" || true

    if [ -s "$PATCHES_DIR/${patch_name}.patch" ]; then
        LINES=$(wc -l < "$PATCHES_DIR/${patch_name}.patch")
        echo -e "${GREEN}  ✓ Created ${patch_name}.patch (${LINES} lines)${NC}"
        GENERATED=$((GENERATED + 1))
    else
        echo -e "${YELLOW}  ⊘ No changes in $file, removing empty patch${NC}"
        rm -f "$PATCHES_DIR/${patch_name}.patch"
    fi
    echo
done

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Patch generation complete!${NC}"
echo -e "${BLUE}Generated ${GENERATED} patch file(s) in ${PATCHES_DIR}${NC}"
echo -e "${BLUE}========================================${NC}"

if [ "$GENERATED" -gt 0 ]; then
    echo
    echo -e "${BLUE}You can now:${NC}"
    echo -e "  1. Review patches in the ${PATCHES_DIR} directory"
    echo -e "  2. Use ./apply-patches.sh --restore to test clean restoration"
    echo -e "  3. Use patch command to apply patches manually if needed"
fi

echo -e "${GREEN}Done!${NC}"
