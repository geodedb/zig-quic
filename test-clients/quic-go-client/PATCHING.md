# QUIC-Go Debug Logging System

This directory contains a vendoring and debug logging system for the quic-go library that adds comprehensive debug logging to key QUIC protocol components.

## Overview

The system provides:

1. **Vendor Directory**: A local copy of quic-go from `/home/benji/src/spyder/quic/forks/quic-go`
2. **Debug Logging Script**: Automated script to add debug printf statements to critical QUIC operations
3. **Patch Files**: Git-style unified diff patches documenting the debug modifications
4. **Reproducible Workflow**: Scripts to restore, modify, and regenerate patches

## Directory Structure

```
quic-go-client/
├── vendor/
│   └── quic-go/                # Vendored quic-go library (with debug logging)
├── patches/
│   ├── 01-connection-debug-logging.patch
│   ├── 02-crypto-stream-manager-debug-logging.patch
│   ├── 03-packet-unpacker-debug-logging.patch
│   ├── 04-packet-packer-debug-logging.patch
│   └── 05-transport-debug-logging.patch
├── apply-patches.sh            # Main script to add/remove debug logging
├── generate-patches.sh         # Script to generate patch files from modifications
├── PATCHING.md                # This file
└── main.go                    # Your QUIC client application
```

## Debug Logging Details

### 01-connection-debug-logging.patch

Adds logging to `connection.go` for:
- First packet received from server with connection ID
- Handshake confirmation events

**Debug output:**
- `[CONN] First packet received from server, switching to new conn ID: <conn_id>`
- `[CONN] Handshake confirmed, dropping handshake packet space`

**Files modified:** `connection.go`
**Changes:** 2 debug statements

### 02-crypto-stream-manager-debug-logging.patch

Adds logging to `crypto_stream_manager.go` for:
- CRYPTO frame handling at different encryption levels (Initial, Handshake, 1-RTT)
- Crypto data retrieval and processing

**Debug output:**
- `[CRYPTO_MGR] Handling CRYPTO frame: enc_level=<level>, offset=<n>, length=<n>`
- `[CRYPTO_MGR] Processing Initial/Handshake/1-RTT CRYPTO frame`

**Files modified:** `crypto_stream_manager.go`
**Changes:** 4 debug statements (HandleCryptoFrame, GetCryptoData cases)

### 03-packet-unpacker-debug-logging.patch

Adds logging to `packet_unpacker.go` for:
- Long header packet unpacking with full header details
- Short header packet unpacking
- Packet type identification (Initial, Handshake)

**Debug output:**
- `[UNPACKER] Unpacking long header packet: type=<type>, version=<v>, dest_conn_id=<id>, src_conn_id=<id>, data_len=<n>`
- `[UNPACKER] Processing Initial/Handshake packet`
- `[UNPACKER] Unpacking short header packet: data_len=<n>`

**Files modified:** `packet_unpacker.go`
**Changes:** 4 debug statements

### 04-packet-packer-debug-logging.patch

Adds logging to `packet_packer.go` for:
- Coalesced packet construction
- Packet encryption and AEAD sealing

**Debug output:**
- `[PACKER] Packing coalesced packet: only_ack=<bool>, max_size=<n>`
- `[PACKER] Encrypting packet: pn=<n>, payload_offset=<n>, pn_len=<n>`
- `[PACKER] Packet encrypted and header protection applied`

**Files modified:** `packet_packer.go`
**Changes:** 3 debug statements

### 05-transport-debug-logging.patch

Adds logging to `transport.go` for:
- Packet reception and routing
- Transport layer packet handling

**Debug output:**
- `[TRANSPORT] Handling packet: size=<n>, from=<addr>`

**Files modified:** `transport.go`
**Changes:** 1 debug statement

## Usage

### Initial Setup

The vendor directory already exists in this project. If you need to recreate it from source:

```bash
./apply-patches.sh --restore
```

This will:
- Remove existing `vendor/quic-go` if present
- Copy fresh source from `/home/benji/src/spyder/quic/forks/quic-go`
- Clean up any git metadata
- Leave the vendor directory in a clean state (no debug logging)

### Add Debug Logging

To add debug logging to the vendor directory:

```bash
./apply-patches.sh
```

This will:
- Check if debug logging is already applied
- Add fmt.Printf debug statements to 5 key files
- Report the number of modifications made to each file
- Be idempotent (can run multiple times safely)

### Remove Debug Logging

To remove debug logging and restore clean source:

```bash
./apply-patches.sh --restore
```

### Regenerate Patch Files

If you manually modify the vendor files and want to regenerate the patch files:

```bash
./generate-patches.sh
```

This will:
- Compare vendor files with source files
- Generate unified diff patches for each modified file
- Save patches in the `patches/` directory

### Complete Workflow Example

```bash
# 1. Start with clean source
./apply-patches.sh --restore

# 2. Add debug logging
./apply-patches.sh

# 3. Build and test your application
go build

# 4. If you make manual changes, regenerate patches
./generate-patches.sh

# 5. To start fresh again
./apply-patches.sh --restore
./apply-patches.sh
```

## Debug Output Example

When you run your QUIC client with debug logging enabled, you'll see output like:

```
[TRANSPORT] Handling packet: size=1200, from=192.168.1.100:443
[UNPACKER] Unpacking long header packet: type=Initial, version=1, dest_conn_id=a1b2c3d4, src_conn_id=e5f6g7h8, data_len=1200
[UNPACKER] Processing Initial packet
[CRYPTO_MGR] Handling CRYPTO frame: enc_level=Initial, offset=0, length=280
[CRYPTO_MGR] Processing Initial CRYPTO frame
[CONN] First packet received from server, switching to new conn ID: e5f6g7h8
[PACKER] Packing coalesced packet: only_ack=false, max_size=1200
[PACKER] Encrypting packet: pn=0, payload_offset=17, pn_len=1
[PACKER] Packet encrypted and header protection applied
[UNPACKER] Processing Handshake packet
[CONN] Handshake confirmed, dropping handshake packet space
```

## Implementation Details

### How It Works

The `apply-patches.sh` script uses `sed` to insert `fmt.Printf` statements at specific locations in the source code:

1. **Pattern Matching**: Searches for specific function signatures or code patterns
2. **Insertion**: Adds debug printf statements immediately after matched lines
3. **Idempotency**: Checks if debug logging is already present before applying
4. **Atomic Operations**: Each sed command is independent and can fail gracefully

### Patch Format

All patches use standard unified diff format:
- `---` line shows source file path
- `+++` line shows modified file path
- `@@` lines show line numbers and context
- Lines starting with `-` are removed
- Lines starting with `+` are added
- Lines starting with space are context

### Why This Approach?

Instead of using traditional `patch` command, this system uses `sed` for several reasons:

1. **Simplicity**: No need to manage patch application state
2. **Flexibility**: Easy to modify debug logging locations
3. **Robustness**: Fails gracefully if patterns don't match
4. **Idempotency**: Built-in detection of already-applied changes
5. **Maintainability**: Easy to add new debug points

## Customization

### Adding New Debug Points

To add debug logging to additional locations:

1. Edit `apply-patches.sh`
2. Add new `sed` commands in the appropriate section
3. Test with `./apply-patches.sh --restore && ./apply-patches.sh`
4. Regenerate patches with `./generate-patches.sh`

Example:

```bash
# Add logging to a new function
sed -i '/func myFunction(/a\
\tfmt.Printf("[DEBUG] My function called\\n")' \
    "$VENDOR_DIR/myfile.go"
```

### Adding New Files

To add debug logging to additional files:

1. Update the `FILES` array in `generate-patches.sh`
2. Update the `PATCH_NAMES` array with corresponding names
3. Add sed commands in `add_debug_logging()` function in `apply-patches.sh`
4. Run `./apply-patches.sh` to apply changes
5. Run `./generate-patches.sh` to create patch files

## Troubleshooting

### Debug logging not appearing

1. Check that `./apply-patches.sh` ran successfully
2. Verify changes: `grep -r "fmt.Printf" vendor/quic-go/*.go`
3. Make sure your application imports use the local vendor directory

### Patches fail to apply

```bash
./apply-patches.sh --restore  # Get clean source
./apply-patches.sh            # Re-apply debug logging
```

### Source directory not found

Ensure `/home/benji/src/spyder/quic/forks/quic-go` exists and is readable.

### Modified vendor files causing issues

The script is designed to handle already-modified files, but if you encounter issues:

```bash
./apply-patches.sh --restore  # Start fresh
# Make your changes
./apply-patches.sh            # Add debug logging
```

## Command Reference

### apply-patches.sh

```bash
./apply-patches.sh              # Add debug logging to vendor
./apply-patches.sh --restore    # Restore clean vendor from source
./apply-patches.sh --help       # Show usage information
```

### generate-patches.sh

```bash
./generate-patches.sh           # Generate patch files from current vendor state
```

## Notes

- The vendor directory should not be committed to git (add to .gitignore)
- Patch files serve as documentation and can be version controlled
- Debug output goes to stdout - redirect to file if needed: `./your-client > debug.log 2>&1`
- Debug logging adds minimal performance overhead (printf calls)
- All debug tags are prefixed with component name for easy filtering

## Advanced Usage

### Filter debug output

```bash
# Show only packet unpacker debug messages
./your-client 2>&1 | grep "\[UNPACKER\]"

# Show only connection-related debug messages
./your-client 2>&1 | grep "\[CONN\]"

# Exclude certain debug categories
./your-client 2>&1 | grep -v "\[TRANSPORT\]"
```

### Save debug output with timestamps

```bash
./your-client 2>&1 | ts '[%Y-%m-%d %H:%M:%.S]' | tee debug.log
```

### Compare with and without debug logging

```bash
# Run without debug logging
./apply-patches.sh --restore
go build -o client-clean
./client-clean > clean.log 2>&1

# Run with debug logging
./apply-patches.sh
go build -o client-debug
./client-debug > debug.log 2>&1

# Compare
diff clean.log debug.log
```

## Maintenance

### Updating Source

When the source quic-go is updated:

1. Pull latest changes to `/home/benji/src/spyder/quic/forks/quic-go`
2. Run `./apply-patches.sh --restore` to get new clean copy
3. Run `./apply-patches.sh` to reapply debug logging
4. If sed commands fail, update patterns in `apply-patches.sh`
5. Regenerate patches: `./generate-patches.sh`

### Version Control

Recommended files to commit:
- `apply-patches.sh`
- `generate-patches.sh`
- `patches/*.patch`
- `PATCHING.md`

Do not commit:
- `vendor/` directory
- Modified source files

## Summary

This debug logging system provides:
- **16 debug points** across 5 critical files
- **Reproducible** modifications via scripts
- **Documented** changes via patch files
- **Flexible** system for adding new debug points
- **Safe** operations with restore capability

The debug logging helps diagnose QUIC protocol issues by providing visibility into:
- Packet processing pipeline
- Encryption/decryption operations
- Connection state changes
- Transport parameter negotiation
- Crypto stream handling
