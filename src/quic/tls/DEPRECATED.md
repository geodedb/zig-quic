# ⚠️ DEPRECATED - Local TLS Implementation

**This directory is deprecated as of 2025-11-05**

All TLS functionality has been migrated to the vendored ztls library at:
```
vendor/ztls/
```

## Migration Status

The QUIC implementation now uses the vendored TLS library instead of these local files.

### Deprecated Files

All files in this directory are deprecated:
- `alert.zig` → `vendor/ztls/src/alert.zig`
- `asn1.zig` → `vendor/ztls/src/asn1.zig`
- `key_schedule.zig` → `vendor/ztls/src/key_schedule.zig`
- `record.zig` → `vendor/ztls/src/record.zig`
- `sig.zig` → `vendor/ztls/src/sig.zig`
- `tls13.zig` → `vendor/ztls/src/tls13.zig`
- `tls13_full.zig` → `vendor/ztls/src/tls13_full.zig`
- `x509.zig` → `vendor/ztls/src/x509.zig`
- `zero_rtt.zig` → `vendor/ztls/src/zero_rtt.zig`

## Why Migrate?

The vendored ztls library provides:
- ✅ Standalone, independently maintained TLS 1.3 implementation
- ✅ Full RFC compliance with citations (RFC 8446, RFC 9001, RFC 9369)
- ✅ Comprehensive testing (77 unit tests + RFC vectors + conformance tests)
- ✅ Zero external dependencies
- ✅ Interoperability testing against major QUIC implementations
- ✅ Better maintainability and code sharing

## Build System

The build system (`build.zig`) has been updated to use the vendored modules.
These local files are no longer referenced in the build.

## Documentation

For details on the migration, see:
- [`TLS_MIGRATION.md`](../../../TLS_MIGRATION.md) - Migration summary and status
- [`vendor/ztls/README.md`](../../../vendor/ztls/README.md) - ztls library documentation
- [`vendor/ztls/CLAUDE.md`](../../../vendor/ztls/CLAUDE.md) - Architecture and development guide

## Cleanup

These files will be removed in a future commit after the migration is fully validated.
They are being preserved temporarily for reference and rollback capability.

**Do not modify files in this directory** - all TLS changes should be made in `vendor/ztls/`.
