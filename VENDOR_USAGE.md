# Using QUIC Library as a Vendor Dependency

When using this QUIC library as a vendor dependency in your project, you need to properly configure all the required modules in your `build.zig` file.

## Quick Setup

### Method 1: Using vendor_setup.zig (Recommended)

1. Copy the QUIC library to your `vendor/quic/` directory
2. In your `build.zig`:

```zig
const std = @import("std");
const quic_vendor_setup = @import("vendor/quic/vendor_setup.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Setup all QUIC modules
    const quic_modules = quic_vendor_setup.setupModules(b, "vendor/quic", target, optimize);

    // Create your executable/library
    const exe = b.addExecutable(.{
        .name = "my_app",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add QUIC modules you need
    exe.root_module.addImport("quic", quic_modules.quic_api);
    exe.root_module.addImport("quic_endpoint", quic_modules.quic_endpoint);
    exe.root_module.addImport("quic_conn", quic_modules.quic_conn);

    b.installArtifact(exe);
}
```

### Method 2: Manual Setup

If you prefer to manually configure the modules, you MUST include the `byteorder` module:

```zig
// In your build.zig

// CRITICAL: Define byteorder module first
const byteorder_mod = b.addModule("byteorder", .{
    .root_source_file = b.path("vendor/quic/src/byteorder/byteorder.zig"),
});

// Then define other QUIC modules
const quic_conn_mod = b.addModule("quic_conn", .{
    .root_source_file = b.path("vendor/quic/src/quic/conn.zig"),
});

// IMPORTANT: Add byteorder as import to modules that need it
quic_conn_mod.addImport("byteorder", byteorder_mod);

const quic_endpoint_mod = b.addModule("quic_endpoint", .{
    .root_source_file = b.path("vendor/quic/src/quic/endpoint.zig"),
});
quic_endpoint_mod.addImport("byteorder", byteorder_mod);

const quic_varint_mod = b.addModule("quic_varint", .{
    .root_source_file = b.path("vendor/quic/src/quic/varint.zig"),
});
quic_varint_mod.addImport("byteorder", byteorder_mod);

const token_mod = b.addModule("token", .{
    .root_source_file = b.path("vendor/quic/src/quic/token.zig"),
});
token_mod.addImport("byteorder", byteorder_mod);

// ... configure all other required modules and their dependencies
```

## Required Modules

The following modules REQUIRE the `byteorder` module to be imported:
- `conn.zig` - Connection management
- `endpoint.zig` - Endpoint handling
- `varint.zig` - Variable-length integer encoding
- `token.zig` - Token generation/validation

## Common Errors and Solutions

### Error: "no module named 'byteorder' available"

**Cause**: The `byteorder` module is not configured in your build.zig

**Solution**:
1. Use the `vendor_setup.zig` helper (recommended), OR
2. Manually add the byteorder module and ensure it's imported by all modules that need it:

```zig
// Define the module
const byteorder_mod = b.addModule("byteorder", .{
    .root_source_file = b.path("vendor/quic/src/byteorder/byteorder.zig"),
});

// Add it as import to modules that need it
your_module.addImport("byteorder", byteorder_mod);
```

## Module Dependency Tree

```
quic_api (main entry point)
├── quic_endpoint
│   ├── byteorder ⚠️
│   ├── quic_conn
│   │   ├── byteorder ⚠️
│   │   └── ...
│   ├── quic_varint
│   │   └── byteorder ⚠️
│   └── token
│       └── byteorder ⚠️
└── ...
```

⚠️ = Requires byteorder module

## Testing Your Integration

After setting up the modules, test with a simple QUIC client:

```zig
const std = @import("std");
const quic = @import("quic");

pub fn main() !void {
    const config = quic.QuicConfig{
        .server_name = "example.com",
        .alpn_protocols = &.{"h3"},
    };

    // Your QUIC code here...
}
```

## Support

If you encounter issues with module configuration, check:
1. All byteorder imports are properly configured
2. Module paths are correct relative to your vendor directory
3. All module dependencies are satisfied

For a complete working example, see `vendor_setup.zig` in the QUIC library root.