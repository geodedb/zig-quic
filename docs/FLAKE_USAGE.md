# Using the QUIC Library in Another Flake

To use this QUIC library in another Zig project via Nix flakes, add it as an input and use it in your build:

## Example flake.nix for a project using quic

```nix
{
  description = "My project using QUIC";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    quic.url = "github:spyderorg/quic";  # or path:/path/to/quic for local
  };

  outputs = { self, nixpkgs, flake-utils, quic, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = { allowUnfree = true; };
        };
        
        # Get the quic package
        quicLib = quic.packages.${system}.quic;
        
      in {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "my-quic-app";
          version = "0.1.0";
          
          src = ./.;
          
          nativeBuildInputs = [ pkgs.zig ];
          
          # Make quic available during build
          buildInputs = [ quicLib ];
          
          buildPhase = ''
            # The quic source is available at:
            # ${quicLib}/src/  - source files
            # ${quicLib}/quic.zig - main module file
            # ${quicLib}/build.zig - build configuration
            
            # You can reference it in your build.zig like:
            # const quic_dep = b.dependency("quic", .{
            #   .target = target,
            #   .optimize = optimize,
            # });
            # exe.root_module.addImport("quic", quic_dep.module("quic"));
            
            zig build -Doptimize=ReleaseSafe
          '';
          
          installPhase = ''
            mkdir -p $out/bin
            cp zig-out/bin/* $out/bin/
          '';
        };
        
        devShell = pkgs.mkShell {
          packages = with pkgs; [
            zig
            # Include quic tools in dev shell
            quicLib
          ];
          
          shellHook = ''
            echo "QUIC library available at: ${quicLib}"
            echo "QUIC tools available in PATH:"
            echo "  - quic-client"
            echo "  - quic-server"
            echo "  - quic-varint"
          '';
        };
      });
}
```

## Using in build.zig.zon

If you want to use the QUIC library directly in your Zig project's `build.zig.zon`, you can reference the source path provided by the Nix package:

```zig
.{
    .name = "my-app",
    .version = "0.1.0",
    .dependencies = .{
        .quic = .{
            // Use the path from the Nix package
            .path = "../path/to/quic",
        },
    },
}
```

## Available Packages

The QUIC flake exports the following packages:

- `quic` - The default ReleaseSafe build with all tools and libraries
- `quic-debug` - Debug build for development
- `default` - Alias for `quic`

## Included Binaries

When you include the quic package, the following tools are available:

- `quic-client` - QUIC client CLI
- `quic-server` - QUIC server CLI  
- `quic-varint` - Variable-length integer encoder/decoder
- `doccheck` - Documentation completeness checker
- `update-gap` - GAP analysis updater
- `interop-runner` - Interoperability test runner
- `qns-endpoint` - QNS test endpoint

## Development Shell

To enter a development shell with the QUIC library and tools available:

```bash
nix develop github:spyderorg/quic
```

Or if using it as a flake input:

```bash
nix develop
```