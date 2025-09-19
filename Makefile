# Makefile for QUIC library with cross-compilation support

ZIG ?= zig
ZIG_FLAGS ?=
RELEASE_FLAGS = -Drelease-safe=true

# Cross-compilation targets
TARGETS = \
	x86_64-linux-gnu \
	x86_64-linux-musl \
	aarch64-linux-gnu \
	aarch64-linux-musl \
	x86_64-macos \
	aarch64-macos \
	x86_64-windows-gnu \
	arm-linux-gnueabihf \
	arm-linux-musleabihf \
	riscv64-linux-musl \
	wasm32-wasi

.PHONY: all build test fuzz bench tools doccheck ci clean
.PHONY: cross-compile cross-compile-all cross-compile-release
.PHONY: $(TARGETS) $(addsuffix -release,$(TARGETS))

# Default target runs full CI including cross-compilation
all: ci cross-compile-quick

build:
	$(ZIG) build $(ZIG_FLAGS)

build-release:
	$(ZIG) build $(RELEASE_FLAGS) $(ZIG_FLAGS)

test:
	$(ZIG) build test $(ZIG_FLAGS)

fuzz:
	$(ZIG) build fuzz $(ZIG_FLAGS)

bench:
	$(ZIG) build bench $(ZIG_FLAGS)

tools:
	$(ZIG) build tools $(ZIG_FLAGS)

doccheck: tools
	./zig-out/bin/doccheck

# Run build, test, fuzz, bench, and doccheck sequentially
ci: build test fuzz bench tools doccheck

# GitHub Actions CI target (includes cross-compilation verification)
ci-github: ci cross-compile-quick
	@echo "✓ GitHub Actions CI completed successfully"

# Cross-compilation for all targets (debug builds)
cross-compile: 
	@echo "Starting cross-compilation for all targets (debug)..."
	@$(MAKE) -j$(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4) $(TARGETS)
	@echo "✓ All cross-compilation targets built successfully (debug)"

# Cross-compilation for all targets (release builds)
cross-compile-release:
	@echo "Starting cross-compilation for all targets (release)..."
	@$(MAKE) -j$(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4) $(addsuffix -release,$(TARGETS))
	@echo "✓ All cross-compilation targets built successfully (release)"

# Quick cross-compile for primary targets only
cross-compile-quick:
	@echo "Quick cross-compilation for primary targets..."
	@$(MAKE) -j4 x86_64-linux-gnu x86_64-macos x86_64-windows-gnu aarch64-linux-gnu
	@echo "✓ Primary targets built successfully"

# Individual cross-compilation targets (debug)
x86_64-linux-gnu:
	@echo "Building for x86_64-linux-gnu..."
	@$(ZIG) build -Dtarget=x86_64-linux-gnu $(ZIG_FLAGS) 2>&1 | tail -1

x86_64-linux-musl:
	@echo "Building for x86_64-linux-musl..."
	@$(ZIG) build -Dtarget=x86_64-linux-musl $(ZIG_FLAGS) 2>&1 | tail -1

aarch64-linux-gnu:
	@echo "Building for aarch64-linux-gnu..."
	@$(ZIG) build -Dtarget=aarch64-linux-gnu $(ZIG_FLAGS) 2>&1 | tail -1

aarch64-linux-musl:
	@echo "Building for aarch64-linux-musl..."
	@$(ZIG) build -Dtarget=aarch64-linux-musl $(ZIG_FLAGS) 2>&1 | tail -1

x86_64-macos:
	@echo "Building for x86_64-macos..."
	@$(ZIG) build -Dtarget=x86_64-macos $(ZIG_FLAGS) 2>&1 | tail -1

aarch64-macos:
	@echo "Building for aarch64-macos..."
	@$(ZIG) build -Dtarget=aarch64-macos $(ZIG_FLAGS) 2>&1 | tail -1

x86_64-windows-gnu:
	@echo "Building for x86_64-windows-gnu..."
	@$(ZIG) build -Dtarget=x86_64-windows-gnu $(ZIG_FLAGS) 2>&1 | tail -1

arm-linux-gnueabihf:
	@echo "Building for arm-linux-gnueabihf..."
	@$(ZIG) build -Dtarget=arm-linux-gnueabihf $(ZIG_FLAGS) 2>&1 | tail -1

arm-linux-musleabihf:
	@echo "Building for arm-linux-musleabihf..."
	@$(ZIG) build -Dtarget=arm-linux-musleabihf $(ZIG_FLAGS) 2>&1 | tail -1

riscv64-linux-musl:
	@echo "Building for riscv64-linux-musl..."
	@$(ZIG) build -Dtarget=riscv64-linux-musl $(ZIG_FLAGS) 2>&1 | tail -1

wasm32-wasi:
	@echo "Building for wasm32-wasi..."
	@$(ZIG) build -Dtarget=wasm32-wasi $(ZIG_FLAGS) 2>&1 | tail -1

# Individual cross-compilation targets (release)
x86_64-linux-gnu-release:
	@echo "Building for x86_64-linux-gnu (release)..."
	@$(ZIG) build -Dtarget=x86_64-linux-gnu $(RELEASE_FLAGS) $(ZIG_FLAGS) 2>&1 | tail -1

x86_64-linux-musl-release:
	@echo "Building for x86_64-linux-musl (release)..."
	@$(ZIG) build -Dtarget=x86_64-linux-musl $(RELEASE_FLAGS) $(ZIG_FLAGS) 2>&1 | tail -1

aarch64-linux-gnu-release:
	@echo "Building for aarch64-linux-gnu (release)..."
	@$(ZIG) build -Dtarget=aarch64-linux-gnu $(RELEASE_FLAGS) $(ZIG_FLAGS) 2>&1 | tail -1

aarch64-linux-musl-release:
	@echo "Building for aarch64-linux-musl (release)..."
	@$(ZIG) build -Dtarget=aarch64-linux-musl $(RELEASE_FLAGS) $(ZIG_FLAGS) 2>&1 | tail -1

x86_64-macos-release:
	@echo "Building for x86_64-macos (release)..."
	@$(ZIG) build -Dtarget=x86_64-macos $(RELEASE_FLAGS) $(ZIG_FLAGS) 2>&1 | tail -1

aarch64-macos-release:
	@echo "Building for aarch64-macos (release)..."
	@$(ZIG) build -Dtarget=aarch64-macos $(RELEASE_FLAGS) $(ZIG_FLAGS) 2>&1 | tail -1

x86_64-windows-gnu-release:
	@echo "Building for x86_64-windows-gnu (release)..."
	@$(ZIG) build -Dtarget=x86_64-windows-gnu $(RELEASE_FLAGS) $(ZIG_FLAGS) 2>&1 | tail -1

arm-linux-gnueabihf-release:
	@echo "Building for arm-linux-gnueabihf (release)..."
	@$(ZIG) build -Dtarget=arm-linux-gnueabihf $(RELEASE_FLAGS) $(ZIG_FLAGS) 2>&1 | tail -1

arm-linux-musleabihf-release:
	@echo "Building for arm-linux-musleabihf (release)..."
	@$(ZIG) build -Dtarget=arm-linux-musleabihf $(RELEASE_FLAGS) $(ZIG_FLAGS) 2>&1 | tail -1

riscv64-linux-musl-release:
	@echo "Building for riscv64-linux-musl (release)..."
	@$(ZIG) build -Dtarget=riscv64-linux-musl $(RELEASE_FLAGS) $(ZIG_FLAGS) 2>&1 | tail -1

wasm32-wasi-release:
	@echo "Building for wasm32-wasi (release)..."
	@$(ZIG) build -Dtarget=wasm32-wasi $(RELEASE_FLAGS) $(ZIG_FLAGS) 2>&1 | tail -1

# Clean build artifacts
clean:
	rm -rf zig-cache zig-out .zig-cache

# Help target
help:
	@echo "QUIC Library Makefile"
	@echo ""
	@echo "Main targets:"
	@echo "  make                      - Run full CI and quick cross-compilation (default)"
	@echo "  make ci                   - Run build, test, fuzz, bench, and doccheck"
	@echo "  make ci-github            - Full CI for GitHub Actions"
	@echo "  make build                - Build the project (debug)"
	@echo "  make build-release        - Build the project (release)"
	@echo "  make test                 - Run tests"
	@echo "  make tools                - Build CLI tools"
	@echo ""
	@echo "Cross-compilation:"
	@echo "  make cross-compile        - Build for all targets in parallel (debug)"
	@echo "  make cross-compile-release- Build for all targets in parallel (release)"
	@echo "  make cross-compile-quick  - Build primary targets only (faster)"
	@echo ""
	@echo "Individual targets:"
	@echo "  make x86_64-linux-gnu     - Build for x86_64 Linux with glibc"
	@echo "  make aarch64-linux-musl   - Build for ARM64 Linux with musl"
	@echo "  make x86_64-macos         - Build for Intel macOS"
	@echo "  make aarch64-macos        - Build for Apple Silicon macOS"
	@echo "  make x86_64-windows-gnu   - Build for Windows x86_64"
	@echo "  make wasm32-wasi          - Build for WebAssembly WASI"
	@echo ""
	@echo "  Add '-release' suffix for release builds"
	@echo ""
	@echo "Other:"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make help         - Show this help message"
