# Simple Makefile to wrap Zig build/test/fuzz/bench/tools

ZIG ?= zig
ZIG_FLAGS ?=

.PHONY: all build test fuzz bench tools doccheck ci

all: ci

build:
	$(ZIG) build $(ZIG_FLAGS)

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
