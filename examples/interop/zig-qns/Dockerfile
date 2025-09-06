FROM martenseemann/quic-network-simulator-endpoint:latest

ARG ZIG_URL
ENV ZIG_VERSION=0.14.1
RUN apt-get update && apt-get install -y curl ca-certificates build-essential git xz-utils && rm -rf /var/lib/apt/lists/*
# Primary ziglang.org host occasionally returns 403 in CI; fall back to GitHub release mirror.
RUN set -eux; \
        TARBALL=/tmp/zig.tar.xz; \
        if [ -f ./zig.tar.xz ]; then echo "Using provided zig.tar.xz from build context"; cp ./zig.tar.xz "$TARBALL"; \
        elif [ -n "${ZIG_URL:-}" ]; then echo "Fetching Zig from custom URL: $ZIG_URL"; curl -fsSL "$ZIG_URL" -o "$TARBALL"; \
        else \
            URL_PRIMARY="https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz"; \
            URL_FALLBACK="https://github.com/ziglang/zig/releases/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz"; \
            if curl -fsSL "$URL_PRIMARY" -o "$TARBALL"; then echo "Fetched Zig from primary"; \
            else echo "Primary failed, using fallback"; curl -fsSL "$URL_FALLBACK" -o "$TARBALL"; fi; \
        fi; \
        mkdir -p /opt/zig; \
        tar -xJf "$TARBALL" -C /opt/zig --strip-components=1 || (echo "Failed to extract Zig tarball"; ls -l "$TARBALL"; exit 1); \
        ln -s /opt/zig/zig /usr/local/bin/zig; \
        rm "$TARBALL"; \
        zig version || (echo "Zig not installed correctly"; exit 1)

WORKDIR /quic
COPY . .
RUN zig version && zig build -Drelease-safe=true cli && zig build -Drelease-safe=true install && cp zig-out/bin/qns-endpoint /usr/local/bin/qns-endpoint

ENTRYPOINT ["/run_endpoint.sh"]
