FROM martenseemann/quic-network-simulator-endpoint:latest

ARG ZIG_URL
ARG ZIG_SHA256
ARG ZIG_VERSION=0.14.1
ENV ZIG_VERSION=${ZIG_VERSION}
RUN apt-get update && apt-get install -y curl ca-certificates build-essential git xz-utils && rm -rf /var/lib/apt/lists/*
# Robust Zig fetch: tries build context, explicit URL, then both naming patterns.
RUN set -eux; \
    TARBALL=/tmp/zig.tar.xz; \
    if [ -f ./zig.tar.xz ]; then \
        echo "Using provided zig.tar.xz from build context"; cp ./zig.tar.xz "$TARBALL"; \
    elif [ -n "${ZIG_URL:-}" ]; then \
        echo "Fetching Zig from custom URL: $ZIG_URL"; curl -fSL "$ZIG_URL" -o "$TARBALL"; \
    else \
        FOUND=false; \
        for NAME in "zig-x86_64-linux-${ZIG_VERSION}.tar.xz" "zig-linux-x86_64-${ZIG_VERSION}.tar.xz"; do \
            URL="https://ziglang.org/download/${ZIG_VERSION}/${NAME}"; \
            echo "Attempting fetch: $URL"; \
            if curl -fSL "$URL" -o "$TARBALL"; then echo "Fetched $NAME"; FOUND=true; break; fi; \
        done; \
        if [ "$FOUND" = false ]; then echo "Failed to download Zig ${ZIG_VERSION}"; exit 1; fi; \
    fi; \
    if [ -n "${ZIG_SHA256:-}" ]; then \
        echo "${ZIG_SHA256}  $TARBALL" | sha256sum -c - || (echo "SHA256 mismatch"; exit 1); \
    else \
        echo "Skipping SHA256 verification"; \
    fi; \
    mkdir -p /opt/zig; \
    tar -xJf "$TARBALL" -C /opt/zig --strip-components=1 || (echo "Failed to extract Zig tarball"; ls -l "$TARBALL"; file "$TARBALL"; exit 1); \
    ln -s /opt/zig/zig /usr/local/bin/zig; \
    rm "$TARBALL"; \
    zig version || (echo "Zig not installed correctly"; exit 1)

WORKDIR /quic
COPY . .
RUN zig version && zig build -Drelease-safe=true cli && zig build -Drelease-safe=true install && cp zig-out/bin/qns-endpoint /usr/local/bin/qns-endpoint

# Copy our custom run_endpoint.sh
COPY examples/interop/zig-qns/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh



ENTRYPOINT ["/run_endpoint.sh"]
