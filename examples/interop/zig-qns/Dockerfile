FROM martenseemann/quic-network-simulator-endpoint@sha256:3b2b9e6fa317da238c8140a7b6d2bf8d4d45a8464b873eecac3ff2a32520b71a

# Expect a prebuilt qns-endpoint copied from host to make builds deterministic and offline-friendly.
# Build locally before invoking docker:
#   zig build -Drelease-safe=true install

WORKDIR /quic

# /setup.sh (from the base image) requires root + CAP_NET_ADMIN to configure
# networking for the simulator. We still run the actual endpoint binary as an
# unprivileged user after setup.
RUN groupadd -r quic && useradd -r -g quic -d /nonexistent -s /usr/sbin/nologin quic \
    && mkdir -p /quic /quic/certs /logs/qlog /downloads /www \
    && chown -R quic:quic /quic /logs /downloads /www

# Copy the endpoint binary
COPY zig-out/bin/qns-endpoint /usr/local/bin/qns-endpoint

# Bundle fallback certs for local runs where /certs isn't mounted.
COPY tests/certs/cert.pem /quic/certs/cert.pem
COPY tests/certs/key.pem /quic/certs/key.pem

# Create version file from git if available
RUN echo "zig-quic-$(date +%Y%m%d)" > /quic/version.txt || echo "zig-quic-dev" > /quic/version.txt

# Copy our custom run_endpoint.sh
COPY examples/interop/zig-qns/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh /usr/local/bin/qns-endpoint

HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD pgrep -x qns-endpoint >/dev/null || exit 1

ENTRYPOINT ["/run_endpoint.sh"]
