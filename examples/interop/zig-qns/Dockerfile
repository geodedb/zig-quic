FROM martenseemann/quic-network-simulator-endpoint:latest

# Expect a prebuilt qns-endpoint copied from host to make builds deterministic and offline-friendly.
# Build locally before invoking docker:
#   zig build -Drelease-safe=true install

WORKDIR /quic
COPY zig-out/bin/qns-endpoint /usr/local/bin/qns-endpoint

# Copy our custom run_endpoint.sh
COPY examples/interop/zig-qns/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh /usr/local/bin/qns-endpoint

ENTRYPOINT ["/run_endpoint.sh"]
