# syntax=docker/dockerfile:1
FROM rust:1.90.0-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY scripts ./scripts
RUN cargo build --release --locked -p petika -p petika-server \
    && python3 scripts/check_licenses.py \
    && python3 scripts/third_party_notices.py > /build/THIRD_PARTY_NOTICES.txt

RUN mkdir -p /runtime/data /runtime/mirror /runtime/run/secrets

FROM gcr.io/distroless/cc-debian13:nonroot AS runtime
COPY --from=build --chown=65532:65532 /runtime/ /
COPY --from=build /build/target/release/petika /usr/local/bin/petika
COPY --from=build /build/target/release/petika-server /usr/local/bin/petika-server
COPY --from=build /build/THIRD_PARTY_NOTICES.txt /usr/share/doc/petika/THIRD_PARTY_NOTICES.txt
COPY LICENSE /usr/share/doc/petika/LICENSE
LABEL org.opencontainers.image.source="https://github.com/k2patel/petika" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="Petika" \
      org.opencontainers.image.description="Experimental encrypted snapshot API and Rust CLI"
ENV PETIKA_LISTEN=0.0.0.0:8080 \
    PETIKA_DATA_DIR=/data \
    PETIKA_GIT_MIRROR=/mirror \
    PETIKA_TOKEN_FILE=/run/secrets/token
WORKDIR /data
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/petika-server"]
