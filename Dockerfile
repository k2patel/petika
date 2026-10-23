# syntax=docker/dockerfile:1
FROM rust:1.90.0-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown \
    && cargo install wasm-bindgen-cli --version 0.2.114 --locked
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY scripts ./scripts
COPY clients/web ./clients/web
RUN sh scripts/build_web.sh
ARG PETIKA_EXPERIMENTAL_ENTRY_FORMAT=0
RUN if [ "$PETIKA_EXPERIMENTAL_ENTRY_FORMAT" = 1 ]; then \
      cargo build --release --locked -p petika -p petika-server --features experimental-entry-format; \
    elif [ "$PETIKA_EXPERIMENTAL_ENTRY_FORMAT" = 0 ]; then \
      cargo build --release --locked -p petika -p petika-server; \
    else exit 1; fi \
    && python3 scripts/check_licenses.py \
    && python3 scripts/third_party_notices.py > /build/THIRD_PARTY_NOTICES.txt

RUN mkdir -p /runtime/data /runtime/mirror /runtime/run/secrets

FROM gcr.io/distroless/cc-debian13:nonroot AS core-runtime
COPY --from=build --chown=65532:65532 /runtime/ /
COPY --from=build /build/target/release/petika /usr/local/bin/petika
COPY --from=build /build/target/release/petika-server /usr/local/bin/petika-server
COPY --from=build /build/THIRD_PARTY_NOTICES.txt /usr/share/doc/petika/THIRD_PARTY_NOTICES.txt
COPY LICENSE /usr/share/doc/petika/LICENSE
COPY --from=build /build/clients/web /usr/share/petika/web
LABEL org.opencontainers.image.source="https://github.com/k2patel/petika" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="Petika" \
      org.opencontainers.image.description="Experimental encrypted snapshot API and Rust CLI"
ENV PETIKA_LISTEN=0.0.0.0:8080 \
    PETIKA_DATA_DIR=/data \
    PETIKA_GIT_MIRROR=/mirror \
    PETIKA_TOKEN_FILE=/run/secrets/token \
    PETIKA_WEB_DIR=/usr/share/petika/web
WORKDIR /data
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/petika-server"]

# Server-side push edition: isolated backup subprocesses need Python, restic and SSH.
FROM debian:trixie-slim AS backup-tools
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl bzip2 && rm -rf /var/lib/apt/lists/*
RUN case "$TARGETARCH" in \
      amd64) checksum=f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c ;; \
      arm64) checksum=a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465 ;; \
      *) exit 1 ;; esac && \
    curl -fsSL "https://github.com/restic/restic/releases/download/v0.19.1/restic_0.19.1_linux_${TARGETARCH}.bz2" -o /tmp/restic.bz2 && \
    echo "$checksum  /tmp/restic.bz2" | sha256sum -c - && \
    bunzip2 /tmp/restic.bz2 && chmod 755 /tmp/restic && \
    curl -fsSL https://raw.githubusercontent.com/restic/restic/v0.19.1/LICENSE -o /tmp/restic-LICENSE

FROM debian:trixie-slim AS push-runtime
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssh-client git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=core-runtime /usr/local/bin/ /usr/local/bin/
COPY --from=core-runtime /usr/share/petika/ /usr/share/petika/
COPY --from=core-runtime /usr/share/doc/petika/ /usr/share/doc/petika/
COPY --from=build --chown=65532:65532 /runtime/ /
COPY --from=backup-tools /tmp/restic /usr/local/bin/restic
COPY --from=backup-tools /tmp/restic-LICENSE /usr/share/doc/restic/LICENSE
COPY scripts/backup_recovery.py scripts/backup_delta.py scripts/user_backup.py scripts/offsite_backup.py scripts/server_backup.py /usr/share/petika/scripts/
ARG PETIKA_RELEASE=development
ENV PETIKA_LISTEN=0.0.0.0:8080 PETIKA_DATA_DIR=/data PETIKA_GIT_MIRROR=/mirror \
    PETIKA_TOKEN_FILE=/run/secrets/token PETIKA_WEB_DIR=/usr/share/petika/web \
    PETIKA_BACKUP_SCRIPT=/usr/share/petika/scripts/server_backup.py PETIKA_BACKUP_RELEASE=$PETIKA_RELEASE \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /data
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/petika-server"]

# Preserve the minimal default image; deployments select push-runtime explicitly.
FROM core-runtime AS runtime
