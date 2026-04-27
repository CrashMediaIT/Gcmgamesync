# Pin the builder to the same Debian release used by the runtime image so the
# resulting binary links against a glibc the runtime can satisfy. Using
# `rust:1-slim` (which floats to the newest Debian) caused the runtime crash
# `version 'GLIBC_2.39' not found` on the bookworm-based runtime.
FROM rust:1-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY shared ./shared
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
# `apt-get upgrade` pulls in the latest security fixes for the base image
# without changing the major release (so glibc stays compatible with the
# builder above).
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin ccgs \
    && mkdir -p /data \
    && chown -R ccgs:ccgs /data
COPY --from=builder /app/target/release/crash-crafts-game-sync /usr/local/bin/crash-crafts-game-sync
COPY shared ./shared
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["crash-crafts-game-sync", "healthcheck"]
CMD ["crash-crafts-game-sync", "server", "--host", "0.0.0.0", "--port", "8080", "--data-dir", "/data"]
