FROM rust:1-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY shared ./shared
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update \
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
CMD ["crash-crafts-game-sync", "server", "--host", "0.0.0.0", "--port", "8080", "--data-dir", "/data"]
