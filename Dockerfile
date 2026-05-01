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
# Self-healing entrypoint: chowns /data to the runtime UID on every boot and
# drops privileges via setpriv before exec'ing the binary. This is required
# because a named Docker volume only inherits image ownership on its FIRST
# attach — a stale volume from an older image stays root-owned forever and
# would otherwise lock the non-root binary out of /data on every restart.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh
# NOTE: do not set USER here. The entrypoint starts as root so it can repair
# /data ownership, then drops privileges to uid 10001 before running the
# server. `no-new-privileges:true` in docker-compose.yml still prevents any
# elevation back to root after the drop.
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["crash-crafts-game-sync", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["crash-crafts-game-sync", "server", "--host", "0.0.0.0", "--port", "8080", "--data-dir", "/data"]
