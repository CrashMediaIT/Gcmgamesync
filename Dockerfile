FROM rust:1-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY shared ./shared
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/gcmgamesync /usr/local/bin/gcmgamesync
COPY shared ./shared
ENV GCM_DATA_DIR=/data GCM_HOST=0.0.0.0 GCM_PORT=8080
VOLUME ["/data"]
EXPOSE 8080
CMD ["gcmgamesync", "server"]
