# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY migration/Cargo.toml migration/Cargo.toml
COPY src src
COPY migration/src migration/src

RUN cargo build --release -p password_manager

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/password_manager /usr/local/bin/password_manager

EXPOSE 3000

CMD ["password_manager"]
