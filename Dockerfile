# syntax=docker/dockerfile:1

FROM rust:1.85 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends musl-tools musl-dev

WORKDIR /app
COPY . .

RUN rustup target add x86_64-unknown-linux-musl

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/certmgt-cli /cert-mgt
ENTRYPOINT ["/cert-mgt"]
