FROM rust:1.82-bookworm AS builder

WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 65532 -g 65532 -m 0750 /run/towel-session
COPY --from=builder /source/target/release/twl /usr/local/bin/twl

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/twl"]
