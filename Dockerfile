FROM rust:1.95-bookworm AS build

ARG TARGETARCH
RUN test "$TARGETARCH" = amd64 \
    && apt-get update \
    && apt-get install -y --no-install-recommends clang libclang-dev libopencore-amrnb-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
RUN cargo build --locked --release --target x86_64-unknown-linux-gnu \
    && install -Dm755 /usr/lib/x86_64-linux-gnu/libopencore-amrnb.so.0 /out/libopencore-amrnb.so.0

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /app/target/x86_64-unknown-linux-gnu/release/jiofiber-sip-proxy /usr/local/bin/jiofiber-sip-proxy
COPY --from=build /out/libopencore-amrnb.so.0 /usr/lib/x86_64-linux-gnu/libopencore-amrnb.so.0
COPY --from=build /usr/share/doc/libopencore-amrnb0/copyright /usr/share/doc/libopencore-amrnb0/copyright
EXPOSE 5061/udp 52000/udp
ENTRYPOINT ["/usr/local/bin/jiofiber-sip-proxy"]
