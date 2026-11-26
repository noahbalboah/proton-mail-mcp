# Static musl binary on an empty image: no shell, no package manager, no libc, nothing else.
FROM rust:1.96.1-alpine3.24@sha256:a41f7740f8b45d45795624eec13a8b42263cc700f19f7e4e86e04d3dda08a479 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
    && install -D -m 0555 target/release/proton-mail-mcp /out/proton-mail-mcp

FROM scratch
COPY --from=build /out/proton-mail-mcp /proton-mail-mcp
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/proton-mail-mcp"]
