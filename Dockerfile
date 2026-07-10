# Multi-stage build: compile with the Rust toolchain, ship a slim runtime.
FROM rust:1-bookworm AS build
WORKDIR /src
# Cache dependencies separately from source for faster rebuilds.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release || true
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd --system --no-create-home warden
COPY --from=build /src/target/release/warden /usr/local/bin/warden
USER warden
# Default: print help. Override with a full `proxy ...` command or a config file.
#   docker run --rm -v $PWD:/cfg warden proxy --config /cfg/warden.toml
ENTRYPOINT ["warden"]
CMD ["help"]
