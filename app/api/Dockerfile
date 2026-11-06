FROM rust:1-bookworm AS build
WORKDIR /app
COPY apps/api/Cargo.toml ./Cargo.toml
COPY apps/api/migrations ./migrations
COPY apps/api/src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --shell /usr/sbin/nologin breakline
COPY --from=build /app/target/release/breakline-api /usr/local/bin/breakline-api
USER breakline
EXPOSE 8080
CMD ["breakline-api"]
