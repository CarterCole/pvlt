# syntax=docker/dockerfile:1
FROM rust:1.96-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p pvlt-server && \
    cp target/release/pvlt /pvlt

# The default feature set only: no dev-insecure.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /pvlt /usr/local/bin/pvlt
USER nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/pvlt"]
CMD ["serve"]
