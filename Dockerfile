# syntax=docker/dockerfile:1
# Base images are pinned by digest (the tag is for people); Dependabot proposes updates.
FROM rust:1.96-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p pvlt-server && \
    cp target/release/pvlt /pvlt

# The default feature set only: no dev-insecure.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /pvlt /usr/local/bin/pvlt
USER nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/pvlt"]
CMD ["serve"]
