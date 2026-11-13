# Container images for the two deployable roles (docs/04 section 4.1): edge and control.
#
#   docker build --target edge    -t xshield-edge .
#   docker build --target control -t xshield-control .
#
# Base images are pinned by digest (no floating tags as a release input);
# the Rust version matches rust-toolchain.toml. Bump both together, and the digests
# with them (`curl -sI` the registry manifest, or `docker buildx imagetools inspect`).
#
# The images contain only the release binaries and the libraries they link; they run
# as an unprivileged user, take every setting from XSHIELD_* environment variables and
# mounted files (docs/03 section 3.3), and carry no configuration, key, or certificate. The control
# binary embeds the console (web/console/dist, docs/07 section 7.2.1), so the console is
# built in its own stage and handed to the Rust build before it compiles.

FROM node:22-bookworm-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da AS console-builder
WORKDIR /src/web/console
COPY web/console/package.json web/console/package-lock.json ./
# `npm ci` installs exactly the locked versions and fails when the lockfile drifts.
RUN npm ci
COPY web/console/ ./
RUN npm run build

FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl-dev pkg-config cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
COPY --from=console-builder /src/web/console/dist ./web/console/dist
# `--locked`: the lockfile is the dependency record; a drifting build must fail.
RUN cargo build --release --locked \
    -p xshield-edge -p xshield-control

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin xshield
USER 10001:10001

FROM runtime-base AS edge
COPY --from=builder /src/target/release/xshield-edge /usr/local/bin/xshield-edge
ENTRYPOINT ["/usr/local/bin/xshield-edge"]

FROM runtime-base AS control
COPY --from=builder /src/target/release/xshield-control /usr/local/bin/xshield-control
ENTRYPOINT ["/usr/local/bin/xshield-control"]

