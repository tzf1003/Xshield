# Container images for the three deployable roles (docs/19): edge, control, worker.
#
#   docker build --target edge    -t xshield-edge .
#   docker build --target control -t xshield-control .
#   docker build --target worker  -t xshield-worker .
#
# Base images are pinned by digest (docs/19: no floating tags as a release input);
# the Rust version matches rust-toolchain.toml. Bump both together, and the digests
# with them (`curl -sI` the registry manifest, or `docker buildx imagetools inspect`).
#
# The images contain only the release binaries and the libraries they link; they run
# as an unprivileged user, take every setting from XSHIELD_* environment variables and
# mounted files (docs/19), and carry no configuration, key, or certificate. The console
# bundle is static files and is served separately.

FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl-dev pkg-config cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# `--locked`: the lockfile is the dependency record; a drifting build must fail.
RUN cargo build --release --locked \
    -p xshield-gateway -p xshield-control -p xshield-worker -p xshield-audit

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin xshield
USER 10001:10001

FROM runtime-base AS edge
COPY --from=builder /src/target/release/xshield-gateway /usr/local/bin/xshield-gateway
ENTRYPOINT ["/usr/local/bin/xshield-gateway"]

FROM runtime-base AS control
COPY --from=builder /src/target/release/xshield-control /usr/local/bin/xshield-control
ENTRYPOINT ["/usr/local/bin/xshield-control"]

# The worker package ships several binaries (publisher, outbox, audit seal, evidence
# retention, model evaluation); the default is the publisher and any other is chosen
# with `docker run --entrypoint`.
FROM runtime-base AS worker
COPY --from=builder /src/target/release/xshield-worker /usr/local/bin/xshield-worker
COPY --from=builder /src/target/release/xshield-outbox-worker /usr/local/bin/xshield-outbox-worker
COPY --from=builder /src/target/release/xshield-audit-seal /usr/local/bin/xshield-audit-seal
COPY --from=builder /src/target/release/xshield-evidence-retain /usr/local/bin/xshield-evidence-retain
COPY --from=builder /src/target/release/xshield-model-eval /usr/local/bin/xshield-model-eval
ENTRYPOINT ["/usr/local/bin/xshield-worker"]
