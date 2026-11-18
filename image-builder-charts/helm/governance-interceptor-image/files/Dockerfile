# OpenShell 0.1.x needs Rust 1.94 (rust-version in its Cargo.toml).
ARG BUILDER_IMAGE=rust:1.94-bookworm
ARG RUNTIME_IMAGE=debian-runtime

FROM ${BUILDER_IMAGE} AS builder

RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev git make cmake g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /build
ARG OPENSHELL_REF=v0.1.6
ARG OPENSHELL_URI=https://github.com/NVIDIA/OpenShell.git
ARG CONTEXT_DIR=examples/governance-interceptor
RUN git init . \
    && git remote add origin "${OPENSHELL_URI}" \
    && git fetch --depth 1 origin "${OPENSHELL_REF}" \
    && git checkout --detach FETCH_HEAD

WORKDIR /build/${CONTEXT_DIR}
# The SAW extension is ordinary Rust source. The reviewed patch connects it
# through the governance API and retains the annotation-order workaround for NVIDIA/OpenShell#3929.
# A different upstream source must satisfy the patch exactly before compilation.
COPY saw-extension/driver_config.rs src/saw_driver_config.rs
COPY saw-extension/integration.patch /tmp/saw-integration.patch
RUN git -C /build apply --check --directory="${CONTEXT_DIR}" /tmp/saw-integration.patch \
    && git -C /build apply --directory="${CONTEXT_DIR}" /tmp/saw-integration.patch
RUN cargo test --locked --release --target-dir /out agent_driver_tests \
    && cargo build --locked --release --target-dir /out

FROM debian:bookworm-slim AS debian-runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

FROM ${RUNTIME_IMAGE}
COPY --from=builder /out/release/governance-interceptor /usr/local/bin/governance-interceptor
ENTRYPOINT ["governance-interceptor"]
