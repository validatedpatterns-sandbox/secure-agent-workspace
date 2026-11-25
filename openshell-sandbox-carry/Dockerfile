# TEMPORARY CARRY: odh-openshell-sandbox v0.1.10-rhaiv.0 with one fix.
#
# On RHEL 9 kernels (5.14) the v0.1.10 sandbox's network broker panics on every
# connect: openshell-binary-identity calls rustix clock_ticks_per_second(),
# which reads the aux vector with prctl(PR_GET_AUXV) (Linux 6.4+) or
# /proc/self/auxv, and a nondumpable non-root process cannot read the latter.
# auxv-warmup.patch caches the aux vector at the top of main(), before the
# sandbox makes itself nondumpable. Everything else is the official image: the
# binary is rebuilt from the same downstream commit the way Konflux builds it
# (static, NSS pinned) and replaces /openshell-sandbox in that image.
#
# Drop this carry once a fixed odh-openshell-sandbox build is released.

ARG BASE_IMAGE=quay.io/opendatahub/odh-openshell-sandbox@sha256:365d321345ea142a10d442f91bebeaf6d67dac4384b6dc29b4e72ada01a9b959

FROM registry.access.redhat.com/ubi9/ubi:9.8@sha256:25a147defd01e19674714f55d17538c8dbe55d8c305fa157ecc3f9c8977b05b6 AS builder
ARG OPENSHELL_URI=https://github.com/opendatahub-io/openshell.git
ARG OPENSHELL_COMMIT=c2775b8df05619cdd57cb354ea8cd829ec79ee40
ARG OPENSHELL_VERSION=0.1.10-rhaiv.0
ARG RUST_VERSION=1.95.0
RUN dnf install -y --nodocs --setopt=install_weak_deps=0 \
        gcc gcc-c++ make cmake glibc-static openssl-devel git-core xz binutils \
    && dnf clean all
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain "${RUST_VERSION}"
ENV PATH=/root/.cargo/bin:${PATH} CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
WORKDIR /build
RUN git init -q . \
    && git remote add origin "${OPENSHELL_URI}" \
    && git fetch -q --depth 1 origin "${OPENSHELL_COMMIT}" \
    && git checkout -q --detach FETCH_HEAD
COPY auxv-warmup.patch /tmp/auxv-warmup.patch
# Fails if the downstream source no longer matches the reviewed patch. Then
# remove .git so the version comes from OPENSHELL_VERSION, as in Konflux.
RUN git apply --check /tmp/auxv-warmup.patch \
    && git apply /tmp/auxv-warmup.patch \
    && rm -rf .git
RUN set -eu; \
    RUST_TARGET="$(uname -m)-unknown-linux-gnu"; \
    export OPENSHELL_GIT_VERSION="${OPENSHELL_VERSION#v}"; \
    gcc -O2 -fPIE -Wall -Wextra -c deploy/konflux/sandbox/pin-nss.c -o /build/pin-nss.o; \
    RUSTFLAGS="-C target-feature=+crt-static -C link-arg=/build/pin-nss.o -C link-arg=-Wl,--undefined=__nss_configure_lookup" \
        cargo build --locked --release --target "${RUST_TARGET}" \
        --package openshell-sandbox --bin openshell-sandbox; \
    install -D -m 0555 "target/${RUST_TARGET}/release/openshell-sandbox" /out/openshell-sandbox; \
    if readelf -l /out/openshell-sandbox | grep -q 'Requesting program interpreter'; then \
        echo "openshell-sandbox is not statically linked" >&2; exit 1; fi; \
    grep -qa 'failed to pin NSS database' /out/openshell-sandbox \
        || { echo "openshell-sandbox is missing the NSS pin" >&2; exit 1; }

FROM ${BASE_IMAGE}
COPY --from=builder --chmod=0555 /out/openshell-sandbox /openshell-sandbox
LABEL io.openshell.saw.carry="auxv-warmup" \
      io.openshell.saw.carry.base="odh-openshell-sandbox v0.1.10-rhaiv.0" \
      io.openshell.saw.carry.source="opendatahub-io/openshell c2775b8df05619cdd57cb354ea8cd829ec79ee40"
