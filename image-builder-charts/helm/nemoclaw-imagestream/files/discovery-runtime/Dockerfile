ARG NODE_VERSION=24.19.0
ARG NODE_DIGEST=sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df
FROM docker.io/library/node:${NODE_VERSION}-bookworm-slim@${NODE_DIGEST} AS builder
WORKDIR /runtime
COPY tools/mcp-tool-discovery-runtime/package*.json tools/mcp-tool-discovery-runtime/*.ts tools/mcp-tool-discovery-runtime/tsconfig.json tools/mcp-tool-discovery-runtime/install-reviewed-runtime.sh ./
ENV NEMOCLAW_MCP_REVIEWED_ARTIFACT=1 \
    NEMOCLAW_MCP_BUNDLE_FILENAME=mcp-tool-discovery.bundle \
    NEMOCLAW_MCP_BUNDLE_OUTPUT_DIR=/reviewed-runtime-bundle/mcp-tool-discovery
RUN sh install-reviewed-runtime.sh

FROM scratch
COPY --from=builder /reviewed-runtime-bundle/ /reviewed-runtime-bundle/
