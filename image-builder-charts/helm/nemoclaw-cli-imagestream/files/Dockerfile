ARG NODE_IMAGE=node:22-trixie-slim

FROM ${NODE_IMAGE} AS builder
ENV NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false
WORKDIR /opt/nemoclaw
COPY package.json package-lock.json ./
COPY nemoclaw/package.json nemoclaw/package-lock.json nemoclaw/tsconfig.json nemoclaw/tsconfig.shared.json ./nemoclaw/
RUN npm ci --ignore-scripts && cd nemoclaw && npm ci --ignore-scripts
COPY . .
ARG NEMOCLAW_VERSION
ARG SOURCE_REVISION
# The build context need not retain Git metadata, and package.json is not the release version.
RUN printf '%s\n' "$SOURCE_REVISION" | grep -Eq '^[0-9a-f]{40}$' \
    && printf '%s\n' "$NEMOCLAW_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
    && printf '%s\n' "$SOURCE_REVISION" > .source-revision \
    && printf '%s\n' "$NEMOCLAW_VERSION" > .version
RUN npm run build:cli

FROM ${NODE_IMAGE}
ARG MAX_OPENSHELL_VERSION=0.0.116
WORKDIR /opt/nemoclaw
COPY --from=builder /opt/nemoclaw/package.json /opt/nemoclaw/package-lock.json ./
COPY --from=builder /opt/nemoclaw/.version /opt/nemoclaw/.source-revision ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=builder /opt/nemoclaw/dist/ ./dist/
COPY --from=builder /opt/nemoclaw/bin/ ./bin/
COPY --from=builder /opt/nemoclaw/nemoclaw/dist/ ./nemoclaw/dist/
COPY --from=builder /opt/nemoclaw/agents/ ./agents/
COPY --from=builder /opt/nemoclaw/scripts/ ./scripts/
COPY --from=builder /opt/nemoclaw/nemoclaw-blueprint/ ./nemoclaw-blueprint/
COPY --from=builder /opt/nemoclaw/managed-inference/ ./managed-inference/
RUN sed -i "s/max_openshell_version: \"[^\"]*\"/max_openshell_version: \"${MAX_OPENSHELL_VERSION}\"/" ./nemoclaw-blueprint/blueprint.yaml \
    && grep -Fq "max_openshell_version: \"${MAX_OPENSHELL_VERSION}\"" ./nemoclaw-blueprint/blueprint.yaml
COPY --from=builder /opt/nemoclaw/schemas/ ./schemas/
COPY --from=builder /opt/nemoclaw/Dockerfile ./Dockerfile
COPY --from=builder /opt/nemoclaw/tsconfig.runtime-preloads.json ./tsconfig.runtime-preloads.json
ENTRYPOINT ["node", "/opt/nemoclaw/bin/nemoclaw.js"]
