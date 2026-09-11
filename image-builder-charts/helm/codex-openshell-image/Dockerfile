FROM registry.access.redhat.com/ubi9/ubi-minimal:latest AS tools

RUN microdnf install -y --setopt=install_weak_deps=0 \
        python3 \
        iproute \
        nftables \
        util-linux \
    && microdnf clean all

FROM quay.io/aipcc/base-images/agentic/codex:latest

USER 0

COPY --from=tools /usr/bin/curl /usr/bin/curl
COPY --from=tools /usr/bin/python3 /usr/bin/python3
COPY --from=tools /usr/bin/nsenter /usr/bin/nsenter
COPY --from=tools /usr/sbin/ip /usr/sbin/ip
COPY --from=tools /usr/sbin/nft /usr/sbin/nft

# Python shared libraries
COPY --from=tools /usr/lib64/libpython3.9.so* /usr/lib64/
COPY --from=tools /usr/lib64/python3.9/ /usr/lib64/python3.9/

# Curl shared libraries
COPY --from=tools /usr/lib64/libcurl.so* /usr/lib64/

# bwrap no-op stub (OpenShell provides sandboxing)
RUN printf '#!/bin/sh\n\
while [ $# -gt 0 ]; do\n\
  case "$1" in\n\
    --) shift; break ;;\n\
    --bind|--ro-bind|--dev-bind|--tmpfs|--proc|--dev|--dir|--symlink|--remount-ro|--setenv|--chdir) shift 2 ;;\n\
    --file|--lock-file) shift 2 ;;\n\
    -*) shift ;;\n\
    *) break ;;\n\
  esac\n\
done\n\
exec "$@"\n' > /usr/local/bin/bwrap && chmod +x /usr/local/bin/bwrap

USER 1001
