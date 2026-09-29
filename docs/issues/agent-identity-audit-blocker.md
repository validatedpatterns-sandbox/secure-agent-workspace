# Dependency blocker: pinned OpenShell token-grant audit lacks identity claims

SAW requires proxy/gateway audit events to identify the sandbox through the
injected token's `azp`/`client_id`, correlated with the request and grant outcome,
without logging the bearer token. The current dependency cannot meet this
acceptance criterion through configuration alone.

## Verified dependency

- Supervisor: `quay.io/opendatahub/odh-openshell-supervisor@sha256:6c56ca2495ee10a77773b154cefd7309ebcab071962ea069ac349a3d9ec8c55a`
- Image label `git.commit`: `243a410b48a9760e7c90abe98a4b1b67414bc1d6`
- Source: https://github.com/opendatahub-io/openshell/blob/243a410b48a9760e7c90abe98a4b1b67414bc1d6/crates/openshell-supervisor-network/src/l7/token_grant_injection.rs#L101-L157

The success branch obtains the access token as a string, injects it, then builds
an OCSF HTTP event with request/destination information and a message naming the
provider. It does not extract or attach `azp` or `client_id`. The failure branch
similarly reports the provider and destination. This is a source-level finding,
not a claim that an end-to-end grant test has passed.

## Reproduction

1. Run `oc image info` against the digest above and inspect `git.commit`.
2. Inspect `inject_if_needed` at the linked immutable revision.
3. Trace the success event: the token is passed to header injection, not to an
   identity-claim field in the audit builder.

## Required dependency work

Add supported structured identity metadata and correlation to grant/injection
audit events. Define behavior for opaque access tokens rather than assuming all
tokens are JWTs. Do not treat unverified decoded claims as authenticated identity,
and never emit raw subject, intermediate, or access tokens.

Acceptance: exercise both grant types; assert sandbox identity and request
correlation in proxy audit output, including cache hits and refreshes; assert no
token values leak. Publish the capability in a supported Red Hat build.

This SAW task is constrained to current builds. Do not patch or replace the
supervisor here, use protected-service logs as a substitute, or mark the full
agent-identity ticket complete while this dependency remains unresolved.
