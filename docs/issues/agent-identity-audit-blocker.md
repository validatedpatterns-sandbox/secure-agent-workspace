# Dependency blocker: pinned OpenShell token-grant audit lacks identity claims

SAW requires proxy/gateway audit events to identify the sandbox through the
injected token's `azp`/`client_id`, correlated with the request and grant outcome,
without logging the bearer token. The current dependency cannot meet this
acceptance criterion through configuration alone.

## Verified dependency used for the live TCP evidence

- Supervisor: `quay.io/opendatahub/odh-openshell-supervisor@sha256:6c56ca2495ee10a77773b154cefd7309ebcab071962ea069ac349a3d9ec8c55a`
- Image label `git.commit`: `243a410b48a9760e7c90abe98a4b1b67414bc1d6`
- Source: https://github.com/NVIDIA/OpenShell/blob/243a410b48a9760e7c90abe98a4b1b67414bc1d6/crates/openshell-supervisor-network/src/l7/token_grant_injection.rs#L101-L157
- Token grant and cache: https://github.com/NVIDIA/OpenShell/blob/243a410b48a9760e7c90abe98a4b1b67414bc1d6/crates/openshell-supervisor-network/src/token_grant.rs#L148-L281

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

### Proposed identity provenance and acceptance checks

On a cache miss, the supervisor obtains the sandbox JWT-SVID for the grant.
The SPIFFE subject from that trusted Workload API response can identify the
sandbox requesting it. The pinned implementation's cache-hit path returns
*before* the SVID fetch, and its cache holds only the access token and expiry.
The dependency change must therefore either cache the subject with the token
and return both on hits, or deliberately fetch and attest again on every
request. The former preserves current cache behavior, provided cache entries
remain scoped to the sandbox and provider revision.

A failed grant also needs structured identity context: returning the subject
only with a successful access token cannot populate the failure event. Carry
the subject through errors that happen after a valid SVID fetch. If the SVID
fetch itself fails, record an explicit identity-unavailable result rather than
guessing the caller identity.

The sandbox SVID subject is **not** proof of the injected access token's
`azp` or `client_id`. For a JWT access token, those fields are authenticated
only after validating the issuer signature and relevant issuer, audience, and
expiry claims. For an opaque token, they require a trusted issuer response or
introspection; otherwise omit them or mark them unverified. The Jira request
specifically calls for the injected token's `azp`/`client_id`, so the proposed
SVID-subject field alone does not close that narrower claim requirement.

Tests should correlate one request across grant outcome and injection events,
and cover client credentials, token exchange, cache hits, refreshes, failures
after a valid SVID, and failure to fetch an SVID. Assert that no bearer token,
client assertion, intermediate token, or subject token appears in emitted
events. Live acceptance requires the supported build and actual proxy output;
this design note is not acceptance evidence.

This SAW task is constrained to current builds. Do not patch or replace the
supervisor here, use protected-service logs as a substitute, or mark the full
agent-identity ticket complete while this dependency remains unresolved.

The 2026-10-05 merge from `main` pins OpenShell `0.1.2-rhaiv.0`:
`quay.io/opendatahub/odh-openshell-supervisor@sha256:0179eb17dcc0098d3fce360035c0be0c26a39949ce09a397c7c259bf728170ff`.
The matching public source is
https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor-network/src/l7/token_grant_injection.rs.
Tag `v0.1.2` still emits the same success and failure events: provider name,
destination, and outcome, with no sandbox SPIFFE ID and no `azp` or
`client_id`. `obtain_provider_token` still returns only `Result<String>`, and
the cache-hit path returns that string before another SVID fetch.
`v0.1.3-pre.3` and `main`, checked the same day, do not add those fields
either. This source recheck does not replace live proxy output. The blocker
remains open. [NVIDIA/OpenShell #4233](https://github.com/NVIDIA/OpenShell/issues/4233)
was opened on 2026-10-06 to request structured, request-correlated identity
and outcome in token-grant audit events. No supported build with that capability
has been validated.
