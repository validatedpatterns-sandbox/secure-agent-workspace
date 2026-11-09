# Credential proxy security audit

Audit date: 2026-11-09. Branch: `proxy-check`. Target: `cluster-clkq2`.
Requested model: `nvidia/nemotron-3.5-lightning-30b-a3b` (already selected by
the data-science profile). This is a working evidence record; pending live
checks and human sign-off are **not passes**.

## Scope and evidence rules

Reference: [NVIDIA Security and Governance Model](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html),
read in full, version dated 2026-10-21. The saved [execution plan](credential-proxy-audit-plan.md)
is authoritative except that the user selected the existing `proxy-check`
branch and current cluster login, approved always-on proxy ingress policy and
pod-local health, and confirmed the existing NVIDIA key file is disposable. Later user instructions
authorized automated login and UI checks, selected an upstream PR from the fork,
and explicitly declined provider-side revocation and the old-key rejection test.

Only synthetic keys are used in local adversarial tests. Live provider values
are compared locally using digests; they are never supplied to the guest scan.
Raw outputs stay in a private scratch directory outside Git. The report and
[checkpoint evidence](credential-proxy-evidence.json) contain redacted observations. Evidence timestamps below are UTC checkpoint times, not
claims of exact request times.

**Assurance limit:** these tests verify specific implementations and attack
cases, not the absence of every defect. No formal model or machine-checked proof
of arbitrary credential non-disclosure has been produced. Byte-pattern response
filtering cannot prove safety against arbitrary encodings, partial disclosures,
or a malicious authorized provider. Process/disk scans are moving snapshots;
unreadable or truncated sources make an absence claim inconclusive. Guest-root
attacks do not justify trusting answers supplied by a compromised guest kernel.

## Penetration tests and regression evidence

`make test-credential-proxy` runs vet and all Go tests with the race detector.
The same suite runs in the Credential proxy GitHub workflow. Final local vet and race tests passed for every Go package on 2026-11-09. Offline shell
checks run through the installer workflow's existing pytest wrappers.

| ID | Method / command | Expected | Actual / status |
|---|---|---|---|
| A01 | `TestDeniedCONNECTNeverResolvesOrDials` | Unknown DNS host, literal metadata/loopback IP and wrong port return 403 without DNS/dial | Local regression passed; live VM-root unknown-host and metadata probes returned 403 |
| A02 | `TestCredentialReflectionFailsClosed` | No synthetic key digest in body, headers, status or trailers | Baseline failed for body/header/trailer/query/base64/error; fixed implementation blocks reflection and removes trailers |
| A03 | `TestStreamNeverReleasesSplitCredential` | Split key never released at any read boundary | Guard checks every split; later violations terminate the stream |
| A04 | A02 compressed / upgrade / informational cases | No uninspected response channel | Compression and 101 rejected; 1xx suppressed |
| A05 | `TestHostMismatchAndSNIRefused`, `TestForwardedHeadersAreRemoved` | Forged authority refused; forwarded metadata absent upstream | Baseline forwarded-header test failed; fixed path strips both standard and arbitrary `X-Forwarded-*` headers |
| A06 | `TestRejectsNonPublicAndClusterAnswersBeforeDial`, `TestPinsPublicAnswerWithoutSecondLookup`, `TestBothPathsRejectPrivateDNSBeforeDial` | No private/link-local/cluster dial or DNS rebinding between validation and connection | IP checks shared by intercepted and spliced traffic; mixed DNS answers rejected |
| A07 | `TestTransportErrorDoesNotLogCredentialPath` | Sanitized 502, no key in output/logs | Baseline transport-error test passed; request paths are now omitted entirely |
| B01 | Built binary test plus `TestHealthCannotBindOutsidePodLoopback` | Health loopback only; debug/metrics/expvar absent | Live fixed image: healthcheck exit 0; /proc/net/tcp binds 8081 to 127.0.0.1; Service exposes 3128 only; VM debug paths on 3128 return 405 |
| B02 | Chart assertions and deployment inspection | Non-root, read-only root, dropped caps, no mounted API token | Live fixed-image inspection passed: non-root, RuntimeDefault seccomp, read-only root, drop ALL, no privilege escalation or API token |
| C01 | Chart renders with `networkPolicy.enabled=false/true` | Same-namespace gateway-only ingress in both states | 181-test targeted suite passed; shell reports 4 passed, 0 failed |
| C02 | `tests/test-network-policy.sh` with audit-a/audit-b | Both proxy pod and Service deny peer ports 3128/8081 | Published-image OFF pod probe: peer 3128 and 8081 both reachable (finding confirmed). VM OFF confirms Service and pod access on both ports; ON blocks all four attempts. Final fixed-image suite: 44 passed, 0 failed |
| C03 | Keyless direct provider request from VM | TCP may connect; no provider key obtained | VM-root keyless direct POST reached NVIDIA and returned HTTP 400; this confirms transport reachability, not successful authentication |
| C04 | `TestCAIsShortLivedAndConstrained` plus self-signed upstream test | Narrow trust and rejected untrusted upstream TLS | Baseline public CA measured 3653 days, no name constraints; new-CA regression passes. Live replacement CA: 365-day validity, critical DNS constraints, all IP certificates excluded; guest fingerprint matches and proxy CA is absent from VM system roots |
| D01 | `tests/test-credential-isolation.sh` | Markers/public CA only in guest; no matching key digests | Sandbox UID 998, provider-key digest absent from its credential value, supervisor environ unreadable, separate network namespace; full VM scan running |
| D02 | `tests/installer/test_credential_modes.py` | Archive before key replacement; rotation warning persists until generation change | Live archive/restore verified by preserved canary and empty recovery ledger after automatic retry. No key-component matches in targeted workspace/gateway-state scans; whole-guest absence and provider invalidation unverified. Apply finalization pending |
| E01 | `TestRotationOnExistingTunnel` | Next request sees changed mounted key without VM/tunnel restart | Existing regression retained |
| E02 | OAuth broker tests and `TestGmailRefreshAndFailureIsolation` | Access lifetime ≤1h, early refresh 5min; sanitized failures | Shipped Gmail profile is 3600s/300s; synthetic issuer tests retained |
| E03 | Vault→ESO→projected-volume rotation measurement | Declared measured propagation time | Distinct-key rotation: ESO 17.33s; mounted key 74.54s; sandbox inference confirmed by 83.29s, VM unchanged. Provider revocation not run by user decision |

The guest-side `scripts/probe-credential-proxy.py` emits status codes and
compressed candidate digests only. The live credential-isolation wrapper compares
those response digests and captured proxy logs with each bound Secret locally.
It does not print captured response bodies, headers, or credential values.

## Findings and fixes

| Finding | Severity | Evidence and fix | Guard |
|---|---|---|---|
| H1: upstream credential reflection | High | Reproduced with a local TLS upstream before changes. Inspect status/headers/streamed body, retain split prefixes, strip trailers, reject compression/upgrades and sanitize error bodies | A02–A04 |
| H2: proxy ingress absent when VM segmentation is off | High | Baseline chart places the only proxy ingress control under an off-by-default Pattern switch. Proxy ingress now always renders; same-namespace podSelector prevents peer tenants | C01/C02; live pod probe confirms peer access with policy off; VM OFF confirms peer Service and pod access; ON refuses all four attempts |
| H3: unchecked DNS destinations | Medium | Original dialers passed hostnames directly to net.Dialer. Resolve, reject prohibited ranges, then connect to the checked IP; configure actual cluster CIDRs including public-addressed ranges | A06 |
| H4: unnecessary VM health surface | Low | Health had no debug handlers but listened on all interfaces, appeared in the Service and was allowed from the VM. Bind loopback, exec readiness and remove 8081 peers; installer checks ordinary CONNECT port | B01 plus migration preflight test |
| H5: broad, long-lived CA | Low | New roots last one year, have critical permitted DNS suffixes and no intermediate-CA authority; issuance verifies those constraints. The CA is not added to guest system roots | C04; existing roots need maintenance rotation |
| H7: forwarded metadata reaches upstream | Medium | Reproduced in integration test. ReverseProxy Rewrite removes forwarding headers without adding client IP | A05 |
| H11: scan skipped process state and block devices | Validation gap | Add process environ/cmdline, readable memory maps and read-only block scans, with explicit byte/source/unreadable/truncation counts. Live execution exposed quadratic trailing-token matching on long ASCII runs; replace with linear suffix handling. The old matcher exceeded 3s on 64 KiB; the guarded 1 MiB regression passes | Guest scanner unit tests and D01 |

H6 is a documentation boundary: EgressFirewall permits keyless direct provider
connections namespace-wide; it does not force all traffic through the proxy.
H8 is an administrative trust dependency: the Secret's HTTPS URL can extend the
bound host set; Vault/portal writers and namespace secret writers remain trusted.
The EgressFirewall and dial guard still apply. Guest-root access alone does not
grant permission to modify those cluster resources. Live SubjectAccessReviews deny Secret updates to the default/gateway/proxy service-account names.
Trusted Argo and operator-created pipeline principals retain namespace write access;
this is an administrative trust boundary. H9 transport errors were sanitized in baseline tests; paths are now
omitted to avoid unsafe redaction assumptions. H10 is an operator acknowledgement,
not enforced provider revocation; the documentation explicitly retains this limit.

## NVIDIA gap analysis

These verdicts distinguish configured mechanisms from deployed qualification.
Existing enterprise integration gaps are not newly verified proxy exploits.

| Phase II attribute / Table 6 contract | Evidence | Verdict and limit |
|---|---|---|
| Kernel containment for tools, hooks, skills and MCP | OpenShell policy configuration; UID, process-read and network-namespace observations | Partial: generated/child-process and complete tool-path enforcement not qualified |
| Deny-by-default platform and sandbox egress | C01/C02, EgressFirewall, sandbox unknown-host/metadata refusals | Partial: tested destinations refused; full VM segmentation is staged off by default; exhaustive policy-path coverage not established |
| Credential mediation / external custody | A01–A07, D01 | Partial qualification: external pod, digest tests and response guards; no formal non-disclosure proof; provider administration trusted |
| Routed inference | Requested model plus sandbox/GUI inference | Live sandbox request returned HTTP 200 with choices; owner-protected CUDA GUI returned OK using the requested model |
| Filesystem and process controls | Governance policies; D01 | Partial: guest-root defeats in-guest enforcement; immutable configuration-path coverage not qualified here |
| Signed policy / controlled releases | Optional APF, digest image pins | Partial: default interceptor policy is unsigned; APF anti-rollback counter is not durable across restart |
| OCSF audit / Table 6 common audit | Redacted proxy request/event logs | Gap: no unified versioned OCSF normalization, SIEM correlation or validated loss detection |
| Incident runbook | Credential isolation rotation/recovery procedures | Partial: credential steps documented; complete measured quarantine/session/downstream-revocation drill pending |
| Runtime/connector/policy rollback | GitOps and pinned images | Partial: operational rollback and retained-state behavior require qualification |
| Identity/delegation | OIDC owner binding and tool approvals | Partial: per-process agent/task authority, child narrowing, replay and pending/cached authority revocation not established by this proxy |
| Prompt-injection validation | No saved composed-input benchmark in this audit | Gap: model/application qualification, benign controls and cost/completion metrics not executed |
| Enforcement validation | Local adversarial suite; live request/tenant/UI/rotation-delivery checks; full scan/transition pending | Partial: precise tested properties only; no policy-prover or unsupported-protocol pass claimed |

| Table 7 compromise level | Residual trusted boundary | Verdict |
|---|---|---|
| Agent behavior / prompt injection | External proxy and platform firewall; tool review when configured | Partial: raw-key custody tests do not prove authorized tool decisions |
| Unprivileged process exploit | Sandbox kernel/process scoping plus external credential pod | Observed UID 998; no provider-key digest in child credential; supervisor environ refused; separate VM/sandbox network namespaces. Full kernel/tool coverage remains partial |
| Guest root / kernel compromise | Cluster-administered proxy, namespace policy and platform telemetry | Partial: root may exercise bound credentials; guest scans cannot prove a hostile kernel's honesty |
| Hypervisor / control plane | Declared platform trusted computing base | Node, hypervisor and control-plane administrators can access projected Secrets or proxy memory and remain trusted. No confidential-workspace or independent watchdog qualification claimed |

Operational-response qualification remains pending for separate quarantine,
process termination, broker-session termination, SSO revocation, downstream
authority revocation and image refresh. A stopped process cannot recall an
already accepted upstream operation. Neither the ESO interval nor a generation
counter is a measured revocation bound.

## Network isolation and debug lockdown

Baseline deployment uses published proxy image and VM NetworkPolicy OFF, as
shipped by Option A. The audit must preserve that observation separately from
the fixed always-on proxy ingress policy. Published-image OFF pod probe from `saw-audit-a` reached `audit-b` proxy ports
3128 and 8081, confirming H2. VM-root OFF probes also reached both peer Service/pod ports. With the published
image and VM segmentation ON, all four peer attempts were refused. The final
fixed-image NetworkPolicy suite passed all 44 checks, including both directions
and both proxy Service/pod ports. With full VM segmentation off on the migration target, a tokenless pod in an
unrestricted source namespace could reach neither peer Service nor pod on 3128.
A same-namespace gateway-labelled positive control reached both on 3128. Port
8081 was unreachable in both controls. The target had only the independent
`saw-credential-proxy` NetworkPolicy; eight socket assertions passed.
Both proxy pod IPs and Service IPs on 3128/8081 are covered by the live script.
Health/debug surface results are recorded under B01.

## Direct-to-proxy transition evidence

Local installer tests exercise volume archiving before provider replacement and
the root-owned exposed-credential state. `rotationRequired` remains until the
operator increments `credentialProxy.keyGeneration`; the counter does not call
the provider or verify revocation. The live throwaway user booted in proxy mode with full provider Secrets detached.
Its state records a direct-to-proxy transition at generation 1, with both inference
and web-search rotation warnings retained. The first CUDA archive upload failed;
the recovery record and archive were retained, and an automatic retry restored
the original `audit-preserve-20261109` canary. The recovery ledger is empty.
Targeted key-blind scans of restored workspace volumes, mounted metadata,
installer state and gateway configuration/state captured no matching old or
replacement key components. These are not whole-guest or raw-disk absence proofs;
two channel entries were unreadable in the workspace scan. Provider-side revocation was explicitly declined by
the user; old-key invalidation is therefore unverified and both provider keys
remain active. The generation stays 1 and the rotation warning must remain. Archiving/deleting
a guest filesystem entry does not prove its previous raw disk blocks were erased.

## Execution checkpoints and completion gates

Published baseline branch push: `eab47bc`. `make ssh-key-generate` preserved the
existing key; `make images-mirror` succeeded. Option A installation completed
against `cluster-clkq2`; `make prereqs-check` was intentionally skipped.

- Local lint: passed (82 Make-interface tests included).
- Initial targeted chart/script/scan suite: 181 passed.
- Final binary/scan/migration suite: 46 passed.
- OIDC templates: 50 passed, 0 failed.
- Tool gate: 10 passed.
- Offline NetworkPolicy: 4 passed, 0 failed.
- Final proxy vet/race suite: passed. Final chart/shell-wrapper suite: 173 passed.
- Complete local pytest: 1,980 passed, three skipped, one checkout-dependent prerequisite fixture failed.
  The fixture now uses its own topology; all 82 Make-interface tests pass afterward.
- Live EgressFirewall: 13 passed, zero failed. Final NetworkPolicy: 44 passed,
  zero failed. Independent proxy ingress with full VM segmentation off: eight assertions passed.
- The fixed proxy has been built, selected by digest, and deployed for live post-fix
  testing. The shipped upstream pin does not automatically include source edits;
  use a branch-specific audit override and follow the documented image release
  process before shipping the default image.
- Normal PKCE account and gateway sign-in completed under the user’s explicit authorization.
  Automated TUI/GUI checks were subsequently authorized. The user declined provider-key
  revocation and will arrange team-lead review personally; no sign-off is inferred.
- Resumed scanner/TUI regression suite: 93 passed; static lint passed.
- CUDA GUI: normal owner sign-in as audit-a and an OK inference response verified.
  The authorized automated README checks exposed a NemoClaw TUI login omission;
  both TUI modes now use the existing password-aware launch path, with regression coverage.
- Both explicit TUI entry points connected; the default TUI returned `OK`.
  CUDA and notebook SSO GUIs returned `OK`. All GUI Make entry points selected
  the corresponding owner-authenticated route. Final README status, VM SSH and
  both sandbox-list commands completed successfully.
- Upstream draft PR: [#155](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/pull/155),
  from `mtalvi:proxy-check` to upstream `main`, with these documents included.
  Go tests, deployment validation, both architecture builds and the installer Python 3.12/3.14 matrix passed at commit `12d9ff7`. The new GUI test inherited CI's
  `SAW_NS=saw-`; its fixture now clears that override and all three cases pass.
  All PR checks pass at `533c2d3`: both Python versions, Go vet/race, both image
  architectures, deployment validation, shared checks, image pin and bundle drift.
- The manual Pattern E2E workflow was not run: its repository configuration targets
  `cluster-df9qg`, rather than the authorized `cluster-clkq2`. This is an outstanding
  workflow qualification gate; the live checks above ran directly on `cluster-clkq2`.

## Sign-off

Team-lead review of `docs/architecture-alignment.md` and
`docs/credential-isolation.md`: **pending**. No reviewer identity, approval or
provider-key revocation is inferred or fabricated. The user declined the revocation
test, so this audit does not claim that old direct-mode credentials are invalid.

## Fresh-cluster compatibility finding

The live owner resolver minted a token with `view-users` but received HTTP 401
from Keycloak Admin REST. The [Keycloak 26.8.2 upgrade guide](https://www.keycloak.org/docs/26.8.2/upgrading/)
requires the built-in `kc-admin-api` client scope for service clients that call
that API. The user explicitly approved adding this scope to the resolver and
redirect registrar, retaining their existing roles and the audience check.
Both bootstrap scripts now reconcile the scope when that built-in scope exists;
older versions without it retain their existing configuration. Targeted resolver
and registrar tests passed (38 tests). This is a deployment compatibility fix,
not evidence of raw provider-key disclosure.

Fixed audit image (amd64 cluster build):
`image-registry.openshift-image-registry.svc:5000/openshell-agents/saw-credential-proxy-audit@sha256:f4501425dc8b537b3a046fb8a308ec72c7560a5e85da76b86b3887e0d9d8d341`.
The branch override selects this image for live qualification. It is not a
published upstream multi-architecture release.
The new exec readiness probe requires the matching binary. Publish and pin the
matching multi-architecture image before deploying with chart defaults. The
audit-only users, internal image override and cluster topology in
`overrides/saw-users.yaml` must also be removed before upstream merge.

## Additional deployment-validation fixes

The README checks confirmed two launch-path failures: the NemoClaw TUI omitted
the local gateway password used in trusted-proxy mode, and the GUI made an SSH
forward without the owner identity headers required by that mode. Both TUI entry
points now use the existing password-aware launch. Trusted-proxy GUI entry points
select exactly one matching workspace/sandbox SSO Route; token mode retains its
process-owned forward. Neither change widens the gateway's authentication rules.
Both explicit TUIs reached `gateway connected | idle`; both owner-protected GUIs
returned `OK` using the requested model. The default entry points are also exercised.

The migration restart initially lacked guest-agent readiness. The VGA console
retained a UEFI image; serial logs later confirmed Fedora startup, so that image
alone did not establish a pre-OS failure. The chart now gives only `rootdisk`
explicit boot order 1 to remove ambiguity among its system/input disks; four
render cases cover direct/proxy and ISO/live inputs. The guest is now booted in
proxy mode with the direct-to-proxy transition and rotation warnings recorded;
archive/restore completed, while final apply status remains in progress.

The observed 74.54-second secret delivery time is one measurement, not an SLA or
a provider revocation bound. Both NVIDIA keys remain active by user decision. The local `~/.nvidia-api-key`
now matches the first-line replacement used by Vault; `.env` is unchanged and
its second line retains the old key.
