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
pod-local health, and confirmed the existing NVIDIA key file is disposable.

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
| A01 | `TestDeniedCONNECTNeverResolvesOrDials` | Unknown DNS host, literal metadata/loopback IP and wrong port return 403 without DNS/dial | Added regression; final run recorded below |
| A02 | `TestCredentialReflectionFailsClosed` | No synthetic key digest in body, headers, status or trailers | Baseline failed for body/header/trailer/query/base64/error; fixed implementation blocks reflection and removes trailers |
| A03 | `TestStreamNeverReleasesSplitCredential` | Split key never released at any read boundary | Guard checks every split; later violations terminate the stream |
| A04 | A02 compressed / upgrade / informational cases | No uninspected response channel | Compression and 101 rejected; 1xx suppressed |
| A05 | `TestHostMismatchAndSNIRefused`, `TestForwardedHeadersAreRemoved` | Forged authority refused; forwarded metadata absent upstream | Baseline forwarded-header test failed; fixed path strips both standard and arbitrary `X-Forwarded-*` headers |
| A06 | `TestRejectsNonPublicAndClusterAnswersBeforeDial`, `TestPinsPublicAnswerWithoutSecondLookup`, `TestBothPathsRejectPrivateDNSBeforeDial` | No private/link-local/cluster dial or DNS rebinding between validation and connection | IP checks shared by intercepted and spliced traffic; mixed DNS answers rejected |
| A07 | `TestTransportErrorDoesNotLogCredentialPath` | Sanitized 502, no key in output/logs | Baseline transport-error test passed; request paths are now omitted entirely |
| B01 | Built binary test plus `TestHealthCannotBindOutsidePodLoopback` | Health loopback only; debug/metrics/expvar absent | Built binary and rejection tests added; Service exposes 3128 only |
| B02 | Chart assertions and deployment inspection | Non-root, read-only root, dropped caps, no mounted API token | Live fixed-image inspection passed: non-root, RuntimeDefault seccomp, read-only root, drop ALL, no privilege escalation or API token |
| C01 | Chart renders with `networkPolicy.enabled=false/true` | Same-namespace gateway-only ingress in both states | 181-test targeted suite passed; shell reports 4 passed, 0 failed |
| C02 | `tests/test-network-policy.sh` with audit-a/audit-b | Both proxy pod and Service deny peer ports 3128/8081 | Published-image OFF pod probe: peer 3128 and 8081 both reachable (finding confirmed). VM OFF confirms Service and pod access on both ports; ON blocks all four attempts. Post-fix checks pending |
| C03 | Keyless direct provider request from VM | TCP may connect; no provider key obtained | VM-root keyless direct POST reached NVIDIA and returned HTTP 400; this confirms transport reachability, not successful authentication |
| C04 | `TestCAIsShortLivedAndConstrained` plus self-signed upstream test | Narrow trust and rejected untrusted upstream TLS | Baseline public CA measured 3653 days, no name constraints; new-CA regression passes. Live replacement CA: 365-day validity, critical DNS constraints, all IP certificates excluded; guest trust reload pending |
| D01 | `tests/test-credential-isolation.sh` | Markers/public CA only in guest; no matching key digests | Extended filesystem/process/memory/block scan wired; live scan pending |
| D02 | `tests/installer/test_credential_modes.py` | Archive before key replacement; rotation warning persists until generation change | Existing behavior tested; live throwaway-user transition pending |
| E01 | `TestRotationOnExistingTunnel` | Next request sees changed mounted key without VM/tunnel restart | Existing regression retained |
| E02 | OAuth broker tests and `TestGmailRefreshAndFailureIsolation` | Access lifetime ≤1h, early refresh 5min; sanitized failures | Shipped Gmail profile is 3600s/300s; synthetic issuer tests retained |
| E03 | Vault→ESO→projected-volume rotation measurement | Declared measured propagation time | Pending; configured ESO refresh period alone is insufficient |

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
| H11: scan skipped process state and block devices | Validation gap | Add process environ/cmdline, readable memory maps and read-only block scans, with explicit byte/source/unreadable/truncation counts | Guest scanner unit tests and D01 |

H6 is a documentation boundary: EgressFirewall permits keyless direct provider
connections namespace-wide; it does not force all traffic through the proxy.
H8 is an administrative trust dependency: the Secret's HTTPS URL can extend the
bound host set; Vault/portal writers and namespace secret writers remain trusted.
The EgressFirewall and dial guard still apply. Guest-root access alone does not
grant permission to modify those cluster resources. Live RBAC review remains
pending. H9 transport errors were sanitized in baseline tests; paths are now
omitted to avoid unsafe redaction assumptions. H10 is an operator acknowledgement,
not enforced provider revocation; the documentation explicitly retains this limit.

## NVIDIA gap analysis

These verdicts distinguish configured mechanisms from deployed qualification.
Existing enterprise integration gaps are not newly verified proxy exploits.

| Phase II attribute / Table 6 contract | Evidence | Verdict and limit |
|---|---|---|
| Kernel containment for tools, hooks, skills and MCP | OpenShell policy configuration; D01 pending | Partial: deployed coverage and generated/child-process execution not yet qualified |
| Deny-by-default platform and sandbox egress | C01/C02 and EgressFirewall | Partial: external firewall configured; Pattern stages VM-wide segmentation off; sandbox enforcement requires live exercise |
| Credential mediation / external custody | A01–A07, D01 | Partial qualification: external pod, digest tests and response guards; no formal non-disclosure proof; provider administration trusted |
| Routed inference | Requested model in profile; live inference pending | Partial: routing configuration exists, post-fix request not yet proven |
| Filesystem and process controls | Governance policies; D01 | Partial: guest-root defeats in-guest enforcement; immutable configuration-path coverage not qualified here |
| Signed policy / controlled releases | Optional APF, digest image pins | Partial: default interceptor policy is unsigned; APF anti-rollback counter is not durable across restart |
| OCSF audit / Table 6 common audit | Redacted proxy request/event logs | Gap: no unified versioned OCSF normalization, SIEM correlation or validated loss detection |
| Incident runbook | Credential isolation rotation/recovery procedures | Partial: credential steps documented; complete measured quarantine/session/downstream-revocation drill pending |
| Runtime/connector/policy rollback | GitOps and pinned images | Partial: operational rollback and retained-state behavior require qualification |
| Identity/delegation | OIDC owner binding and tool approvals | Partial: per-process agent/task authority, child narrowing, replay and pending/cached authority revocation not established by this proxy |
| Prompt-injection validation | No saved composed-input benchmark in this audit | Gap: model/application qualification, benign controls and cost/completion metrics not executed |
| Enforcement validation | Local adversarial suite; live A–E pending | Partial: precise tested properties only; no policy-prover or unsupported-protocol pass claimed |

| Table 7 compromise level | Residual trusted boundary | Verdict |
|---|---|---|
| Agent behavior / prompt injection | External proxy and platform firewall; tool review when configured | Partial: raw-key custody tests do not prove authorized tool decisions |
| Unprivileged process exploit | Sandbox kernel/process scoping plus external credential pod | Partial: live sandbox inspection pending |
| Guest root / kernel compromise | Cluster-administered proxy, namespace policy and platform telemetry | Partial: root may exercise bound credentials; guest scans cannot prove a hostile kernel's honesty |
| Hypervisor / control plane | Declared platform trusted computing base | Gap outside ordinary VM isolation; no confidential-workspace or independent watchdog qualification claimed |

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
image and VM segmentation ON, all four peer attempts were refused. Post-fix
checks remain pending; chart success is not a substitute.
Both proxy pod IPs and Service IPs on 3128/8081 are covered by the live script.
Health/debug surface results are recorded under B01.

## Direct-to-proxy transition proof

Local installer tests exercise volume archiving before provider replacement and
the root-owned exposed-credential state. `rotationRequired` remains until the
operator increments `credentialProxy.keyGeneration`; the counter does not call
the provider or verify revocation. A live throwaway-user transition, old-key
digest scan and provider-side revocation are still required. Archiving/deleting
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
- Live EgressFirewall: 13 passed, zero failed. Further post-fix guest checks remain pending.
- The fixed proxy has been built, selected by digest, and deployed for live post-fix
  testing. The shipped upstream pin does not automatically include source edits;
  use a branch-specific audit override and follow the documented image release
  process before shipping the default image.
- Normal PKCE account and gateway sign-in completed under the user’s explicit authorization.
  TUI/GUI, disposable provider-key revocation and team-lead sign-off remain human checkpoints.
- Upstream draft PR: [#155](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/pull/155),
  from `mtalvi:proxy-check` to upstream `main`, with these documents included.
  Go tests, deployment validation and both architecture builds passed in CI; installer matrix pending.

## Sign-off

Team-lead review of `docs/architecture-alignment.md` and
`docs/credential-isolation.md`: **pending**. No reviewer identity, approval or
provider-key revocation is inferred or fabricated.

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
