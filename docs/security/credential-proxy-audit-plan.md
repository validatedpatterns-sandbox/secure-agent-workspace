## Execution decisions (user overrides)

The original plan below is preserved for traceability. The user selected the
existing `proxy-check` branch and cluster-clkq2, approved always-on proxy ingress
and pod-local health, authorized automated browser login and TUI/GUI checks,
and requested the PR from `mtalvi:proxy-check` to upstream `main`.
The user is handling team-lead review personally. They explicitly declined
provider-side NVIDIA key revocation and its rejection test; do not revoke either
key or treat invalidation as verified. The live delivery test switched Vault to
the first-line `.env` key. `keyGeneration` stays 1 while invalidation is unverified.
The user subsequently stopped the long full-disk scan after its measured rate
implied several hours. Record full guest qualification as incomplete; do not
restart that scan without a new request. The user also chose not to wait for
migration finalization; leave the installer running and record its final check
as pending.
The live audit configuration is preserved on fork branch
`codex/credential-proxy-audit-clkq2` at `9fa13c2`, while implementation and the
upstream PR remain on `proxy-check`. This allows the PR to restore the normal
empty `overrides/saw-users.yaml` without pruning the running audit VMs.

---

Plan: Security audit of saw-credential-proxy against the NVIDIA Security and Governance Model

 Context

 SAW runs OpenShell sandboxes inside per-user KubeVirt VMs. In proxy mode (credentialProxy.enabled: true, the default), provider keys stay in a per-namespace proxy pod (<user>-credential-proxy in saw-<user>). The VM receives only these:
 - nonsecret markers (saw-cred.<secret>.<key>)
 - <secret>-meta Secrets
 - the public saw-proxy-ca

 The Jira ticket asks for four things:
 1. Formal verification that no defect lets the guest or sandbox obtain raw credentials.
 2. A gap analysis against NVIDIA's Phase II Agent Runtime Controls and Table 7.
 3. Negative tests in CI.
 4. A proof of the direct-mode to proxy-mode transition, plus a doc review signed off by the team lead.

 User decisions:
 - Fix every confirmed finding in this ticket.
 - Commit the report in the repo under docs/ in the same PR.

 Environment:
 - A fresh cluster, deployed with README Option A (Validated Pattern).
 - Skip make prereqs-check.
 - NVIDIA model: nvidia/nemotron-3.5-lightning-30b-a3b.
 - The README Validating the deployment section must be executed.

 Authoritative reference. NVIDIA Security and Governance Model:
 [https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html)
 Read it in full before starting. A text copy may still be at /private/tmp/claude-501/-Users-mtalvi-secure-agent-workspace/bce1f2e3-33ae-461b-b486-bc101e2bf62f/scratchpad/nvidia-sgm.txt; re-download it if not. The parts that matter:
 - Table 6, Control Surface Contracts: the Credential mediation and Audit / revocation control rows.
 - Phase II Agent Runtime Controls:
   - deny-by-default egress
   - credential proxy and isolation
   - routed inference
   - OCSF audit
   - incident runbook
   - rollback
   - identity and delegation
   - enforcement validation
 - Table 7: the four compromise levels.
 - Operational responses: kill switch, application session and token revocation with a measured propagation bound, image refresh, SSO revocation, telemetry.

 Ground rules for the executing agent

 - Never print, log or commit a raw key. Compare by digest only, reusing the key-blind pattern in tests/test-credential-isolation.sh:131-158 and scripts/scan-guest-credentials.py (token_digests). Apply the same digest comparison to any captured HTTP response or log.
 - Use a dedicated, disposable NVIDIA key for the audit. Rotate it when the audit ends.
 - Human checkpoints (stop and ask mtalvi):
   - oc login, make login and gateway browser sign-in
   - interactive TUI and GUI checks
   - creating and revoking NVIDIA keys
   - team-lead sign-off
 - For each test, record the ID, command, expected result, actual result, PASS/FAIL and timestamp. Raw evidence stays in the scratchpad; only redacted results go into the report.

 Phase 0: Deploy with Option A

 1. git checkout -b security/credential-proxy-audit and push it to origin (MatanTalvi10/secure-agent-workspace). Then export TARGET_BRANCH=security/credential-proxy-audit TARGET_ORIGIN=origin.
 2. Follow README steps 2–6 (README.md:201-259):
    - oc login.
    - make ssh-key-generate.
    - Fill ~/values-secret.yaml: the inference entry gets provider: build and api_key from ~/.nvidia-api-key.
    - Confirm the model in charts/saw-bom/profiles/data-science/default/sandbox.yaml.
    - Keep web search on only if ~/.brave-api-key exists. Otherwise install with WEB_SEARCH_ENABLED=false.
    - make images-mirror, make check-oidc-ca, ./pattern.sh make install.
 3. Add two proxy-mode users, audit-a and audit-b, to overrides/saw-users.yaml. Push, then run make keycloak-add-users. Wait until both Argo CD apps are Synced/Healthy and make saw-logs shows apply: Done.
 4. Record the as-shipped network posture. Option A stages NetworkPolicy off (charts/saw-users/values.yaml:64). Run the Phase 3 §C tenant checks in this state first.
 5. Enable NetworkPolicy for both users:
    - Get the topology snippet with uv run --locked scripts/network-topology.py check-pattern (this replaces the full prereqs-check).
    - Paste it under defaults.openshellSaw.
    - Set values.networkPolicy.enabled: true per user, push and sync.
    - Procedure: docs/deployment-guide.md:316.

 Phase 1: Run "Validating the deployment" from the README

 Run every command in README.md:704-753, after make login, make saw-configure and openshell gateway login audit-a:
 - openshell sandbox list, with and without --workspace cuda-dev.
 - TUI and GUI targets (human).
 - make sandbox-ui, make saw-status, make saw-vm-ssh.
 - make lint, make test, make test-tool-gate, ./tests/test-oidc-templates.sh.
 - SKIP_LIVE=1 ./tests/test-network-policy.sh, then the live network test with audit-a and audit-b as the peer pair (REQUIRE_PEER=1).
 - Baselines:
   - make test-credential-isolation OPENSHELL_SAW_NAME=audit-a SAW_NS=saw-audit-a
   - tests/test-egress-firewall.sh
   - one sandbox inference request, reusing scripts/ci/pattern_e2e.py:1540-1552

 Phase 2: Review findings to confirm or refute

 Treat each item as a hypothesis until a test confirms it.

 #: H1
 Area to verify: Where credentials are injected: rewrite.Request substitutes in path, query and all headers.
 Upstream responses are returned unmodified (no ModifyResponse). Verify responses can never carry a credential
 value.
 Where: credential-proxy/internal/rewrite/rewrite.go, internal/proxy/proxy.go:148-219
 Ticket §: §1
 ────────────────────────────────────────
 #: H2
 Area to verify: Tenant boundary: the proxy has no client authentication. Its only ingress control is the
 saw-credential-proxy NetworkPolicy, which renders only when networkPolicy.enabled, and Option A defaults that to
 off.
 Where: charts/openshell-saw/templates/networkpolicy.yaml, credential-proxy.yaml
 Ticket §: §3
 ────────────────────────────────────────
 #: H3
 Area to verify: Dial-time destination checks: CONNECT refuses IP literals and non-443 ports, but the resolved
 upstream IP is not checked against loopback, link-local or cluster ranges.
 Where: proxy.go:52-66,122-127
 Ticket §: §1 SSRF
 ────────────────────────────────────────
 #: H4
 Area to verify: :8081/healthz listens on all interfaces. The Service exposes it, and the VM NetworkPolicy allows
 it. Confirm no pprof, expvar or metrics handlers exist, and decide whether the VM needs this port at all.
 Where: cmd/saw-credential-proxy/main.go, Service, NP
 Ticket §: §2
 ────────────────────────────────────────
 #: H5
 Area to verify: Proxy CA: 10-year life, no name constraints. Check where the VM trusts it (driver proxy_ca_bundle
 only, or the system trust store too).
 Where: internal/ca/ca.go, apply_bom.py ~3110
 Ticket §: §3 CA
 ────────────────────────────────────────
 #: H6
 Area to verify: The EgressFirewall is namespace-wide, so the VM can reach provider hosts directly without a key.
 The "all provider traffic is forced through the proxy" claim needs accurate wording.
 Where: templates/egressfirewall.yaml
 Ticket §: §3 egress
 ────────────────────────────────────────
 #: H7
 Area to verify: Forwarded headers: X-Forwarded-* passes through and the client IP is added.
 Where: proxy.go ReverseProxy
 Ticket §: §1
 ────────────────────────────────────────
 #: H8
 Area to verify: Custom url in a Secret extends the bound hosts. Check who can write it (Vault path, portal) and
 that the namespace EgressFirewall bounds it.
 Where: internal/config/config.go Snapshot
 Ticket §: §1
 ────────────────────────────────────────
 #: H9
 Area to verify: Log redaction: confirm on every error path, including transport errors when the key sits in the
 query.
 Where: proxy.go:174-187, oauth/broker.go
 Ticket §: §5
 ────────────────────────────────────────
 #: H10
 Area to verify: Rotation after direct mode is advisory: rotationRequired produces a WARN and nothing is enforced.
 keyGeneration is bumped by the operator.
 Where: apply_bom.py:6749-6814
 Ticket §: §4 B
 ────────────────────────────────────────
 #: H11
 Area to verify: Guest scan coverage: the guest scan skips /proc, /sys and /dev, but Table 7 State B needs environ,
 cmdline, process memory and raw disks.
 Where: scripts/scan-guest-credentials.py
 Ticket §: §4 B

 Phase 3: Live verification (baseline, published image)

 Run as VM root with SAW_NS=… VM_NAME=… scripts/openshell-saw-vm-ssh.sh "<cmd>", and in sandbox context with openshell sandbox exec -n notebook --no-tty -- …. Read proxy logs with oc logs deploy/<u>-credential-proxy -n saw-<u>.

 Universal pass criterion for every request-path test: the response body, the response headers and the proxy logs contain no digest match for any bound key (compare with the key-blind digest helper), and a disallowed request is refused with a sanitized 4xx/5xx.

 §A. Credential reflection, SSRF and error handling (ticket Scope 1)

 From the sandbox and from VM root, drive the proxy through its normal client path (https_proxy + the proxy CA) and confirm the boundary holds. Verify, capturing response + logs each time and checking for a digest match:
 - A request to a non-allowlisted host (an arbitrary external name, and 169.254.169.254) is refused before any upstream dial.
 - A request whose effect would be to reflect request data back (a header-echo style endpoint, or a marker placed in a path/response-visible field on a bound host) does not return a key digest.
 - Upstream failures — 4xx, 5xx, timeout, DNS failure, truncated TLS — return the proxy's sanitized body, not raw upstream content, and no Authorization value.
 - Manipulated Host / X-Forwarded-* headers do not change the bound destination; Host must still match SNI (proxy.go:192-199).
 - Confirm H3: resolve whether the upstream IP is checked. If a bound/allowlisted name resolves to loopback/link-local/cluster-internal, note whether the dial is still allowed.

 §B. Proxy process surface (ticket Scope 2)

 - From the VM, probe :8081 and :3128 for /debug/pprof, /metrics, /healthz, expvar. Expected: only /healthz on 8081, CONNECT-only on 3128; everything else refused. Confirm H4.
 - Confirm the proxy container keeps readOnlyRootFilesystem, dropped caps, non-root, automountServiceAccountToken: false (credential-proxy.yaml).
 - Confirm keys live only in the proxy's projected Secret volume and memory — not reachable from the VM.

 §C. Network and tenant isolation (ticket Scope 3) — run twice: NetworkPolicy OFF (as-shipped) and ON

 - Cross-tenant: from audit-a's VM, attempt to reach audit-b's proxy Service/pod on 3128/8081. Record OFF vs ON. This is the core of H2.
 - Egress lockdown: from the VM, attempt direct outbound to a provider host on 443 without the proxy. Document H6 — the EgressFirewall allows provider hostnames namespace-wide, so a keyless direct call may connect but cannot obtain the key.
 - CA validation: confirm the VM trusts saw-proxy-ca where it is wired, and that a self-signed cert for a provider host is rejected on the real request path (H5).

 §D. Table 7 states (ticket Scope 4)

 - State A — unprivileged sandbox: confirm the sandbox sees only placeholders/markers, has no host-network visibility, and cannot read the supervisor's markers.
 - State B — root in guest: from VM root, run an extended key-blind scan that covers what scripts/scan-guest-credentials.py currently skips — process environ/cmdline, in-memory process maps, and raw disk/block devices — in addition to the filesystem. Expected: only saw-cred.* markers and the public CA; no key digest anywhere. This drives fix H11.
 - Transition (Scope 4, third bullet + Acceptance "Direct-to-Proxy Transition Proof"): take a throwaway user from direct mode to proxy mode. Confirm the installer archives /sandbox, replaces real keys with markers, and reports rotationRequired until credentialProxy.keyGeneration is bumped (apply_bom.py:6749-6814). Record that rotation is operator-acknowledged, not enforced (H10). Prove previous VM secrets are invalidated: scan the VM after transition for the old key digest.

 §E. Logging and lifecycle (ticket Scope 5)

 - Confirm proxy stdout/stderr redact Authorization, token values and sensitive URI params on success and on every error path (H9).
 - Confirm Gmail/OAuth token lifetime: access tokens cached ≤ 1h, refreshed 5 min early (oauth/broker.go, charts/openshell-saw/files/provider-profiles/gmail.yaml:21-22).
 - Confirm a Vault/Secret rotation propagates without a VM restart — the proxy re-reads the projected key per request (config.go Snapshot; ESO refreshInterval: 15s). Measure the actual propagation delay for the NVIDIA "revocation within a measured bound" requirement.

 Phase 4: Fix every confirmed finding (user decision)

 Fix only what Phase 3 confirms. For each fix: add or extend a unit/integration test that fails before and passes after, keep CI green, and record the before/after evidence. Likely fixes, by area:

 - Response-side leakage (H1, if confirmed): add a ModifyResponse to the ReverseProxy in proxy.go that scans response status line, headers and (bounded) body for any bound key value and fails closed with a sanitized 502 + audit line. Unit test in internal/proxy/proxy_test.go.
 - Tenant boundary (H2): make the saw-credential-proxy NetworkPolicy independent of networkPolicy.enabled where feasible, or add proxy-side client authn (e.g. require a per-namespace credential on CONNECT), so an off-by-default policy is not the only control. Decide with mtalvi which layer. Add offline chart assertion in tests/charts/test_openshell_saw_network_policy.py and a live assertion in tests/test-network-policy.sh.
 - SSRF dial guard (H3): reject resolved upstream IPs in loopback/link-local/cluster CIDRs at dial time in proxy.go (splice and intercept dialers). Unit test with a custom DialUpstream.
 - Health/debug surface (H4): bind :8081 to the pod only, confirm no debug handlers are importable, and drop the VM NetworkPolicy allowance for 8081 if the VM does not need it.
 - CA hardening (H5): add name constraints / shorter life to the proxy CA if feasible without breaking issuance.
 - Guest scan coverage (H11): extend scripts/scan-guest-credentials.py to cover environ, cmdline, process memory and raw devices, and wire it into tests/test-credential-isolation.sh.
 - Doc accuracy (H6, H10): correct any overstated claim in docs/credential-isolation.md and docs/architecture-alignment.md (egress "forced through proxy"; rotation "enforced") to match actual behavior.

 If any finding is better split out, confirm with mtalvi before descoping — the default is fix-all.

 Phase 5: CI regression coverage (ticket Scope "Automated Regression Coverage" + Acceptance)

 Codify the negative scenarios so they run in CI:
 - Add adversarial cases to tests/test-credential-isolation.sh (ticket names this file): non-allowlisted target refused, tenant cross-talk blocked, response carries no key digest, spoofed Host/X-Forwarded-* ineffective, tag-only / empty proxy image refused (extend existing tests/charts/test_credential_proxy_bindings.py:52).
 - Add Go unit tests under credential-proxy/internal/** for each confirmed code fix; they run in the Credential proxy workflow (.github/workflows/credential-proxy.yml) via go test -race.
 - Add offline chart assertions to tests/charts/ (NetworkPolicy presence, no debug ports) — these run in installer-tests.yml via make test-installer.
 - Ensure the shell wrappers tests/scripts/test_network_policy_script.py and test_make_interface.py still pass so the new shell checks execute in CI.

 Phase 6: Report, gap analysis and sign-off (Acceptance criteria)

 Write the committed report to docs/security/credential-proxy-audit.md (user chose in-repo docs/). Structure:
 1. Penetration test report: every test ID, method, expected/actual, PASS/FAIL, redacted evidence — proving SSRF, arbitrary host forwarding, header reflection and error-dump attempts fail to expose raw credentials.
 2. NVIDIA gap analysis: a row per Phase II attribute and per Table 7 compromise level, each mapped to the test(s) that exercised it and a verdict (aligned / partial / gap). Reconcile against the existing table in docs/architecture-alignment.md §6 and update that file where the audit changes the status.
 3. Network isolation verification: NetworkPolicy OFF vs ON results.
 4. Debug-endpoint lockdown: results of §B.
 5. Direct-to-proxy transition proof: §D transition evidence.
 6. Findings and fixes: each confirmed finding, severity, the fix, and the CI test that now guards it. List any explicitly deferred item as a filed follow-up.
 7. Sign-off: record team-lead review of docs/architecture-alignment.md and docs/credential-isolation.md against observed cluster behavior (Acceptance: "signed off by the team lead").

 Deliverables / Definition of Done mapping

 - [ ] Penetration test report committed at docs/security/credential-proxy-audit.md (Phase 6).
 - [ ] Network isolation automated tests (Phase 5: tests/test-network-policy.sh, chart tests).
 - [ ] Debug-endpoint lockdown verified and, if needed, fixed (Phase 3 §B, Phase 4 H4).
 - [ ] Negative integration tests in tests/test-credential-isolation.sh + CI (Phase 5).
 - [ ] docs/architecture-alignment.md and docs/credential-isolation.md reviewed vs cluster behavior and signed off (Phase 6).
 - [ ] Direct-to-proxy transition proof (Phase 3 §D).
 - [ ] Every confirmed finding fixed with a guarding test (Phase 4).

 Verification (how to prove the work end to end)

 1. Local, no cluster: make lint, make test, make test-credential-proxy, SKIP_LIVE=1 ./tests/test-credential-isolation.sh, SKIP_LIVE=1 ./tests/test-network-policy.sh all green.
 2. On the cluster: the full Phase 3 suite re-run after fixes, with every §A–§E pass criterion met and no key digest observed anywhere.
 3. CI: push the branch; confirm Credential proxy, In-guest installer and chart tests, and Pattern E2E workflows are green, including the new negative tests.
 4. Open the PR from security/credential-proxy-audit with the report, fixes and tests together; request team-lead review for the doc sign-off.
 5. Rotate the disposable audit NVIDIA key.

 Open coordination points (ask mtalvi, don't assume)

 - H2 fix layer: policy-always-on vs proxy client authn.
 - Whether the VM should keep any access to proxy :8081.
 - Whether docs/security/ is the right home or an existing docs path is preferred.

