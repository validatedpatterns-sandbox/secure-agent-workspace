# Reboot acceptance investigation (#161)

Two independent failures were observed during the OpenShell 0.1.6 release
acceptance tracked in [#157](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/issues/157).
The public interceptor pin remains scoped to
[#160](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/pull/160).

## Saved inference credential placeholders

OpenShell issues opaque, revision-bound credential placeholders to sandbox
processes. A placeholder saved as a literal in OpenClaw's provider configuration
can become invalid after the runtime restarts. In the affected custom-inference
workspace, the saved value returned HTTP 500 with `credential_unavailable` and
`Credential placeholder could not be resolved`, while a fresh exec's placeholder
returned HTTP 200 through the same sandbox, endpoint and credential proxy.
Replacing the saved literal with an environment SecretRef made a real gateway
agent turn succeed. This experiment did not require new provider credentials,
network exceptions, package changes or sandbox recreation.

The installer now requests OpenClaw's reference credential-persistence mode.
For custom providers, it also replaces the temporary onboarding alias
`CUSTOM_API_KEY` with a reference to the governance profile's actual variable
(for example, `CUSTOM_INFERENCE_API_KEY` or `NVIDIA_API_KEY`). Later processes
therefore use the placeholder issued to their current runtime. Reapply can
also save an inactive replacement credential in OpenClaw's auth store. The
installer binds that new profile through OpenClaw's supported `secrets apply`
plan API before activating it, including provider metadata when the agent-local
auth-profile mapping must be created. The preflight runs before writes and the
broad scrub passes are disabled so unrelated credentials remain intact. OpenShell's endpoint and
credential-identity enforcement remains in effect.

Reapply repairs the managed provider configuration in place. Validate the
shipped ConfigMap/installer path on new workspaces and existing data: perform
real inference and workspace-tool checks before and after reapply and documented
VM restart. Verify the configured SecretRef names the actual provider variable,
and verify the live agent can use it; a Ready VM or successful boot apply alone
does not establish inference health. Repeat for the default OpenClaw, NemoClaw
and custom-inference profiles, preserving files, passwords, identity, policy and
workspace confinement.

## Damaged Podman catalog and shutdown evidence

Another VM had independently confirmed SQLite overflow/index damage. No
pre-restart integrity measurement exists for that VM, so the damage's cause and
onset remain unproven. Virtualization logs establish that its normal
`make saw-restart` signalled graceful shutdown, then exceeded the 30-second grace
period and killed the VM (`Shutoff` / `Destroyed`). This proves the shutdown did
not finish; it does not prove the kill caused the catalog damage.

Keep the original damaged catalog and workspace volumes intact. Diagnose on
fresh isolated control VMs, recording consistent SQLite integrity checks before
workloads, after inference/reapply, immediately before restart and after restart.
Capture the old VM's console and virtualization shutdown result, including grace
expiry, rather than assuming a non-force restart command guarantees a completed
guest shutdown. Use SQLite's backup API or a read transaction with the required
journal/WAL state for live checks; immutable database reads are suitable only
for verified frozen evidence.

The credential-reference correction does not repair or establish the cause of
catalog corruption. Keep [#161](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/issues/161)
and the release deployment hold open until their remaining acceptance gates
have actual evidence.
