# Demo options

Two walks of the SAME personal assistant. The honest axis is the provider
strategy: point the providers at external accounts, or run the services
inside the cluster. Choose by what you can set up: accounts or services.

## Personal Assistant (Quick Demo) with external providers: Slack and Gmail

Step-by-step walkthrough: [personal-assistant-demo.md](personal-assistant-demo.md)
(how the briefing works under the hood: [daily-briefing.md](daily-briefing.md)).

- The agent reads real Slack and Gmail, so you need two external demo
  accounts (Slack app, Google Cloud OAuth client): about 30 minutes, once.
- Quick to run: one workspace, one prompt, a ~10-minute demo.
- Same platform install, same profile shape: one NemoClaw sandbox with the
  `daily-briefing` harness bundle, NVIDIA inference, read-only Slack and
  Gmail providers, and token placeholders the agent never resolves.
- Self-service via the Red Hat Developer Hub portal: the user `dana` picks
  the profile, enters her keys, and gets her own workspace.

## Personal Assistant (Longer Setup) with on-cluster providers: chat, email and calendar

Walkthrough: [on-cluster-demo.md](on-cluster-demo.md).

- Chat, email and calendar services (Mattermost, Mailpit, Radicale) run
  inside the cluster, so you stand up three demo services instead: about
  20 minutes, once.
- Setup: services + profile placement + seeding + two
  workspaces ≈ 1.5 to 2 hours, mostly waiting; the demo itself is ~12 to
  15 minutes.
- As a consequence of the on-cluster providers, it shows more of the
  enforcement layers: a fake credential re-registration email prompting the
  agent into denied actions (calendar call denied at the sandbox proxy, exfil
  denied at egress, circumvention denied at the provider-create gate), VM
  containment of the agent, a policy-as-data capability grant through
  GitOps, and workspace provisioning.
- The grant is the story: the block surfaces the legitimate need, the
  interceptor loads profiles at startup, the new capability arrives as data
  (a YAML file), and the same request that was denied is allowed after the
  sync.

## Choosing

Short on time? Take the external-providers demo. Want to see every layer of the
guardrails in detail and can invest in the setup? Take the on-cluster demo.
Same assistant, different setup times and provider strategies.

## Charts

The demo charts are standalone helm installs from this directory:

```
helm install mailpit demo/charts/mailpit -n openshell-agents
helm install radicale demo/charts/radicale -n openshell-agents
helm install mattermost demo/charts/mattermost -n openshell-agents
```

On OpenShift with restricted-v2, Mattermost may need the service account
anyuid grant; the charts already set the security contexts and probe delays
for that case.

## Profiles

The governance profiles for the on-cluster providers are copied here as the
portable artifacts-to-place: `mailpit.yaml`, `mattermost.yaml`,
`calendar.yaml`. Copy them into `charts/governance-policy/profiles/` BEFORE
deploying the sandbox (the interceptor loads profiles at startup), or after
deployment and let Argo auto-sync.

- For EXISTING sandboxes, the sync is not enough: use the two-step
  `provider create` + `sandbox provider attach` (see the on-cluster demo).
- If the new capability is still denied after the sync, restart the
  interceptor pod: profile hot-reload does not always fire.
- In the on-cluster demo, `calendar.yaml` is the live beat-4 commit: leave it out of
  the pre-placed set if you want the genuine "this capability was not there
  before" moment.

The copies in `charts/governance-policy/profiles/` are the live source the
cluster's Argo self-heals from; keep them in place.
