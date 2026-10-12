# Deploying on an NVIDIA LaunchPad cluster

NVIDIA LaunchPad gives you an OpenShift cluster, for example on GB200
(arm64) nodes, behind an SSH gateway. The cluster's API, console and routes
(`*.apps.<cluster domain>`) can only be reached from inside LaunchPad, so you
work through the bastion host, or from your workstation through an SSH SOCKS
tunnel. This page covers access, installing the pattern from the bastion, and
what is different about these clusters.

LaunchPad's environment details give you the following; replace the
placeholders below with them:

| Placeholder | Example |
|---|---|
| `<ssh-user>` | `nvidia@3eaae69e-c3e7bad4` (the SSH gateway login) |
| `<apps-domain>` | `apps.launchpad.nvidia.com` |

## 1. SSH access

Add a host entry to `~/.ssh/config` on your workstation:

```
Host launchpad
  HostName global.prd.ga.launchpad.nvidia.com
  User <ssh-user>
  DynamicForward 1080
```

`ssh launchpad` opens a shell on the bastion. `DynamicForward 1080` is what
the tunnel below uses.

## 2. The SOCKS tunnel (workstation)

```bash
ssh -N launchpad        # leave it running; it prints nothing
```

Check it from another terminal:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' --socks5-hostname 127.0.0.1:1080 \
  https://console-openshift-console.<apps-domain>
```

A `200` or `301` means the tunnel and the router answer. `000` means the
tunnel is not running.

## 3. `oc` from the workstation (optional)

Copy the bastion's kubeconfig once:

```bash
scp launchpad:~/.kube/config ~/.kube/launchpad-config
```

Then in every terminal that should talk to this cluster:

```bash
export KUBECONFIG=~/.kube/launchpad-config HTTPS_PROXY=socks5://127.0.0.1:1080
oc whoami
```

Without these, `oc` uses your default kubeconfig and talks to another cluster
(or fails with "the server has asked for the client to provide credentials").

## 4. A browser through the tunnel (macOS)

Close any window using this profile first (Chrome ignores the flags when that
profile is already open), then run this as a single line:

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --user-data-dir="$HOME/.chrome-launchpad" --proxy-server="socks5://127.0.0.1:1080" --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" https://console-openshift-console.<apps-domain>
```

- `--user-data-dir` gives a separate profile, so your normal Chrome keeps
  running.
- `--host-resolver-rules` sends name lookups through the tunnel too:
  `*.<apps-domain>` only resolves inside LaunchPad. Chrome warns that the flag
  is unsupported; that is expected.
- "Your connection is not private": the cluster keeps OpenShift's
  self-signed `*.apps` certificate. Choose Advanced, then Proceed, once per
  host name (the console, Keycloak, each workspace route).
- LaunchPad's "Your environment is no longer active" page means the request
  did not go through the tunnel (the command was pasted with broken line
  continuations, or the profile was already open), the host name has no
  route, or the reservation has really ended.

Useful hosts for a workspace `<user>`:

| What | Host |
|---|---|
| OpenShell dashboard (oauth2-proxy) | `<user>-webui-saw-<user>.<apps-domain>` |
| A sandbox's web UI | `<user>-<workspace>-<sandbox>-ui.<apps-domain>` |
| Keycloak | `openshell-keycloak-ingress-saw-keycloak.<apps-domain>` |

List them with `oc get route -n saw-<user>`. Users' passwords:
`make keycloak-passwords` lists who has one, `make keycloak-password KC_USER=<user>`
names the Secret that holds it, and
`oc -n saw-keycloak extract secret/<that Secret> --keys=<user> --to=-` reads it.

## 5. Installing the pattern from the bastion

The bastion is x86_64 Ubuntu without podman and, usually, without sudo, so
`./pattern.sh make install` (which runs the utility container) does not work.
Run the same Ansible natively in a virtualenv:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh; source ~/.local/bin/env
uv venv ~/vp-venv --python 3.12; source ~/vp-venv/bin/activate
uv pip install ansible-core kubernetes==31.0.0 jmespath pyyaml
export ANSIBLE_COLLECTIONS_PATH=~/.ansible/collections ANSIBLE_EXECUTABLE=/bin/bash
ansible-galaxy collection install -p ~/.ansible/collections kubernetes.core community.general
ansible-galaxy collection install -p ~/.ansible/collections \
  git+https://github.com/validatedpatterns/rhvp.cluster_utils.git

git clone <your fork> secure-agent-workspace && cd secure-agent-workspace
export TARGET_BRANCH=<branch> TARGET_ORIGIN=origin
make install
```

Why each workaround:

| Workaround | Because |
|---|---|
| `-p ~/.ansible/collections` and `ANSIBLE_COLLECTIONS_PATH` | the default collections path is not writable without sudo |
| `rhvp.cluster_utils` from git | it is not on Ansible Galaxy |
| `ANSIBLE_EXECUTABLE=/bin/bash` | Ubuntu's `/bin/sh` is dash, which has no `pipefail` |
| `kubernetes==31.0.0` | newer Python clients break `kubernetes.core.k8s_exec` ("core_v1_api is not defined") |

The branch you deploy must exist on the remote (`TARGET_ORIGIN`): Argo CD
pulls it from there.

### virtctl

SSH into a workspace VM needs `virtctl`. Get it from the cluster's own
download route (the bastion is x86_64 even when the nodes are arm64):

```bash
mkdir -p ~/.local/bin
curl -skL https://hyperconverged-cluster-cli-download-openshift-cnv.<apps-domain>/amd64/linux/virtctl.tar.gz \
  | tar -xz -C ~/.local/bin
virtctl ssh -n saw-<user> -i ~/.generated-ssh-keys/sandbox-ssh \
  --local-ssh-opts="-o StrictHostKeyChecking=no" cloud-user@vm/<user>
```

## 6. What is different on these clusters

- **Self-signed `*.apps` certificate.** Workspace VMs do not trust Keycloak's
  route on their own, and every workspace's install fails at OIDC discovery
  ("cannot verify the OIDC issuer's certificate", or the gateway not
  listening on port 17670). The pattern trusts the cluster's ingress CA by
  itself (PR #84); run `make check-oidc-ca` before installing to confirm.
  To set it by hand, set `oidc.caBundle` to the output of
  `oc get cm default-ingress-cert -n openshift-config-managed -o jsonpath='{.data.ca-bundle\.crt}'`.
- **arm64 nodes (GB200).** Needs the `feat/arm64` branch (multi-arch
  OpenShell, a per-architecture VM image; its `docs/arm64.md` has the steps):
  turn the internal image registry on (it is often `Removed`; an
  `nfs-client` PVC works), build the golden VM image and the governance
  interceptor on the cluster with `PUSH=false`, and do not run
  `make images-mirror`.
- **Argo CD resource names.** Plain `application` can resolve to another
  API group (`app.k8s.io`) on these clusters; use
  `applications.argoproj.io`, for example
  `oc -n vp-gitops get applications.argoproj.io`.
- **Reservations expire.** When a reservation ends, the cluster and
  everything on it are gone; nothing carries over to the next one.

## Following an install

```bash
# Argo CD applications that are not Synced/Healthy
oc get applications.argoproj.io -A | grep -v 'Synced *Healthy'

# A workspace VM's installer (install, then apply)
POD=$(oc get pod -n saw-<user> -o name --sort-by=.metadata.creationTimestamp \
  | grep virt-launcher-<user> | tail -1)
oc logs -f -n saw-<user> $POD -c guest-console-log \
  | grep --line-buffered -E 'saw-installer\] (install|apply):|Trusting|ERROR'
```

The first `apply` on arm64 can take ten minutes or more while a NemoClaw
sandbox runs under emulation (x86_64 NemoClaw images; `docs/arm64.md` on
`feat/arm64`).
