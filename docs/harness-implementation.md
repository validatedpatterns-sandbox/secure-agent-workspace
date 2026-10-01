# Harness bundles: implementation

How an agent sandbox gets its skills, MCP servers and tool plugins: what is
built, where each piece lives, and what was checked. It builds on PR #53
(harness bundles in SAW-BOM) and replaces its `sandbox exec` copier. For
authoring and publishing a bundle, see [harness-bundles.md](harness-bundles.md).

**Status:** checked end to end on OpenShell 0.1.2-rhaiv.0 (SAW alice, podman
driver, governance interceptor v0.1.2); see §11. The mount mechanics were
first probed on OpenShell 0.0.116 and OpenClaw 2026.9.5.

## 1. Summary

A **harness bundle** is a directory tree in the layout OpenClaw loads:
`plugin.json`, `skills/`, `mcp.json`, `plugins/`. A SAW-BOM sandbox names one
with `harnessRef`, and it reaches the sandbox **only as a read-only mount at
`/sandbox/harness`, exactly as written**:

| `harnessRef` | Source | Reaches the sandbox as | On a change |
|---|---|---|---|
| `image: <repo>@sha256:…` | OCI image built from `harness-bundles/` by CI, published to GHCR | pulled by digest, unpacked unchanged (file modes kept) into the sandbox's podman volume | volume refilled; sandbox kept |
| `name: <bundle>` | inline, `charts/saw-bom/harness/<bundle>/` in the profiles ConfigMap | copied unchanged into the sandbox's podman volume | volume refilled; sandbox kept |

OpenClaw is configured to load from `/sandbox/harness`. Governance is checked
against the gateway's live provider-profile catalog, and against the
sandbox's providers, before anything is written.

## 2. What changed from PR #53

| PR #53 | Now |
|---|---|
| Files base64-piped into the sandbox with `sandbox exec … sh -c 'base64 -d > <path>'` | Mounted read-only; nothing is written inside the sandbox |
| Staged under `/sandbox/.openclaw/{skills,tools}`, wiped each reconcile | `/sandbox/harness`, which the sandbox can only read |
| `tools/*.yaml` copied, never read by OpenClaw | MCP servers in `mcp.json`, code tools in `plugins/<id>/` (`.mjs`), both loaded by OpenClaw from the mount |
| Only inline bundles (1 MiB ConfigMap, 64-character keys) | Also OCI images with no size or name limits |
| `governanceProfiles` list kept in saw-bom values; name check only | Live catalog from the gateway, per workspace; remote MCP hosts checked against the profile's endpoints; the sandbox must have a provider of each profile |
| `harnessRef.digest` required | Optional for inline bundles; the image digest is the pin for OCI |
| Unquoted paths in shell commands | No shell involved in delivering files |

## 3. Architecture

```
 Git
 ├─ harness-bundles/<bundle>/ ──(CI: harness-bundles.yml)──► ghcr.io/<owner>/saw-harness-<bundle>@sha256:…
 └─ charts/saw-bom/
    ├─ harness/<bundle>/ ──► profiles ConfigMap keys harness__<bundle>__<path> (base64)
    │                        + harness-index.yaml (the digest Helm computed)
    └─ profiles/…/sandbox.yaml: harnessRef {image} or {name}
                    │
                    ▼  Argo CD → ConfigMap → disk (or virtiofs) → /run/saw/profiles
 Gateway VM: apply_bom.py apply-profiles, as the runtime user (rootless podman)
   1. read      volume already holds it │ image: pull + export │ inline: ConfigMap files
   2. govern    openshell provider list-profiles [--workspace <ws>] -o json; sandbox providers
   3. fill      volume saw-harness-<ws>-<sb>-<hash>, labelled attachable for <ws>
   4. mount     sandbox create --driver-config-json {podman.mounts: [volume → /sandbox/harness, ro]}
                a running sandbox mounting something else, or a removed harness, is recreated
   5. configure openclaw config set plugins.load.paths …
   6. verify    volume intact + podman inspect .Mounts + read back through the mount
   7. clean up  harness volumes no enabled sandbox wants
                    │
                    ▼
 Sandbox container (OpenShell podman driver)
   /sandbox/harness  (read-only)  plugin.json  skills/  mcp.json  mcp/  plugins/<id>/
   OpenClaw: Agent Plugins bundle at /sandbox/harness (skills + MCP servers),
             native plugins under /sandbox/harness/plugins
```

## 4. Bundle format

```
<bundle>/
  harness.yaml            kind HarnessBundle; read only by the installer
  plugin.json             Agent Plugins manifest
  skills/<name>/SKILL.md
  mcp.json                MCP servers (Agent Plugins 1.0.0)
  mcp/…                   files a stdio MCP server runs
  plugins/<id>/           native OpenClaw plugins
    package.json          "openclaw": {"extensions": ["./index.mjs"]}
    openclaw.plugin.json  id, contracts.tools
    index.mjs             api.registerTool(...)
```

### `harness.yaml`

OpenClaw never reads it. The installer uses it for metadata and governance:

```yaml
apiVersion: saw.redhat.com/v1alpha1
kind: HarnessBundle
metadata:
  name: ds-default
spec:
  agent: openclaw              # only openclaw is supported
  version: 0.1.0               # image tag used by CI
  plugins:                     # plugins that call a service
    - name: my-plugin
      governanceProfile: github
  mcpServers:                  # remote servers, and stdio servers that call a service
    - name: local-mcp
      governanceProfile: local-mcp
```

### MCP servers

OpenClaw reads them from the Agent Plugins bundle's `mcp.json`. Each entry
needs a `type`; OpenClaw 2026.9.5 drops entries without one, so the installer
refuses them:

| `type` | Fields | Runs |
|---|---|---|
| `stdio` | `command` (bare name or `./`-relative), `args`, `env`, `cwd` | inside the sandbox, under OpenShell's policy |
| `streamable-http`, `sse` | `url`, `headers` | remote; the sandbox connects to it |

`${PLUGIN_ROOT}` and `${PLUGIN_DATA}` are the only placeholders. A bundle holds
no key; §7.9 is how a server gets one. The agent sees a server's tools as
`<server>__<tool>`.

### Tool plugins

Self-contained ES modules; nothing runs `npm install`. OpenClaw finds every
plugin under `plugins/` from one load path, so adding or removing a plugin
needs no config change.

## 5. Building and publishing

| Piece | What it does |
|---|---|
| `harness-bundles/Containerfile` | `FROM scratch`, `COPY . /`: the bundle tree is the image root |
| `.github/workflows/harness-bundles.yml` | For each `harness-bundles/<bundle>/`: checks `harness.yaml`, the `mcp.json` types and that there are no links; builds; on `main` pushes `ghcr.io/<owner>/saw-harness-<bundle>:<version>` and `:sha-<commit>`, signs the digest with cosign (keyless), writes the `harnessRef` to the job summary. Pull requests build only. |
| `scripts/harness-bundle.sh` | `build`, `push` (prints the `harnessRef`), `ref` |
| `make harness-bundle-build` / `harness-bundle-push` | Wrappers (`HARNESS_BUNDLE`, `HARNESS_REPO`) |

`charts/saw-bom/harness/ds-default` (inline) and `harness-bundles/ds-default`
(OCI) hold the same tree; `test_chart_bundle_matches_the_published_bundle`
keeps them equal.

## 6. Referencing a bundle (`sandbox.yaml`)

```yaml
harnessRef:
  image: ghcr.io/<owner>/saw-harness-ds-default@sha256:<64 hex>
```

```yaml
harnessRef:
  name: ds-default
  # digest: sha256:…     optional; checked when set
```

`image` and `name` are mutually exclusive. The saw-bom chart fails the render
for an unpinned image, for both at once, or for a digest that does not match.
It ships only the inline bundles that some `harnessRef.name` uses, plus
`harness-index.yaml` with the digest it computed for each.

## 7. Installer (`apply_bom.py`)

Everything below runs in `apply-profiles` as the runtime user (`cloud-user`),
in the same rootless podman that OpenShell's podman driver runs sandboxes in.
The module comment above `HARNESS_MOUNT` lists the steps and the functions
that implement them.

### 7.1 Validation, before anything changes (`validate_harness`, `check_harness_index`)

- only `openclaw` sandboxes may have a `harnessRef`;
- `image` must be `repo@sha256:<64 hex>`, and not combined with `name`/`digest`;
- `name` must be a delivered inline bundle; `digest`, when set, must match
  (`pinned_bundle`);
- each inline bundle's digest must equal the one in `harness-index.yaml`, so
  the chart and the installer agree on the files and on `tree_digest`.

Returns `{sandbox: source}` for `status.json` `appliedRevision`.

### 7.2 Reading the bundle (`prepare_harness`)

Called from `create_sandbox`, before the sandbox is created or checked.

- **Volume already current:** `HarnessVolume.current()` finds the marker names
  this source and the tree digest matches; the tree is read from the volume.
  Nothing is pulled.
- **Image:** `podman image exists`, else `podman pull --quiet <image>`; then
  `podman create` + `podman export` and `read_harness_tar()`. This keeps
  regular files with their executable bit, skips AppleDouble `._*`, refuses
  links, devices and `..` paths, and requires `/harness.yaml`.
- **Inline:** decoded from the ConfigMap keys. A ConfigMap keeps no file
  modes, so an inline stdio server whose `command` is a bundled file is
  refused (run it through its interpreter, or ship an image).

### 7.3 Governance (`check_harness_governance`)

`describe_harness_tree()` lists what needs a profile:

- plugins with a `governanceProfile` in `harness.yaml`;
- every remote MCP server in `mcp.json`, with the host of its `url`. Its
  profile comes from `harness.yaml` `spec.mcpServers`, and one is required;
- stdio servers with a `governanceProfile` (those that call a service). A
  stdio server without one runs under the sandbox policy alone.

For each, three checks, in the sandbox's workspace:

1. the gateway serves the profile. The catalog is read with
   `openshell provider list-profiles [--workspace <ws>] -o json`
   (`parse_profile_catalog()` → `{id: {endpoint hosts}}`), once per workspace:
   in 0.1.x the listing is per workspace;
2. the sandbox has a usable provider of that type. The profile's endpoints and
   its key reach a sandbox only through an attached provider;
3. a remote MCP server's host is one of the profile's endpoints.

Any failure stops the apply **before anything is written**. If the catalog
cannot be read, the harness is refused (fail closed). Because it asks the
gateway, it works the same with the governance interceptor and with APF.

### 7.4 The harness volume (`HarnessVolume`)

- one volume per sandbox, `saw-harness-<ws>-<sb>-<hash>` (`harness_volume_name`;
  the hash of `<ws>/<sb>` keeps `a-b`/`c` and `a`/`b-c` apart);
- created with the labels OpenShell 0.1.x admission requires,
  `openshell.ai/sandbox-attachable=true` and
  `openshell.ai/sandbox-attachable-workspace=<ws>`, plus
  `saw.redhat.com/harness-volume=true`. Labels cannot be added to an existing
  volume, so one without them is replaced once the bundle has passed
  governance: its sandbox is deleted first, then the volume, then both are
  created again;
- when the content differs: wipe (in Python; `podman unshare rm -rf` for
  anything not owned by the runtime user), then `podman volume import` a
  tarball from `write_harness_tar()`. The tarball holds the bundle files
  unchanged, uid/gid 0 (the runtime user on the host), directories 0755,
  files 0644 (0755 if executable), and the marker `.saw-harness-revision`:
  `{"source": "<image>" | "bundle:<name>@<digest>", "treeDigest": …}`.

The volume is refilled **in place**, never recreated under a running sandbox:
the 0.1.x podman driver records the identity of every attached volume (name,
driver, options, creation time) and stops a sandbox whose volume changed.
`treeDigest` is PR #53's `tree_digest`, so a volume edited on the VM is
detected (`verify`) and refilled on the next apply.

### 7.5 Mounting (`create_sandbox`, `harness_mount_ok`)

```
openshell sandbox create --name <sb> … --driver-config-json \
  '{"podman":{"mounts":[{"type":"volume","source":"saw-harness-<ws>-<sb>-<hash>","target":"/sandbox/harness","read_only":true}]}}'
```

OpenShell 0.1.x accepts caller driver config only when the gateway sets
`allow_driver_config = true` in `[openshell.drivers.podman]`; the openshell-saw
chart does (`allowDriverConfig`, on by default), and the installer refuses to
start when a sandbox has a `harnessRef` and `gateway.toml` lacks it
(`check_driver_config_allowed`). Turning it off later stops every sandbox
created with caller driver config: the driver labels them
`openshell.ai/caller-driver-config-used=true` and its reconcile re-checks. Resource admission stays on
and `enable_bind_mounts` stays off, so image and host-path mounts are refused
and a caller can attach only volumes labelled for its own workspace.

Mounts are fixed at creation, so for a sandbox that already runs,
`harness_mount_ok()` compares its container's mount at `/sandbox/harness`
with the desired one: the sandbox's volume, or nothing when it has no
`harnessRef`. `sandbox_harness_mount()` finds the container by its labels
`openshell.ai/sandbox-name` and `openshell.ai/sandbox-workspace` and reads
`podman inspect --format '{{json .Mounts}}'`, where a volume is
`{"Type":"volume","Name":"<volume>"}`. In 0.1.x each sandbox runs as two
containers with those labels, the workload and its supervisor, and only the
workload (`openshell.ai/isolation-role=sandbox`) has the user's mounts, so
that label is filtered on too. When they differ (a sandbox created
before its `harnessRef`, or one whose `harnessRef` was removed), the sandbox
is deleted and created again. 0.1.x may accept a delete with clean-up still
pending, so the installer waits until the sandbox and its workload container
are gone (`delete_sandbox_and_wait`).

### 7.6 OpenClaw configuration (`configure_harness`)

From `openclaw_harness_config()`, set with `openclaw config set` during
onboarding (values `shlex.quote`d):

| Bundle has | Setting |
|---|---|
| `plugin.json` | `plugins.load.paths` += `/sandbox/harness` (skills and `mcp.json`) |
| no `plugin.json`, but `skills/` | `skills.load.extraDirs = ["/sandbox/harness/skills"]` |
| `plugins/` | `plugins.load.paths` += `/sandbox/harness/plugins` |

Config only; bundle content never goes through `exec`, and no key is
written. `plugins.allow` is deliberately not set: it would restrict every
plugin, and it warns about stale entries when a plugin is removed.

### 7.7 Verification (`verify_harness`)

- the volume exists, carries its admission labels, and holds the source
  intact (`HarnessVolume.verify`);
- the container mounts that volume at `/sandbox/harness`;
- `cat /sandbox/harness/.saw-harness-revision` in the sandbox matches the
  marker;
- a sandbox with no `harnessRef` mounts nothing there.

Failures join the normal verification list, so the SAW is not marked ready.

### 7.8 Clean-up (`cleanup_harness_volumes`)

After the apply (and any prune), every `saw-harness-*` volume that no enabled
sandbox wants is removed. podman refuses to remove a volume a container
still mounts, so a disabled but still running sandbox keeps its volume.

### 7.9 Keys for MCP servers and plugins: providers

A bundle never holds a key, and the installer never puts one in the sandbox.
A stdio server or plugin that calls a keyed service names the provider type
as its `governanceProfile`, and the sandbox gets a provider of that type
(SAW-BOM `providers.yaml` and the sandbox's `providers`). OpenShell then
gives the sandbox's processes a placeholder in the profile's env var (for
example `BRAVE_API_KEY`), and the sandbox's egress proxy puts the real key in
only on requests to the profile's endpoints from its listed binaries. This
is how OpenClaw already gets its model key (`start_openclaw`).

An earlier revision resolved a `credentialSecret` and exported the real key
into the OpenClaw gateway process in the sandbox. The agent runs as the same
user there and could read it (`/proc/<pid>/environ`, or a tool process that
inherits the environment), and the key passed through a `sandbox exec`
command line. `describe_harness_tree` now refuses `credentialSecret`,
`credentialSecretKey` and `credentialEnvVar` with a message pointing here.

A service with no provider profile (Tavily, for one) needs a profile with a
`credentials` entry in `charts/governance-policy/profiles/` first.

## 8. Lifecycle

| Event | What happens |
|---|---|
| First apply | Bundle read, governance checked, volume created and filled, sandbox created with the mount, OpenClaw configured |
| Re-apply, nothing changed | Volume intact: no pull, no write, sandbox kept |
| New image digest, or inline bundle edited | Volume wiped and refilled in place; the running sandbox sees it through the mount (briefly empty while it is refilled); OpenClaw reloads skills and plugins, MCP servers apply from the next session |
| Sandbox created before its `harnessRef` | Recreated with the mount on the next apply |
| Volume edited on the VM | Verify fails; next apply refills it |
| Volume without admission labels | Its sandbox and the volume are recreated |
| `harnessRef` removed | Sandbox recreated without the mount; the volume is removed |
| Sandbox disabled or pruned | Its volume is removed once no container uses it |

With `vm.liveInputs` (PR #54), a saw-bom change reaches the VM over virtiofs
and reconcile runs apply, so neither kind of update needs a VM restart.

## 9. Security properties

- The sandbox cannot change its harness: the mount is read-only. A user of
  the workspace could create another sandbox that mounts the volume writable
  (caller driver config is on); the next apply sees the changed tree digest
  and refills it, and verification fails until then.
- Caller driver config can attach only volumes labelled for the caller's own
  workspace: resource admission stays on, bind mounts stay off, image mounts
  are refused.
- An OCI bundle is pinned by digest, and what lands in the volume is exactly
  what was published. CI signs it with cosign; the installer does not verify
  that signature, so the digest in `harnessRef` is the trust anchor. Next
  work: verify it at pull time (`harnessRef.signature`).
- Only regular files are read from an image; links and `..` paths are
  refused.
- Governance comes from the gateway's live catalog and endpoint hosts, not a
  list in the same repository as the bundle, and needs a provider on the
  sandbox for every governed item.
- Keys never enter the sandbox (§7.9).
- `npx`-style servers fetch code at run time, outside the digest. Vendor the
  package into the bundle when that matters.

## 10. Tests

`make test-installer` runs the installer and chart tests.

| File | Covers |
|---|---|
| `tests/installer/test_harness.py` | digest contract; `harness-index.yaml` cross-check; validation (optional digest, image pinning, `name`/`image` exclusivity); reading an image root tree (links, `..`, AppleDouble, missing manifest); the volume tarball's ownership and modes; the `--driver-config-json` shape (a volume); volume names that cannot collide; OpenClaw config; `mcp.json` types; remote server, stdio server and plugin governance; `credentialSecret` and friends refused; an inline stdio server running a bundled file refused; catalog parsing; inline and published bundles identical; plan round-trip |
| `tests/installer/test_harness_mount.py` | image unpacked into a labelled volume (modes kept), never mounted; no second pull; unchanged image keeps the sandbox; new digest refills in place; sandbox without a harness recreated; verify catches another image; removing `harnessRef` unmounts it and removes the volume; a volume in use is kept; an unlabelled volume is recreated with its sandbox; inline volume mounted, refilled in place (dropped files removed, sandbox kept), tamper detected and repaired; unserved profile, missing provider and `search.internal` refused before anything is written; a stdio server gets its key only through its provider; catalog read once per workspace; OpenClaw config set with no exec copies |
| `tests/installer/test_apply_profiles.py` | full apply mounts the inline `ds-default` into `notebook`; a denied `openclaw` does not affect harness delivery |
| `tests/charts/test_openshell_saw_chart.py` | `allow_driver_config` on by default, admission and bind mounts left at their defaults, and it can be turned off |
| `tests/charts/test_saw_bom_chart.py` | no governance list in the chart; optional digest; image refs render without shipping a bundle; unpinned image fails |

The fakes model the podman driver: the fake openshell records
`--driver-config-json` and serves `sandbox exec cat` through the mount; the
fake podman lists sandbox containers by their `openshell.ai/*` labels,
reports `.Mounts` in podman's shape, exports image trees, keeps volumes as
directories with their labels, and refuses to remove a volume a sandbox
mounts.

## 11. Checked, and open items

**Checked live** (OpenShell 0.0.116-rhaiv.0, podman 5.8.1, OpenClaw 2026.9.5):

- `--driver-config-json` volume mounts, read-only in the sandbox;
- how podman reports them, and the container labels
  `openshell.ai/sandbox-name` and `openshell.ai/sandbox-workspace`;
- a skill loaded from the mount and visible to the model;
- an Agent Plugins bundle detected from `plugins.load.paths`, with its MCP
  servers listed (once each entry has a `type`);
- two tool plugins loaded from one parent path;
- a volume refill seen by the running sandbox: a removed plugin gone, a skill
  at its new version, a new MCP server listed;
- `openshell provider list-profiles -o json` returns ids and endpoint hosts.

**Checked live on OpenShell 0.1.2-rhaiv.0** (alice, inline `ds-default`):

- with `allow_driver_config = true`, `sandbox create --driver-config-json`
  with the volume mount is accepted; an existing `notebook` without the mount
  was recreated once;
- the volume carries `openshell.ai/sandbox-attachable=true` and
  `openshell.ai/sandbox-attachable-workspace=default`; the workload container
  (`isolation-role=sandbox`) mounts it read-only at `/sandbox/harness`, the
  supervisor container does not;
- in the sandbox, `/sandbox/harness` is read-only and holds the marker;
  OpenClaw lists the `pattern-author` skill, the `ds-default` bundle and the
  `saw-echo` plugin;
- a re-apply keeps the workload container and the volume (same ID and
  creation time); a file edited in the volume on the VM is seen by the
  sandbox, then repaired by the next apply in place, and the sandbox is still
  `Ready` after the driver's 30-second admission re-check;
- an agent turn through the running OpenClaw gateway called both bundle
  tools: `saw-echo: hello-plugin` (native plugin) and `saw-mcp-echo:
  hello-mcp` (stdio MCP server);
- a keyed stdio server end to end on an inline bundle: with `env:
  {BRAVE_API_KEY: "${BRAVE_API_KEY}"}` declared in its `mcp.json` entry
  (the documented fallback), the server reported the provider placeholder
  (`SET`), whereas without it, `NOT SET`. Only the placeholder is
  forwarded, never the real key; `credentialSecret`/`credentialSecretKey`/
  `credentialEnvVar` stay refused;
- pulling a public bundle image from GHCR in the VM (no credentials) and
  unpacking it into the sandbox's labelled volume: `appliedRevision` carries
  the full digest-pinned ref, the mount stays `Type: volume`, and a new
  digest refills the volume in place with the same container kept
  (`/sandbox/persist` and `/sandbox/tmp` survive);
- governance refusals fail closed before anything is mounted: an unserved
  profile, a missing provider of the profile's type, and an unreadable
  catalog (the gateway itself refuses to start without the interceptor);
- a `protocol: mcp` endpoint is accepted with `rules` of the form
  `{allow: {method: tools/call, tool: <name>}}` (`access` is mutually
  exclusive with `rules`; `path`/`query` are rejected for mcp);
- a keyed stdio server end to end on an image-sourced bundle: same as the
  inline case above, but the volume marker names a GHCR digest; an agent
  turn calling `saw-brave-probe__brave_probe` got back the provider
  placeholder (`BRAVE_API_KEY=SET`), never the raw key;
- `harnessRef` removed from a running sandbox: recreated mountless, its
  volume pruned;
- an unlabelled volume (same name, pre-created with no labels, no sandbox):
  next apply recreated both, volume regained all three admission labels,
  content refilled from the same bundle source.

**From the OpenShell v0.1.2 source** (the rules the design follows):

- caller driver config needs `allow_driver_config`
  (`openshell-core/src/resource_admission.rs`, `check_driver_config`);
- image and bind mounts are refused while resource admission is on
  (`openshell-driver-podman/src/container.rs`, `admit_mount_types`);
- a volume needs the `openshell.ai/sandbox-attachable*` labels, and a running
  sandbox is stopped if an attached volume's identity changes
  (`openshell-driver-podman/src/driver.rs`);
- `provider list-profiles` lists one workspace
  (`openshell-cli/src/commands/provider.rs`).

**Open:**

1. Reaching an in-cluster MCP Service from inside a sandbox: the network
   path works, but the platform's default-deny L7 policy answers `403
   policy_denied`, live policy updates are governance-blocked, and a
   governance profile for the host does not open it. No repo-side knob
   exists; needs an OpenShell-side answer.
2. Next work: verifying the bundle image's cosign signature at pull time.

## 12. Files

| Area | Files |
|---|---|
| Installer | `charts/openshell-saw/files/installer/apply_bom.py` |
| Gateway config | `charts/openshell-saw/templates/_helpers.tpl`, `values.yaml` (`allowDriverConfig`) |
| Chart | `charts/saw-bom/templates/configmap-bom.yaml`, `values.yaml`, `harness/ds-default/`, `profiles/data-science/default/sandbox.yaml` |
| Bundles | `harness-bundles/Containerfile`, `harness-bundles/ds-default/` |
| Build | `.github/workflows/harness-bundles.yml`, `scripts/harness-bundle.sh`, `Makefile-quickstart` |
| Tests | `tests/installer/test_harness.py`, `test_harness_mount.py`, `test_apply_profiles.py`, `fakes/podman`, `fakes/openshell`, `tests/charts/test_saw_bom_chart.py`, `tests/charts/test_openshell_saw_chart.py` |
| Docs | `docs/harness-bundles.md` (usage), this file, `README.md` |
