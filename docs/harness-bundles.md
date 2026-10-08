# Harness bundles: skills, MCP servers and tool plugins

A harness bundle is what an OpenClaw sandbox loads on top of its image:
skills, MCP servers and tool code. A SAW-BOM sandbox names one with
`harnessRef`, and the installer **mounts it read-only at `/sandbox/harness`,
exactly as written**. Nothing is copied into the sandbox with `sandbox exec`,
and nothing is converted: the files in the bundle are the files OpenClaw
reads.

## Layout

```
harness-bundles/<bundle>/
  harness.yaml            kind HarnessBundle: name, version, governance (read by the installer only)
  plugin.json             Agent Plugins manifest: OpenClaw loads skills/ and mcp.json from the bundle root
  skills/<name>/SKILL.md  skills
  mcp.json                MCP servers
  mcp/…                   files a stdio MCP server runs (optional)
  plugins/<id>/           native OpenClaw plugins (tool code)
    package.json          "openclaw": { "extensions": ["./index.mjs"] }
    openclaw.plugin.json  id, contracts.tools
    index.mjs             calls api.registerTool(...)
```

`harness-bundles/ds-default` is the sample: the `pattern-author` skill, the
`saw-echo` tool plugin and a stdio `saw-mcp-echo` MCP server.

### MCP servers (`mcp.json`)

Agent Plugins format. Every server needs a `type`; OpenClaw ignores an entry
without one.

```json
{
  "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
  "mcpServers": {
    "local-tool": { "type": "stdio", "command": "node", "args": ["${PLUGIN_ROOT}/mcp/server.mjs"] },
    "local-mcp":  { "type": "streamable-http", "url": "http://my-mcp.mcp-servers.svc.cluster.local:8080/mcp" }
  }
}
```

| `type` | Fields | Runs |
|---|---|---|
| `stdio` | `command` (a bare name or `./`-relative), `args`, `env`, `cwd` | inside the sandbox |
| `streamable-http`, `sse` | `url`, `headers` | elsewhere; the sandbox connects to it |

The only path placeholders are `${PLUGIN_ROOT}` and `${PLUGIN_DATA}` (a
credential placeholder like `${BRAVE_API_KEY}` is separate, see below); a
bundle never holds a key. The agent sees a server's tools as
`<server>__<tool>`, e.g. `local-mcp__search`.

A remote server must be declared in `harness.yaml` with a governance profile,
and its host must be one of that profile's endpoints:

```yaml
spec:
  mcpServers:
    - name: local-mcp
      governanceProfile: local-mcp
```

#### Servers that need an API key

A server that calls a keyed service gets its key the same way OpenClaw gets
its model key: from an OpenShell **provider** attached to the sandbox. The
sandbox's environment holds only a placeholder in the provider profile's env
var (for example `BRAVE_API_KEY`), and the sandbox's egress proxy puts the
real key in only on requests to that profile's endpoints, from its listed
programs (`node`, `curl`). The real key never enters the sandbox, so the agent
cannot read it.

1. Declare the server in `harness.yaml` with the provider type as its
   `governanceProfile`:

   ```yaml
   spec:
     mcpServers:
       - name: brave-search
         governanceProfile: brave
   ```

2. Give the sandbox a provider of that type in the SAW-BOM profile
   (`providers.yaml`, and the sandbox's `providers` list):

   ```yaml
   - name: notebook
     providers: [nvidia, brave]
     harnessRef: {name: my-bundle}
   ```

3. Have the server read the profile's env var (`BRAVE_API_KEY`) and call only
   the profile's endpoints. OpenShell gives every process started in the
   sandbox the placeholder; name the variable in its `mcp.json` entry as
   exactly `${VAR}` (or `Bearer ${VAR}` for Authorization headers):
   `"env": {"BRAVE_API_KEY": "${BRAVE_API_KEY}"}`. Checked end to end: with
   that declaration the server sees the placeholder (`SET`); without it,
   `NOT SET`. Any other value is refused so a literal secret cannot ship in
   the bundle, ConfigMap or image. A provider attached to a running sandbox
   reaches OpenClaw after its gateway restarts.

The installer refuses a bundle whose governed server or plugin names a profile
the gateway does not serve in that workspace, or one the sandbox has no
provider for. For a service no profile covers yet (Tavily, for instance), add
a profile with a `credentials` entry to `charts/governance-policy/profiles/`
first. The older `credentialSecret` / `credentialEnvVar` fields are refused:
they put the real key in the sandbox, where the agent could read it.

Everything a stdio server downloads at start (`npx -y <package>`) needs a
profile that allows `registry.npmjs.org` too; a server shipped in the bundle
(`node ${PLUGIN_ROOT}/mcp/server.mjs`) does not.

### Tool plugins (`plugins/<id>/`)

Plain ES modules (`.mjs`, or `.js` with `"type": "module"`), self-contained:
nothing runs `npm install`, so bundle any dependency into one file. A plugin
that makes network calls names a `governanceProfile` in `harness.yaml`
`spec.plugins`.

## Two ways to ship a bundle

Both end up the same way: the installer puts the bundle, unchanged, into a
podman volume that belongs to the sandbox (`saw-harness-<workspace>-<sandbox>-<hash>`),
and the sandbox mounts that volume read-only at `/sandbox/harness`. **An
update refills the volume in place; the running sandbox is kept** and sees
the new files through the mount (checked live on 0.0.116: a removed plugin
gone, a skill at its new version, a new MCP server listed).

Why a volume and not an image mount: OpenShell 0.1.x refuses image and host
path mounts while resource admission is on (the default), and admits a volume
only when it carries the `openshell.ai/sandbox-attachable=true` and
`openshell.ai/sandbox-attachable-workspace=<workspace>` labels, which the
installer sets. The gateway also needs `allow_driver_config = true`
(`allowDriverConfig` in the openshell-saw chart, **off by default** — turn
it on together with a profile that has a `harnessRef`, e.g. saw-bom's
`harnessEnabled`); the installer stops before changing anything when a sandbox
has a `harnessRef` and it is off. Turning it off later stops every sandbox
created with a harness (the podman driver re-checks them), so recreate those
first. With admission on and bind mounts off, a signed-in user of the
workspace can attach nothing but the workspace's own labelled volumes; if
one is attached writable and changed, the next apply finds the tree digest
changed and refills it.

The shipped `ds-default` demo pin is opt-in (`harnessEnabled: false` in
saw-bom). With it off, sandbox.yaml loses its `harnessRef` and no harness
keys ship, so an upgrade does not recreate notebooks. Set `harnessEnabled: true`
to try the demo; under saw-users that also sets `allowDriverConfig: true` on
the user's openshell-saw app (`saw-users.openshellValues`), so the two flags
can't drift apart. Driving saw-bom and openshell-saw directly (no saw-users)
still needs both set by hand.

### OCI image (recommended)

```yaml
harnessRef:
  image: ghcr.io/<owner>/saw-harness-ds-default@sha256:<digest>
```

The image is `FROM scratch` with the bundle tree at its root. The installer
pulls it by digest, verifies the cosign signature against
`harness.cosign.identity` / `issuer` (the keyless GitHub Actions identity of
`.github/workflows/harness-bundles.yml`), then unpacks it into the volume,
keeping file modes, so a stdio server can run a script from the bundle
directly. A missing or wrong signature refuses the apply before anything is
mounted. Inline ConfigMap bundles skip this check. The digest in
`harnessRef` is still the pin; cosign proves that pin was signed by CI.

`.github/workflows/harness-bundles.yml` builds every `harness-bundles/<bundle>/`,
pushes `ghcr.io/<owner>/saw-harness-<bundle>:<version>` on `main`, signs the
digest with cosign, and prints the `harnessRef` in the job summary. Locally:

```bash
make harness-bundle-build HARNESS_BUNDLE=ds-default
make harness-bundle-push  HARNESS_BUNDLE=ds-default \
     HARNESS_REPO=ghcr.io/<owner>/saw-harness-ds-default
```

The gateway VM pulls as its runtime user, so the package must be public, or
the VM needs pull credentials for it. `make images-mirror` does not mirror
harness images; a disconnected cluster needs them in a reachable registry.

### Inline, in the saw-bom chart

```yaml
harnessRef:
  name: ds-default
  # digest: sha256:…   optional; checked when set
```

The bundle lives in `charts/saw-bom/harness/<bundle>/` and ships in the
profiles ConfigMap. Each file's ConfigMap key is a hash of its relpath
(`harness__<bundle>__<hash>`), not the relpath itself, with a
`harness__<bundle>__map` key carrying the hash -> relpath mapping; this keeps
any file layout under the ISO 9660/Joliet 64-character filename limit of the
disk KubeVirt makes from the ConfigMap, so there is no path-length or `__`
restriction on a bundle's files. Limits:

- the 1 MiB ConfigMap size;
- no file modes: a stdio server must run a bundled file through its
  interpreter (`command: node`, `args: ["${PLUGIN_ROOT}/mcp/server.mjs"]`).

A bundle that does not fit ships as an image.

## What happens at apply

For each sandbox with a `harnessRef`:

1. **Read the bundle**: from the volume when it already holds this source
   intact (nothing is pulled), otherwise pull the image by digest and unpack
   it, or take the inline bundle from the ConfigMap. An inline bundle's
   digest is also checked against the one Helm computed
   (`harness-index.yaml`).
2. **Check governance** against the gateway's live catalog for the sandbox's
   workspace (`openshell provider list-profiles [--workspace <ws>] -o json`).
   Every `governanceProfile` must be served, the sandbox must have a provider
   of that type, and a remote MCP server's host must be one of the profile's
   endpoints (a profile endpoint may be a single-label glob, e.g.
   `*-aiplatform.googleapis.com`; ports are ignored). Plugins or stdio
   servers with no `harness.yaml` entry are only warned; their egress is
   enforced at runtime by the sandbox proxy. Nothing is written before this
   passes.
3. **Fill the volume** if its content differs.
4. **Mount:** create the sandbox with the volume at `/sandbox/harness`
   **read-only**. A running sandbox that does not mount its volume, still
   mounts a harness it no longer has, or mounts it writable, is recreated;
   anything the agent wrote outside `/sandbox/persist` or other
   data volumes is lost, as with a pod restart.
5. **Configure OpenClaw:** `plugins.load.paths` gets `/sandbox/harness`
   (skills and MCP servers) and `/sandbox/harness/plugins` (every tool
   plugin). A bundle without `plugin.json` uses `skills.load.extraDirs`.
   Re-apply re-sets these keys; verify fails if they drifted.
6. **Verify:** the volume holds the source intact, the container mounts it
   read-only, `openclaw plugins list --json` shows the bundle row loaded
   from the mount (`mcp list` only shows OpenClaw-managed servers, never
   bundle ones) and the config keys match, and the sandbox reads the same
   content through it. `status.json`
   records the source as `appliedRevision`.
7. **Clean up** harness volumes no enabled sandbox wants (a volume still
   mounted by a sandbox stays until that sandbox is gone).

`--dry-run` still reads the bundle (inline ConfigMap or image export),
verifies a harness image's cosign signature, and runs the governance check;
it only skips volume writes and sandbox changes.
A bundle that would fail a real apply must fail dry-run too.

### Installer details

Validation before any change: only `openclaw` sandboxes may have a
`harnessRef`; image refs are `repo@sha256:<64 hex>`; inline names must match
a delivered bundle and optional digests must match `harness-index.yaml`.

Volume: one per sandbox, `saw-harness-<ws>-<sb>-<hash>`, labelled
`openshell.ai/sandbox-attachable=true` and
`openshell.ai/sandbox-attachable-workspace=<ws>`. Content change wipes then
`podman volume import`s the tree plus `.saw-harness-revision`
(`source`, `treeDigest`). A failed import restores the previous tree.
Image trees keep executable bits; links, devices
and `..` paths are refused. Integrity digests come from the ConfigMap or
ledger, not the in-volume marker alone.

OpenClaw config (values only, never bundle bytes through `exec`):

| Bundle has | Setting |
|---|---|
| `plugin.json` | `plugins.load.paths` += `/sandbox/harness` |
| no `plugin.json`, but `skills/` | `skills.load.extraDirs = ["/sandbox/harness/skills"]` |
| `plugins/` | `plugins.load.paths` += `/sandbox/harness/plugins` |

### Lifecycle

| Event | What happens |
|---|---|
| First apply | Read, govern, fill volume, create sandbox with mount, configure OpenClaw |
| Re-apply, unchanged | Volume intact: no pull/write; sandbox kept |
| New digest / edited inline | Volume refilled in place (briefly empty mid-import); sandbox kept; its OpenClaw gateway restarts so new plugin code loads (live sessions reconnect) |
| Sandbox created before `harnessRef` | Recreated with the mount |
| Volume edited on the VM | Verify fails; next apply refills |
| `harnessRef` removed | Sandbox recreated without the mount; volume removed when unused |
| Image signature refused | Existing sandbox with a harness is recreated without it; rejected content is cleaned up and apply fails. A later successful verification restores the mount. |

### Signature rechecks and network access

The installer checks image trust before using either a cached volume or a
new image. Successful verification of a digest may be reused from the trusted
installer ledger for `harness.cosign.cacheTtlSeconds` (default 300, allowed
range 0–300). Set it to 0 for a fresh online check on every apply. Changing
the identity or issuer invalidates cached verification immediately. Applies
can reuse the last successful verification for up to five minutes; removal
of a registry signature is detected on the next uncached apply. There is no
background revocation monitor. Cache use is logged with its age.
Invalid/future timestamps are refused, dry-run does not save trust, and
installations without a ledger check every apply.

Once the cache expires, failed verification never extends the old trust.
The installer removes an active harness even when verification fails because
of a network outage, then reports the apply failure. Operators must keep
registry and Sigstore access available for periodic verification: public
Sigstore uses `rekor.sigstore.dev` and `tuf-repo-cdn.sigstore.dev`, in addition
to the image registry and its blob/redirect hosts (for GHCR, `ghcr.io` and
`pkg-containers.githubusercontent.com`). With PR #68's default-deny firewall,
declare these in `egress.extraAllow` before enabling image harnesses. A
five-minute cache reduces repeated network checks; it is not offline support.
Recreation keeps `/sandbox/persist`; other temporary sandbox work is lost,
as with removing a harness reference or restarting a sandbox.

### MCP registration checks

The installer and H3 inspect the mounted bundle's actual plugin id using
`openclaw plugins inspect <id> --runtime --json`. They match declared names
against supported `mcpServers` entries exactly, and reject inspection errors
and error diagnostics. A name appearing in a description or error message
does not count. Older OpenClaw CLIs without runtime inspection produce an
explicit warning that registration is unverified. Other command failures or
malformed output fail verification.

This confirms registration, not that an MCP process starts, connects, or
answers requests. Process readiness requires an MCP initialize/tools-list
probe or a real agent turn; neither is claimed by this inspection check.

### E2E harness disable/restore drill

`scripts/e2e-harness.sh --gateway <name>` checks H1–H8 without changing
deployment state. H3 uses the registration checks above and explicitly skips
process readiness. The opt-in `--revoke-drill` flag runs H9: disable the
harness, verify the recreated sandbox has no mount or harness load path,
then restore its original state. This exercises harness disable/restore;
it does not revoke a signature or test the signature verification cache.
Sandbox recreation loses work outside persistent data volumes.

For Helm deployments, pass `--bom-release <release>` when the release is
not `saw-bom`. H9 preserves the original `harnessEnabled` value, including
`false`. For Argo CD, H9 automatically finds the Application whose source
path is `charts/saw-bom` and whose destination is the SAW namespace
(`SAW_NS`, default `saw-<gateway>`). Use `--bom-application <application>`
and `--argo-namespace <namespace>` to disambiguate or restrict discovery.
Explicit drills fail when no deployment is found or discovery is ambiguous.

H9 saves the exact Argo Helm parameter list and automated sync settings,
pauses automation on the BOM Application and any managing Application
identified by Argo tracking annotations/labels, changes the child desired
parameter and requests manual sync. It waits for the sandbox's rendered
`harnessRef` in `saw-bom-profiles` before restarting a VM without live inputs,
then polls the running sandbox and its OpenClaw config. Multi-source
Applications, ApplicationSet ownership and unresolvable parent ownership
are refused. The drill requires permission to inspect and patch the child
and managing Applications; discovery errors fail rather than guessing.

Normal completion, polling failures, INT and TERM restore the original
parameters/harness state and automation. Signals terminate the script after
restoration. If restoration itself fails, the script reports failure and
retains its temporary JSON snapshot for recovery; automation restoration is
still attempted. `DRILL_TIMEOUT` controls polling time per phase (default
1500 seconds), and `DRILL_POLL_INTERVAL` defaults to 15 seconds. The drill
requires `oc`, Python with PyYAML, the deployment controller's tooling, and
`virtctl` when VM inputs require a restart.

### Security properties

- With the governance interceptor enabled, caller driver config requires
  an mTLS platform admin and permits only the installer's read-only podman
  harness volume at `/sandbox/harness`. OIDC admins, bind mounts, writable
  mounts, other targets and other driver options are refused at creation.
  OpenShell 0.1.2 does not support intercepting `CreateSandboxTemplate`;
  template-based `CreateSandbox` requests are refused because the gateway
  resolves their driver config after interception. Templates may be stored,
  but cannot be used to create sandboxes while this guard is enabled.
  The installer also detects existing writable/remapped mounts and recreates
  the sandbox on the next apply.
  Stronger drift protection comes from the combination: RO by default,
  recreate on RW, tree-digest / config verify on drift, and re-setting
  OpenClaw harness config on every apply.
- Caller driver config can attach only volumes labelled for that workspace
  (admission on, bind mounts off).
- OCI pin is the digest in `harnessRef`; the installer verifies CI's cosign
  signature (`harness.cosign`) before using the image, subject to the bounded
  successful-verification cache described above.
- Governance uses the gateway's live catalog and requires a matching provider
  on the sandbox; keys never enter the sandbox (providers + egress proxy only).
- `npx`-style servers fetch code at run time, outside the digest — vendor
  when that matters.
