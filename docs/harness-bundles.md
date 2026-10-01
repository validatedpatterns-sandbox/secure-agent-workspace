# Harness bundles: skills, MCP servers and tool plugins

A harness bundle is what an OpenClaw sandbox loads on top of its image:
skills, MCP servers and tool code. A SAW-BOM sandbox names one with
`harnessRef`, and the installer **mounts it read-only at `/sandbox/harness`,
exactly as written**. Nothing is copied into the sandbox with `sandbox exec`,
and nothing is converted: the files in the bundle are the files OpenClaw
reads.

How it is built: [harness-implementation.md](harness-implementation.md).

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

The only placeholders are `${PLUGIN_ROOT}` and `${PLUGIN_DATA}`, and a
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
   sandbox the placeholder; whether OpenClaw passes its whole environment to
   a stdio server is not confirmed yet, so if the server does not see it,
   name the variable in its `mcp.json` entry:
   `"env": {"BRAVE_API_KEY": "${BRAVE_API_KEY}"}`. A provider attached to a
   running sandbox reaches OpenClaw after its gateway restarts.

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
(`allowDriverConfig` in the openshell-saw chart, on by default); the
installer stops before changing anything when a sandbox has a `harnessRef`
and it is off. Turning it off later stops every sandbox created with a
harness (the podman driver re-checks them), so recreate those first. With
admission on and bind mounts off, a signed-in user of the workspace can
attach nothing but the workspace's own labelled volumes; if one is attached
writable and changed, the next apply finds the tree digest changed and
refills it.

### OCI image (recommended)

```yaml
harnessRef:
  image: ghcr.io/<owner>/saw-harness-ds-default@sha256:<digest>
```

The image is `FROM scratch` with the bundle tree at its root. The installer
pulls it by digest and unpacks it into the volume, keeping file modes, so a
stdio server can run a script from the bundle directly. The digest in
`harnessRef` is the trust anchor: the installer does not check the cosign
signature CI adds.

`.github/workflows/harness-bundles.yml` builds every `harness-bundles/<bundle>/`,
pushes `ghcr.io/<owner>/saw-harness-<bundle>:<version>` on `main`, signs the
digest with cosign, and prints the `harnessRef` in the job summary. Locally:

```bash
make -f Makefile-quickstart harness-bundle-build HARNESS_BUNDLE=ds-default
make -f Makefile-quickstart harness-bundle-push  HARNESS_BUNDLE=ds-default \
     HARNESS_REPO=ghcr.io/<owner>/saw-harness-ds-default
```

The gateway VM pulls as its runtime user, so the package must be public, or
the VM needs pull credentials for it. `make copy-images` does not mirror
harness images; a disconnected cluster needs them in a reachable registry.

### Inline, in the saw-bom chart

```yaml
harnessRef:
  name: ds-default
  # digest: sha256:…   optional; checked when set
```

The bundle lives in `charts/saw-bom/harness/<bundle>/` and ships in the
profiles ConfigMap. Limits:

- the 1 MiB ConfigMap size;
- 64-character file keys (`harness__<bundle>__<path>`, the ISO 9660/Joliet
  limit of the disk KubeVirt makes from the ConfigMap);
- no `__` in any path segment (it is the key separator), so a Python package
  (`__init__.py`) cannot ship inline;
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
   endpoints. Nothing is written before this passes.
3. **Fill the volume** if its content differs.
4. **Mount:** create the sandbox with the volume at `/sandbox/harness`. A
   running sandbox that does not mount its volume (created before its
   `harnessRef`), or that still mounts a harness it no longer has, is
   recreated; anything the agent wrote outside `/sandbox/persist` or other
   data volumes is lost, as with a pod restart.
5. **Configure OpenClaw:** `plugins.load.paths` gets `/sandbox/harness`
   (skills and MCP servers) and `/sandbox/harness/plugins` (every tool
   plugin). A bundle without `plugin.json` uses `skills.load.extraDirs`.
6. **Verify:** the volume holds the source intact, the container mounts it,
   and the sandbox reads the same content through it. `status.json` records
   the source as `appliedRevision`.
7. **Clean up** harness volumes no enabled sandbox wants (a volume still
   mounted by a sandbox stays until that sandbox is gone).
