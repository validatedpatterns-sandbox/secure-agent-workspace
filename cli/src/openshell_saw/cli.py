"""openshell-saw CLI — admin provisioning tool for OpenShell sandboxes on OpenShift.

Users interact with their sandboxes via the upstream 'openshell' CLI.
This tool is for provisioning, teardown, and cluster-level operations."""

import subprocess

import click

from . import config, helm, kube, oidc


@click.group()
@click.option("--namespace", "-n", default=None, help="Kubernetes namespace (default: openshell-agents)")
@click.option("--shared-namespace", default=None, help="Shared infrastructure namespace (default: openshell-agents)")
@click.option("--ssh-key", default=None, help="Path to SSH private key")
@click.pass_context
def main(ctx, namespace, shared_namespace, ssh_key):
    """Admin provisioning CLI for OpenShell sandboxes on OpenShift."""
    cfg = config.load_config()
    if shared_namespace:
        cfg["shared_namespace"] = shared_namespace
    if ssh_key:
        cfg["ssh_key"] = ssh_key
    if namespace:
        cfg["namespace"] = namespace

    ctx.ensure_object(dict)
    ctx.obj["cfg"] = cfg


# --- OIDC commands (for provisioning — users authenticate via 'openshell login') ---


@main.command()
@click.option("--issuer", default=None, help="OIDC issuer URL")
@click.option("--flow", type=click.Choice(["browser", "device-code"]), default=None)
@click.pass_context
def login(ctx, issuer, flow):
    """Authenticate with the OIDC provider (for provisioning)."""
    cfg = ctx.obj["cfg"]
    oidc_cfg = cfg["oidc"]
    oidc.login(
        issuer=issuer,
        namespace=cfg["shared_namespace"],
        client_id=oidc_cfg["client_id"],
        flow=flow or oidc_cfg["flow"],
        token_dir=oidc_cfg["token_dir"],
        callback_port=oidc_cfg.get("callback_port", 8400),
    )


@main.command()
@click.pass_context
def whoami(ctx):
    """Show current OIDC identity and token status."""
    oidc.whoami(ctx.obj["cfg"]["oidc"]["token_dir"])


# --- Sandbox commands ---


@main.group()
def sandbox():
    """Provision and manage agent sandboxes."""


@sandbox.command("create")
@click.argument("name")
@click.option("--owner", "-o", default=None, help="Owner username (for access control)")
@click.option("--namespace-mode", type=click.Choice(["shared", "perUser"]), default=None,
              help="Namespace strategy: shared (default) or perUser")
@click.option("--provider", "-p", required=True, help="Inference provider (gemini, anthropic, openai, build, openrouter, ollama, custom)")
@click.option("--model", "-m", required=True, help="Model name")
@click.option("--api-key", "-k", required=True, help="API key")
@click.option("--agent", "-a", default=None, help="Agent type (default: openclaw)")
@click.option("--endpoint-url", default=None, help="Custom endpoint URL")
@click.option("--web-search", default=None, help="Enable web search")
@click.option("--gcp-sa-json", default=None, help="GCP service account JSON file (Vertex AI)")
@click.option("--source-mode", default=None, help="VM source mode (containerDisk or snapshot)")
@click.pass_context
def sandbox_create(ctx, name, owner, namespace_mode, provider, model, api_key,
                   agent, endpoint_url, web_search, gcp_sa_json, source_mode):
    """Provision a new agent sandbox."""
    cfg = ctx.obj["cfg"]
    shared_ns = cfg["shared_namespace"]
    oidc_cfg = cfg["oidc"]
    ns_mode = namespace_mode or cfg.get("namespace_mode", "shared")

    # Determine the deploy namespace
    ns = cfg["namespace"]
    if ns_mode == "perUser" and owner:
        ns = config.user_namespace(owner)

    # Ensure namespace exists
    kube.ensure_namespace(ns)

    # SSH key
    pubkey = config.ssh_pubkey(cfg["ssh_key"])
    kube.ensure_ssh_secret(cfg["ssh_key"], ns)

    # OIDC auto-detection (look in shared namespace for Keycloak/gateway)
    issuer = oidc.auto_detect_issuer(
        None, ns, oidc_cfg["token_dir"], oidc_cfg["client_id"],
        shared_namespace=shared_ns,
    )
    oidc_sets = {}
    oidc_strings = {}
    if issuer:
        token = oidc.get_token(oidc_cfg["token_dir"], oidc_cfg["client_id"], issuer)
        if not token:
            raise click.ClickException(
                f"OIDC authentication required.\n\n"
                f"  Run: openshell-saw login --issuer {issuer}\n"
            )
        oidc_strings["oidc.token"] = token
        oidc_sets["oidc.issuerUrl"] = issuer
        oidc_sets["oidc.clientId"] = oidc_cfg["client_id"]

        # Auto-detect owner from OIDC token if not explicitly set
        if not owner:
            owner = config.get_username_from_token(oidc_cfg["token_dir"])

    # Resolve chart
    chart = config.chart_path("openshell-sandbox")

    src_mode = source_mode or cfg.get("source_mode", "containerDisk")
    sets = {
        "sandboxName": name,
        "sshPublicKey": pubkey,
        "agent": agent or cfg.get("agent", "openclaw"),
        "inference.provider": provider,
        "inference.model": model,
        "inference.apiKey": api_key,
        "inference.endpointUrl": endpoint_url or "",
        "inference.webSearch": web_search or "",
        "route.enabled": "true",
        "route.dashboard": "true",
        "sourceGoldenImageNamespace": shared_ns,
        "namespaceMode": ns_mode,
    }
    if src_mode == "containerDisk":
        sets["sourceMode"] = "containerDisk"

    # Access control
    if owner:
        sets["accessControl.enabled"] = "true"
        sets["accessControl.owner"] = owner

    sets.update(oidc_sets)

    set_files = {}
    if gcp_sa_json:
        set_files["vertexSaJson"] = gcp_sa_json

    click.echo(f"Provisioning sandbox '{name}' in namespace '{ns}'...")
    if owner:
        click.echo(f"  Owner: {owner}")
    helm.install_chart(
        release=name,
        chart_path=chart,
        namespace=ns,
        sets=sets,
        set_strings=oidc_strings,
        set_files=set_files,
    )

    click.echo(f"\nSandbox '{name}' deployed.\n")

    gw_url = kube.get_route_url(f"{name}-gateway", ns)
    if gw_url:
        click.echo(f"  Gateway:   {gw_url}")
    dash_url = kube.get_route_url(f"{name}-dashboard", ns)
    if dash_url:
        click.echo(f"  Dashboard: {dash_url}")
    if owner:
        click.echo(f"  Owner:     {owner}")

    click.echo(f"\nMonitor setup:  openshell-saw sandbox logs {name}")
    click.echo(f"SSH (debug):    openshell-saw sandbox ssh {name}")


@sandbox.command("list")
@click.pass_context
def sandbox_list(ctx):
    """List all sandboxes."""
    ns = ctx.obj["cfg"]["namespace"]
    sandboxes = helm.list_sandboxes(ns)
    if not sandboxes:
        click.echo("No sandboxes found.")
        return

    click.echo(f"{'NAME':<20} {'STATUS':<12} {'VM':<10} {'CREATED'}")
    for sb in sandboxes:
        click.echo(f"{sb['name']:<20} {sb['status']:<12} {sb['vm_status']:<10} {sb['updated']}")


@sandbox.command("delete")
@click.argument("name")
@click.confirmation_option(prompt="Are you sure you want to delete this sandbox?")
@click.pass_context
def sandbox_delete(ctx, name):
    """Delete a sandbox."""
    ns = ctx.obj["cfg"]["namespace"]
    helm.uninstall(name, ns)
    click.echo(f"Sandbox '{name}' deleted.")


@sandbox.command("ssh")
@click.argument("name")
@click.pass_context
def sandbox_ssh(ctx, name):
    """SSH into a sandbox VM."""
    kube.ssh_sandbox(name, ctx.obj["cfg"]["namespace"])


@sandbox.command("logs")
@click.argument("name")
@click.pass_context
def sandbox_logs(ctx, name):
    """Follow sandbox setup job logs."""
    kube.follow_logs(f"job/{name}-setup", ctx.obj["cfg"]["namespace"])


@sandbox.command("url")
@click.argument("name")
@click.pass_context
def sandbox_url(ctx, name):
    """Show gateway and dashboard URLs for a sandbox."""
    ns = ctx.obj["cfg"]["namespace"]
    gw_url = kube.get_route_url(f"{name}-gateway", ns)
    dash_url = kube.get_route_url(f"{name}-dashboard", ns)

    if gw_url:
        click.echo(f"Gateway:   {gw_url}")
    else:
        click.echo("Gateway:   (route not found)")
    if dash_url:
        click.echo(f"Dashboard: {dash_url}")
    else:
        click.echo("Dashboard: (route not found)")


# --- Build commands ---


@main.group()
def build():
    """Build VM images and components."""


@build.command("gateway-image")
@click.pass_context
def build_gateway_image(ctx):
    """Build the pre-baked gateway VM image (containerDisk)."""
    ns = ctx.obj["cfg"]["shared_namespace"]
    chart = config.chart_path("openshell-gateway-image")
    click.echo("Installing openshell-gateway-image chart...")
    helm.install_chart("openshell-gateway-image", chart, ns)
    click.echo("Starting build...")
    kube.start_build("openshell-gateway", ns)


@build.command("gateway-image-logs")
@click.pass_context
def build_gateway_image_logs(ctx):
    """Follow gateway image build logs."""
    kube.follow_logs("bc/openshell-gateway", ctx.obj["cfg"]["shared_namespace"])


# --- Status ---


@main.command()
@click.pass_context
def status(ctx):
    """Show status of all OpenShell resources."""
    cfg = ctx.obj["cfg"]
    ns = cfg["namespace"]
    click.echo(f"Namespace: {ns}")
    click.echo()
    sections = [
        ("Helm releases", ["helm", "list", "-n", ns]),
        ("VMs", ["oc", "-n", ns, "get", "vm"]),
        ("VMIs", ["oc", "-n", ns, "get", "vmi"]),
        ("Jobs", ["oc", "-n", ns, "get", "jobs"]),
        ("Routes", ["oc", "-n", ns, "get", "routes"]),
    ]
    for title, cmd in sections:
        click.echo(f"=== {title} ===")
        subprocess.run(cmd, check=False)
        click.echo()


if __name__ == "__main__":
    main()
