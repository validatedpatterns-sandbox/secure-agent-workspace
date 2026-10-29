"""openshell-saw CLI — admin provisioning tool for OpenShell sandboxes on OpenShift.

Users interact with their sandboxes via the upstream 'openshell' CLI.
This tool is for provisioning, teardown, and cluster-level operations."""

import subprocess

import click

from . import config, helm, kube, oidc


@click.group()
@click.option("--namespace", "-n", default=None, help="SAW namespace (default: saw-<sandbox name>)")
@click.option("--shared-namespace", default=None, help="Shared infrastructure namespace (default: openshell-agents)")
@click.option("--ssh-key", default=None, help="Path to SSH private key")
@click.pass_context
def main(ctx, namespace, shared_namespace, ssh_key):
    """Admin provisioning CLI for OpenShell Secure Agent Workspace (SAW) sandboxes on OpenShift."""
    cfg = config.load_config()
    if shared_namespace:
        cfg["shared_namespace"] = shared_namespace
    if ssh_key:
        cfg["ssh_key"] = ssh_key
    cfg["namespace_explicit"] = bool(namespace)
    if namespace:
        cfg["namespace"] = namespace

    ctx.ensure_object(dict)
    ctx.obj["cfg"] = cfg


# --- OIDC commands (for provisioning — users authenticate via 'openshell login') ---


@main.command()
@click.option("--issuer", default=None, help="OIDC issuer URL")
@click.option("--flow", type=click.Choice(["browser", "device-code"]), default=None)
@click.option("--ca-bundle", type=click.Path(exists=True, dir_okay=False), envvar="OIDC_CA_BUNDLE",
              help="PEM CA bundle for the issuer (or OIDC_CA_BUNDLE)")
@click.pass_context
def login(ctx, issuer, flow, ca_bundle):
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
        ca_bundle=ca_bundle,
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


def saw_namespace(cfg, name):
    """Namespace of a SAW: -n if given, otherwise its own saw-<name>."""
    return cfg["namespace"] if cfg.get("namespace_explicit") else config.saw_namespace(name)


@sandbox.command("create")
@click.argument("name")
@click.option("--owner", "-o", default=None, help="Owner username (for labels)")
@click.option("--provider", "-p", required=True, help="Provider the key is for (must match the SAW-BOM profile, e.g. build for NVIDIA)")
@click.option("--model", "-m", required=True, help="Model name")
@click.option("--api-key", "-k", required=True, help="API key (stored in the SAW's 'inference' Secret)")
@click.pass_context
def sandbox_create(ctx, name, owner, provider, model, api_key):
    """Provision a new SAW in its own namespace."""
    cfg = ctx.obj["cfg"]
    shared_ns = cfg["shared_namespace"]
    oidc_cfg = cfg["oidc"]
    ns = saw_namespace(cfg, name)

    issuer = oidc.auto_detect_issuer(
        None, ns, oidc_cfg["token_dir"], oidc_cfg["client_id"],
        shared_namespace=cfg.get("keycloak_namespace", config.KEYCLOAK_NAMESPACE),
    )
    owner_subject = None
    if issuer:
        claims = oidc.token_claims(oidc_cfg["token_dir"])
        owner_subject = claims.get("sub")
        owner = owner or claims.get("preferred_username")

    kube.ensure_namespace(ns)
    kube.label_saw_namespace(ns, owner)
    # The VM's installer reads provider keys only from mounted Secrets; the
    # key never goes into Helm values.
    kube.apply_secret("inference", ns, {"api_key": api_key, "provider": provider, "model": model})

    sets = {
        "sandboxName": name,
        "sshPublicKey": config.ssh_pubkey(cfg["ssh_key"]),
        "route.enabled": "true",
        "route.dashboard": "true",
        "source.dataSourceNamespace": shared_ns,
        "governance.namespace": shared_ns,
        "oidc.keycloakNamespace": cfg.get("keycloak_namespace", config.KEYCLOAK_NAMESPACE),
    }
    set_strings = {}
    if owner:
        sets["accessControl.owner"] = owner
    if owner_subject:
        set_strings["accessControl.ownerSubject"] = owner_subject
    if issuer:
        sets["oidc.issuerUrl"] = issuer
        sets["oidc.clientId"] = oidc_cfg["client_id"]

    click.echo(f"Provisioning SAW '{name}' in namespace '{ns}'...")
    helm.install_chart(release=name, chart_path=config.chart_path("openshell-saw"),
                       namespace=ns, sets=sets, set_strings=set_strings)

    click.echo(f"\nSAW '{name}' deployed in namespace '{ns}'.\n")
    for label, route in (("Gateway", "gateway"), ("Dashboard", "dashboard")):
        url = kube.get_route_url(f"{name}-{route}", ns)
        if url:
            click.echo(f"  {label + ':':<10} {url}")
    click.echo(f"\nFollow the in-VM installer:  openshell-saw sandbox logs {name}")


@sandbox.command("list")
@click.pass_context
def sandbox_list(ctx):
    """List SAWs (all SAW namespaces, or the one given with -n)."""
    cfg = ctx.obj["cfg"]
    sandboxes = helm.list_sandboxes(cfg["namespace"] if cfg.get("namespace_explicit") else None)
    if not sandboxes:
        click.echo("No sandboxes found.")
        return

    click.echo(f"{'NAME':<20} {'NAMESPACE':<24} {'STATUS':<12} {'VM':<10} {'UPDATED'}")
    for sb in sandboxes:
        click.echo(f"{sb['name']:<20} {sb.get('namespace', ''):<24} {sb['status']:<12} "
                   f"{sb['vm_status']:<10} {sb['updated']}")


@sandbox.command("delete")
@click.argument("name")
@click.confirmation_option(prompt="Are you sure you want to delete this sandbox?")
@click.pass_context
def sandbox_delete(ctx, name):
    """Delete a SAW (its namespace is kept; delete it with oc if wanted)."""
    ns = saw_namespace(ctx.obj["cfg"], name)
    helm.uninstall(name, ns)
    click.echo(f"Sandbox '{name}' deleted from namespace '{ns}'.")


@sandbox.command("ssh")
@click.argument("name")
@click.pass_context
def sandbox_ssh(ctx, name):
    """SSH into a SAW VM (needs sshPublicKey)."""
    kube.ssh_sandbox(name, saw_namespace(ctx.obj["cfg"], name))


@sandbox.command("logs")
@click.argument("name")
@click.pass_context
def sandbox_logs(ctx, name):
    """Follow the in-guest installer (VM serial console)."""
    kube.follow_vm_console(name, saw_namespace(ctx.obj["cfg"], name))


@sandbox.command("url")
@click.argument("name")
@click.pass_context
def sandbox_url(ctx, name):
    """Show gateway and dashboard URLs for a sandbox."""
    ns = saw_namespace(ctx.obj["cfg"], name)
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
