"""Owner commands use the same RHDH templates and status service as the browser."""
import json
import re
from urllib.parse import urlsplit

import click
import requests


@click.group()
@click.option("--url", envvar="SAW_RHDH_URL", required=True, help="HTTPS origin of Developer Hub.")
@click.option("--token-file", envvar="SAW_RHDH_TOKEN_FILE", required=True, type=click.File("r"),
              help="File containing a Backstage identity token. Use - for stdin.")
@click.pass_context
def workspace(ctx, url, token_file):
    """Manage your workspace through Developer Hub."""
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise click.UsageError("Provide the HTTPS origin of Developer Hub.")
    token = token_file.read().strip()
    if not token or any(char.isspace() for char in token):
        raise click.UsageError("Expected one identity token.")
    ctx.obj = (url.rstrip("/"), token)


def call(context, path, payload=None):
    url, token = context
    headers = {"Authorization": "Bearer " + token}
    if path.startswith("/api/proxy/saw-status/"):
        headers["X-Saw-Token"] = token
    try:
        response = requests.request("GET" if payload is None else "POST", url + path,
                                    headers=headers, json=payload, timeout=30, allow_redirects=False)
    except requests.RequestException as exc:
        raise click.ClickException("Developer Hub request failed") from exc
    if not 200 <= response.status_code < 300:
        raise click.ClickException(f"Developer Hub returned HTTP {response.status_code}")
    return response.json()


@workspace.command()
@click.pass_obj
def status(context):
    """Show desired and observed workspace state."""
    click.echo(json.dumps(call(context, "/api/proxy/saw-status/workspace"), indent=2))


@workspace.command()
@click.argument("run")
@click.pass_obj
def logs(context, run):
    """Read the provisioning log for one of your Tekton runs."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,61}[a-z0-9]", run):
        raise click.UsageError("Expected a Tekton run name.")
    click.echo(call(context, "/api/proxy/saw-status/run/" + run)["text"])


def set_state(context, operation):
    task = call(context, "/api/scaffolder/v2/tasks", {
        "templateRef": "template:default/set-saw-workspace-state",
        "values": {"operation": operation}, "secrets": {}})
    click.echo(json.dumps({"task": task["id"]}))


@workspace.command()
@click.pass_obj
def stop(context):
    """Stop the sandboxes and retain their storage."""
    set_state(context, "stop")


@workspace.command()
@click.pass_obj
def start(context):
    """Resume the registered sandboxes."""
    set_state(context, "start")
