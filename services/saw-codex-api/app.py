"""saw-codex-api — REST API for managing Codex sessions on SAW."""

import asyncio
import re
import time

from fastapi import Depends, FastAPI, HTTPException
from jose import jwt as jose_jwt
from pydantic import BaseModel

from . import config
from .auth import get_current_user
from .k8s import (
    ConnectionInfo,
    Session,
    get_codex_secret,
    get_vm_owner,
    helm_install,
    helm_uninstall,
    list_user_vms,
    _get_route_url,
)

app = FastAPI(title="saw-codex-api", version="0.1.0")

_SAFE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,18}$")


def _validate_name(name: str) -> str:
    if not _SAFE_NAME_RE.match(name):
        raise HTTPException(
            status_code=400,
            detail="Name must be 1-19 lowercase alphanumeric chars or hyphens, "
            "starting with a letter",
        )
    return name


class SessionResponse(BaseModel):
    name: str
    status: str
    created: str
    owner: str
    ws_url: str | None
    has_secret: bool


class ConnectResponse(BaseModel):
    ws_url: str
    token: str
    expires_in: int


class CreateRequest(BaseModel):
    name: str


class CreateResponse(BaseModel):
    name: str
    status: str


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(username: str = Depends(get_current_user)):
    sessions = await asyncio.to_thread(list_user_vms, username)
    return [
        SessionResponse(
            name=s.name,
            status=s.status,
            created=s.created,
            owner=s.owner,
            ws_url=s.ws_url,
            has_secret=s.has_secret,
        )
        for s in sessions
    ]


@app.post("/sessions", response_model=CreateResponse, status_code=202)
async def create_session(
    body: CreateRequest, username: str = Depends(get_current_user)
):
    name = _validate_name(body.name)

    existing = await asyncio.to_thread(list_user_vms, username)
    if len(existing) >= config.MAX_SESSIONS_PER_USER:
        raise HTTPException(
            status_code=429,
            detail=f"Session limit reached ({config.MAX_SESSIONS_PER_USER}). "
            "Delete an existing session first.",
        )

    asyncio.get_event_loop().run_in_executor(
        None, helm_install, name, username
    )
    return CreateResponse(name=name, status="creating")


@app.delete("/sessions/{name}", status_code=204)
async def delete_session(name: str, username: str = Depends(get_current_user)):
    _validate_name(name)
    owner = await asyncio.to_thread(get_vm_owner, name)
    if owner is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if owner != username:
        raise HTTPException(status_code=403, detail="Not your session")

    ok = await asyncio.to_thread(helm_uninstall, name)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to delete session")


@app.get("/sessions/{name}/connect", response_model=ConnectResponse)
async def connect_session(
    name: str, username: str = Depends(get_current_user)
):
    _validate_name(name)
    owner = await asyncio.to_thread(get_vm_owner, name)
    if owner is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if owner != username:
        raise HTTPException(status_code=403, detail="Not your session")

    ws_secret = await asyncio.to_thread(get_codex_secret, name)
    if not ws_secret:
        raise HTTPException(
            status_code=503,
            detail="Session not ready — codex secret not yet available",
        )

    ws_url = await asyncio.to_thread(
        _get_route_url, name, config.MANAGED_NAMESPACE
    )
    if not ws_url:
        raise HTTPException(
            status_code=503, detail="Session not ready — route not available"
        )

    now = int(time.time())
    ttl = config.SESSION_TOKEN_TTL
    token = jose_jwt.encode(
        {
            "iss": "saw-codex",
            "aud": "codex-session",
            "sub": username,
            "exp": now + ttl,
        },
        ws_secret,
        algorithm="HS256",
    )

    return ConnectResponse(ws_url=ws_url, token=token, expires_in=ttl)
