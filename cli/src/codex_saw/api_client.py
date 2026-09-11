"""HTTP client for the saw-codex-api service."""

import httpx


class SawCodexClient:
    def __init__(self, api_url: str, token: str):
        self.api_url = api_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}

    def list_sessions(self) -> list[dict]:
        r = httpx.get(
            f"{self.api_url}/sessions",
            headers=self.headers,
            timeout=15,
            verify=False,
        )
        r.raise_for_status()
        return r.json()

    def create_session(self, name: str) -> dict:
        r = httpx.post(
            f"{self.api_url}/sessions",
            json={"name": name},
            headers=self.headers,
            timeout=60,
            verify=False,
        )
        r.raise_for_status()
        return r.json()

    def delete_session(self, name: str) -> bool:
        r = httpx.delete(
            f"{self.api_url}/sessions/{name}",
            headers=self.headers,
            timeout=30,
            verify=False,
        )
        return r.status_code in (200, 204)

    def get_connection_info(self, name: str) -> dict:
        r = httpx.get(
            f"{self.api_url}/sessions/{name}/connect",
            headers=self.headers,
            timeout=15,
            verify=False,
        )
        r.raise_for_status()
        return r.json()
