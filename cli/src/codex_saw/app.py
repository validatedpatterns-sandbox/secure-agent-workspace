"""Codex SAW TUI — terminal UI for managing Codex sessions."""

import os
import secrets as secrets_mod
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import httpx

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Center, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
)

from . import auth, config
from .api_client import SawCodexClient


def _to_local_time(iso_str: str) -> str:
    if not iso_str:
        return ""
    try:
        utc = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        local = utc.astimezone()
        return local.strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return iso_str


class LoginScreen(Screen):
    BINDINGS = [
        Binding("enter", "login", "Login"),
        Binding("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Center():
            with Vertical(id="login-box"):
                yield Static(
                    "\n  Codex Workspaces\n\n"
                    "  Press [bold]Enter[/bold] to authenticate via browser,\n"
                    "  or set SAW_CODEX_OIDC_ISSUER if not configured.\n",
                    id="login-prompt",
                )
        yield Footer()

    def action_login(self):
        self.app.do_login()

    def action_quit(self):
        self.app.exit()


class CreateSessionScreen(ModalScreen[str | None]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        default_name = f"codex-{secrets_mod.token_hex(2)}"
        with Vertical(id="create-dialog"):
            yield Label("Create new Codex session")
            yield Input(value=default_name, placeholder="Session name", id="session-name")
            yield Static("Press [bold]Enter[/bold] to create, [bold]Escape[/bold] to cancel")

    def on_input_submitted(self, event: Input.Submitted):
        name = event.value.strip()
        if name:
            self.dismiss(name)

    def action_cancel(self):
        self.dismiss(None)


class SessionsScreen(Screen):
    BINDINGS = [
        Binding("n", "new_session", "New"),
        Binding("d", "delete_session", "Delete"),
        Binding("enter", "connect", "Connect"),
        Binding("r", "refresh", "Refresh"),
        Binding("slash", "search", "Search"),
        Binding("s", "sort", "Sort"),
        Binding("l", "logout", "Logout"),
        Binding("q", "quit", "Quit"),
    ]

    _filter: str = ""
    _sort_by: str = "created"
    _sort_reverse: bool = True
    _all_sessions: list = []

    def compose(self) -> ComposeResult:
        username = auth.get_username(self.app.cfg["oidc"]["token_dir"]) or "unknown"
        yield Header()
        yield Static(f"  Logged in as [bold]{username}[/bold]", id="user-info")
        yield Input(placeholder="Type to filter by name...", id="search-input")
        yield DataTable(id="sessions-table")
        yield Footer()

    def on_mount(self):
        table = self.query_one("#sessions-table", DataTable)
        table.add_columns("NAME", "STATUS", "CREATED", "URL")
        table.cursor_type = "row"
        self.query_one("#search-input", Input).display = False
        self.load_sessions()
        self.set_interval(10, self.load_sessions)

    def action_search(self):
        search = self.query_one("#search-input", Input)
        search.display = not search.display
        if search.display:
            search.focus()
            search.value = self._filter
        else:
            self._filter = ""
            self._render_table()

    def on_input_changed(self, event: Input.Changed):
        if event.input.id == "search-input":
            self._filter = event.value.strip().lower()
            self._render_table()

    def action_sort(self):
        if self._sort_by == "created":
            self._sort_by = "name"
            self._sort_reverse = False
        else:
            self._sort_by = "created"
            self._sort_reverse = True
        self.app.notify(f"Sorted by {self._sort_by}")
        self._render_table()

    @work(thread=True, exclusive=True)
    def load_sessions(self):
        try:
            client = self.app.get_client()
            self._all_sessions = client.list_sessions()
        except Exception as e:
            self.app.notify(f"Failed to load sessions: {e}", severity="error")
            return

        self.app.call_from_thread(self._render_table)

    def _render_table(self):
        table = self.query_one("#sessions-table", DataTable)
        table.clear()

        filtered = [
            s for s in self._all_sessions
            if s.get("ws_url")
            and (not self._filter or self._filter in s.get("name", "").lower())
        ]

        filtered.sort(
            key=lambda s: s.get(self._sort_by, ""),
            reverse=self._sort_reverse,
        )

        for s in filtered:
            table.add_row(
                s.get("name", ""),
                s.get("status", ""),
                _to_local_time(s.get("created", "")),
                s.get("ws_url", ""),
                key=s.get("name", ""),
            )

    def action_new_session(self):
        def on_result(name: str | None):
            if name:
                self.create_session(name)

        self.app.push_screen(CreateSessionScreen(), callback=on_result)

    @work(thread=True)
    def create_session(self, name: str):
        self.app.notify(f"Creating session '{name}'...")
        try:
            client = self.app.get_client()
            client.create_session(name)
            self.app.notify(f"Session '{name}' created.")
            self.load_sessions()
        except Exception as e:
            self.app.notify(f"Failed to create session: {e}", severity="error")

    def action_delete_session(self):
        table = self.query_one("#sessions-table", DataTable)
        if table.row_count == 0:
            return
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        name = row_key.value if hasattr(row_key, "value") else str(row_key)
        if name:
            self.delete_session(name)

    @work(thread=True)
    def delete_session(self, name: str):
        self.app.notify(f"Deleting session '{name}'...")
        try:
            client = self.app.get_client()
            client.delete_session(name)
            self.app.notify(f"Session '{name}' deleted.")
            self.load_sessions()
        except Exception as e:
            self.app.notify(f"Failed to delete session: {e}", severity="error")

    def _get_selected_session(self):
        table = self.query_one("#sessions-table", DataTable)
        if table.row_count == 0:
            return None, None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        name = row_key.value if hasattr(row_key, "value") else str(row_key)
        row = table.get_row(row_key)
        status = str(row[1]) if len(row) > 1 else ""
        return name, status

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        name = event.row_key.value if hasattr(event.row_key, "value") else str(event.row_key)
        row = self.query_one("#sessions-table", DataTable).get_row(event.row_key)
        status = str(row[1]) if len(row) > 1 else ""
        if status not in ("running", "unmanaged"):
            return
        if name:
            self._fetch_and_connect(name)

    def action_connect(self):
        name, status = self._get_selected_session()
        if not name or status not in ("running", "unmanaged"):
            return
        self._fetch_and_connect(name)

    @work(thread=True)
    def _fetch_and_connect(self, name: str):
        self.app.notify(f"Connecting to '{name}'...")
        try:
            client = self.app.get_client()
            info = client.get_connection_info(name)
            self.app.call_from_thread(
                self.app._launch_codex, info["ws_url"], info["token"]
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 503:
                detail = e.response.json().get("detail", "not ready")
                self.app.call_from_thread(
                    self.app.notify, f"Session not ready: {detail}", severity="warning"
                )
            else:
                self.app.call_from_thread(
                    self.app.notify, f"Failed to connect: {e}", severity="error"
                )
        except Exception as e:
            self.app.call_from_thread(
                self.app.notify, f"Failed to connect: {e}", severity="error"
            )

    def action_refresh(self):
        self.load_sessions()
        self.app.notify("Refreshed.")

    def action_logout(self):
        token_dir = self.app.cfg["oidc"]["token_dir"]
        token_file = Path(token_dir) / "token.json"
        if token_file.exists():
            token_file.unlink()
        self.app._token = None
        self.app.notify("Logged out.")
        self.app.switch_screen(LoginScreen())

    def action_quit(self):
        self.app.exit()


class CodexSawApp(App):
    TITLE = "Codex Workspaces"
    CSS = """
    #login-box {
        width: 60;
        height: 12;
        border: solid green;
        padding: 1 2;
    }
    #login-prompt {
        text-align: center;
    }
    #user-info {
        height: 1;
        margin: 0 0 1 0;
    }
    #create-dialog {
        width: 50;
        height: 10;
        border: solid green;
        padding: 1 2;
        background: $surface;
    }
    #search-input {
        height: 1;
        margin: 0 0 0 0;
        dock: top;
    }
    """

    def __init__(self):
        super().__init__()
        self.cfg = config.load_config()
        self._token = None

    def on_mount(self):
        self._token = auth.ensure_authenticated(self.cfg)
        if self._token:
            self.push_screen(SessionsScreen())
        else:
            self.push_screen(LoginScreen())

    def do_login(self):
        issuer = self.cfg["oidc"].get("issuer_url", "")
        client_id = self.cfg["oidc"]["client_id"]
        token_dir = self.cfg["oidc"]["token_dir"]

        if not issuer:
            self.notify("Set SAW_CODEX_OIDC_ISSUER or oidc.issuer_url in config.", severity="error")
            return

        self._run_browser_login(issuer, client_id, token_dir)

    @work(thread=True)
    def _run_browser_login(self, issuer, client_id, token_dir):
        try:
            self._token = auth.browser_login(issuer, client_id, token_dir)
            self.call_from_thread(self.switch_screen, SessionsScreen())
        except Exception as e:
            self.call_from_thread(self.notify, f"Login failed: {e}", severity="error")

    def _launch_codex(self, ws_url: str, token: str):
        os.environ["CODEX_TOKEN"] = token
        with self.suspend():
            os.system("clear")
            subprocess.run(
                ["codex", "--remote", ws_url,
                 "--remote-auth-token-env", "CODEX_TOKEN"],
            )

    def get_client(self) -> SawCodexClient:
        token = auth.get_token(
            self.cfg["oidc"]["token_dir"],
            self.cfg["oidc"]["client_id"],
        )
        if not token:
            raise RuntimeError("Not authenticated. Restart codex-saw to login.")
        return SawCodexClient(self.cfg["api_url"], token)
