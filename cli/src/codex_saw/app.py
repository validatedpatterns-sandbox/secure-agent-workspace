"""Codex SAW TUI — terminal UI for managing Codex sessions."""

import os
import secrets as secrets_mod

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
        Binding("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        username = auth.get_username(self.app.cfg["oidc"]["token_dir"]) or "unknown"
        yield Header()
        yield Static(f"  Logged in as [bold]{username}[/bold]", id="user-info")
        yield DataTable(id="sessions-table")
        yield Footer()

    def on_mount(self):
        table = self.query_one("#sessions-table", DataTable)
        table.add_columns("NAME", "STATUS", "CREATED", "URL")
        table.cursor_type = "row"
        self.load_sessions()
        self.set_interval(10, self.load_sessions)

    @work(thread=True)
    def load_sessions(self):
        try:
            client = self.app.get_client()
            sessions = client.list_sessions()
        except Exception as e:
            self.app.notify(f"Failed to load sessions: {e}", severity="error")
            return

        table = self.query_one("#sessions-table", DataTable)
        table.clear()
        for s in sessions:
            table.add_row(
                s.get("name", ""),
                s.get("status", ""),
                s.get("created", ""),
                s.get("url", ""),
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
        name = str(row_key)
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

    def action_connect(self):
        table = self.query_one("#sessions-table", DataTable)
        if table.row_count == 0:
            return
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        name = str(row_key)
        if name:
            self.connect_session(name)

    @work(thread=True)
    def connect_session(self, name: str):
        self.app.notify(f"Connecting to '{name}'...")
        try:
            client = self.app.get_client()
            info = client.get_connection_info(name)
            ws_url = info["ws_url"]
            token = info["token"]
            os.environ["CODEX_TOKEN"] = token
            self.app.exit()
            os.execvp(
                "codex",
                ["codex", "--remote", f"{ws_url}:443", "--remote-auth-token-env", "CODEX_TOKEN"],
            )
        except Exception as e:
            self.app.notify(f"Failed to connect: {e}", severity="error")

    def action_refresh(self):
        self.load_sessions()
        self.app.notify("Refreshed.")

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
            self.switch_screen(SessionsScreen())
        except Exception as e:
            self.notify(f"Login failed: {e}", severity="error")

    def get_client(self) -> SawCodexClient:
        token = auth.get_token(
            self.cfg["oidc"]["token_dir"],
            self.cfg["oidc"]["client_id"],
        )
        if not token:
            raise RuntimeError("Not authenticated. Restart codex-saw to login.")
        return SawCodexClient(self.cfg["api_url"], token)
