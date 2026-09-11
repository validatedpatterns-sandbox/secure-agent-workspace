"""Entry point for codex-saw TUI."""


def main():
    from .app import CodexSawApp

    app = CodexSawApp()
    app.run()


if __name__ == "__main__":
    main()
