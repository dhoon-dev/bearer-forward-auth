"""Compatibility entrypoint for ASGI servers and direct module execution."""

from pathlib import Path

from bearer_auth.api import create_app
from bearer_auth.cli import main

DEFAULT_TOKENS_FILE = "/run/tokens/tokens.txt"

app = create_app(Path(DEFAULT_TOKENS_FILE))


if __name__ == "__main__":
    main()
