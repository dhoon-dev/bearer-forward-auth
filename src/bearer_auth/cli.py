"""Command line interface for bearer-auth."""

import logging
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.logging import RichHandler
from rich.traceback import install as install_rich_traceback

from bearer_auth.api import create_app

DEFAULT_HOST = "0.0.0.0"  # noqa: S104 - Required for Docker container networking.
DEFAULT_PORT = 8080
DEFAULT_TOKENS_FILE = "/run/tokens/tokens.txt"
DEFAULT_TOKENS_PATH = Path(DEFAULT_TOKENS_FILE)
MIN_PORT = 1
MAX_PORT = 65535

CONSOLE = Console()
ERROR_CONSOLE = Console(stderr=True)


class LogLevel(StrEnum):
    """Supported CLI log levels."""

    debug = "DEBUG"
    info = "INFO"
    warning = "WARNING"
    error = "ERROR"
    critical = "CRITICAL"


def configure_logging(log_level: LogLevel) -> None:
    """Configure Rich logging."""
    logging.basicConfig(
        level=log_level.value,
        format="%(message)s",
        handlers=[
            RichHandler(
                console=ERROR_CONSOLE,
                markup=True,
                rich_tracebacks=True,
                show_path=False,
            ),
        ],
    )


def run_server(
    host: Annotated[
        str,
        typer.Option("--host", help="Address to bind."),
    ] = DEFAULT_HOST,
    port: Annotated[
        int,
        typer.Option("--port", help="Port to listen on.", min=MIN_PORT, max=MAX_PORT),
    ] = DEFAULT_PORT,
    tokens_file: Annotated[
        Path,
        typer.Option(
            "--tokens-file",
            dir_okay=False,
            exists=True,
            help="Path to the newline-delimited token file.",
            readable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_TOKENS_PATH,
    log_level: Annotated[
        LogLevel,
        typer.Option("--log-level", case_sensitive=False, help="Log level."),
    ] = LogLevel.info,
) -> None:
    """Run the auth service with Uvicorn."""
    install_rich_traceback(console=ERROR_CONSOLE, show_locals=False)
    configure_logging(log_level)
    service_app = create_app(tokens_file)

    CONSOLE.print(
        f"[bold green]bearer-auth[/bold green] listening on [cyan]{host}:{port}[/cyan]",
    )
    uvicorn.run(service_app, host=host, port=port, access_log=False)


def main() -> None:
    """Parse CLI options with Typer and run the server."""
    typer.run(run_server)
