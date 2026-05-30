"""FastAPI adapter for bearer token authentication."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, cast

from fastapi import FastAPI, Header, HTTPException, Request, Response, status

from bearer_auth.auth import is_authorized
from bearer_auth.tokens import load_tokens

LOGGER = logging.getLogger("bearer-auth")


def create_app(tokens_file: Path) -> FastAPI:
    """Create the FastAPI application."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        """Load the token file once when FastAPI starts."""
        tokens = load_tokens(tokens_file)
        _app.state.tokens = tokens
        LOGGER.info("loaded %s token(s) from %s", len(tokens), tokens_file)
        yield

    app = FastAPI(title="bearer-auth", docs_url=None, redoc_url=None, lifespan=lifespan)

    @app.api_route("/health", methods=["GET", "HEAD"])
    async def health() -> dict[str, bool]:
        """Return an unauthenticated health response."""
        return {"ok": True}

    @app.api_route(
        "/auth",
        methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        status_code=status.HTTP_204_NO_CONTENT,
    )
    async def auth(
        request: Request,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ) -> Response:
        """Validate a bearer token for Traefik ForwardAuth."""
        tokens = cast("frozenset[str]", request.app.state.tokens)

        if is_authorized(authorization, tokens):
            return Response(status_code=status.HTTP_204_NO_CONTENT)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return app
