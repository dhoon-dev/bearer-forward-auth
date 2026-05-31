"""FastAPI adapter for bearer token authentication."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, cast

from fastapi import FastAPI, Header, HTTPException, Request, Response, status

from bearer_auth.auth import is_domain_authorized
from bearer_auth.tokens import TokenStore

LOGGER = logging.getLogger("bearer-auth")
FORWARDED_HOST_HEADER = "X-Forwarded-Host"


def create_app(tokens_file: Path) -> FastAPI:
    """Create the FastAPI application."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        """Load the token file when FastAPI starts."""
        token_store = TokenStore(tokens_file)
        tokens_by_domain = token_store.reload()
        _app.state.token_store = token_store
        token_count = sum(len(tokens) for tokens in tokens_by_domain.values())
        LOGGER.info(
            "loaded %s token(s) for %s domain(s) from %s",
            token_count,
            len(tokens_by_domain),
            tokens_file,
        )
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
        forwarded_host: Annotated[str | None, Header(alias=FORWARDED_HOST_HEADER)] = None,
        host: Annotated[str | None, Header(alias="Host")] = None,
    ) -> Response:
        """Validate a bearer token for Traefik ForwardAuth."""
        token_store = cast("TokenStore", request.app.state.token_store)
        tokens_by_domain = token_store.get_tokens()
        request_host = forwarded_host or host

        if is_domain_authorized(request_host, authorization, tokens_by_domain):
            return Response(status_code=status.HTTP_204_NO_CONTENT)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return app
