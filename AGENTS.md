# AGENTS.md

## Project Purpose

This project provides a small FastAPI bearer-token auth service for reverse-proxy external authentication flows.

The service checks `Authorization: Bearer <token>` against the request domain's token section and returns:

- `204 No Content` for allowed tokens
- `401 Unauthorized` for missing, malformed, or unknown domains/tokens
- `200 OK` for unauthenticated `/health`
- Token file changes must be detected on the next `/auth` request without restarting the process

## Architecture Rules

Keep business logic and IO adapters separated:

- `src/bearer_auth/auth.py`
  - Pure bearer-token/domain parsing and authorization decisions
  - No FastAPI, Typer, Rich, file IO, logging, or process startup
- `src/bearer_auth/tokens.py`
  - Token file loading and change detection only
  - Ignore empty lines and lines starting with `#`
  - Load `[domain]` sections with ASCII/punycode domain names only
  - Never log token values
- `src/bearer_auth/api.py`
  - FastAPI routes and HTTP status mapping
  - Use `auth.py` for authorization decisions
  - Use `tokens.py` for startup token loading
- `src/bearer_auth/cli.py`
  - Typer CLI options, Rich console/logging, Uvicorn startup
  - Runtime configuration should be CLI arguments, not app-specific environment variables
- `src/bearer_auth/server.py`
  - Thin compatibility entrypoint only
  - Expose `app` for ASGI use and support direct module execution

## Runtime Contract

Supported CLI options:

- `--host`
- `--port`
- `--tokens-file`
- `--log-level`

Do not add runtime configuration through environment variables unless there is a strong deployment reason. Prefer explicit CLI options and update README/Compose examples when adding options.

## Security Rules

- Never log bearer token values.
- Keep real token files out of Git.
- Keep `tokens/tokens.txt` as an example or local runtime file only.
- Mount the token directory, not only the token file, so atomic file replacements are visible inside the container.
- Warn users that in-place token file rewrites can temporarily produce incomplete reads and `401 Unauthorized`; prefer atomic replacement until lock-based updates are implemented.
- Domain matching must use normalized ASCII/punycode host names only. Reject non-ASCII host headers, URLs, paths, IP literals, wildcard domains, malformed labels, and invalid ports.
- `/auth` should prefer the proxy-supplied `X-Forwarded-Host` header and fall back to `Host` for local/direct checks.
- Documentation must warn users not to pass client-supplied forwarded host headers through unchanged.
- Keep the upstream `Authorization` header stripping warning in documentation when showing proxy examples.
- `/health` must remain unauthenticated.
- `/auth` success must remain `204 No Content`; auth failure must remain `401 Unauthorized`.

## Python Tooling

Use `uv`.

Required checks before finishing code changes:

```sh
uv run ruff check .
uv run ruff format --check .
uv run ty check
docker compose config
```

For package or Docker changes, also run:

```sh
uv build
docker compose build
```

When verifying behavior locally:

```sh
uv run bearer-auth --tokens-file ./tokens/tokens.txt
```

Then check:

```sh
curl -i http://127.0.0.1:8080/health
curl -i http://127.0.0.1:8080/auth
curl -i -H 'Host: <domain>' -H 'Authorization: Bearer <token>' http://127.0.0.1:8080/auth
```

## Commit Message Rule

Use Conventional Commits:

```text
<type>(optional-scope): <description>
```

Allowed types:

- `feat`: new user-facing capability
- `fix`: bug fix
- `docs`: documentation-only change
- `chore`: maintenance, cleanup, or tooling
- `refactor`: code change without behavior change
- `test`: test or verification-related change
- `ci`: CI/CD configuration change

Guidelines:

- Use imperative mood in the description.
- Keep the first line under 72 characters when practical.
- Do not end the subject line with a period.
- Use a body when the reason for the change is not obvious.

Examples:

```text
feat: add bearer token auth service
docs: document Traefik middleware setup
fix: reject malformed authorization headers
chore: update uv lockfile
```

## Ruff and Type Checking

Ruff uses `select = ["ALL"]`.

Current intentional ignores:

- `COM812`: formatter conflict
- `D203`: conflicts with `D211`
- `D213`: conflicts with `D212`

Do not add new Ruff ignores casually. Prefer changing code. If an ignore is necessary, document why in README or AGENTS.md.

## Docker and Compose

The Docker image should:

- Use the uv Python Alpine base image
- Install with `uv sync --locked --no-editable`
- Use `ENTRYPOINT ["bearer-auth"]`
- Receive runtime settings through Compose `command:`

The Compose service should:

- Not publish host ports
- Join the external `proxy` network
- Mount the token directory read-only
- Read runtime settings from `.env` via `BEARER_AUTH_*` variables
- Run with a configurable UID/GID so private host-owned token files can be read

## External Docs

When changing third-party API usage or config, consult Context7 first. Relevant packages and surfaces include:

- FastAPI route definitions, lifespan, headers, exceptions
- Typer options and Rich-powered help
- Rich console/logging
- Uvicorn startup
- uv package/Docker workflows
- Docker Compose syntax
