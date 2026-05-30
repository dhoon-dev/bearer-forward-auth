# bearer-auth

Small FastAPI service for checking `Authorization: Bearer <token>` headers.

It is designed for reverse-proxy external auth flows such as Traefik ForwardAuth, NGINX `auth_request`, or Caddy `forward_auth`. The service returns `204 No Content` when the bearer token is allowed and `401 Unauthorized` otherwise.

## Behavior

- `GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS /auth`
  - Reads `Authorization: Bearer <token>`
  - Returns `204 No Content` when the token exists in the token file
  - Returns `401 Unauthorized` when the header is missing, malformed, or unknown
- `GET|HEAD /health`
  - Returns `200 OK`
  - Does not require authentication

Tokens are loaded once at startup. Restart the process or container after editing the token file.

## Token File

The token file is newline-delimited:

```text
# Lines starting with # are ignored.
# Empty lines are ignored.
sk-local-abc...
sk-local-def...
```

Do not commit real token files. Mount them at runtime.

## CLI

```sh
bearer-auth --tokens-file ./tokens/tokens.txt
```

Options:

```text
--host TEXT                         Address to bind. Default: 0.0.0.0
--port INTEGER RANGE [1<=x<=65535]  Port to listen on. Default: 8080
--tokens-file FILE                  Token file path. Default: /run/tokens/tokens.txt
--log-level LEVEL                   debug, info, warning, error, critical
```

Show Rich-powered help:

```sh
uv run bearer-auth --help
```

Run from a Git tag without installing:

```sh
uvx --from git+https://github.com/dhoon-dev/bearer-forward-auth.git@v0.1.0 bearer-auth --tokens-file ./tokens/tokens.txt
```

## Docker

Build locally:

```sh
docker build -t bearer-auth:local .
```

Run:

```sh
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/tokens/tokens.txt:/run/tokens/tokens.txt:ro" \
  bearer-auth:local \
  --tokens-file /run/tokens/tokens.txt
```

Build directly from a Git tag:

```sh
docker build \
  -t bearer-auth:local \
  https://github.com/dhoon-dev/bearer-forward-auth.git#v0.1.0
```

If this project is inside a larger monorepo:

```sh
docker build \
  -t bearer-auth:local \
  https://github.com/dhoon-dev/bearer-forward-auth.git#v0.1.0:path/to/bearer-auth
```

## Docker Compose

Create `.env` from the example and edit it for the host:

```sh
cp .env.example .env
```

```dotenv
BEARER_AUTH_HOST=0.0.0.0
BEARER_AUTH_PORT=8080
BEARER_AUTH_TOKENS_SOURCE=./tokens/tokens.txt
BEARER_AUTH_TOKENS_FILE=/run/tokens/tokens.txt
BEARER_AUTH_LOG_LEVEL=INFO
BEARER_AUTH_UID=1000
BEARER_AUTH_GID=1000
```

```sh
docker compose up -d --build
```

The included Compose file:

- Does not publish host ports
- Connects the service to the external `proxy` network
- Reads runtime settings from `.env`
- Mounts `${BEARER_AUTH_TOKENS_SOURCE}` read-only at `${BEARER_AUTH_TOKENS_FILE}`
- Runs as `${BEARER_AUTH_UID:-1000}:${BEARER_AUTH_GID:-1000}` so a host-owned `0600` token file can remain private

The service is reachable to other containers on the `proxy` network at:

```text
http://bearer-auth:8080/auth
```

If you change `BEARER_AUTH_PORT`, update any reverse-proxy ForwardAuth URL that points to this service.

Override values by editing `.env`, or pass them for one command:

```sh
BEARER_AUTH_PORT=8080 BEARER_AUTH_UID="$(id -u)" BEARER_AUTH_GID="$(id -g)" docker compose up -d --build
```

## Traefik Example

Remove direct host port publishing from the upstream service and attach it to the `proxy` network. Apply the auth middleware before stripping the `Authorization` header, so the auth service sees the bearer token but the upstream service does not.

```yaml
services:
  upstream-api:
    image: traefik/whoami:v1.11
    networks:
      - proxy
    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=proxy"
      - "traefik.http.routers.upstream-api.rule=Host(`api.example.com`)"
      - "traefik.http.routers.upstream-api.entrypoints=websecure"
      - "traefik.http.routers.upstream-api.tls.certresolver=le"
      - "traefik.http.routers.upstream-api.service=upstream-api"
      - "traefik.http.routers.upstream-api.middlewares=upstream-api-auth@docker,upstream-api-strip-auth@docker"
      - "traefik.http.middlewares.upstream-api-auth.forwardauth.address=http://bearer-auth:8080/auth"
      - "traefik.http.middlewares.upstream-api-strip-auth.headers.customrequestheaders.Authorization="
      - "traefik.http.services.upstream-api.loadbalancer.server.port=80"
    restart: unless-stopped

networks:
  proxy:
    name: proxy
    external: true
```

Replace `api.example.com` and `loadbalancer.server.port` with the upstream service's internal hostname and port. Keep the upstream service unpublished on the host unless you intentionally need a bypass path.

## Development

```sh
uv sync
uv run ruff check .
uv run ruff format .
uv run ty check
uv run bearer-auth --tokens-file ./tokens/tokens.txt
```

Build the package:

```sh
uv build
```

## Contributing

Use Conventional Commits for commit messages. See `AGENTS.md` for the project rules and examples.

## Project Layout

```text
src/bearer_auth/
├── auth.py      # Pure bearer-token parsing and authorization rules
├── tokens.py    # Token file loading
├── api.py       # FastAPI adapter
├── cli.py       # Typer/Rich CLI and Uvicorn process runner
└── server.py    # Compatibility ASGI/module entrypoint
```
