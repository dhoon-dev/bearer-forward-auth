FROM ghcr.io/astral-sh/uv:0.8.15-python3.13-alpine

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV UV_NO_DEV=1
ENV PATH=/app/.venv/bin:$PATH

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-editable

EXPOSE 8080

ENTRYPOINT ["bearer-auth"]
