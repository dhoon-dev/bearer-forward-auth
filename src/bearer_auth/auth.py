"""Bearer token validation rules."""

BEARER_TOKEN_PARTS = 2


def extract_bearer_token(authorization: str | None) -> str | None:
    """Extract the token from an Authorization: Bearer header."""
    if not authorization:
        return None

    parts = authorization.strip().split()
    if len(parts) != BEARER_TOKEN_PARTS or parts[0].lower() != "bearer":
        return None

    return parts[1]


def is_authorized(authorization: str | None, allowed_tokens: frozenset[str]) -> bool:
    """Return whether an Authorization header contains an allowed bearer token."""
    token = extract_bearer_token(authorization)
    return bool(token and token in allowed_tokens)
