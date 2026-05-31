"""Bearer token validation rules."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address

BEARER_TOKEN_PARTS = 2
MAX_DOMAIN_LENGTH = 253
MAX_DOMAIN_LABEL_LENGTH = 63
MIN_PORT = 1
MAX_PORT = 65535

DOMAIN_PATTERN = re.compile(r"^[a-z0-9.-]+$")


@dataclass(frozen=True)
class TokenEntry:
    """Authorization metadata for a bearer token."""

    expires_at: datetime | None = None

    def is_valid_at(self, now: datetime) -> bool:
        """Return whether the token has not expired at the given time."""
        if now.tzinfo is None or now.utcoffset() is None:
            msg = "now must be timezone-aware"
            raise ValueError(msg)

        return self.expires_at is None or now.astimezone(UTC) < self.expires_at


type AllowedTokens = Mapping[str, TokenEntry]
type TokensByDomain = Mapping[str, AllowedTokens]


def extract_bearer_token(authorization: str | None) -> str | None:
    """Extract the token from an Authorization: Bearer header."""
    if not authorization:
        return None

    parts = authorization.strip().split()
    if len(parts) != BEARER_TOKEN_PARTS or parts[0].lower() != "bearer":
        return None

    return parts[1]


def is_authorized(
    authorization: str | None,
    allowed_tokens: AllowedTokens,
    now: datetime,
) -> bool:
    """Return whether an Authorization header contains an allowed bearer token."""
    token = extract_bearer_token(authorization)
    if token is None:
        return False

    token_entry = allowed_tokens.get(token)
    return token_entry is not None and token_entry.is_valid_at(now)


def normalize_domain(value: str | None) -> str | None:
    """Return the canonical ASCII domain form for auth comparisons."""
    domain = strip_optional_port(value)
    if domain is None:
        return None

    domain = domain.rstrip(".").lower()
    if is_valid_domain(domain):
        return domain

    return None


def strip_optional_port(value: str | None) -> str | None:
    """Remove a valid host port when one is present."""
    if not value:
        return None

    domain = value.strip()
    if not domain or "://" in domain or "/" in domain or "\\" in domain or "@" in domain:
        return None

    if domain.startswith("["):
        return None

    if ":" in domain:
        domain, port = domain.rsplit(":", 1)
        if not is_valid_port(port) or not domain or ":" in domain:
            return None

    return domain


def is_valid_port(value: str) -> bool:
    """Return whether a host port is in range."""
    if not value.isdigit():
        return False

    port_number = int(value)
    return MIN_PORT <= port_number <= MAX_PORT


def is_valid_domain(domain: str) -> bool:
    """Return whether a normalized domain is allowed."""
    if not domain or len(domain) > MAX_DOMAIN_LENGTH or not DOMAIN_PATTERN.fullmatch(domain):
        return False
    if is_ip_address(domain):
        return False

    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        return False

    labels = domain.split(".")
    return not any(
        not label
        or len(label) > MAX_DOMAIN_LABEL_LENGTH
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    )


def is_ip_address(value: str) -> bool:
    """Return whether a host value is an IP literal."""
    try:
        ip_address(value)
    except ValueError:
        return False

    return True


def is_domain_authorized(
    host: str | None,
    authorization: str | None,
    tokens_by_domain: TokensByDomain,
    now: datetime,
) -> bool:
    """Return whether a bearer token is allowed for the request host."""
    domain = normalize_domain(host)
    if domain is None:
        return False

    return is_authorized(authorization, tokens_by_domain.get(domain, {}), now)
