"""Token file loading and reload state."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from bearer_auth.auth import TokenEntry, normalize_domain

type TokensByDomain = Mapping[str, Mapping[str, TokenEntry]]

EXPIRATION_FIELD = "expires"
MAX_TOKEN_ENTRY_PARTS = 2


@dataclass(frozen=True)
class TokenFileState:
    """File metadata used to detect token file changes."""

    mtime_ns: int
    size: int


class TokenStore:
    """Load tokens and refresh them when the token file changes."""

    def __init__(self, file_path: Path) -> None:
        """Create a token store backed by a token file."""
        self._file_path = file_path
        self._state: TokenFileState | None = None
        self._tokens: TokensByDomain = {}

    @property
    def file_path(self) -> Path:
        """Return the configured token file path."""
        return self._file_path

    def reload(self) -> TokensByDomain:
        """Reload tokens from disk and remember the current file state."""
        state = get_token_file_state(self._file_path)
        tokens = load_tokens(self._file_path)
        self._state = state
        self._tokens = tokens
        return tokens

    def get_tokens(self) -> TokensByDomain:
        """Return current tokens, reloading them if the file changed."""
        state = get_token_file_state(self._file_path)
        if state != self._state:
            return self.reload()

        return self._tokens


def get_token_file_state(file_path: Path) -> TokenFileState:
    """Return metadata relevant for detecting token file changes."""
    file_stat = file_path.stat()
    return TokenFileState(mtime_ns=file_stat.st_mtime_ns, size=file_stat.st_size)


class TokenFileError(ValueError):
    """Raised when a token file cannot be parsed safely."""


def load_tokens(file_path: Path) -> TokensByDomain:
    """Load bearer tokens from a sectioned token file."""
    tokens_by_domain: dict[str, dict[str, TokenEntry]] = {}
    current_domain: str | None = None

    with file_path.open(encoding="utf-8") as token_file:
        for line_number, raw_line in enumerate(token_file, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("[") and line.endswith("]"):
                current_domain = parse_domain_section(file_path, line_number, line)
                tokens_by_domain.setdefault(current_domain, {})
                continue

            if current_domain is None:
                raise token_file_error(file_path, line_number, "token entry before domain section")

            token, token_entry = parse_token_entry(file_path, line_number, line)
            tokens_by_domain[current_domain][token] = token_entry

    return tokens_by_domain


def parse_domain_section(file_path: Path, line_number: int, line: str) -> str:
    """Parse and normalize a token file domain section header."""
    domain = normalize_domain(line[1:-1])
    if domain is None:
        raise token_file_error(file_path, line_number, "invalid domain section")

    return domain


def parse_token_entry(file_path: Path, line_number: int, line: str) -> tuple[str, TokenEntry]:
    """Parse a bearer token and its optional metadata."""
    parts = line.split()
    if len(parts) > MAX_TOKEN_ENTRY_PARTS:
        raise token_file_error(file_path, line_number, "invalid token entry")

    token = parts[0]
    if len(parts) == 1:
        return token, TokenEntry()

    key, separator, value = parts[1].partition("=")
    if key != EXPIRATION_FIELD or separator != "=" or not value:
        raise token_file_error(file_path, line_number, "invalid token metadata")

    return token, TokenEntry(expires_at=parse_token_expiration(file_path, line_number, value))


def parse_token_expiration(file_path: Path, line_number: int, value: str) -> datetime:
    """Parse a timezone-aware token expiration timestamp."""
    normalized_value = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        expires_at = datetime.fromisoformat(normalized_value)
    except ValueError as error:
        raise token_file_error(file_path, line_number, "invalid token expiration") from error

    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        raise token_file_error(file_path, line_number, "token expiration must include a timezone")

    return expires_at.astimezone(UTC)


def token_file_error(file_path: Path, line_number: int, detail: str) -> TokenFileError:
    """Create a token file parse error."""
    return TokenFileError(f"{file_path}: line {line_number}: {detail}")
