"""Token file loading and reload state."""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from bearer_auth.auth import normalize_domain

type TokensByDomain = Mapping[str, frozenset[str]]


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
    tokens_by_domain: dict[str, set[str]] = {}
    current_domain: str | None = None

    with file_path.open(encoding="utf-8") as token_file:
        for line_number, raw_line in enumerate(token_file, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("[") and line.endswith("]"):
                current_domain = parse_domain_section(file_path, line_number, line)
                tokens_by_domain.setdefault(current_domain, set())
                continue

            if current_domain is None:
                raise token_file_error(file_path, line_number, "token entry before domain section")

            tokens_by_domain[current_domain].add(line)

    return {domain: frozenset(tokens) for domain, tokens in tokens_by_domain.items()}


def parse_domain_section(file_path: Path, line_number: int, line: str) -> str:
    """Parse and normalize a token file domain section header."""
    domain = normalize_domain(line[1:-1])
    if domain is None:
        raise token_file_error(file_path, line_number, "invalid domain section")

    return domain


def token_file_error(file_path: Path, line_number: int, detail: str) -> TokenFileError:
    """Create a token file parse error."""
    return TokenFileError(f"{file_path}: line {line_number}: {detail}")
