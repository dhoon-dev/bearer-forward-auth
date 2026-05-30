"""Token file loading and reload state."""

from dataclasses import dataclass
from pathlib import Path


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
        self._tokens: frozenset[str] = frozenset()

    @property
    def file_path(self) -> Path:
        """Return the configured token file path."""
        return self._file_path

    def reload(self) -> frozenset[str]:
        """Reload tokens from disk and remember the current file state."""
        state = get_token_file_state(self._file_path)
        tokens = load_tokens(self._file_path)
        self._state = state
        self._tokens = tokens
        return tokens

    def get_tokens(self) -> frozenset[str]:
        """Return current tokens, reloading them if the file changed."""
        state = get_token_file_state(self._file_path)
        if state != self._state:
            return self.reload()

        return self._tokens


def get_token_file_state(file_path: Path) -> TokenFileState:
    """Return metadata relevant for detecting token file changes."""
    file_stat = file_path.stat()
    return TokenFileState(mtime_ns=file_stat.st_mtime_ns, size=file_stat.st_size)


def load_tokens(file_path: Path) -> frozenset[str]:
    """Load bearer tokens from a newline-delimited token file."""
    tokens: set[str] = set()
    with file_path.open(encoding="utf-8") as token_file:
        for raw_line in token_file:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            tokens.add(line)

    return frozenset(tokens)
