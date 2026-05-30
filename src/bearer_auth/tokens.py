"""Token file loading."""

from pathlib import Path


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
