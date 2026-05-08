from pathlib import Path

from core.config import IGNORED_DIRS, IGNORED_EXTENSIONS


def should_skip_path(path: Path) -> bool:
    for part in path.parts:
        if part in IGNORED_DIRS:
            return True

    if path.suffix.lower() in IGNORED_EXTENSIONS:
        return True

    return False


def is_binary_file(path: Path) -> bool:
    try:
        with open(path, "rb") as file:
            chunk = file.read(1024)
            return b"\0" in chunk
    except OSError:
        return True
