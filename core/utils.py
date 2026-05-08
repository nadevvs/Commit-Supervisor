from pathlib import Path


def safe_read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def mask_secret(value: str) -> str:
    value = value.strip()

    if len(value) <= 24:
        return value

    return value[:12] + "..." + value[-6:]
