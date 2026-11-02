"""Save opted-in binary uploads (UPLOAD_SAVE_EXTENSIONS) to disk for Claude to open."""

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def safe_upload_name(file_name: Optional[str], now: Optional[datetime] = None) -> str:
    """Return a timestamped file name with no directory parts or unusual characters."""
    base = Path(file_name or "upload").name  # drop any directory components
    base = _UNSAFE_CHARS.sub("_", base).lstrip(".") or "upload"
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}_{base[:150]}"


def resolve_upload_path(
    working_directory: Path,
    save_dir: str,
    approved_directory: Path,
    file_name: Optional[str],
    now: Optional[datetime] = None,
) -> Path:
    """Path for a saved upload under ``working_directory/save_dir``.

    Raises ValueError if the result would fall outside ``approved_directory``.
    """
    target_dir = (Path(working_directory) / save_dir).resolve()
    approved = Path(approved_directory).resolve()
    if target_dir != approved and approved not in target_dir.parents:
        raise ValueError("Upload directory is outside the approved directory")
    return target_dir / safe_upload_name(file_name, now)
