"""Tests for saving opted-in binary uploads (UPLOAD_SAVE_EXTENSIONS)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.bot.utils.uploads import resolve_upload_path, safe_upload_name

NOW = datetime(2026, 11, 2, 9, 30, 5, tzinfo=UTC)


def test_safe_upload_name_timestamps_and_keeps_simple_names() -> None:
    assert safe_upload_name("paper.pdf", NOW) == "20261102-093005_paper.pdf"


@pytest.mark.parametrize(
    "name, expected",
    [
        ("../../etc/passwd.pdf", "20261102-093005_passwd.pdf"),
        ("/abs/dir/x.pdf", "20261102-093005_x.pdf"),
        ("my paper (v2).pdf", "20261102-093005_my_paper_v2_.pdf"),
        (".hidden.pdf", "20261102-093005_hidden.pdf"),
        ("", "20261102-093005_upload"),
        (None, "20261102-093005_upload"),
    ],
)
def test_safe_upload_name_strips_unsafe_parts(name: str, expected: str) -> None:
    assert safe_upload_name(name, NOW) == expected


def test_resolve_upload_path_inside_working_directory(tmp_path: Path) -> None:
    work = tmp_path / "proj"
    work.mkdir()
    p = resolve_upload_path(work, ".telegram-uploads", tmp_path, "a.pdf", NOW)
    assert p == (work / ".telegram-uploads" / "20261102-093005_a.pdf").resolve()


def test_resolve_upload_path_rejects_dir_outside_approved(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    with pytest.raises(ValueError):
        resolve_upload_path(outside, "uploads", approved, "a.pdf", NOW)


def test_resolve_upload_path_rejects_symlink_escape(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    (approved / "link").symlink_to(tmp_path)
    with pytest.raises(ValueError):
        resolve_upload_path(approved, "link", approved / "sub", "a.pdf", NOW)
