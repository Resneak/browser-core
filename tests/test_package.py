from __future__ import annotations

import re
from pathlib import Path

import browser_core


def test_runtime_version_matches_project_metadata() -> None:
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', pyproject, flags=re.MULTILINE)
    assert match is not None
    assert browser_core.__version__ == match.group(1)
