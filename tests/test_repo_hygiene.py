"""Encoding mistakes here stopped scripts from running, so they are tested directly."""

import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SKIP_DIRS = {"venv", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "data", "logs",
             "reporter-output", ".git"}


def text_files():
    for folder, dirs, files in os.walk(REPO):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        for name in files:
            yield Path(folder) / name


@pytest.mark.parametrize("path", list(text_files()), ids=lambda p: p.relative_to(REPO).as_posix())
def test_utf8_without_bom_and_lf_endings(path):
    data = path.read_bytes()
    assert not data.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM breaks shebang lines"
    assert b"\r\n" not in data, "CRLF breaks shell scripts on Linux"


@pytest.mark.parametrize(
    "script",
    ["daemon/sentinel_daemon.sh", "utils/setup.sh", "responder/auto_response.sh"],
)
def test_entry_points_are_real_scripts(script):
    # Regression: sentinel_daemon.sh and setup.sh were 0 bytes.
    content = (REPO / script).read_text(encoding="utf-8")
    assert content.startswith("#!/usr/bin/env bash\n")
    assert len(content) > 100
