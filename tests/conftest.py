"""Redirect every test to a throwaway home so project data is never touched."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

# Has to happen before any SentinelAI module is imported.
_HOME = Path(tempfile.mkdtemp(prefix="sentinelai-tests-"))
shutil.copytree(REPO / "config", _HOME / "config")
os.environ["SENTINELAI_HOME"] = str(_HOME)
os.environ.pop("SENTINELAI_DATA_DIR", None)
os.environ.pop("SENTINELAI_LOGS_DIR", None)
os.environ.pop("SENTINELAI_RUN_MODE", None)


@pytest.fixture(autouse=True)
def clean_state():
    for name in ("data", "logs"):
        shutil.rmtree(_HOME / name, ignore_errors=True)
    yield


@pytest.fixture
def home() -> Path:
    return _HOME


@pytest.fixture
def paths():
    from common.runtime import get_paths

    return get_paths().ensure()


@pytest.fixture
def config():
    from common.runtime import load_config

    return load_config()


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_HOME, ignore_errors=True)
