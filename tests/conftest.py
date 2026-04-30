"""Test config: register golden directory."""
from pathlib import Path

import pytest

GOLDEN_DIR = Path(__file__).parent / "golden"


@pytest.fixture
def golden_dir() -> Path:
    return GOLDEN_DIR
