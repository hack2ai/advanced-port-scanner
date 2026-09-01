from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_package_declares_main_as_a_module() -> None:
    """The console entry point must remain installable from a built package."""
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'aps = "main:main"' in pyproject
    assert 'py-modules = ["main"]' in pyproject


def test_main_module_is_importable() -> None:
    """Catch accidental removal/renaming of the CLI module."""
    result = subprocess.run(
        [sys.executable, "-c", "from main import main; print(callable(main))"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "True"
