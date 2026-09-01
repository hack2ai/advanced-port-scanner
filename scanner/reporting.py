"""Compatibility helpers for rendering persisted HTML scan reports."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from .html_report import generate_html_report


def render_html_report(results: dict[str, Any]) -> str:
    """Render a structured scan result into an HTML string."""
    with tempfile.TemporaryDirectory(prefix="aps-report-") as tmp:
        path = Path(tmp) / "report.html"
        generate_html_report(results, str(path))
        return path.read_text(encoding="utf-8")


__all__ = ["generate_html_report", "render_html_report"]
