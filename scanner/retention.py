"""Retention helpers for long-running scanner deployments."""
from __future__ import annotations

from pathlib import Path


def prune_reports(reports_dir: str | Path, keep_scans: int = 100) -> list[Path]:
    """Delete report files older than the newest ``keep_scans`` scan groups."""
    keep_scans = max(1, int(keep_scans))
    root = Path(reports_dir)
    if not root.exists():
        return []
    files = [path for path in root.iterdir() if path.is_file()]
    groups: dict[str, list[Path]] = {}
    for path in files:
        stem = path.stem
        group = stem.rsplit("_", 1)[0] if "_" in stem else stem
        groups.setdefault(group, []).append(path)
    ordered = sorted(groups.items(), key=lambda item: max(p.stat().st_mtime for p in item[1]), reverse=True)
    removed: list[Path] = []
    for _, paths in ordered[keep_scans:]:
        for path in paths:
            try:
                path.unlink()
                removed.append(path)
            except FileNotFoundError:
                pass
    return removed
