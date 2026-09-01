"""Operational metrics derived from in-process jobs and persisted scan history."""
from __future__ import annotations

from collections import Counter
from statistics import mean
from typing import Any, Iterable


def summarize_metrics(active_jobs: Iterable[dict[str, Any]], history: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Return a compact, dependency-free operational metrics snapshot."""
    active = list(active_jobs)
    stored = list(history)
    statuses = Counter(str(item.get("status", "unknown")) for item in stored)
    durations = [float(item["duration"]) for item in stored if isinstance(item.get("duration"), (int, float))]
    total_open = sum(int(item.get("total_open", 0) or 0) for item in stored)

    return {
        "active_jobs": sum(1 for item in active if item.get("status") in {"queued", "running"}),
        "queued_jobs": sum(1 for item in active if item.get("status") == "queued"),
        "running_jobs": sum(1 for item in active if item.get("status") == "running"),
        "retained_history": len(stored),
        "completed_scans": statuses.get("completed", 0),
        "failed_scans": statuses.get("failed", 0),
        "cancelled_scans": statuses.get("cancelled", 0),
        "average_duration_seconds": round(mean(durations), 2) if durations else 0.0,
        "total_open_ports": total_open,
    }
