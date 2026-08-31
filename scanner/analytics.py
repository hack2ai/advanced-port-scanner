"""Analytics over persisted authorized network-discovery scan results."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable


RISK_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def summarize_scans(items: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Return deterministic dashboard metrics from history records."""
    scans = list(items)
    targets: set[str] = set()
    open_ports = 0
    risks = Counter({level: 0 for level in RISK_LEVELS})
    services: Counter[str] = Counter()
    durations: list[float] = []

    for item in scans:
        duration = item.get("duration")
        try:
            if duration is not None:
                durations.append(float(duration))
        except (TypeError, ValueError):
            pass
        for target, result in (item.get("results") or {}).items():
            targets.add(str(target))
            for port in result.get("open_ports") or []:
                open_ports += 1
                risk = str(port.get("risk", "INFO")).upper()
                risks[risk] += 1
                services[str(port.get("service", "unknown"))] += 1

    average_duration = round(sum(durations) / len(durations), 2) if durations else 0.0
    return {
        "scans": len(scans),
        "targets": len(targets),
        "open_ports": open_ports,
        "high_risk": risks["CRITICAL"] + risks["HIGH"],
        "average_duration": average_duration,
        "risk_distribution": {level: risks[level] for level in RISK_LEVELS},
        "top_services": dict(sorted(services.items(), key=lambda pair: (-pair[1], pair[0]))[:10]),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
