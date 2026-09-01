"""Optional CVE enrichment for observed service products and versions.

CVE enrichment is deliberately separate from port-risk hints. It never turns an
open port into a vulnerability finding. Results are source-aware and may run in
offline mode from a local JSON feed or in explicitly enabled online mode.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class CVERecord:
    cve_id: str
    summary: str
    severity: str = "UNKNOWN"
    score: float | None = None
    source: str = "local"
    url: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _matches_version(observed: str, vulnerable: str | None) -> bool:
    if not vulnerable:
        return True
    return observed.strip().lower() == vulnerable.strip().lower()


def load_offline_feed(path: str | Path) -> list[dict[str, Any]]:
    """Load a small, operator-supplied JSON enrichment feed.

    Supported rows:
      {"product": "OpenSSH", "version": "9.8", "cve_id": "CVE-...", ...}
    """
    feed_path = Path(path)
    if not feed_path.is_file():
        return []
    payload = json.loads(feed_path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, list) else []


def lookup_offline(product: str, version: str, feed: Iterable[dict[str, Any]]) -> list[CVERecord]:
    product_key = product.strip().lower()
    matches: list[CVERecord] = []
    for row in feed:
        if not isinstance(row, dict):
            continue
        if str(row.get("product", "")).strip().lower() != product_key:
            continue
        if not _matches_version(version, row.get("version")):
            continue
        cve_id = str(row.get("cve_id", "")).strip()
        if not cve_id:
            continue
        matches.append(
            CVERecord(
                cve_id=cve_id,
                summary=str(row.get("summary", "")).strip(),
                severity=str(row.get("severity", "UNKNOWN")).upper(),
                score=float(row["score"]) if isinstance(row.get("score"), (int, float)) else None,
                source=str(row.get("source", "local")),
                url=str(row.get("url", "")),
            )
        )
    return matches


def lookup_nvd(product: str, version: str, *, timeout: float = 5.0, base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0") -> list[CVERecord]:
    """Query NVD's public CVE API using a conservative keyword search.

    The caller must explicitly enable online mode. Network errors return an
    empty result rather than failing an otherwise valid scan.
    """
    keywords = " ".join(part for part in (product.strip(), version.strip()) if part)
    if not keywords:
        return []
    query = urllib.parse.urlencode({"keywordSearch": keywords, "resultsPerPage": "20"})
    request = urllib.request.Request(
        f"{base_url}?{query}",
        headers={"Accept": "application/json", "User-Agent": "advanced-port-scanner-cve/1.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return []

    records: list[CVERecord] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = str(cve.get("id", "")).strip()
        descriptions = cve.get("descriptions", [])
        summary = next((str(d.get("value", "")).strip() for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score = None
        severity = "UNKNOWN"
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                metric = entries[0]
                cvss = metric.get("cvssData", {})
                raw_score = cvss.get("baseScore")
                score = float(raw_score) if isinstance(raw_score, (int, float)) else None
                severity = str(cvss.get("baseSeverity") or metric.get("baseSeverity") or "UNKNOWN").upper()
                break
        if cve_id:
            records.append(
                CVERecord(
                    cve_id=cve_id,
                    summary=summary,
                    severity=severity,
                    score=score,
                    source="nvd",
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                )
            )
    return records


def enrich(product: str, version: str, *, mode: str = "off", feed_path: str | Path = "data/cve_feed.json", timeout: float = 5.0, base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0") -> dict[str, Any]:
    """Return source-aware CVE enrichment without making it scan-critical."""
    normalized = mode.strip().lower()
    if normalized not in {"off", "offline", "online"}:
        normalized = "off"
    records: list[CVERecord] = []
    if normalized == "offline":
        records = lookup_offline(product, version, load_offline_feed(feed_path))
    elif normalized == "online":
        records = lookup_nvd(product, version, timeout=timeout, base_url=base_url)
    return {
        "mode": normalized,
        "product": product.strip(),
        "version": version.strip(),
        "matches": [record.as_dict() for record in records],
    }
