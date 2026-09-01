from pathlib import Path

from scanner.history import ScanHistory
from scanner.retention import prune_reports


def _job(job_id: str, started_at: str) -> dict:
    return {
        "job_id": job_id,
        "started_at": started_at,
        "duration": 1.0,
        "status": "completed",
        "targets": "127.0.0.1",
        "ports": "1-10",
        "scan_type": "TCP",
        "total_open": 0,
        "results": {},
    }


def test_history_retention_keeps_newest_rows(tmp_path: Path):
    history = ScanHistory(tmp_path / "scans.db", retention=2)
    history.save(_job("one", "2026-01-01T00:00:00+00:00"))
    history.save(_job("two", "2026-01-02T00:00:00+00:00"))
    history.save(_job("three", "2026-01-03T00:00:00+00:00"))

    items = history.list(10)
    assert [item["job_id"] for item in items] == ["three", "two"]
    assert history.get("one") is None


def test_report_retention_keeps_complete_scan_groups(tmp_path: Path):
    for timestamp, job_id in [("20260101_010101", "aaa111"), ("20260102_010101", "bbb222")]:
        for ext in ("json", "csv", "txt", "html"):
            path = tmp_path / f"scan_{timestamp}_{job_id}.{ext}"
            path.write_text("report", encoding="utf-8")

    removed = prune_reports(tmp_path, keep_scans=1)
    assert len(removed) == 4
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "scan_20260102_010101_bbb222.csv",
        "scan_20260102_010101_bbb222.html",
        "scan_20260102_010101_bbb222.json",
        "scan_20260102_010101_bbb222.txt",
    ]
