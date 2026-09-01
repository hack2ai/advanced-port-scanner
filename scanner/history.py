"""SQLite-backed persistence for completed scan jobs."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class ScanHistory:
    def __init__(self, db_path: str | Path, retention: int = 100) -> None:
        self.db_path = str(db_path)
        self.retention = max(1, int(retention))
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS scans (
                job_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, duration REAL,
                status TEXT NOT NULL, targets TEXT NOT NULL, ports TEXT NOT NULL,
                scan_type TEXT NOT NULL, total_open INTEGER NOT NULL DEFAULT 0,
                results_json TEXT NOT NULL)""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at)")

    def save(self, job: dict[str, Any]) -> None:
        started_at = job.get("started_at") or job.get("created_at")
        if not started_at:
            raise ValueError("History records require started_at or created_at")
        with self._connect() as conn:
            conn.execute("""INSERT OR REPLACE INTO scans
                (job_id, started_at, duration, status, targets, ports, scan_type, total_open, results_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
                job["job_id"],
                started_at,
                job.get("duration"),
                job["status"],
                job["targets"],
                job["ports"],
                job["scan_type"],
                job.get("total_open", 0),
                json.dumps(job.get("results", {})),
            ))
            # Keep history bounded without touching in-flight jobs (only terminal
            # records are written here).
            conn.execute(
                """DELETE FROM scans WHERE job_id IN (
                    SELECT job_id FROM scans ORDER BY started_at DESC LIMIT -1 OFFSET ?
                )""",
                (self.retention,),
            )

    def list(self, limit: int = 50, include_results: bool = False) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 200))
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._row(row, include_results) for row in rows]

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE job_id = ?", (job_id,)).fetchone()
        return self._row(row, True) if row else None

    def _row(self, row: sqlite3.Row, include_results: bool) -> dict[str, Any]:
        item = {
            "job_id": row["job_id"],
            "started_at": row["started_at"],
            "duration": row["duration"],
            "status": row["status"],
            "targets": row["targets"],
            "ports": row["ports"],
            "scan_type": row["scan_type"],
            "total_open": row["total_open"],
        }
        if include_results:
            item["results"] = json.loads(row["results_json"])
        return item
