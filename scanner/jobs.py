"""Bounded in-process job management for authorized network discovery."""
from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

TERMINAL_STATES = {"completed", "failed", "cancelled"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanJob:
    job_id: str
    targets: str
    ports: str
    scan_type: str
    created_at: str
    status: str = "queued"
    started_at: str | None = None
    finished_at: str | None = None
    total_work: int = 0
    completed_work: int = 0
    current_target: str | None = None
    total_open: int = 0
    results: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    elapsed_seconds: float = 0.0
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)
    future: Future[Any] | None = field(default=None, repr=False)
    started_monotonic: float | None = field(default=None, repr=False)

    def snapshot(self, include_results: bool = True) -> dict[str, Any]:
        elapsed = self.elapsed_seconds
        if self.started_monotonic is not None and self.status not in TERMINAL_STATES:
            elapsed = round(max(0.0, time.monotonic() - self.started_monotonic), 2)
        percent = round((self.completed_work / self.total_work) * 100, 2) if self.total_work else 0.0
        item = {
            "job_id": self.job_id,
            "status": self.status,
            "targets": self.targets,
            "ports": self.ports,
            "scan_type": self.scan_type,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "progress": {"completed": self.completed_work, "total": self.total_work, "percent": percent},
            "current_target": self.current_target,
            "total_open": self.total_open,
            "elapsed_seconds": elapsed,
            "error": self.error,
        }
        if include_results:
            item["results"] = self.results
        return item


class JobManager:
    """Bounded executor with cooperative cancellation and observable progress."""

    def __init__(self, max_workers: int = 2, max_queue: int = 16, retention: int = 100) -> None:
        if max_workers < 1 or max_queue < 0 or retention < 1:
            raise ValueError("Invalid job manager limits")
        self.max_workers = max_workers
        self.max_queue = max_queue
        self.retention = retention
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan-job")
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.RLock()

    def submit(
        self,
        targets: str,
        ports: str,
        scan_type: str,
        total_work: int,
        runner: Callable[[ScanJob], None],
    ) -> ScanJob:
        with self._lock:
            queued_or_running = sum(1 for job in self._jobs.values() if job.status in {"queued", "running"})
            if queued_or_running >= self.max_workers + self.max_queue:
                raise RuntimeError("Job queue is full")
            job = ScanJob(
                job_id=uuid.uuid4().hex[:12],
                targets=targets,
                ports=ports,
                scan_type=scan_type.upper(),
                created_at=_utc_now(),
                total_work=total_work,
            )
            self._jobs[job.job_id] = job
            job.future = self._executor.submit(self._run, job, runner)
            return job

    def _finish_locked(self, job: ScanJob) -> None:
        if job.started_monotonic is not None:
            job.elapsed_seconds = round(max(0.0, time.monotonic() - job.started_monotonic), 2)
        if job.finished_at is None:
            job.finished_at = _utc_now()

    def _run(self, job: ScanJob, runner: Callable[[ScanJob], None]) -> None:
        with self._lock:
            if job.cancel_event.is_set():
                job.status = "cancelled"
                self._finish_locked(job)
                return
            job.status = "running"
            job.started_at = _utc_now()
            job.started_monotonic = time.monotonic()
        try:
            runner(job)
            with self._lock:
                if job.cancel_event.is_set() and job.status not in TERMINAL_STATES:
                    job.status = "cancelled"
                elif job.status not in TERMINAL_STATES:
                    job.status = "completed"
                self._finish_locked(job)
        except Exception:
            with self._lock:
                job.status = "failed"
                job.error = "Internal scan error"
                self._finish_locked(job)
        finally:
            with self._lock:
                self._prune_locked()

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            items = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)[: max(1, min(limit, 200))]
            return [job.snapshot(include_results=False) for job in items]

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status in TERMINAL_STATES:
                return False
            job.cancel_event.set()
            if job.status == "queued":
                job.status = "cancelled"
                self._finish_locked(job)
                if job.future is not None:
                    job.future.cancel()
            return True

    def update_progress(
        self,
        job: ScanJob,
        *,
        completed: int | None = None,
        current_target: str | None = None,
        total_open: int | None = None,
        result_target: str | None = None,
        result: Any = None,
    ) -> None:
        with self._lock:
            if completed is not None:
                job.completed_work = max(0, min(completed, job.total_work))
            if current_target is not None:
                job.current_target = current_target
            if total_open is not None:
                job.total_open = max(0, total_open)
            if result_target is not None:
                job.results[result_target] = result

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _prune_locked(self) -> None:
        if len(self._jobs) <= self.retention:
            return
        removable = sorted(
            (job for job in self._jobs.values() if job.status in TERMINAL_STATES),
            key=lambda j: j.created_at,
        )
        for job in removable[: max(0, len(self._jobs) - self.retention)]:
            self._jobs.pop(job.job_id, None)
