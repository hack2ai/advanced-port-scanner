import threading
import time
from concurrent.futures import ThreadPoolExecutor as RealThreadPoolExecutor

from scanner.history import ScanHistory
from scanner.jobs import JobManager
from scanner.scanner import scan_target


def test_finished_job_keeps_elapsed_time():
    manager = JobManager(max_workers=1, max_queue=0, retention=10)
    try:
        def runner(_job):
            time.sleep(0.02)

        job = manager.submit("127.0.0.1", "1-1", "tcp", 1, runner)
        deadline = time.monotonic() + 2
        while job.status not in {"completed", "failed", "cancelled"} and time.monotonic() < deadline:
            time.sleep(0.005)

        snapshot = job.snapshot()
        assert job.status == "completed"
        assert snapshot["elapsed_seconds"] >= 0.02
    finally:
        manager.close()


def test_queued_cancellation_does_not_start_runner():
    manager = JobManager(max_workers=1, max_queue=1, retention=10)
    blocker = threading.Event()
    started = threading.Event()
    try:
        def first_runner(_job):
            started.set()
            blocker.wait(2)

        first = manager.submit("127.0.0.1", "1-1", "tcp", 1, first_runner)
        assert started.wait(1)

        second_started = threading.Event()
        second = manager.submit("127.0.0.1", "2-2", "tcp", 1, lambda _job: second_started.set())
        assert manager.cancel(second.job_id) is True

        blocker.set()
        deadline = time.monotonic() + 2
        while first.status not in {"completed", "failed", "cancelled"} and time.monotonic() < deadline:
            time.sleep(0.005)
        time.sleep(0.02)

        assert second.status == "cancelled"
        assert second_started.is_set() is False
    finally:
        blocker.set()
        manager.close()


def test_running_cancellation_keeps_elapsed_time():
    manager = JobManager(max_workers=1, max_queue=0, retention=10)
    started = threading.Event()
    release = threading.Event()
    try:
        def runner(job):
            started.set()
            release.wait(2)
            if job.cancel_event.is_set():
                return

        job = manager.submit("127.0.0.1", "1-1", "tcp", 1, runner)
        assert started.wait(1)
        time.sleep(0.02)
        assert manager.cancel(job.job_id) is True
        release.set()

        deadline = time.monotonic() + 2
        while job.status not in {"completed", "failed", "cancelled"} and time.monotonic() < deadline:
            time.sleep(0.005)

        snapshot = job.snapshot()
        assert job.status == "cancelled"
        assert snapshot["elapsed_seconds"] >= 0.02
    finally:
        release.set()
        manager.close()


def test_scan_target_bounds_in_flight_futures(monkeypatch):
    monkeypatch.setattr("scanner.scanner.get_ttl", lambda _ip: None)
    monkeypatch.setattr("scanner.scanner.tcp_connect_scan", lambda _ip, port: (port, False))

    stats = {"pending": 0, "max_pending": 0, "submitted": 0}

    class SpyExecutor:
        def __init__(self, max_workers):
            self._pool = RealThreadPoolExecutor(max_workers=max_workers)

        def submit(self, fn, *args, **kwargs):
            stats["pending"] += 1
            stats["submitted"] += 1
            stats["max_pending"] = max(stats["max_pending"], stats["pending"])
            future = self._pool.submit(fn, *args, **kwargs)
            future.add_done_callback(lambda _future: stats.__setitem__("pending", stats["pending"] - 1))
            return future

        def shutdown(self, wait=True, cancel_futures=False):
            self._pool.shutdown(wait=wait, cancel_futures=cancel_futures)

    monkeypatch.setattr("scanner.scanner.concurrent.futures.ThreadPoolExecutor", SpyExecutor)
    scan_target("127.0.0.1", 1, 1000)

    assert stats["submitted"] == 1000
    assert stats["max_pending"] <= 256


def test_history_accepts_queued_cancellation_record(tmp_path):
    history = ScanHistory(tmp_path / "scans.db")
    history.save(
        {
            "job_id": "queued-cancelled",
            "created_at": "2026-09-01T00:00:00+00:00",
            "status": "cancelled",
            "targets": "127.0.0.1",
            "ports": "1-10",
            "scan_type": "TCP",
            "results": {},
        }
    )

    item = history.get("queued-cancelled")
    assert item is not None
    assert item["started_at"] == "2026-09-01T00:00:00+00:00"
    assert item["status"] == "cancelled"
