import threading
import time

import pytest

from scanner.jobs import JobManager


def test_job_completes_and_reports_progress():
    manager = JobManager(max_workers=1, max_queue=1, retention=10)

    def runner(job):
        for i in range(1, 6):
            time.sleep(0.01)
            manager.update_progress(job, completed=i, current_target="127.0.0.1")
        job.status = "completed"

    job = manager.submit("127.0.0.1", "1-5", "tcp", 5, runner)
    for _ in range(100):
        snapshot = job.snapshot()
        if snapshot["status"] == "completed":
            break
        time.sleep(0.01)

    snapshot = job.snapshot()
    assert snapshot["status"] == "completed"
    assert snapshot["progress"]["completed"] == 5
    assert snapshot["progress"]["percent"] == 100.0
    manager.close()


def test_cancel_queued_job():
    manager = JobManager(max_workers=1, max_queue=1, retention=10)
    gate = threading.Event()

    def blocker(job):
        gate.wait(timeout=1)
        job.status = "completed"

    first = manager.submit("127.0.0.1", "1-1", "tcp", 1, blocker)
    second = manager.submit("127.0.0.1", "2-2", "tcp", 1, lambda job: None)

    assert manager.cancel(second.job_id) is True
    assert second.status == "cancelled"
    assert manager.cancel(second.job_id) is False

    gate.set()
    manager.close()


def test_queue_limit():
    manager = JobManager(max_workers=1, max_queue=0, retention=10)
    gate = threading.Event()

    def blocker(job):
        gate.wait(timeout=1)

    manager.submit("127.0.0.1", "1-1", "tcp", 1, blocker)
    with pytest.raises(RuntimeError, match="Job queue is full"):
        manager.submit("127.0.0.1", "2-2", "tcp", 1, blocker)
    gate.set()
    manager.close()
