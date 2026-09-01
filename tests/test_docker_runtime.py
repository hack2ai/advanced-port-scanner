from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_docker_uses_single_worker_for_in_memory_jobs():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert '"--workers", "1"' in dockerfile
    assert '"--threads", "4"' in dockerfile
