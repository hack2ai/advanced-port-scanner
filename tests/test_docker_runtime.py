from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_docker_uses_single_worker_for_in_memory_jobs():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert '"--workers", "1"' in dockerfile
    assert '"--threads", "4"' in dockerfile
    assert "/app/data /app/reports /app/logs" in dockerfile


def test_compose_uses_managed_persistent_volumes():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "scanner_data:/app/data" in compose
    assert "scanner_reports:/app/reports" in compose
    assert "scanner_logs:/app/logs" in compose
    assert "scanner_data:" in compose
    assert "scanner_reports:" in compose
    assert "scanner_logs:" in compose
