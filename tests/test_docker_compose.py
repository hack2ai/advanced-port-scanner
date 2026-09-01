from pathlib import Path


def test_docker_compose_persists_data_and_retention_defaults():
    content = (Path(__file__).parents[1] / "docker-compose.yml").read_text(encoding="utf-8")
    assert "./data:/app/data" in content
    assert "./reports:/app/reports" in content
    assert "./logs:/app/logs" in content
    assert "HISTORY_RETENTION: 100" in content
    assert "REPORT_RETENTION: 100" in content
