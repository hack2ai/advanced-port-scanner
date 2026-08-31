from web.app import app


def test_health_endpoint():
    client = app.test_client()
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_scan_validation():
    client = app.test_client()
    response = client.post("/api/scan", json={"targets": "127.0.0.1", "ports": "0"})
    assert response.status_code == 400
