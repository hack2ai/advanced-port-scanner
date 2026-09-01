from web.app import app


def test_v1_metrics_endpoint_uses_standard_envelope():
    client = app.test_client()
    response = client.get("/api/v1/metrics")

    assert response.status_code == 200
    body = response.get_json()
    assert body["request_id"]
    assert body["data"]["active_jobs"] >= 0
    assert body["data"]["queued_jobs"] >= 0
    assert body["data"]["running_jobs"] >= 0
    assert body["data"]["retained_history"] >= 0
    assert body["data"]["completed_scans"] >= 0
