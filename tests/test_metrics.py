from scanner.metrics import summarize_metrics


def test_metrics_empty_snapshot():
    result = summarize_metrics([], [])

    assert result == {
        "active_jobs": 0,
        "queued_jobs": 0,
        "running_jobs": 0,
        "retained_history": 0,
        "completed_scans": 0,
        "failed_scans": 0,
        "cancelled_scans": 0,
        "average_duration_seconds": 0.0,
        "total_open_ports": 0,
    }


def test_metrics_aggregate_status_and_duration():
    active = [
        {"status": "queued"},
        {"status": "running"},
        {"status": "completed"},
    ]
    history = [
        {"status": "completed", "duration": 2.0, "total_open": 3},
        {"status": "failed", "duration": 4.0, "total_open": 1},
        {"status": "cancelled", "duration": 6.0, "total_open": 2},
        {"status": "completed", "duration": 8.0, "total_open": 4},
    ]

    result = summarize_metrics(active, history)

    assert result["active_jobs"] == 2
    assert result["queued_jobs"] == 1
    assert result["running_jobs"] == 1
    assert result["retained_history"] == 4
    assert result["completed_scans"] == 2
    assert result["failed_scans"] == 1
    assert result["cancelled_scans"] == 1
    assert result["average_duration_seconds"] == 5.0
    assert result["total_open_ports"] == 10
