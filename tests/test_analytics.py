from scanner.analytics import summarize_scans


def test_summarize_scans_counts_targets_ports_risks_and_services():
    items = [
        {
            "job_id": "one",
            "duration": 2.0,
            "results": {
                "host-a": {
                    "open_ports": [
                        {"port": 22, "service": "ssh", "risk": "HIGH"},
                        {"port": 80, "service": "http", "risk": "LOW"},
                    ]
                },
                "host-b": {
                    "open_ports": [{"port": 443, "service": "https", "risk": "INFO"}]
                },
            },
        },
        {
            "job_id": "two",
            "duration": 4.0,
            "results": {
                "host-a": {"open_ports": [{"port": 22, "service": "ssh", "risk": "HIGH"}]}
            },
        },
    ]
    summary = summarize_scans(items)
    assert summary["scans"] == 2
    assert summary["targets"] == 2
    assert summary["open_ports"] == 4
    assert summary["high_risk"] == 2
    assert summary["average_duration"] == 3.0
    assert summary["risk_distribution"]["HIGH"] == 2
    assert summary["risk_distribution"]["LOW"] == 1
    assert summary["risk_distribution"]["INFO"] == 1
    assert summary["top_services"]["ssh"] == 2


def test_empty_analytics_is_well_formed():
    summary = summarize_scans([])
    assert summary["scans"] == 0
    assert summary["targets"] == 0
    assert summary["open_ports"] == 0
    assert summary["high_risk"] == 0
    assert summary["average_duration"] == 0.0
    assert summary["top_services"] == {}
