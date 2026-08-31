from web.app import app


def test_profiles_endpoint():
    response = app.test_client().get("/api/profiles")
    assert response.status_code == 200
    payload = response.get_json()
    assert [item["name"] for item in payload] == ["quick", "standard", "extended", "full"]
    assert payload[1]["ports"] == "1-1024"


def test_scan_profile_validation_rejects_unknown_profile():
    response = app.test_client().post(
        "/api/scan",
        json={"targets": "127.0.0.1", "profile": "does-not-exist"},
    )
    assert response.status_code == 400
