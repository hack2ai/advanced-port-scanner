from types import SimpleNamespace

from flask import Flask

from web.api_v1 import api_v1


def _settings():
    return SimpleNamespace(
        auth_enabled=False,
        cve_mode="off",
        cve_feed="data/cve_feed.json",
        cve_timeout=5.0,
        cve_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
    )


def test_cve_lookup_requires_product():
    app = Flask(__name__)
    app.config["APS_SETTINGS"] = _settings()
    app.register_blueprint(api_v1)
    client = app.test_client()

    response = client.get("/api/v1/cve/lookup")
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "INVALID_PRODUCT"


def test_cve_lookup_off_mode_is_non_network_default():
    app = Flask(__name__)
    app.config["APS_SETTINGS"] = _settings()
    app.register_blueprint(api_v1)
    client = app.test_client()

    response = client.get("/api/v1/cve/lookup?product=OpenSSH&version=9.8")
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["mode"] == "off"
    assert data["product"] == "OpenSSH"
    assert data["version"] == "9.8"
    assert data["matches"] == []
