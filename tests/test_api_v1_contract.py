from flask import Flask

from web.api_v1 import api_v1, data_response, error_response


def test_v1_blueprint_metadata():
    assert api_v1.name == "api_v1"
    assert api_v1.url_prefix == "/api/v1"


def test_v1_response_helpers():
    app = Flask(__name__)
    app.register_blueprint(api_v1)
    with app.test_request_context("/api/v1/health"):
        response = data_response({"status": "ok"})
        assert response.status_code == 200
        body = response.get_json()
        assert body["data"]["status"] == "ok"
        assert body["request_id"]
        assert response.headers["X-Request-ID"] == body["request_id"]

    with app.test_request_context("/api/v1/test"):
        response = error_response("BAD_REQUEST", "invalid input", 400)
        assert response.status_code == 400
        body = response.get_json()
        assert body["error"]["code"] == "BAD_REQUEST"
        assert body["error"]["message"] == "invalid input"
        assert body["request_id"]
