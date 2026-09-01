from flask import Flask, jsonify

from scanner.security import RateLimiter, require_csrf


def test_rate_limiter_blocks_after_limit():
    limiter = RateLimiter(limit=2, window_seconds=60)
    assert limiter.allow("client") is True
    assert limiter.allow("client") is True
    assert limiter.allow("client") is False


def test_security_headers_present():
    from web.app import app

    response = app.test_client().get("/api/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in response.headers


def test_csrf_token_requires_authenticated_session_for_json_mutation():
    protected = require_csrf(lambda: jsonify({"ok": True}))
    protected.__name__ = "protected"

    test_app = Flask(__name__)
    test_app.secret_key = "test-secret"
    test_app.add_url_rule("/_test-csrf", view_func=protected, methods=["POST"])

    client = test_app.test_client()
    with client.session_transaction() as sess:
        sess["username"] = "tester"
        sess["csrf_token"] = "expected-token"

    missing = client.post("/_test-csrf", json={})
    assert missing.status_code == 403
    valid = client.post("/_test-csrf", json={}, headers={"X-CSRF-Token": "expected-token"})
    assert valid.status_code == 200
