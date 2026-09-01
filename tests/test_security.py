from dataclasses import replace

from flask import Flask, jsonify, request

from scanner.security import RateLimiter, csrf_token, require_csrf


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


def test_csrf_rejects_authenticated_session_without_session_token():
    protected = require_csrf(lambda: jsonify({"ok": True}))
    protected.__name__ = "protected_without_token"

    test_app = Flask(__name__)
    test_app.secret_key = "test-secret"
    test_app.add_url_rule("/_test-csrf-no-token", view_func=protected, methods=["POST"])

    client = test_app.test_client()
    with client.session_transaction() as sess:
        sess["username"] = "tester"

    response = client.post("/_test-csrf-no-token", json={})
    assert response.status_code == 403


def test_client_key_uses_remote_addr_by_default(monkeypatch):
    import web.app as app_module

    monkeypatch.setattr(
        app_module,
        "settings",
        replace(app_module.settings, trust_proxy_headers=False),
    )
    with app_module.app.test_request_context(
        "/", headers={"X-Forwarded-For": "198.51.100.44"}, environ_base={"REMOTE_ADDR": "127.0.0.1"}
    ):
        assert app_module._client_key("login") == "login:127.0.0.1"


def test_client_key_can_use_forwarded_addr_when_explicitly_enabled(monkeypatch):
    import web.app as app_module

    monkeypatch.setattr(
        app_module,
        "settings",
        replace(app_module.settings, trust_proxy_headers=True),
    )
    with app_module.app.test_request_context(
        "/", headers={"X-Forwarded-For": "198.51.100.44, 10.0.0.2"}, environ_base={"REMOTE_ADDR": "127.0.0.1"}
    ):
        assert app_module._client_key("login") == "login:198.51.100.44"
