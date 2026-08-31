"""Versioned API helpers for the Advanced Port Scanner."""
from __future__ import annotations

from functools import wraps
from typing import Any, Callable
from uuid import uuid4

from flask import Blueprint, g, jsonify, request

api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")


def request_id() -> str:
    value = getattr(g, "request_id", None)
    if value is None:
        value = uuid4().hex
        g.request_id = value
    return value


def data_response(data: Any, status: int = 200):
    response = jsonify({"data": data, "request_id": request_id()})
    response.status_code = status
    response.headers["X-Request-ID"] = request_id()
    return response


def error_response(code: str, message: str, status: int):
    response = jsonify({"error": {"code": code, "message": message}, "request_id": request_id()})
    response.status_code = status
    response.headers["X-Request-ID"] = request_id()
    return response


def _auth_required(view: Callable[..., Any]):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # v1 routes are registered by the Flask application and may reuse its
        # existing authentication decorator. This guard only normalizes the
        # failure shape when no authenticated principal is present.
        if request.environ.get("APS_API_V1_AUTH_REQUIRED") == "1" and not getattr(g, "principal", None):
            return error_response("AUTH_REQUIRED", "Authentication required", 401)
        return view(*args, **kwargs)

    return wrapped


@api_v1.after_request
def add_request_id(response):
    response.headers["X-Request-ID"] = request_id()
    return response


@api_v1.get("/health")
def health():
    return data_response({"status": "ok", "service": "advanced-port-scanner"})


@api_v1.get("/profiles")
def profiles():
    from scanner.profiles import list_profiles

    return data_response(list_profiles())


# These thin endpoints deliberately delegate through application callbacks.
# The app can inject concrete handlers when registering the blueprint.
def configure_callbacks(*, list_jobs=None, list_history=None, analytics=None):
    if list_jobs is not None:
        api_v1.view_functions["api_v1.list_jobs"] = list_jobs
    if list_history is not None:
        api_v1.view_functions["api_v1.list_history"] = list_history
    if analytics is not None:
        api_v1.view_functions["api_v1.analytics"] = analytics


@api_v1.get("/jobs")
@_auth_required
def list_jobs():
    return data_response([])


@api_v1.get("/history")
@_auth_required
def list_history():
    return data_response([])


@api_v1.get("/analytics")
@_auth_required
def analytics():
    return data_response({"scans": 0, "targets": 0, "open_ports": 0})
