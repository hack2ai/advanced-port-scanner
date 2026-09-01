"""Versioned API endpoints for the Advanced Port Scanner."""
from __future__ import annotations

from functools import wraps
from typing import Any
from uuid import uuid4

from flask import Blueprint, Response, current_app, g, jsonify, request, session

api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")


def request_id() -> str:
    value = getattr(g, "request_id", None)
    if value is None:
        value = request.headers.get("X-Request-ID") or uuid4().hex
        g.request_id = value
    return value


def data_response(data: Any, status: int = 200):
    rid = request_id()
    response = jsonify({"data": data, "request_id": rid})
    response.status_code = status
    response.headers["X-Request-ID"] = rid
    return response


def error_response(code: str, message: str, status: int):
    rid = request_id()
    response = jsonify({"error": {"code": code, "message": message}, "request_id": rid})
    response.status_code = status
    response.headers["X-Request-ID"] = rid
    return response


def _require(action: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            settings = current_app.config["APS_SETTINGS"]
            if not settings.auth_enabled:
                return view(*args, **kwargs)
            username = session.get("username", "")
            role = session.get("role", "")
            allowed = bool(username) and (
                role == "admin"
                or (role == "operator" and action in {"view", "scan", "cancel"})
                or (role == "viewer" and action == "view")
            )
            if not allowed:
                return error_response(
                    "AUTH_REQUIRED" if not username else "FORBIDDEN",
                    "Authentication required" if not username else "Permission denied",
                    401 if not username else 403,
                )
            return view(*args, **kwargs)
        return wrapped
    return decorator


def _forward_result(result: Any, error_code: str):
    """Adapt a Flask view result without mistaking successful tuples for errors."""
    if isinstance(result, tuple):
        body, status = result
        payload = body.get_json() if hasattr(body, "get_json") else {}
        if status >= 400 or "error" in payload:
            message = payload.get("error", "Request failed")
            return error_response(error_code, message, status)
        return data_response(payload, status)
    return data_response(result.get_json(), result.status_code)


@api_v1.after_request
def add_request_id(response):
    response.headers["X-Request-ID"] = request_id()
    return response


@api_v1.get("/health")
def health():
    settings = current_app.config["APS_SETTINGS"]
    return data_response({"status": "ok", "service": "advanced-port-scanner", "auth_enabled": settings.auth_enabled})


@api_v1.get("/profiles")
def profiles():
    from scanner.profiles import list_profiles
    return data_response(list_profiles())


@api_v1.post("/scans")
@_require("scan")
def create_scan():
    result = current_app.view_functions["start_scan"]()
    return _forward_result(result, "SCAN_REQUEST_FAILED")


@api_v1.get("/scans/<job_id>")
@_require("view")
def get_scan(job_id: str):
    result = current_app.view_functions["status"](job_id)
    if isinstance(result, tuple):
        body, status = result
        payload = body.get_json() if hasattr(body, "get_json") else {}
        return error_response("SCAN_NOT_FOUND", payload.get("error", "Job not found"), status)
    return data_response(result.get_json(), result.status_code)


@api_v1.post("/scans/<job_id>/cancel")
@_require("cancel")
def cancel_scan(job_id: str):
    result = current_app.view_functions["cancel"](job_id)
    return _forward_result(result, "SCAN_CANCEL_FAILED")


@api_v1.get("/jobs")
@_require("view")
def list_jobs():
    result = current_app.view_functions["list_jobs"]()
    return data_response(result.get_json(), result.status_code)


@api_v1.get("/history")
@_require("view")
def list_history():
    result = current_app.view_functions["list_history"]()
    return data_response(result.get_json(), result.status_code)


@api_v1.get("/history/<job_id>")
@_require("view")
def history_detail(job_id: str):
    result = current_app.view_functions["history_detail"](job_id)
    if isinstance(result, tuple):
        body, status = result
        payload = body.get_json() if hasattr(body, "get_json") else {}
        return error_response("HISTORY_NOT_FOUND", payload.get("error", "History entry not found"), status)
    return data_response(result.get_json(), result.status_code)


@api_v1.get("/reports/<job_id>/html")
@_require("view")
def html_report(job_id: str):
    result = current_app.view_functions["html_report"](job_id)
    if isinstance(result, tuple):
        body, status = result
        payload = body.get_json() if hasattr(body, "get_json") else {}
        return error_response("REPORT_NOT_FOUND", payload.get("error", "Report not found"), status)
    if isinstance(result, Response):
        result.headers["X-Request-ID"] = request_id()
    return result


@api_v1.get("/analytics")
@_require("view")
def analytics():
    from scanner.analytics import summarize_scans

    history = current_app.config["APS_HISTORY"]
    items = history.list(200, include_results=True)
    return data_response(summarize_scans(items))


@api_v1.get("/metrics")
@_require("view")
def metrics():
    from scanner.metrics import summarize_metrics

    history = current_app.config["APS_HISTORY"]
    job_manager = current_app.config["APS_JOB_MANAGER"]
    return data_response(summarize_metrics(job_manager.list(200), history.list(200, include_results=False)))


@api_v1.get("/cve/lookup")
@_require("view")
def cve_lookup():
    from scanner.cve import enrich

    product = request.args.get("product", "").strip()
    version = request.args.get("version", "").strip()
    if not product:
        return error_response("INVALID_PRODUCT", "product is required", 400)
    settings = current_app.config["APS_SETTINGS"]
    return data_response(
        enrich(
            product,
            version,
            mode=settings.cve_mode,
            feed_path=settings.cve_feed,
            timeout=settings.cve_timeout,
            base_url=settings.cve_api_url,
        )
    )
