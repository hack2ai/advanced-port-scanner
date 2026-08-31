"""Flask dashboard and REST API for authorized network discovery."""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, session

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.auth import authenticate
from scanner.config import settings
from scanner.history import ScanHistory
from scanner.jobs import JobManager, ScanJob
from scanner.profiles import get_profile, list_profiles
from scanner.reporting import render_html_report
from scanner.scanner import scan_target
from scanner.security import RateLimiter, csrf_token, require_csrf, security_headers
from scanner.utils import audit, parse_port_range, resolve_target, save_csv, save_json, save_txt, setup_logging

app = Flask(__name__, template_folder="templates")
app.config["JSON_SORT_KEYS"] = False
app.secret_key = settings.secret_key or "development-only-insecure-key"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = settings.secure_cookies
logger = setup_logging(str(ROOT / "logs"))
history = ScanHistory(settings.scan_db)
job_manager = JobManager(max_workers=settings.max_concurrent_jobs, max_queue=16, retention=100)
auth_limiter = RateLimiter(settings.auth_rate_limit, settings.auth_rate_window)
scan_limiter = RateLimiter(settings.scan_rate_limit, settings.scan_rate_window)

if settings.auth_enabled and (not settings.secret_key or not settings.auth_username or not settings.auth_password_hash):
    raise RuntimeError("AUTH_ENABLED requires SECRET_KEY, AUTH_USERNAME, and AUTH_PASSWORD_HASH")
if settings.auth_role not in {"viewer", "operator", "admin"}:
    raise RuntimeError("AUTH_ROLE must be viewer, operator, or admin")


@app.after_request
def add_security_headers(response):
    return security_headers(response)


def _client_key(prefix: str) -> str:
    address = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",", 1)[0].strip()
    return f"{prefix}:{address}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require(action: str):
    def decorator(view):
        @wraps(view)
        @require_csrf
        def wrapped(*args, **kwargs):
            if not settings.auth_enabled:
                return view(*args, **kwargs)
            username = session.get("username", "")
            role = session.get("role", "")
            if not username:
                return jsonify({"error": "Authentication required"}), 401
            allowed = role == "admin" or (role == "operator" and action in {"view", "scan", "cancel"}) or (role == "viewer" and action == "view")
            if not allowed:
                audit(logger, "permission_denied", username=username, action=action)
                return jsonify({"error": "Permission denied"}), 403
            return view(*args, **kwargs)
        return decorator_body_safe(wrapped)
    return decorator


def decorator_body_safe(view):
    return view


@app.post("/api/auth/login")
def login():
    if not settings.auth_enabled:
        return jsonify({"error": "Authentication is disabled"}), 400
    if not auth_limiter.allow(_client_key("login")):
        audit(logger, "auth.rate_limited")
        return jsonify({"error": "Too many login attempts; try again later"}), 429
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be JSON"}), 400
    user = authenticate(str(body.get("username", "")), str(body.get("password", "")), settings.auth_username, settings.auth_password_hash, settings.auth_role)
    if user is None:
        audit(logger, "auth.login.failure")
        return jsonify({"error": "Invalid credentials"}), 401
    session.clear()
    session["username"] = user.username
    session["role"] = user.role
    token = csrf_token()
    audit(logger, "auth.login.success", username=user.username, role=user.role)
    return jsonify({"username": user.username, "role": user.role, "csrf_token": token})


@app.post("/api/auth/logout")
@require_csrf
def logout():
    username = session.get("username")
    session.clear()
    if username:
        audit(logger, "auth.logout", username=username)
    return jsonify({"status": "ok"})


@app.get("/api/auth/me")
def me():
    if not settings.auth_enabled:
        return jsonify({"authenticated": False, "auth_enabled": False})
    username = session.get("username")
    token = csrf_token() if username else None
    return jsonify({"authenticated": bool(username), "username": username, "role": session.get("role"), "csrf_token": token})


def _validate_request(body: dict):
    targets_raw = str(body.get("targets", "")).strip()
    profile_name = str(body.get("profile", "")).strip().lower()
    ports_raw = str(body.get("ports", "")).strip()
    scan_type = str(body.get("scan_type", "tcp")).lower()
    grab_banner = bool(body.get("grab_banner", True))
    if not targets_raw:
        return None, None, None, None, None, "No targets provided"
    if scan_type not in {"tcp", "syn"}:
        return None, None, None, None, None, "scan_type must be 'tcp' or 'syn'"
    if profile_name:
        profile = get_profile(profile_name)
        if profile is None:
            return None, None, None, None, None, "Unknown scan profile"
        if ports_raw:
            return None, None, None, None, None, "Specify either profile or ports, not both"
        ports_raw = profile.port_range
    else:
        ports_raw = ports_raw or "1-1024"
    port_range = parse_port_range(ports_raw)
    if not port_range:
        return None, None, None, None, None, "Invalid port range"
    start, end = port_range
    if end - start + 1 > settings.max_ports:
        return None, None, None, None, None, f"Port range exceeds configured limit of {settings.max_ports} ports"
    targets = list(dict.fromkeys(t.strip() for t in targets_raw.split(",") if t.strip()))
    if len(targets) > settings.max_targets:
        return None, None, None, None, None, f"Too many targets; maximum is {settings.max_targets} ports"
    return targets_raw, port_range, scan_type, grab_banner, profile_name or "custom", targets


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "advanced-port-scanner", "time": _utc_now(), "auth_enabled": settings.auth_enabled})


@app.get("/api/profiles")
def profiles():
    return jsonify(list_profiles())


@app.post("/api/scan")
@_require("scan")
def start_scan():
    if not scan_limiter.allow(_client_key("scan")):
        return jsonify({"error": "Too many scan requests; try again later"}), 429
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be JSON"}), 400
    targets_raw, port_range, scan_type, grab_banner, profile_name, targets_or_error = _validate_request(body)
    if targets_raw is None:
        return jsonify({"error": targets_or_error}), 400
    targets = targets_or_error
    start_port, end_port = port_range
    total_work = len(targets) * (end_port - start_port + 1)

    def runner(job: ScanJob) -> None:
        completed_offset = 0
        for target in targets:
            if job.cancel_event.is_set():
                job.status = "cancelled"
                job.finished_at = _utc_now()
                history.save(job.snapshot(include_results=True))
                return
            job.current_target = target
            ip = resolve_target(target, logger)
            if not ip:
                result = {"ip": None, "open_ports": [], "os_guess": "Unknown", "ttl": None, "error": "Target could not be resolved"}
                completed_offset += end_port - start_port + 1
                job_manager.update_progress(job, completed=completed_offset, current_target=target, result_target=target, result=result)
                continue

            def progress(done: int, total: int) -> None:
                job_manager.update_progress(job, completed=completed_offset + done, current_target=target)

            try:
                result = scan_target(ip, start_port, end_port, scan_type, grab_banner, logger, progress_callback=progress, cancel_event=job.cancel_event)
            except InterruptedError:
                job.status = "cancelled"
                job.finished_at = _utc_now()
                history.save(job.snapshot(include_results=True))
                audit(logger, "scan_cancelled", job_id=job.job_id)
                return

            completed_offset += end_port - start_port + 1
            job_manager.update_progress(job, completed=completed_offset, current_target=target, total_open=job.total_open + len(result.get("open_ports", [])), result_target=target, result=result)

        elapsed = round(max(0.0, time.monotonic() - (job.started_monotonic or time.monotonic())), 2)
        payload = {"schema_version": "1.0", "scan_time": job.started_at or job.created_at, "duration": f"{elapsed}s", "scan_type": job.scan_type, "profile": profile_name, "port_range": job.ports, "total_open": job.total_open, "targets": job.results}
        job.status = "completed"
        job.finished_at = _utc_now()
        history.save(job.snapshot(include_results=True) | {"duration": elapsed})
        report_dir = ROOT / settings.reports_dir
        report_dir.mkdir(exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        save_json(payload, str(report_dir / f"scan_{timestamp}_{job.job_id}.json"))
        save_csv(payload, str(report_dir / f"scan_{timestamp}_{job.job_id}.csv"))
        save_txt(payload, str(report_dir / f"scan_{timestamp}_{job.job_id}.txt"))
        html_path = report_dir / f"scan_{timestamp}_{job.job_id}.html"
        html_path.write_text(render_html_report(payload), encoding="utf-8")

    try:
        job = job_manager.submit(targets_raw, f"{start_port}-{end_port}", scan_type, total_work, runner)
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 429
    audit(logger, "scan_queued", job_id=job.job_id, target_count=len(targets), total_work=total_work, profile=profile_name)
    return jsonify({"job_id": job.job_id, "status": job.status, "profile": profile_name}), 202


@app.get("/api/status/<job_id>")
@_require("view")
def status(job_id: str):
    job = job_manager.get(job_id)
    if job is not None:
        return jsonify(job.snapshot(include_results=True))
    stored = history.get(job_id)
    return jsonify(stored) if stored else (jsonify({"error": "Job not found"}), 404)


@app.post("/api/status/<job_id>/cancel")
@_require("cancel")
def cancel(job_id: str):
    if not job_manager.cancel(job_id):
        job = job_manager.get(job_id)
        if job is None:
            return jsonify({"error": "Job not found or already expired"}), 404
        return jsonify({"error": "Job is already finished"}), 409
    audit(logger, "scan_cancel_requested", job_id=job_id, username=session.get("username"))
    job = job_manager.get(job_id)
    return jsonify(job.snapshot(include_results=True))


@app.get("/api/jobs")
@_require("view")
def list_jobs():
    return jsonify(job_manager.list(50))


@app.get("/api/history")
@_require("view")
def list_history():
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    return jsonify(history.list(limit))


@app.get("/api/history/<job_id>")
@_require("view")
def history_detail(job_id: str):
    item = history.get(job_id)
    return jsonify(item) if item else (jsonify({"error": "History entry not found"}), 404)


@app.get("/api/reports/<job_id>/html")
@_require("view")
def html_report(job_id: str):
    item = history.get(job_id)
    if not item:
        return jsonify({"error": "History entry not found"}), 404
    payload = {
        "schema_version": item.get("schema_version", "1.0"),
        "scanner_version": item.get("scanner_version", "3.0.0"),
        "scan_time": item.get("started_at") or item.get("created_at") or _utc_now(),
        "duration": str(item.get("duration", item.get("elapsed_seconds", "N/A"))),
        "scan_type": item.get("scan_type", "N/A"),
        "profile": item.get("profile", "custom"),
        "port_range": item.get("ports", "N/A"),
        "total_open": item.get("total_open", 0),
        "targets": item.get("results", {}),
    }
    audit(logger, "report_viewed", job_id=job_id, format="html", username=session.get("username"))
    return Response(render_html_report(payload), mimetype="text/html")


if __name__ == "__main__":
    app.run(host=settings.host, port=settings.port, debug=False)
