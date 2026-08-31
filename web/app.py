"""Flask dashboard and REST API for authorized network discovery."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.config import settings
from scanner.history import ScanHistory
from scanner.jobs import JobManager, ScanJob
from scanner.scanner import scan_target
from scanner.utils import audit, parse_port_range, resolve_target, save_csv, save_json, save_txt, setup_logging

app = Flask(__name__, template_folder="templates")
app.config["JSON_SORT_KEYS"] = False
logger = setup_logging(str(ROOT / "logs"))
history = ScanHistory(settings.scan_db)
job_manager = JobManager(max_workers=settings.max_concurrent_jobs, max_queue=16, retention=100)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_request(body: dict):
    targets_raw = str(body.get("targets", "")).strip()
    ports_raw = str(body.get("ports", "1-1024")).strip()
    scan_type = str(body.get("scan_type", "tcp")).lower()
    grab_banner = bool(body.get("grab_banner", True))
    if not targets_raw:
        return None, None, None, None, "No targets provided"
    if scan_type not in {"tcp", "syn"}:
        return None, None, None, None, "scan_type must be 'tcp' or 'syn'"
    port_range = parse_port_range(ports_raw)
    if not port_range:
        return None, None, None, None, "Invalid port range"
    start, end = port_range
    if end - start + 1 > settings.max_ports:
        return None, None, None, None, f"Port range exceeds configured limit of {settings.max_ports} ports"
    targets = list(dict.fromkeys(t.strip() for t in targets_raw.split(",") if t.strip()))
    if len(targets) > settings.max_targets:
        return None, None, None, None, f"Too many targets; maximum is {settings.max_targets}"
    return targets_raw, port_range, scan_type, grab_banner, targets


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "advanced-port-scanner", "time": _utc_now()})


@app.post("/api/scan")
def start_scan():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be JSON"}), 400
    targets_raw, port_range, scan_type, grab_banner, targets_or_error = _validate_request(body)
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
                return
            job.current_target = target
            ip = resolve_target(target, logger)
            if not ip:
                job.results[target] = {
                    "ip": None,
                    "open_ports": [],
                    "os_guess": "Unknown",
                    "ttl": None,
                    "error": "Target could not be resolved",
                }
                completed_offset += end_port - start_port + 1
                job_manager.update_progress(job, completed=completed_offset, current_target=target, result_target=target, result=job.results[target])
                continue

            def progress(done: int, total: int) -> None:
                job_manager.update_progress(
                    job,
                    completed=completed_offset + done,
                    current_target=target,
                )

            try:
                result = scan_target(
                    ip,
                    start_port,
                    end_port,
                    scan_type,
                    grab_banner,
                    logger,
                    progress_callback=progress,
                    cancel_event=job.cancel_event,
                )
            except InterruptedError:
                job.status = "cancelled"
                return

            completed_offset += end_port - start_port + 1
            job_manager.update_progress(
                job,
                completed=completed_offset,
                current_target=target,
                total_open=job.total_open + len(result.get("open_ports", [])),
                result_target=target,
                result=result,
            )
            job.total_open += len(result.get("open_ports", []))

        elapsed = 0.0
        if job.started_monotonic is not None:
            import time
            elapsed = round(max(0.0, time.monotonic() - job.started_monotonic), 2)
        payload = {
            "schema_version": "1.0",
            "scan_time": job.started_at or job.created_at,
            "duration": f"{elapsed}s",
            "scan_type": job.scan_type,
            "port_range": job.ports,
            "total_open": job.total_open,
            "targets": job.results,
        }
        history.save(job.snapshot(include_results=True))
        report_dir = ROOT / settings.reports_dir
        report_dir.mkdir(exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        save_json(payload, str(report_dir / f"scan_{timestamp}_{job.job_id}.json"))
        save_csv(payload, str(report_dir / f"scan_{timestamp}_{job.job_id}.csv"))
        save_txt(payload, str(report_dir / f"scan_{timestamp}_{job.job_id}.txt"))

    try:
        job = job_manager.submit(
            targets_raw,
            f"{start_port}-{end_port}",
            scan_type,
            total_work,
            runner,
        )
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 429

    audit(logger, "scan_queued", job_id=job.job_id, target_count=len(targets), total_work=total_work)
    return jsonify({"job_id": job.job_id, "status": job.status}), 202


@app.get("/api/status/<job_id>")
def status(job_id: str):
    job = job_manager.get(job_id)
    if job is not None:
        return jsonify(job.snapshot(include_results=True))
    stored = history.get(job_id)
    return jsonify(stored) if stored else (jsonify({"error": "Job not found"}), 404)


@app.post("/api/status/<job_id>/cancel")
def cancel(job_id: str):
    if not job_manager.cancel(job_id):
        job = job_manager.get(job_id)
        if job is None:
            return jsonify({"error": "Job not found or already expired"}), 404
        return jsonify({"error": "Job is already finished"}), 409
    audit(logger, "scan_cancel_requested", job_id=job_id)
    job = job_manager.get(job_id)
    return jsonify(job.snapshot(include_results=True))


@app.get("/api/jobs")
def list_jobs():
    return jsonify(job_manager.list(50))


@app.get("/api/history")
def list_history():
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    return jsonify(history.list(limit))


@app.get("/api/history/<job_id>")
def history_detail(job_id: str):
    item = history.get(job_id)
    return jsonify(item) if item else (jsonify({"error": "History entry not found"}), 404)


if __name__ == "__main__":
    app.run(host=settings.host, port=settings.port, debug=False)
