"""Flask dashboard and REST API for authorized network discovery."""

from __future__ import annotations

import os
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.scanner import scan_target
from scanner.utils import parse_port_range, resolve_target, save_csv, save_json, save_txt, setup_logging

app = Flask(__name__, template_folder="templates")
app.config["JSON_SORT_KEYS"] = False
logger = setup_logging(str(ROOT / "logs"))

jobs: dict[str, dict] = {}
jobs_lock = threading.Lock()
MAX_JOBS = int(os.getenv("MAX_CONCURRENT_JOBS", "2"))
MAX_TARGETS = int(os.getenv("MAX_TARGETS", "16"))
MAX_PORTS = int(os.getenv("MAX_PORTS", "4096"))
job_semaphore = threading.BoundedSemaphore(MAX_JOBS)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_request(body: dict) -> tuple[str, tuple[int, int], str, bool, list[str]] | tuple[None, None, None, None, str]:
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
    if end - start + 1 > MAX_PORTS:
        return None, None, None, None, f"Port range exceeds configured limit of {MAX_PORTS} ports"

    targets = list(dict.fromkeys(t.strip() for t in targets_raw.split(",") if t.strip()))
    if len(targets) > MAX_TARGETS:
        return None, None, None, None, f"Too many targets; maximum is {MAX_TARGETS}"
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

    job_id = uuid.uuid4().hex[:12]
    with jobs_lock:
        jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "targets": targets_raw,
            "ports": f"{port_range[0]}-{port_range[1]}",
            "scan_type": scan_type.upper(),
            "results": {},
            "total_open": 0,
            "started": time.time(),
            "started_at": _utc_now(),
            "duration": None,
            "error": None,
        }

    def run() -> None:
        acquired = job_semaphore.acquire(timeout=1)
        if not acquired:
            with jobs_lock:
                jobs[job_id]["status"] = "error"
                jobs[job_id]["error"] = "Server is busy; try again shortly"
            return
        try:
            with jobs_lock:
                jobs[job_id]["status"] = "scanning"
            start, end = port_range
            for target in targets:
                ip = resolve_target(target, logger)
                if not ip:
                    result = {"ip": None, "open_ports": [], "os_guess": "Unknown", "ttl": None, "error": "Target could not be resolved"}
                else:
                    result = scan_target(ip, start, end, scan_type, grab_banner, logger)
                with jobs_lock:
                    jobs[job_id]["results"][target] = result
                    jobs[job_id]["total_open"] += len(result.get("open_ports", []))

            with jobs_lock:
                elapsed = round(time.time() - jobs[job_id]["started"], 2)
                jobs[job_id]["status"] = "done"
                jobs[job_id]["duration"] = elapsed
                payload = {
                    "scan_time": jobs[job_id]["started_at"],
                    "duration": f"{elapsed}s",
                    "scan_type": scan_type.upper(),
                    "port_range": jobs[job_id]["ports"],
                    "total_open": jobs[job_id]["total_open"],
                    "targets": jobs[job_id]["results"],
                }
            report_dir = ROOT / "reports"
            report_dir.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_json(payload, str(report_dir / f"scan_{timestamp}_{job_id}.json"))
            save_csv(payload, str(report_dir / f"scan_{timestamp}_{job_id}.csv"))
            save_txt(payload, str(report_dir / f"scan_{timestamp}_{job_id}.txt"))
        except Exception as exc:
            logger.exception("Scan job %s failed", job_id)
            with jobs_lock:
                jobs[job_id]["status"] = "error"
                jobs[job_id]["error"] = "Internal scan error"
        finally:
            job_semaphore.release()

    threading.Thread(target=run, daemon=True, name=f"scan-{job_id}").start()
    return jsonify({"job_id": job_id, "status": "queued"}), 202


@app.get("/api/status/<job_id>")
def status(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
        if job is None:
            return jsonify({"error": "Job not found"}), 404
        return jsonify(dict(job))


@app.get("/api/jobs")
def list_jobs():
    with jobs_lock:
        summaries = [
            {key: job[key] for key in ("job_id", "status", "targets", "ports", "scan_type", "total_open", "started_at", "duration", "error")}
            for job in jobs.values()
        ]
    return jsonify(sorted(summaries, key=lambda item: item["started_at"], reverse=True)[-50:])


if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    app.run(host=host, port=port, debug=False)
