"""
web/app.py — Flask Web Dashboard & REST API for the Advanced Port Scanner.

Endpoints:
  GET  /               → Main dashboard (HTML)
  POST /api/scan       → Start a scan job  → { job_id }
  GET  /api/status/<id>→ Poll job status   → { status, results, ... }
  GET  /api/jobs       → List recent jobs

Run:
  python web/app.py
  # or
  flask --app web/app.py run --host 0.0.0.0 --port 5000
"""

import os
import sys
import time
import uuid
import threading
from datetime import datetime

from flask import Flask, jsonify, render_template, request

# Allow imports from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.scanner import scan_target
from scanner.utils   import (
    resolve_target,
    parse_port_range,
    setup_logging,
    save_json,
    save_csv,
    save_txt,
)


# ─────────────────────────────────────────────────────────────────────────────
#  App setup
# ─────────────────────────────────────────────────────────────────────────────

app    = Flask(__name__, template_folder="templates")
logger = setup_logging(log_dir=os.path.join(os.path.dirname(__file__), "..", "logs"))

# In-memory job store  { job_id: { status, results, started, duration } }
scan_jobs: dict[str, dict] = {}
jobs_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main web dashboard."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """
    Start an async port scan job.

    Expected JSON body:
      {
        "targets":      "192.168.1.1,scanme.nmap.org",
        "ports":        "1-1024",
        "scan_type":    "tcp",          // "tcp" | "syn"
        "grab_banner":  true
      }

    Returns:
      { "job_id": "<8-char id>" }
    """
    body = request.get_json(silent=True) or {}

    targets_raw  = str(body.get("targets", "")).strip()
    ports_raw    = str(body.get("ports", "1-1024")).strip()
    scan_type    = body.get("scan_type", "tcp")
    grab_banner  = bool(body.get("grab_banner", True))

    if not targets_raw:
        return jsonify({"error": "No targets provided"}), 400

    port_range = parse_port_range(ports_raw)
    if not port_range:
        return jsonify({"error": f"Invalid port range: {ports_raw}"}), 400

    raw_targets = [t.strip() for t in targets_raw.split(",") if t.strip()]

    job_id = str(uuid.uuid4())[:8]

    with jobs_lock:
        scan_jobs[job_id] = {
            "status":       "resolving",
            "targets_raw":  targets_raw,
            "ports":        ports_raw,
            "scan_type":    scan_type,
            "results":      {},
            "started":      time.time(),
            "duration":     None,
            "total_open":   0,
            "error":        None,
        }

    def _run() -> None:
        start, end = port_range
        try:
            with jobs_lock:
                scan_jobs[job_id]["status"] = "scanning"

            for raw_t in raw_targets:
                ip = resolve_target(raw_t, logger)
                if not ip:
                    with jobs_lock:
                        scan_jobs[job_id]["results"][raw_t] = {
                            "ip": None,
                            "error": f"Could not resolve '{raw_t}'",
                            "open_ports": [],
                            "os_guess": "Unknown",
                        }
                    continue

                data = scan_target(ip, start, end, scan_type, grab_banner, logger)

                with jobs_lock:
                    scan_jobs[job_id]["results"][raw_t] = data
                    scan_jobs[job_id]["total_open"] += len(data.get("open_ports", []))

            elapsed = round(time.time() - scan_jobs[job_id]["started"], 2)
            with jobs_lock:
                scan_jobs[job_id]["status"]   = "done"
                scan_jobs[job_id]["duration"] = elapsed

            # Auto-save reports to disk
            results_payload = {
                "scan_time":  datetime.now().isoformat(),
                "duration":   f"{elapsed}s",
                "scan_type":  scan_type.upper(),
                "port_range": ports_raw,
                "total_open": scan_jobs[job_id]["total_open"],
                "targets":    scan_jobs[job_id]["results"],
            }
            ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
            rep_dir = os.path.join(
                os.path.dirname(__file__), "..", "reports"
            )
            os.makedirs(rep_dir, exist_ok=True)
            save_json(results_payload, os.path.join(rep_dir, f"scan_{ts}.json"))
            save_csv (results_payload, os.path.join(rep_dir, f"scan_{ts}.csv"))
            save_txt (results_payload, os.path.join(rep_dir, f"scan_{ts}.txt"))

        except Exception as exc:
            logger.exception(f"Scan job {job_id} failed: {exc}")
            with jobs_lock:
                scan_jobs[job_id]["status"] = "error"
                scan_jobs[job_id]["error"]  = str(exc)

    thread = threading.Thread(target=_run, daemon=True, name=f"scan-{job_id}")
    thread.start()

    return jsonify({"job_id": job_id}), 202


@app.route("/api/status/<job_id>")
def scan_status(job_id: str):
    """
    Poll the status and partial/full results of a scan job.

    Returns the full job dict including results once complete.
    """
    with jobs_lock:
        job = scan_jobs.get(job_id)

    if not job:
        return jsonify({"error": "Job not found"}), 404

    return jsonify(job)


@app.route("/api/jobs")
def list_jobs():
    """Return a summary list of all scan jobs (most recent first)."""
    with jobs_lock:
        summaries = [
            {
                "job_id":     jid,
                "status":     j["status"],
                "targets":    j["targets_raw"],
                "ports":      j["ports"],
                "total_open": j["total_open"],
                "duration":   j["duration"],
                "started":    j["started"],
            }
            for jid, j in scan_jobs.items()
        ]
    summaries.sort(key=lambda x: x["started"], reverse=True)
    return jsonify(summaries)


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  🚀  Dashboard running at  http://localhost:{port}\n")
    app.run(debug=True, host="0.0.0.0", port=port)
