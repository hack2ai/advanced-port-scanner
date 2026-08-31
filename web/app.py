"""Flask dashboard and REST API for authorized network discovery."""
from __future__ import annotations
import os, sys, threading, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, jsonify, render_template, request
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.history import ScanHistory
from scanner.scanner import scan_target
from scanner.utils import parse_port_range, resolve_target, save_csv, save_json, save_txt, setup_logging
app = Flask(__name__, template_folder="templates")
app.config["JSON_SORT_KEYS"] = False
logger = setup_logging(str(ROOT / "logs"))
history = ScanHistory(os.getenv("SCAN_DB", str(ROOT / "data" / "scans.db")))
jobs: dict[str, dict] = {}
jobs_lock = threading.Lock()
MAX_JOBS = int(os.getenv("MAX_CONCURRENT_JOBS", "2")); MAX_TARGETS = int(os.getenv("MAX_TARGETS", "16")); MAX_PORTS = int(os.getenv("MAX_PORTS", "4096"))
job_semaphore = threading.BoundedSemaphore(MAX_JOBS)

def _utc_now() -> str: return datetime.now(timezone.utc).isoformat()

def _validate_request(body: dict):
    targets_raw = str(body.get("targets", "")).strip(); ports_raw = str(body.get("ports", "1-1024")).strip(); scan_type = str(body.get("scan_type", "tcp")).lower(); grab_banner = bool(body.get("grab_banner", True))
    if not targets_raw: return None, None, None, None, "No targets provided"
    if scan_type not in {"tcp", "syn"}: return None, None, None, None, "scan_type must be 'tcp' or 'syn'"
    port_range = parse_port_range(ports_raw)
    if not port_range: return None, None, None, None, "Invalid port range"
    start, end = port_range
    if end - start + 1 > MAX_PORTS: return None, None, None, None, f"Port range exceeds configured limit of {MAX_PORTS} ports"
    targets = list(dict.fromkeys(t.strip() for t in targets_raw.split(",") if t.strip()))
    if len(targets) > MAX_TARGETS: return None, None, None, None, f"Too many targets; maximum is {MAX_TARGETS}"
    return targets_raw, port_range, scan_type, grab_banner, targets

@app.get("/")
def index(): return render_template("index.html")

@app.get("/api/health")
def health(): return jsonify({"status":"ok","service":"advanced-port-scanner","time":_utc_now()})

@app.post("/api/scan")
def start_scan():
    body = request.get_json(silent=True)
    if not isinstance(body, dict): return jsonify({"error":"Request body must be JSON"}), 400
    targets_raw, port_range, scan_type, grab_banner, targets_or_error = _validate_request(body)
    if targets_raw is None: return jsonify({"error":targets_or_error}), 400
    targets = targets_or_error; job_id = uuid.uuid4().hex[:12]
    with jobs_lock:
        jobs[job_id] = {"job_id":job_id,"status":"queued","targets":targets_raw,"ports":f"{port_range[0]}-{port_range[1]}","scan_type":scan_type.upper(),"results":{},"total_open":0,"started":time.time(),"started_at":_utc_now(),"duration":None,"error":None}
    def run():
        acquired = job_semaphore.acquire(timeout=1)
        if not acquired:
            with jobs_lock: jobs[job_id]["status"]="error"; jobs[job_id]["error"]="Server is busy; try again shortly"
            return
        try:
            with jobs_lock: jobs[job_id]["status"]="scanning"
            start,end=port_range
            for target in targets:
                ip=resolve_target(target,logger)
                result={"ip":None,"open_ports":[],"os_guess":"Unknown","ttl":None,"error":"Target could not be resolved"} if not ip else scan_target(ip,start,end,scan_type,grab_banner,logger)
                with jobs_lock:
                    jobs[job_id]["results"][target]=result; jobs[job_id]["total_open"]+=len(result.get("open_ports",[]))
            with jobs_lock:
                elapsed=round(time.time()-jobs[job_id]["started"],2); jobs[job_id]["status"]="done"; jobs[job_id]["duration"]=elapsed; payload={"scan_time":jobs[job_id]["started_at"],"duration":f"{elapsed}s","scan_type":scan_type.upper(),"port_range":jobs[job_id]["ports"],"total_open":jobs[job_id]["total_open"],"targets":jobs[job_id]["results"]}
                completed=dict(jobs[job_id])
            history.save(completed)
            report_dir=ROOT/"reports"; report_dir.mkdir(exist_ok=True); timestamp=datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            save_json(payload,str(report_dir/f"scan_{timestamp}_{job_id}.json")); save_csv(payload,str(report_dir/f"scan_{timestamp}_{job_id}.csv")); save_txt(payload,str(report_dir/f"scan_{timestamp}_{job_id}.txt"))
        except Exception:
            logger.exception("Scan job %s failed",job_id)
            with jobs_lock: jobs[job_id]["status"]="error"; jobs[job_id]["error"]="Internal scan error"
            try:
                with jobs_lock: failed=dict(jobs[job_id])
                history.save(failed)
            except Exception: logger.exception("Could not persist failed job %s",job_id)
        finally: job_semaphore.release()
    threading.Thread(target=run,daemon=True,name=f"scan-{job_id}").start()
    return jsonify({"job_id":job_id,"status":"queued"}),202

@app.get("/api/status/<job_id>")
def status(job_id):
    with jobs_lock: job=jobs.get(job_id)
    if job is not None: return jsonify(dict(job))
    stored=history.get(job_id)
    return jsonify(stored) if stored else (jsonify({"error":"Job not found"}),404)

@app.get("/api/jobs")
def list_jobs():
    with jobs_lock:
        live=[{key:job[key] for key in ("job_id","status","targets","ports","scan_type","total_open","started_at","duration","error")} for job in jobs.values()]
    return jsonify(live[:50] if live else history.list(50))

@app.get("/api/history")
def list_history():
    try: limit=max(1,min(int(request.args.get("limit",50)),200))
    except ValueError: return jsonify({"error":"limit must be an integer"}),400
    return jsonify(history.list(limit))

@app.get("/api/history/<job_id>")
def history_detail(job_id):
    item=history.get(job_id)
    return jsonify(item) if item else (jsonify({"error":"History entry not found"}),404)

if __name__ == "__main__":
    host=os.getenv("HOST","127.0.0.1"); port=int(os.getenv("PORT","5000")); app.run(host=host,port=port,debug=False)
