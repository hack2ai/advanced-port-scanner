# Advanced Port Scanner

A professional Python tool for **authorized network asset discovery**. It provides a focused CLI, a Flask dashboard/API, concurrent TCP discovery, optional lab-only SYN probing, lightweight service banners, informational risk hints, and JSON/CSV/TXT reporting.

> **Authorized use only.** Scan systems you own or have explicit permission to assess.

## What changed in v3

- Fixed the repository/package layout so CLI, web app, Docker, and imports use the same structure.
- Added input validation and configurable resource limits for web jobs.
- Reduced scanner concurrency to a safer default and added IPv4/IPv6 connection handling.
- Added UTC timestamps and a versioned report schema.
- Added a health endpoint and production Gunicorn container startup.
- Added non-root container execution, `no-new-privileges`, and dropped Linux capabilities by default.
- Added automated pytest coverage and GitHub Actions CI.
- Rebuilt the dashboard around a responsive, lightweight interface.
- Clarified that risk metadata is informational and is not proof of a vulnerability.

## Architecture

```text
CLI / Web UI
     │
     ▼
Input validation ──► target resolution
     │
     ▼
Concurrent scan engine
     ├── TCP Connect
     ├── optional SYN (controlled lab)
     └── lightweight banner probe
     │
     ├── service metadata
     ├── informational risk hints
     └── heuristic TTL/OS indication
     │
     ▼
Structured results ──► JSON / CSV / TXT
```

## Project structure

```text
advanced-port-scanner/
├── scanner/
│   ├── __init__.py
│   ├── scanner.py
│   ├── utils.py
│   └── vuln_hints.py
├── web/
│   ├── app.py
│   └── templates/
│       └── index.html
├── tests/
│   ├── test_scanner.py
│   ├── test_utils.py
│   └── test_web.py
├── .github/workflows/ci.yml
├── main.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Quick start

### Local

```bash
git clone https://github.com/hack2ai/advanced-port-scanner.git
cd advanced-port-scanner
python -m venv .venv
```

Activate `.venv`, then:

```bash
python -m pip install -r requirements.txt
python main.py --help
```

Example against an authorized local/lab target:

```bash
python main.py -t 127.0.0.1 -p 1-1024 --save-json --save-csv --save-txt
```

### Dashboard

```bash
python web/app.py
```

Open `http://127.0.0.1:5000`.

Useful endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/scan` | Queue an authorized scan |
| GET | `/api/status/<job_id>` | Poll a scan |
| GET | `/api/jobs` | List recent jobs |

### Docker

```bash
docker compose up --build
```

The container runs the dashboard through Gunicorn as a non-root user. Reports and logs are persisted in local `reports/` and `logs/` directories.

SYN mode is **not** enabled by default in the container. If you deliberately need raw packets in an isolated lab, review and explicitly enable the `NET_RAW` capability in `docker-compose.yml`.

## Scanner options

```text
-t, --targets       Comma-separated IPs/hostnames
-p, --ports         Single port or inclusive range
--scan-type         tcp or syn
--no-banner         Disable lightweight banner collection
--save-json         Export JSON
--save-csv          Export CSV
--save-txt          Export TXT
--output-dir        Report destination
-V, --version       Show scanner version
```

The web service applies configurable limits:

- `MAX_CONCURRENT_JOBS` — default `2`
- `MAX_TARGETS` — default `16`
- `MAX_PORTS` — default `4096`

## Reports

JSON reports include a `schema_version` and `scanner_version` so downstream tooling can evolve safely. CSV contains one row per discovered open port; TXT is intended for quick human review.

## Testing

Run the local test suite:

```bash
python -m pytest -q
```

GitHub Actions runs the suite on supported Python 3.11–3.13 environments.

## Security notes

- Open ports indicate reachability, not vulnerability.
- Risk hints are static defensive guidance and should be validated against authoritative vulnerability intelligence.
- Banner collection is intentionally small and non-invasive.
- TTL-based OS identification is heuristic and can be affected by routing and network devices.
- The web API is designed for local/controlled deployment. Put it behind authentication, TLS, and network access controls before exposing it to untrusted users.
- Do not add stealth, credential attacks, exploitation, or evasion features to this project.

## Roadmap

- [ ] Persistent scan history
- [ ] Authentication and role-based authorization for the dashboard
- [ ] Structured audit events
- [ ] Improved service identification
- [ ] Optional authoritative CVE enrichment
- [ ] Export filtering and report templates
- [ ] Packaging as an installable CLI (`pipx` friendly)

## License

See the repository license file for the applicable project license.
