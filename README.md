# Advanced Port Scanner

A professional Python tool for **authorized network asset discovery**. It provides a focused CLI, a Flask dashboard/API, concurrent TCP discovery, optional lab-only SYN probing, lightweight service banners, informational risk hints, and JSON/CSV/TXT reporting.

> **Authorized use only.** Scan systems you own or have explicit permission to assess.

## Release baseline — v0.1.0

The `release-v0.1.0` branch consolidates the current professional foundation:

- Clean `scanner/` and `web/` package layout
- Input validation and configurable resource limits
- IPv4/IPv6 connection handling and bounded concurrency
- Persistent SQLite scan history
- Centralized environment-based configuration
- Structured JSON audit logging
- Versioned JSON reports plus CSV/TXT exports
- Health and job APIs
- Responsive dashboard
- Automated pytest suite and GitHub Actions CI
- Non-root Docker execution, dropped capabilities, and `no-new-privileges`
- Installable Python package metadata with an `aps` console entry point

Risk metadata is informational guidance, not proof of a vulnerability.

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
     ├──────────────► SQLite scan history
     │
     └──────────────► JSON / CSV / TXT reports
```

## Project structure

```text
advanced-port-scanner/
├── scanner/
│   ├── __init__.py
│   ├── config.py
│   ├── history.py
│   ├── scanner.py
│   ├── utils.py
│   └── vuln_hints.py
├── web/
│   ├── app.py
│   └── templates/index.html
├── tests/
├── docs/
│   ├── installation.md
│   └── configuration.md
├── data/
├── reports/
├── logs/
├── .github/workflows/ci.yml
├── main.py
├── pyproject.toml
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

Activate the environment, then install the package:

```bash
python -m pip install -e .
```

CLI help:

```bash
aps --help
```

The legacy-compatible entry point remains available:

```bash
python main.py --help
```

Example against an authorized local/lab target:

```bash
aps scan 127.0.0.1 --ports 1-1024
```

### Dashboard

```bash
python web/app.py
```

Open `http://127.0.0.1:5000`.

Current API endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/scan` | Queue an authorized scan |
| GET | `/api/status/<job_id>` | Poll a scan |
| GET | `/api/jobs` | List recent jobs |
| GET | `/api/history` | List persisted scan history |
| GET | `/api/history/<job_id>` | Retrieve persisted scan details |

### Docker

```bash
docker compose up --build
```

The container runs the dashboard through Gunicorn as a non-root user. Reports, database data, and logs are intended to be persisted through the configured local volumes.

SYN mode is **not** enabled by default in the container. If you deliberately need raw packets in an isolated lab, review and explicitly enable the required capability in `docker-compose.yml`.

## Configuration

Configuration is centralized in `scanner/config.py` and can be overridden with environment variables. See [`docs/configuration.md`](docs/configuration.md).

Important limits include:

- `MAX_CONCURRENT_JOBS` — default `2`
- `MAX_TARGETS` — default `16`
- `MAX_PORTS` — default `4096`
- scanner socket/banner timeouts
- database and report paths

## Reports and history

Completed jobs are stored in SQLite for persistent history. JSON reports include schema metadata. CSV contains one row per discovered open port, while TXT is intended for quick human review.

Structured audit events are emitted as JSON logs for operational visibility.

## Testing

Run the local test suite:

```bash
python -m pytest -q
```

GitHub Actions runs the configured test matrix.

## Security notes

- Scan only systems you own or have explicit permission to assess.
- Open ports indicate reachability, not vulnerability.
- Risk hints are static defensive guidance and should be validated against authoritative vulnerability intelligence.
- Banner collection is intentionally small and non-invasive.
- TTL-based OS identification is heuristic and can be affected by routing and network devices.
- Before exposing the web API beyond a trusted local/controlled environment, add authentication, TLS, and network access controls.
- Do not add credential attacks, exploitation, stealth, or evasion functionality.

## Roadmap

- [ ] Authentication and role-based authorization
- [ ] Dedicated job manager with cooperative cancellation and accurate progress
- [ ] Improved service identification
- [ ] Optional authoritative CVE enrichment
- [ ] HTML report templates
- [ ] Expanded analytics dashboard
- [ ] `pipx` release workflow

## License

See the repository license file for the applicable project license.
