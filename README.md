# Advanced Port Scanner

<p align="center">
  <strong>Professional defensive network discovery for authorized security testing.</strong><br>
  Fast local CLI • Flask dashboard • Versioned API • Persistent history • Reports • Analytics • Operational metrics
</p>

<p align="center">
  <a href="https://github.com/hack2ai/advanced-port-scanner/actions/workflows/ci.yml"><img src="https://github.com/hack2ai/advanced-port-scanner/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/hack2ai/advanced-port-scanner/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/release-0.2.1-informational.svg" alt="v0.2.1">
</p>

> **Authorized use only.** Scan systems you own or have explicit permission to assess.

## Overview

Advanced Port Scanner is a Python-based network discovery platform designed for controlled, authorized security assessment. It combines a focused command-line interface with a Flask dashboard and versioned REST API.

The project is built around predictable resource controls, persistent scan history, cooperative job cancellation, structured reporting, operational metrics, and security-conscious deployment defaults.

## Why this project

- **One scanner, multiple interfaces** — use the CLI for focused work or the dashboard/API for repeatable operations.
- **Bounded by design** — target, port, concurrency, timeout, queue, and retention limits keep workloads predictable.
- **Operationally useful** — scans persist to SQLite, exports can be generated as JSON/CSV/TXT/HTML, analytics are derived from stored results, and operational metrics expose current workload and historical outcomes.
- **Security-aware** — authentication, RBAC, CSRF protection, rate limiting, security headers, non-root containers, and dropped Linux capabilities are included.
- **Transparent results** — service and risk metadata are presented as observations and guidance, not as proof of vulnerabilities.

## Features

### Scanning

- Concurrent TCP connect scanning with bounded worker usage
- Optional SYN mode for controlled lab environments
- IPv4/IPv6 connection handling
- Lightweight banner collection
- Service/product/version fingerprinting with confidence metadata
- Heuristic TTL/OS indication
- Configurable socket and banner timeouts
- Reusable scan profiles

### Job management

- Bounded asynchronous scan queue
- Live progress reporting
- Cooperative cancellation
- Accurate terminal status and elapsed time
- Persistent history for completed, failed, and cancelled jobs
- Configurable history retention

### Reporting, analytics & metrics

- Versioned JSON report model
- CSV and TXT exports
- HTML reports with scan metadata and findings
- Persistent scan history in SQLite
- Configurable report retention
- Analytics for scan volume, unique targets, open ports, high-risk findings, duration, risk distribution, and top services
- Operational metrics for active/queued/running jobs, retained history, completed/failed/cancelled scans, average duration, and total open ports

### Web & API

- Responsive Flask dashboard
- Versioned `/api/v1` endpoints
- Request IDs for API responses
- Session authentication with `viewer`, `operator`, and `admin` roles
- Login and scan rate limiting
- CSRF protection for protected mutations
- Security response headers
- Trusted-proxy support only when explicitly enabled

### Deployment

- Installable Python package with an `aps` console command
- Gunicorn-compatible web deployment
- Non-root Docker execution
- `no-new-privileges` and dropped capabilities in Compose
- Persistent Docker storage for SQLite data, reports, and logs
- CI across Python 3.11, 3.12, and 3.13

## Architecture

```text
                    ┌─────────────────────┐
                    │     CLI / Web UI     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Input validation &   │
                    │ target resolution    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Job Manager      │
                    │ queue • progress •  │
                    │ cancellation        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Scan Engine       │
                    │ TCP • SYN • banner  │
                    │ service detection   │
                    └───────┬─────┬───────┘
                            │     │
                ┌───────────┘     └────────────┐
                ▼                              ▼
        ┌─────────────────┐          ┌─────────────────┐
        │ SQLite history  │          │ JSON/CSV/TXT/   │
        │ + analytics     │          │ HTML reports    │
        └────────┬────────┘          └─────────────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Operational     │
        │ metrics         │
        └─────────────────┘
```

## Project layout

```text
advanced-port-scanner/
├── scanner/
│   ├── analytics.py
│   ├── auth.py
│   ├── config.py
│   ├── history.py
│   ├── jobs.py
│   ├── metrics.py
│   ├── profiles.py
│   ├── reporting.py
│   ├── retention.py
│   ├── scanner.py
│   ├── security.py
│   ├── service_detection.py
│   ├── utils.py
│   ├── version.py
│   └── vuln_hints.py
├── web/
│   ├── api_v1.py
│   ├── app.py
│   └── templates/
├── tests/
├── docs/
│   ├── configuration.md
│   └── installation.md
├── data/
├── reports/
├── logs/
├── .github/workflows/ci.yml
├── Dockerfile
├── docker-compose.yml
├── main.py
├── pyproject.toml
├── requirements.txt
├── CHANGELOG.md
└── README.md
```

## Requirements

- Python 3.11 or newer
- For normal TCP scanning: standard Python runtime plus project dependencies
- Optional Scapy installation for SYN mode
- Docker and Docker Compose for container deployment

## Installation

### From source

```bash
git clone https://github.com/hack2ai/advanced-port-scanner.git
cd advanced-port-scanner
python -m venv .venv
```

Activate the environment and install the project:

```bash
python -m pip install -e .
```

Optional SYN support:

```bash
python -m pip install -e '.[syn]'
```

Verify the installation:

```bash
aps --version
aps --help
```

## CLI usage

List available profiles:

```bash
aps profiles
```

Run a small authorized local/lab scan:

```bash
aps scan 127.0.0.1 --profile quick
```

Use the standard profile:

```bash
aps scan 127.0.0.1 --profile standard
```

Specify an explicit range:

```bash
aps scan 127.0.0.1 --ports 1-1024
```

Disable banner collection:

```bash
aps scan 127.0.0.1 --profile standard --no-banner
```

Save reports:

```bash
aps scan 127.0.0.1 --profile standard \
  --save-json --save-csv --save-txt \
  --output-dir reports
```

The CLI and web API both enforce `MAX_TARGETS` and `MAX_PORTS` safety limits. Profiles cannot bypass those controls.

## Dashboard

Start the Flask application locally:

```bash
python web/app.py
```

Open:

```text
http://127.0.0.1:5000
```

For a production-style process, use Gunicorn as described in [`docs/installation.md`](docs/installation.md).

## API v1

The preferred machine-readable interface is `/api/v1`.

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Service health |
| `GET` | `/api/v1/profiles` | Available profiles |
| `POST` | `/api/v1/scans` | Queue an authorized scan |
| `GET` | `/api/v1/scans/<job_id>` | Read scan status/results |
| `POST` | `/api/v1/scans/<job_id>/cancel` | Request cancellation |
| `GET` | `/api/v1/jobs` | List recent jobs |
| `GET` | `/api/v1/history` | List persisted history |
| `GET` | `/api/v1/history/<job_id>` | Read stored scan details |
| `GET` | `/api/v1/reports/<job_id>/html` | Render an HTML report |
| `GET` | `/api/v1/analytics` | Read persisted analytics |
| `GET` | `/api/v1/metrics` | Read operational metrics |

The metrics response currently includes:

```json
{
  "data": {
    "active_jobs": 0,
    "queued_jobs": 0,
    "running_jobs": 0,
    "retained_history": 0,
    "completed_scans": 0,
    "failed_scans": 0,
    "cancelled_scans": 0,
    "average_duration_seconds": 0.0,
    "total_open_ports": 0
  },
  "request_id": "..."
}
```

Successful JSON responses use a request-aware envelope:

```json
{
  "data": {},
  "request_id": "..."
}
```

Errors use a structured form:

```json
{
  "error": {
    "code": "...",
    "message": "..."
  },
  "request_id": "..."
}
```

Legacy `/api/...` endpoints remain available for compatibility.

## Scan profiles

| Profile | Range | Intended use |
| --- | --- | --- |
| `quick` | `1-100` | Fast first-pass discovery |
| `standard` | `1-1024` | General-purpose discovery |
| `extended` | `1-10000` | Broader service discovery |
| `full` | `1-65535` | Full TCP port coverage when explicitly permitted |

The effective range is always subject to the configured `MAX_PORTS` limit.

## Configuration

Configuration is centralized in `scanner/config.py` and can be overridden using environment variables.

Key controls include:

| Variable | Default | Purpose |
| --- | ---: | --- |
| `HOST` | `127.0.0.1` | Bind address |
| `PORT` | `5000` | Web port |
| `MAX_CONCURRENT_JOBS` | `2` | Concurrent queued scans |
| `MAX_TARGETS` | `16` | Maximum targets per request |
| `MAX_PORTS` | `4096` | Maximum ports per scan |
| `SOCKET_TIMEOUT` | `0.5` | TCP connection timeout |
| `BANNER_TIMEOUT` | `0.75` | Banner probe timeout |
| `HISTORY_RETENTION` | `100` | Stored history records |
| `REPORT_RETENTION` | `100` | Stored report groups |
| `AUTH_ENABLED` | `false` | Enable session authentication |
| `SECURE_COOKIES` | `false` | Mark cookies Secure |
| `TRUST_PROXY_HEADERS` | `false` | Trust `X-Forwarded-For` when behind a configured proxy |

See [`docs/configuration.md`](docs/configuration.md) for authentication, password hashing, rate limits, and deployment guidance.

## Docker

Build and start the stack:

```bash
docker compose up --build
```

The Compose configuration:

- runs the application as a non-root user
- drops Linux capabilities
- enables `no-new-privileges`
- persists data, reports, and logs using Docker-managed volumes
- keeps SYN/raw-packet capability disabled by default

The container intentionally uses one Gunicorn worker with multiple threads because scan job state and rate-limit state are process-local. Multi-process scaling requires a shared job/rate-limit backend.

For authorized lab environments that require SYN mode, review the commented capability configuration in `docker-compose.yml` and enable it deliberately.

## Security model

Authentication is disabled by default for local development. For controlled deployments, enable authentication and configure a strong secret, credentials, and appropriate cookie settings.

Roles:

- **viewer** — read-only access to jobs, history, analytics, and reports
- **operator** — viewer access plus scan and cancellation operations
- **admin** — operator access plus administrative capability reserved for future expansion

Additional protections include CSRF validation, login/scan rate limiting, response security headers, bounded workloads, and explicit trusted-proxy configuration.

### Important limitations

- Open ports indicate network reachability, not vulnerability.
- Risk labels are informational guidance, not a substitute for vulnerability research.
- Service fingerprinting is heuristic and reports confidence rather than certainty.
- TTL/OS identification is heuristic and can be influenced by routing devices.
- Banner collection is intentionally lightweight.
- Operational metrics are derived from process-local jobs and retained history, not a long-term telemetry system.
- Before exposing the dashboard/API outside a trusted environment, use authentication, TLS, and network access controls.

## Reports & history

A completed scan can produce a structured report with:

- schema and scanner version
- scan time and duration
- scan type and profile
- selected port range
- target-level results
- service/version/banner observations
- risk guidance

The HTML report is designed for human review, while JSON is the preferred structured format for automation.

Persisted history is stored in SQLite and is bounded by `HISTORY_RETENTION`. Generated report groups are bounded by `REPORT_RETENTION`.

## Testing & development

Run the complete test suite locally:

```bash
python -m pytest -q
```

The repository CI validates the project across Python 3.11, 3.12, and 3.13.

Recommended development loop:

```bash
python -m pytest -q
aps --help
aps profiles
```

When changing API or deployment behavior, add or update regression coverage in `tests/`.

## Roadmap

- [ ] Metrics dashboard visualization and historical time-series storage
- [ ] Authoritative CVE enrichment with explicit offline/online modes
- [ ] PyPI / `pipx` release workflow
- [ ] Expanded multi-user administration
- [ ] Additional operational observability

## Release

Current application version: **0.2.1**.

See [`CHANGELOG.md`](CHANGELOG.md) for release history.

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE).

## Responsible use

Use Advanced Port Scanner only on systems and networks you are authorized to assess. The project is intended for defensive discovery, validation, and security testing—not credential attacks, exploitation, stealth, or evasion.
