# 🔍 Advanced Port Scanner

<p align="center">
  <strong>Professional defensive network discovery for authorized security testing.</strong><br>
  Fast CLI • Live dashboard • Versioned API • Persistent history • Reports • Analytics • Operational metrics • Controlled CVE enrichment
</p>

<p align="center">
  <a href="https://github.com/hack2ai/advanced-port-scanner/actions/workflows/ci.yml"><img src="https://github.com/hack2ai/advanced-port-scanner/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/hack2ai/advanced-port-scanner/releases/tag/v0.3.0"><img src="https://img.shields.io/badge/release-v0.3.0-informational.svg" alt="v0.3.0"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License"></a>
</p>

> **Authorized use only.** Scan systems and networks that you own or have explicit permission to assess.

---

## Product Preview

The project is designed around a focused operator workflow: define the target, choose the scan profile, monitor progress, review observed services, and export the resulting evidence.

```text
┌──────────────────────────────────────────────────────────────┐
│  🔍 Advanced Port Scanner             [▶ New Scan] [📥 Export]│
├────────────────┬─────────────────────────────────────────────┤
│  Target        │  192.168.1.1                                │
│  Scan Mode     │  ● TCP Connect    ○ SYN (lab-only)         │
│  Profile       │  standard                                   │
│  Port Range    │  1 ──────────────────────────── 1024        │
├────────────────┴─────────────────────────────────────────────┤
│  PROGRESS   ████████████████░░░░  78%   [LIVE]              │
├──────────────────────────────────────────────────────────────┤
│  PORT   SERVICE   VERSION / BANNER          RISK             │
│  22     SSH       OpenSSH 8.9p1             🟡 MEDIUM        │
│  80     HTTP      Apache/2.4.54             🟠 HIGH          │
│  443    HTTPS     nginx/1.22.0              🟢 LOW           │
│  3306   MySQL     5.7.39-log                 🔴 CRITICAL      │
├──────────────────────────────────────────────────────────────┤
│  Jobs: 1 active   History: 42   Open ports: 7               │
└──────────────────────────────────────────────────────────────┘
```

The block above is a **representative UI preview**, not a screenshot of a specific scan result. Actual findings depend on the authorized target and detected services.

---

## Why Advanced Port Scanner?

Advanced Port Scanner is a Python-based network discovery platform built for predictable, controlled assessments rather than unrestricted scanning.

- **Operator-first:** use the CLI for focused work or the Flask dashboard for repeatable workflows.
- **Bounded by design:** target, port, timeout, worker, queue, and retention limits prevent accidental workload expansion.
- **Evidence-oriented:** service, version, banner, risk, history, analytics, and reports are persisted in structured form.
- **Security-conscious:** authentication, RBAC, CSRF protection, rate limiting, security headers, hardened containers, and controlled proxy behavior are built in.
- **Transparent:** open ports, risk hints, and service fingerprints are observations—not proof that a host is vulnerable.

## Feature Set

### 🔎 Discovery & Fingerprinting

- Concurrent TCP connect scanning
- Optional SYN probing for controlled laboratory environments
- IPv4 and IPv6 target handling
- Lightweight banner collection
- Product/version/service fingerprinting with confidence metadata
- Heuristic TTL/OS indication
- Configurable socket and banner timeouts
- Reusable `quick`, `standard`, `extended`, and `full` profiles

### ⚙️ Job Management

- Bounded asynchronous scan queue
- Live progress reporting
- Cooperative cancellation
- Accurate terminal status and duration tracking
- Configurable history retention
- Persistent completed, failed, and cancelled job records

### 📊 Reports, Analytics & Metrics

- Structured JSON reports
- CSV and TXT exports
- Human-readable HTML reports
- SQLite-backed scan history
- Analytics for volume, targets, ports, services, risk distribution, and duration
- Operational metrics for active, queued, running, completed, failed, and cancelled work

### 🛡️ Controlled CVE Enrichment

- Separate from heuristic port-risk hints
- Explicit modes: `off`, `offline`, and `online`
- Operator-supplied offline JSON feeds
- Optional NVD API lookup in online mode
- Source-aware CVE records
- Non-critical enrichment: lookup failure does not invalidate an otherwise valid scan

### 🌐 Dashboard & API

- Responsive Flask dashboard
- Versioned `/api/v1` interface
- Request IDs on API responses
- Session authentication with `viewer`, `operator`, and `admin` roles
- Login and scan rate limiting
- CSRF protection for protected mutations
- Security response headers
- Explicit trusted-proxy configuration

### 🐳 Deployment & Distribution

- Installable Python package with the `aps` console command
- Gunicorn-compatible deployment
- Non-root Docker runtime
- Dropped Linux capabilities and `no-new-privileges`
- Persistent Docker volumes for application state
- GitHub Actions CI on Python 3.11, 3.12, and 3.13
- Tag-driven PyPI release workflow with OIDC trusted publishing support

---

## Architecture

```text
                         ┌────────────────────────┐
                         │       CLI / Web UI      │
                         └────────────┬───────────┘
                                      │
                                      ▼
                         ┌────────────────────────┐
                         │ Validation + Resolution│
                         │ bounds • auth • proxy  │
                         └────────────┬───────────┘
                                      │
                                      ▼
                         ┌────────────────────────┐
                         │      Job Manager        │
                         │ queue • progress •      │
                         │ cancellation • limits   │
                         └────────────┬───────────┘
                                      │
                                      ▼
                         ┌────────────────────────┐
                         │      Scan Engine        │
                         │ TCP • SYN • banners •   │
                         │ service fingerprinting  │
                         └───────────┬─────┬───────┘
                                     │     │
                        ┌────────────┘     └────────────┐
                        ▼                              ▼
              ┌──────────────────┐          ┌──────────────────┐
              │ SQLite History   │          │ Report Generator │
              │ + Analytics      │          │ JSON/CSV/TXT/HTML│
              └────────┬─────────┘          └──────────────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ Operational      │
              │ Metrics          │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ CVE Enrichment   │
              │ off/offline/online│
              └──────────────────┘
```

---

## Project Layout

```text
advanced-port-scanner/
├── scanner/
│   ├── analytics.py
│   ├── auth.py
│   ├── config.py
│   ├── cve.py
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
│   ├── installation.md
│   └── v0.3-release.md
├── data/
├── reports/
├── logs/
├── .github/workflows/
│   ├── ci.yml
│   └── pypi.yml
├── Dockerfile
├── docker-compose.yml
├── main.py
├── pyproject.toml
├── requirements.txt
├── CHANGELOG.md
└── README.md
```

---

## Requirements

- Python **3.11+**
- Project dependencies installed from `pyproject.toml`
- Optional Scapy support for SYN mode
- Docker + Docker Compose for container deployment

---

## Installation

### From source

```bash
git clone https://github.com/hack2ai/advanced-port-scanner.git
cd advanced-port-scanner
python -m venv .venv
```

Activate the virtual environment, then install the project:

```bash
python -m pip install -e .
```

Optional SYN support:

```bash
python -m pip install -e '.[syn]'
```

Verify the CLI:

```bash
aps --version
aps --help
aps profiles
```

### Python package

The repository includes a PEP 517 package definition and an automated release workflow. PyPI publishing uses GitHub OIDC when the corresponding PyPI Trusted Publisher is configured.

---

## CLI Quick Start

Run a small authorized local/lab scan:

```bash
aps scan 127.0.0.1 --profile quick
```

Use the standard profile:

```bash
aps scan 127.0.0.1 --profile standard
```

Scan an explicit range:

```bash
aps scan 127.0.0.1 --ports 1-1024
```

Disable banner collection:

```bash
aps scan 127.0.0.1 --profile standard --no-banner
```

Generate reports:

```bash
aps scan 127.0.0.1 --profile standard \
  --save-json --save-csv --save-txt \
  --output-dir reports
```

The CLI and web API enforce the configured `MAX_TARGETS` and `MAX_PORTS` limits. Scan profiles cannot bypass those controls.

---

## Dashboard

Start the Flask application locally:

```bash
python web/app.py
```

Then open:

```text
http://127.0.0.1:5000
```

For a production-style deployment, use Gunicorn as described in [`docs/installation.md`](docs/installation.md).

---

## API v1

The preferred machine-readable interface is `/api/v1`.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Service health |
| `GET` | `/api/v1/profiles` | Available scan profiles |
| `POST` | `/api/v1/scans` | Queue an authorized scan |
| `GET` | `/api/v1/scans/<job_id>` | Read scan status/results |
| `POST` | `/api/v1/scans/<job_id>/cancel` | Request cancellation |
| `GET` | `/api/v1/jobs` | List recent jobs |
| `GET` | `/api/v1/history` | List persisted history |
| `GET` | `/api/v1/history/<job_id>` | Read stored scan details |
| `GET` | `/api/v1/reports/<job_id>/html` | Render HTML report |
| `GET` | `/api/v1/analytics` | Read persisted analytics |
| `GET` | `/api/v1/metrics` | Read operational metrics |
| `GET` | `/api/v1/cve/lookup` | Lookup CVE enrichment for a product/version |

### Metrics response

```json
{
  "data": {
    "active_jobs": 0,
    "queued_jobs": 0,
    "running_jobs": 0,
    "retained_history": 42,
    "completed_scans": 38,
    "failed_scans": 2,
    "cancelled_scans": 2,
    "average_duration_seconds": 3.42,
    "total_open_ports": 71
  },
  "request_id": "..."
}
```

### CVE lookup

```text
GET /api/v1/cve/lookup?product=OpenSSH&version=9.8
```

CVE enrichment respects the configured mode and is `off` by default.

Successful responses use:

```json
{
  "data": {},
  "request_id": "..."
}
```

Errors use:

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

---

## Scan Profiles

| Profile | Default range | Intended use |
| --- | --- | --- |
| `quick` | `1-100` | Fast first-pass discovery |
| `standard` | `1-1024` | General-purpose discovery |
| `extended` | `1-10000` | Broader service discovery |
| `full` | `1-65535` | Full TCP coverage when explicitly permitted |

The effective range is always constrained by `MAX_PORTS`.

---

## Configuration

Configuration is centralized in `scanner/config.py` and can be overridden with environment variables.

| Variable | Default | Purpose |
| --- | ---: | --- |
| `HOST` | `127.0.0.1` | Web bind address |
| `PORT` | `5000` | Web port |
| `MAX_CONCURRENT_JOBS` | `2` | Concurrent job capacity |
| `MAX_TARGETS` | `16` | Maximum targets per request |
| `MAX_PORTS` | `4096` | Maximum ports per scan |
| `SOCKET_TIMEOUT` | `0.5` | TCP connection timeout |
| `BANNER_TIMEOUT` | `0.75` | Banner probe timeout |
| `HISTORY_RETENTION` | `100` | Stored history records |
| `REPORT_RETENTION` | `100` | Stored report groups |
| `AUTH_ENABLED` | `false` | Enable session authentication |
| `SECURE_COOKIES` | `false` | Mark cookies as Secure |
| `TRUST_PROXY_HEADERS` | `false` | Trust proxy forwarding headers |
| `CVE_MODE` | `off` | `off`, `offline`, or `online` |
| `CVE_FEED` | empty | Local CVE JSON feed path |
| `CVE_TIMEOUT` | `5.0` | Online CVE request timeout |
| `CVE_API_URL` | NVD v2 endpoint | Online CVE provider URL |

See [`docs/configuration.md`](docs/configuration.md) for authentication, password handling, rate limits, proxy settings, CVE enrichment, and deployment guidance.

---

## CVE Enrichment

CVE enrichment deliberately remains separate from the scanner's heuristic risk hints.

### Modes

- **`off`** — no CVE lookup
- **`offline`** — search an operator-supplied local JSON feed
- **`online`** — query the configured NVD-compatible endpoint

Example offline configuration:

```bash
export CVE_MODE=offline
export CVE_FEED=data/cve-feed.json
```

Online mode must be explicitly enabled. A CVE match should be interpreted as a research signal tied to an observed product/version—not as automatic proof that a specific host is vulnerable.

---

## Docker Deployment

Build and start the application:

```bash
docker compose up --build
```

The container stack is hardened to:

- run as a non-root user
- drop unnecessary Linux capabilities
- enable `no-new-privileges`
- persist SQLite data, reports, and logs with Docker-managed volumes
- keep SYN/raw-packet capability disabled by default

The default deployment intentionally uses one Gunicorn worker with multiple threads because scan job and rate-limit state are process-local. Multi-process scaling requires a shared backend for that state.

For an authorized lab that requires SYN mode, enable the relevant capability deliberately and review the deployment guidance first.

---

## Security Model

Authentication is disabled by default for local development. Controlled deployments should enable authentication and configure strong credentials, cookies, TLS, and network access controls.

### Roles

| Role | Capabilities |
| --- | --- |
| **viewer** | Read-only jobs, history, analytics, reports, metrics, and CVE lookup |
| **operator** | Viewer permissions plus scan and cancellation operations |
| **admin** | Operator permissions plus administrative capability reserved for future expansion |

Additional protections include CSRF validation, login and scan rate limiting, security headers, bounded workloads, and explicit trusted-proxy configuration.

### Important limitations

- An open port indicates reachability, **not vulnerability**.
- Risk labels are informational guidance, not a substitute for vulnerability research.
- Service fingerprinting is heuristic and includes confidence metadata rather than certainty.
- TTL/OS identification is heuristic and may be affected by routing devices.
- Banner collection is intentionally lightweight.
- CVE enrichment depends on product/version identification and the selected data source.
- Operational metrics are derived from process-local jobs and retained history, not a long-term telemetry platform.

---

## Reports & History

A completed scan can produce a structured report containing:

- scanner and schema version
- scan time and duration
- scan type and profile
- selected port range
- target-level results
- service/version/banner observations
- risk guidance

JSON is the preferred structured format for automation. HTML is intended for human review.

Persisted history is stored in SQLite and bounded by `HISTORY_RETENTION`. Generated report groups are bounded by `REPORT_RETENTION`.

---

## Testing & Development

Run the full test suite locally:

```bash
python -m pytest -q
```

The repository CI validates Python 3.11, 3.12, and 3.13.

Recommended development loop:

```bash
python -m pytest -q
aps --help
aps profiles
```

When changing API, security, scanner, or deployment behavior, add or update regression coverage in `tests/`.

---

## Release

Current application version: **0.3.0**.

- **GitHub release:** [v0.3.0](https://github.com/hack2ai/advanced-port-scanner/releases/tag/v0.3.0)
- **Changelog:** [`CHANGELOG.md`](CHANGELOG.md)
- **Release notes:** [`docs/v0.3-release.md`](docs/v0.3-release.md)

The project includes a tag-driven PyPI workflow using GitHub OIDC. Actual publishing requires the corresponding PyPI Trusted Publisher configuration on the PyPI side.

---

## Contributing

1. Create a focused branch.
2. Make the smallest change that solves the problem.
3. Add regression tests for behavior changes.
4. Run `python -m pytest -q` locally.
5. Open a pull request with a clear summary and validation notes.

---

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE).

## Responsible Use

Advanced Port Scanner is intended for **defensive discovery, validation, and authorized security testing**. Do not use it for credential attacks, exploitation, stealth, evasion, or unauthorized access.
