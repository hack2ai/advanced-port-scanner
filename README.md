# Advanced Network Port Scanner

> A Python network-security project combining multithreaded TCP scanning, optional SYN probing, service/banner detection, risk hints, report generation, and a Flask-based monitoring dashboard.

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Web%20Dashboard-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)

## Overview

**Advanced Network Port Scanner** is a defensive security and network-engineering project for authorized asset discovery and service visibility.

The application provides both a command-line interface and a Flask web dashboard. The scanning engine supports concurrent TCP checks, optional SYN probing, banner collection, basic OS fingerprinting, risk classification, and exportable scan reports.

> **Authorized use only:** scan only systems you own or have explicit permission to test. This project is intended for controlled labs, defensive administration, and authorized security assessments.

## Architecture

```text
                 Target / Lab Network
                         │
                         ▼
                Scanner Configuration
                         │
              ┌──────────┴──────────┐
              │                     │
        TCP Connect             SYN Probe
              │                     │
              └──────────┬──────────┘
                         ▼
                Concurrent Scan Engine
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
           Banner      Risk       OS / TTL
          Detection   Hints       Analysis
              │          │          │
              └──────────┼──────────┘
                         ▼
                  Results / Reports
                    │           │
                    ▼           ▼
                  CLI      Flask Dashboard
```

## Key Capabilities

- Multithreaded TCP port discovery
- Optional SYN probing through Scapy
- Service/banner detection
- Basic TTL-based OS indication
- Port/service risk hints
- JSON, CSV and TXT report export
- Flask dashboard with scan-job status
- REST API for starting and monitoring jobs
- Docker support
- Timestamped logs and reports
- Configurable target and port ranges

## Technology Stack

| Area | Technology |
|---|---|
| Language | Python |
| CLI | argparse + Rich |
| Scanner | Python sockets + optional Scapy |
| Web | Flask |
| Frontend charts | Chart.js |
| API | Flask REST endpoints |
| Containerization | Docker / Docker Compose |
| Reports | JSON • CSV • TXT |

## Project Structure

```text
advanced-port-scanner/
├── scanner/
│   ├── scanner.py          # Scanning engine
│   ├── utils.py            # Logging, resolution and reporting helpers
│   └── vuln_hints.py       # Service/risk classification
├── web/
│   ├── app.py              # Flask dashboard + API
│   └── templates/
│       └── index.html
├── reports/                # Generated scan reports
├── logs/                   # Scan logs
├── main.py                 # CLI entry point
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Getting Started

### Prerequisites

- Python 3.x
- `pip`
- Docker (optional)
- Scapy (optional, for SYN probing)

### Install

```bash
git clone https://github.com/hack2ai/advanced-port-scanner.git
cd advanced-port-scanner
python -m venv venv
```

Activate the virtual environment, then install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Use the scanner only against an authorized lab or system.

### CLI

```bash
python main.py --help
```

The CLI supports configurable targets, port ranges, scan mode, banner collection, and report output.

For safe experimentation, use a local VM/lab environment or another target for which you have explicit authorization.

### Web Dashboard

Start the Flask application:

```bash
python web/app.py
```

The dashboard exposes scan configuration, job progress, result tables, risk distribution, and top-port visualizations.

### REST API

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/scan` | Create an authorized scan job |
| `GET` | `/api/status/<id>` | Retrieve job status/results |
| `GET` | `/api/jobs` | List recent jobs |

## Scanning Modes

| Mode | Description | Typical Requirement |
|---|---|---|
| TCP Connect | Uses normal TCP connection attempts | Standard user privileges |
| SYN | Sends raw SYN probes through Scapy | Elevated privileges may be required |

The SYN mode is provided for controlled security-testing environments and should not be used against systems without authorization.

## Reporting

Scan results can be exported for later analysis:

```text
reports/
├── scan_<timestamp>.json
├── scan_<timestamp>.csv
└── scan_<timestamp>.txt
```

## Docker

The repository includes Docker configuration for reproducible local execution. Review container privileges before enabling raw-packet scanning in a production environment.

```bash
docker compose up --build
```

## Security & Responsible Use

This project is intended for:

- Personal cybersecurity labs
- Authorized penetration-testing exercises
- Defensive asset inventory
- Network administration and troubleshooting
- Security education

Do not scan third-party infrastructure without explicit authorization.

For a production-grade security platform, additional controls would be appropriate, including authentication, authorization, rate limiting, audit logging, tenant isolation, job quotas, secret management, and stronger service/CVE verification.

## Limitations

- Port availability does not prove a service is vulnerable.
- Banner data can be incomplete or misleading.
- TTL-based OS identification is heuristic rather than definitive.
- Risk hints are informational and should be validated against authoritative vulnerability intelligence.
- Network filtering, NAT, firewalls, IDS/IPS controls, and rate limits can affect results.

## Roadmap

- [ ] Automated pytest coverage
- [ ] CI quality checks
- [ ] Persistent scan history
- [ ] Authenticated dashboard
- [ ] NVD/CVE enrichment
- [ ] UDP discovery research in an isolated lab environment
- [ ] Improved service identification
- [ ] Structured audit logging
- [ ] Semantic versioning and changelog

## Project Value

This project demonstrates practical **Python security engineering, concurrent networking, REST API development, web visualization, Dockerization, reporting, and defensive network reconnaissance concepts**.

## Author

**Pankaj (Tony) Kumar**  
AI Engineer • Full Stack Developer • Generative AI & RAG Specialist

[GitHub](https://github.com/hack2ai) • [LinkedIn](https://www.linkedin.com/in/pankaj-kumar-ab591a216)

## License

See the repository license file for the applicable project license.
