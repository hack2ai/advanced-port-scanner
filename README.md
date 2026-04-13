# ⚡ Advanced Network Port Scanner

A **professional-grade, multi-threaded port scanner** written in Python.
Features TCP/SYN scanning, banner grabbing, vulnerability hints, OS fingerprinting,
a rich CLI interface, and a sleek Flask web dashboard.

> ⚠ **For authorised use only.** Only scan systems you own or have explicit
> written permission to test. Unauthorised scanning is illegal.

---

## 📁 Project Structure

```
advanced-port-scanner/
│
├── scanner/                  # Core scanning package
│   ├── __init__.py           # Package exports
│   ├── scanner.py            # TCP/SYN scan engine, banner grabbing, threading
│   ├── utils.py              # Logging, IP resolution, OS fingerprint, report export
│   └── vuln_hints.py         # 30+ port vulnerability hints & risk levels
│
├── web/                      # Flask web dashboard
│   ├── app.py                # REST API + async scan jobs
│   └── templates/
│       └── index.html        # Single-page dashboard (Chart.js, live polling)
│
├── reports/                  # Auto-saved scan reports (JSON / CSV / TXT)
├── logs/                     # Timestamped scan log files
│
├── main.py                   # CLI entry point (argparse + rich output)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 🚀 Quick Start

### 1. Clone / download the project

```bash
git clone https://github.com/yourname/advanced-port-scanner.git
cd advanced-port-scanner
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv

# Activate:
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. (Optional) Install Scapy for SYN scan

```bash
pip install scapy
# Linux: also run as root / use sudo
# Windows: install Npcap from https://npcap.com first
```

---

## 💻 CLI Usage

```bash
# Basic scan (ports 1-1024)
python main.py -t 192.168.1.1

# Scan a hostname
python main.py -t scanme.nmap.org

# Multiple targets
python main.py -t 192.168.1.1,192.168.1.2 -p 1-65535

# Custom port range
python main.py -t 192.168.1.1 -p 20-1000

# Single port
python main.py -t 192.168.1.1 -p 80

# SYN stealth scan (requires root/Administrator)
sudo python main.py -t 192.168.1.1 --scan-type syn

# Skip banner grabbing (faster)
python main.py -t 192.168.1.1 --no-banner

# Save reports
python main.py -t 192.168.1.1 --save-json --save-csv --save-txt

# Full options
python main.py --help
```

### CLI flags

| Flag            | Description                                       | Default     |
|-----------------|---------------------------------------------------|-------------|
| `-t, --targets` | Target IP(s) or hostname(s), comma-separated      | **required**|
| `-p, --ports`   | Port range: `80`, `20-1000`, `1-65535`            | `1-1024`    |
| `--scan-type`   | `tcp` (no root) or `syn` (root required)          | `tcp`       |
| `--no-banner`   | Skip banner grabbing for faster scans             | off         |
| `--save-json`   | Export results to `reports/scan_<ts>.json`        | off         |
| `--save-csv`    | Export results to `reports/scan_<ts>.csv`         | off         |
| `--save-txt`    | Export results to `reports/scan_<ts>.txt`         | off         |
| `--output-dir`  | Directory for saved reports                       | `reports/`  |

---

## 🌐 Web Dashboard

```bash
python web/app.py
# Open http://localhost:5000 in your browser
```

Features:
- Input target(s), port range, scan type from the browser
- Live progress with terminal log
- Results table with risk badges and vulnerability hints
- **Risk Distribution** doughnut chart
- **Top Open Ports** bar chart

### REST API

| Method | Endpoint             | Description                          |
|--------|----------------------|--------------------------------------|
| POST   | `/api/scan`          | Start a scan job → `{ job_id }`      |
| GET    | `/api/status/<id>`   | Poll job status & results            |
| GET    | `/api/jobs`          | List all recent scan jobs            |

**Example POST body:**
```json
{
  "targets":     "192.168.1.1",
  "ports":       "1-1024",
  "scan_type":   "tcp",
  "grab_banner": true
}
```

---

## 🐳 Docker

```bash
# Build and start web dashboard
docker-compose up --build

# CLI scan via Docker
docker run --rm -it port-scanner \
  python main.py -t 192.168.1.1 -p 1-1024

# SYN scan (needs NET_RAW capability)
docker run --rm -it --cap-add NET_RAW port-scanner \
  python main.py -t 192.168.1.1 --scan-type syn
```

---

## 🔍 Feature Details

### Scan Types

| Type        | How it works                              | Privileges     |
|-------------|-------------------------------------------|----------------|
| TCP Connect | Full 3-way handshake via `connect_ex()`   | None required  |
| SYN Stealth | Raw SYN packet via Scapy; no full connect | Root / Admin   |

### OS Fingerprinting (TTL-based)

| TTL Range | OS Guess                    |
|-----------|-----------------------------|
| ≤ 64      | Linux / macOS / Unix        |
| ≤ 128     | Windows                     |
| ≤ 255     | Cisco / Network Device      |

### Risk Levels

| Level    | Examples                                      |
|----------|-----------------------------------------------|
| CRITICAL | Port 4444, Redis (6379), MongoDB (27017), SMB |
| HIGH     | FTP, Telnet, RDP, MSSQL, MySQL, VNC           |
| MEDIUM   | SSH, SMTP, DNS, LDAP                          |
| LOW      | HTTP, HTTPS, HTTP-Alt                         |
| INFO     | Unknown / unlisted ports                      |

---

## 🧪 Test Targets (authorised)

These are publicly available targets for legal scanner testing:

```bash
python main.py -t scanme.nmap.org -p 1-1024
```

---

## 🧩 Extending the Project

- **Add UDP scanning** — use `SOCK_DGRAM` with payload-based probes
- **Integrate Shodan API** — enrich results with Shodan intelligence
- **CVE lookup** — query NVD/CVE APIs per open port/service
- **Email alerts** — send report via SMTP when scan completes
- **Rate limiting** — add token-bucket throttling for responsible scanning
- **Database storage** — swap in-memory job store for SQLite / PostgreSQL

---

## 📄 Output Files

All reports are saved in `reports/` with timestamps:

```
reports/
├── scan_20240315_142301.json    ← Full structured results
├── scan_20240315_142301.csv     ← Flat table (one row per open port)
└── scan_20240315_142301.txt     ← Human-readable report
```

---

## 💼 Resume / GitHub Suggestions

To make this project stand out:

1. **Add a demo GIF** in your README — record a scan with `asciinema` or screen capture
2. **Write unit tests** (`pytest`) for `utils.py` and `vuln_hints.py`
3. **CI/CD pipeline** — add `.github/workflows/test.yml` with pytest + flake8
4. **Add a CHANGELOG.md** to show versioning discipline
5. **Highlight in resume as:** "Built a multi-threaded Python port scanner with Flask dashboard, REST API, Dockerisation, and CVE-mapped vulnerability hints — 300+ concurrent threads, supports TCP and SYN scan modes"
6. **Add a `--version` flag** and use semantic versioning (1.0.0, 1.1.0, etc.)
7. **Star and fork similar projects** on GitHub and link yours

---

## 📜 Legal Disclaimer

This tool is intended for **educational purposes** and **authorised penetration testing only**.
The author is not responsible for any misuse. Always obtain written permission before
scanning any system you do not own.
