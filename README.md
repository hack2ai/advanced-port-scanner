# 🔍 Advanced Port Scanner

<p align="center">
  <strong>Professional defensive network discovery for authorized security testing.</strong><br>
  Fast CLI • Live dashboard • Versioned API • Persistent history • Reports • Analytics • Operational metrics • Controlled CVE enrichment
</p>

<p align="center">
  <a href="https://github.com/hack2ai/advanced-port-scanner/actions/workflows/ci.yml"><img src="https://github.com/hack2ai/advanced-port-scanner/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/hack2ai/advanced-port-scanner/releases/latest"><img src="https://img.shields.io/github/v/release/hack2ai/advanced-port-scanner?sort=semver" alt="Latest release"></a>
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
