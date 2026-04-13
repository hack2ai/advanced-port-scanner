"""
utils.py — Helper utilities for the Advanced Port Scanner.

Includes:
  - Logging setup
  - Target resolution & validation
  - Port range parsing
  - OS fingerprinting (TTL-based)
  - Report export (JSON, CSV, TXT)
"""

import socket
import ipaddress
import json
import csv
import logging
import os
import re
import subprocess
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(log_dir: str = "logs") -> logging.Logger:
    """
    Configure a logger that writes DEBUG+ to file and WARNING+ to console.

    Args:
        log_dir: Directory where log files are stored.

    Returns:
        Configured Logger instance.
    """
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file  = os.path.join(log_dir, f"scan_{timestamp}.log")

    logger = logging.getLogger("portscanner")
    logger.setLevel(logging.DEBUG)

    # Avoid adding duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger


# ─────────────────────────────────────────────────────────────────────────────
#  Target validation & resolution
# ─────────────────────────────────────────────────────────────────────────────

def resolve_target(target: str, logger: Optional[logging.Logger] = None) -> Optional[str]:
    """
    Validate an IP address or resolve a hostname to its IP.

    Args:
        target: IP string or hostname.
        logger: Optional logger for info/error messages.

    Returns:
        Resolved IP string, or None if resolution fails.
    """
    target = target.strip()

    # Try as a literal IP first
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Attempt DNS resolution
    try:
        resolved = socket.gethostbyname(target)
        if logger:
            logger.info(f"Resolved '{target}' → {resolved}")
        return resolved
    except socket.gaierror as exc:
        if logger:
            logger.error(f"Cannot resolve '{target}': {exc}")
        return None


def parse_port_range(port_str: str) -> Optional[tuple[int, int]]:
    """
    Parse a port specification into a (start, end) tuple.

    Accepted formats:
      "80"        → (80, 80)
      "20-1000"   → (20, 1000)
      "1-65535"   → (1, 65535)

    Returns:
        Tuple (start, end) or None if input is invalid.
    """
    port_str = port_str.strip()

    if re.fullmatch(r"\d+", port_str):
        p = int(port_str)
        if 1 <= p <= 65535:
            return (p, p)

    m = re.fullmatch(r"(\d+)-(\d+)", port_str)
    if m:
        start, end = int(m.group(1)), int(m.group(2))
        if 1 <= start <= end <= 65535:
            return (start, end)

    return None


# ─────────────────────────────────────────────────────────────────────────────
#  OS fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

def get_ttl(ip: str) -> Optional[int]:
    """
    Ping the target and extract the TTL value from the response.

    Returns:
        Integer TTL, or None if the ping fails / is blocked.
    """
    try:
        if os.name == "nt":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=4
        )
        match = re.search(r"[Tt][Tt][Ll]=(\d+)", result.stdout)
        if match:
            return int(match.group(1))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def detect_os(ttl: int) -> str:
    """
    Guess the OS family from a TTL value.

    Common TTL defaults:
      64  → Linux / macOS / Unix
      128 → Windows
      255 → Cisco IOS / network appliance

    Args:
        ttl: TTL integer extracted from a ping response.

    Returns:
        Human-readable OS guess string.
    """
    if ttl <= 64:
        return "Linux / macOS / Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Cisco / Network Device"
    return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
#  Report export
# ─────────────────────────────────────────────────────────────────────────────

def _ensure_dir(filepath: str) -> None:
    """Create parent directories for a file path if they don't exist."""
    parent = os.path.dirname(filepath)
    if parent:
        os.makedirs(parent, exist_ok=True)


def save_json(results: dict, filepath: str) -> None:
    """
    Serialize the full results dictionary to a pretty-printed JSON file.

    Args:
        results:  The scan results dict produced by build_results_dict().
        filepath: Destination file path.
    """
    _ensure_dir(filepath)
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=4, default=str)


def save_csv(results: dict, filepath: str) -> None:
    """
    Flatten scan results into a CSV where each row is one open port.

    Columns: target, ip, port, service, banner, risk, vuln_hint

    Args:
        results:  The scan results dict.
        filepath: Destination file path.
    """
    _ensure_dir(filepath)
    rows = []
    for target, data in results.get("targets", {}).items():
        for p in data.get("open_ports", []):
            rows.append({
                "target":    target,
                "ip":        data.get("ip", target),
                "port":      p["port"],
                "service":   p.get("service", ""),
                "banner":    p.get("banner", ""),
                "risk":      p.get("risk", ""),
                "vuln_hint": p.get("vuln_hint", ""),
            })

    if not rows:
        rows = [{"note": "No open ports found"}]

    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def save_txt(results: dict, filepath: str) -> None:
    """
    Write a human-readable plain-text scan report.

    Args:
        results:  The scan results dict.
        filepath: Destination file path.
    """
    _ensure_dir(filepath)
    sep  = "=" * 62
    sep2 = "-" * 42

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(f"{sep}\n")
        fh.write("     ADVANCED PORT SCANNER — SCAN REPORT\n")
        fh.write(f"{sep}\n")
        fh.write(f"  Scan Time  : {results.get('scan_time', 'N/A')}\n")
        fh.write(f"  Duration   : {results.get('duration', 'N/A')}\n")
        fh.write(f"  Scan Type  : {results.get('scan_type', 'N/A')}\n")
        fh.write(f"  Port Range : {results.get('port_range', 'N/A')}\n")
        fh.write(f"  Total Open : {results.get('total_open', 0)}\n")
        fh.write(f"{sep}\n\n")

        for target, data in results.get("targets", {}).items():
            fh.write(f"  Target   : {target}\n")
            fh.write(f"  IP       : {data.get('ip', target)}\n")
            fh.write(f"  OS Guess : {data.get('os_guess', 'Unknown')}\n")
            open_ports = data.get("open_ports", [])
            fh.write(f"  Open Ports: {len(open_ports)}\n")
            fh.write(f"  {sep2}\n")

            if open_ports:
                fh.write(f"  {'PORT':<8} {'SERVICE':<16} {'RISK':<10} BANNER\n")
                fh.write(f"  {'─'*8} {'─'*16} {'─'*10} {'─'*30}\n")
                for p in open_ports:
                    banner_short = (p.get("banner") or "")[:40]
                    fh.write(
                        f"  {p['port']:<8} {p.get('service',''):<16} "
                        f"{p.get('risk','INFO'):<10} {banner_short}\n"
                    )
                    hint = p.get("vuln_hint", "")
                    if hint:
                        fh.write(f"  {'':8} ⚠  {hint}\n")
            else:
                fh.write("  No open ports found.\n")

            fh.write("\n")
