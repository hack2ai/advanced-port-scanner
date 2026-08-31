"""Validation, logging, fingerprinting, and report helpers."""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
from datetime import datetime, timezone
from typing import Optional


def setup_logging(log_dir: str = "logs") -> logging.Logger:
    """Create the application logger once and return it."""
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger("portscanner")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if logger.handlers:
        return logger

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    formatter = logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s", "%Y-%m-%d %H:%M:%S")
    file_handler = logging.FileHandler(os.path.join(log_dir, f"scan_{timestamp}.log"), encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.WARNING)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def resolve_target(target: str, logger: Optional[logging.Logger] = None) -> Optional[str]:
    """Validate a literal IP or resolve a hostname to a usable address."""
    target = target.strip()
    if not target or len(target) > 253:
        return None
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass

    # Keep hostname input deliberately conservative; shell execution is never used.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", target):
        return None
    try:
        addresses = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        if not addresses:
            return None
        resolved = addresses[0][4][0]
        if logger:
            logger.info("Resolved %s -> %s", target, resolved)
        return resolved
    except socket.gaierror as exc:
        if logger:
            logger.warning("Cannot resolve %s: %s", target, exc)
        return None


def parse_port_range(port_str: str) -> Optional[tuple[int, int]]:
    """Parse one port or an inclusive port range."""
    value = port_str.strip()
    if re.fullmatch(r"\d+", value):
        port = int(value)
        return (port, port) if 1 <= port <= 65535 else None
    match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", value)
    if match:
        start, end = map(int, match.groups())
        return (start, end) if 1 <= start <= end <= 65535 else None
    return None


def get_ttl(ip: str) -> Optional[int]:
    """Read a TTL from one system ping without invoking a shell."""
    try:
        if os.name == "nt":
            command = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            command = ["ping", "-c", "1", "-W", "1", ip]
        result = subprocess.run(command, capture_output=True, text=True, timeout=4, check=False)
        match = re.search(r"(?:TTL|ttl)[=:\s](\d+)", result.stdout)
        return int(match.group(1)) if match else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def detect_os(ttl: int) -> str:
    """Return a broad heuristic OS family based on observed TTL."""
    if ttl <= 64:
        return "Linux / macOS / Unix (heuristic)"
    if ttl <= 128:
        return "Windows (heuristic)"
    if ttl <= 255:
        return "Network Device / Unix (heuristic)"
    return "Unknown"


def _ensure_dir(filepath: str) -> None:
    parent = os.path.dirname(filepath)
    if parent:
        os.makedirs(parent, exist_ok=True)


def save_json(results: dict, filepath: str) -> None:
    _ensure_dir(filepath)
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False, default=str)


def save_csv(results: dict, filepath: str) -> None:
    _ensure_dir(filepath)
    fields = ["target", "ip", "port", "service", "banner", "risk", "vuln_hint"]
    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for target, data in results.get("targets", {}).items():
            for port in data.get("open_ports", []):
                writer.writerow({
                    "target": target,
                    "ip": data.get("ip", ""),
                    "port": port.get("port", ""),
                    "service": port.get("service", ""),
                    "banner": port.get("banner", ""),
                    "risk": port.get("risk", "INFO"),
                    "vuln_hint": port.get("vuln_hint", ""),
                })


def save_txt(results: dict, filepath: str) -> None:
    _ensure_dir(filepath)
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("ADVANCED PORT SCANNER — SCAN REPORT\n")
        fh.write("=" * 72 + "\n")
        fh.write(f"Scan Time: {results.get('scan_time', 'N/A')}\n")
        fh.write(f"Duration: {results.get('duration', 'N/A')}\n")
        fh.write(f"Scan Type: {results.get('scan_type', 'N/A')}\n")
        fh.write(f"Port Range: {results.get('port_range', 'N/A')}\n")
        fh.write(f"Total Open: {results.get('total_open', 0)}\n\n")
        for target, data in results.get("targets", {}).items():
            fh.write(f"Target: {target}\nIP: {data.get('ip', 'N/A')}\nOS: {data.get('os_guess', 'Unknown')}\n")
            for port in data.get("open_ports", []):
                fh.write(f"  {port['port']:<6} {port.get('service','unknown'):<16} {port.get('risk','INFO'):<9} {port.get('banner','')}\n")
                if port.get("vuln_hint"):
                    fh.write(f"         Hint: {port['vuln_hint']}\n")
            fh.write("\n")
