"""
scanner.py — Core scanning engine for the Advanced Port Scanner.

Features:
  - TCP connect scan  (no root required)
  - SYN stealth scan  (requires root; falls back to TCP if scapy unavailable)
  - Banner grabbing   (HTTP probe + raw recv)
  - Service detection (socket database + local map)
  - Multi-threaded via ThreadPoolExecutor
  - Progress bar via tqdm
"""

import socket
import concurrent.futures
import logging
from typing import Optional

from tqdm import tqdm

from scanner.vuln_hints import VULNERABILITY_HINTS
from scanner.utils import detect_os, get_ttl


# ─────────────────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────────────────

CONNECT_TIMEOUT: float = 1.0    # seconds for TCP connect
BANNER_TIMEOUT:  float = 2.0    # seconds for banner grabbing
MAX_THREADS:     int   = 300    # concurrent scanning threads

# Well-known port → friendly name (supplement the OS service database)
COMMON_SERVICES: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    69:    "TFTP",
    80:    "HTTP",
    110:   "POP3",
    111:   "RPCbind",
    135:   "MS-RPC",
    139:   "NetBIOS",
    143:   "IMAP",
    161:   "SNMP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "Oracle DB",
    2049:  "NFS",
    2181:  "ZooKeeper",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Backdoor/MSF",
    5432:  "PostgreSQL",
    5900:  "VNC",
    5984:  "CouchDB",
    6379:  "Redis",
    7001:  "WebLogic",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "Jupyter/HTTP",
    9200:  "Elasticsearch",
    9300:  "ES-Transport",
    11211: "Memcached",
    27017: "MongoDB",
    28017: "MongoDB-Web",
}

# Ports where an HTTP probe makes sense
HTTP_PORTS  = {80, 8080, 8000, 8888, 8008}
HTTPS_PORTS = {443, 8443, 9443}


# ─────────────────────────────────────────────────────────────────────────────
#  Service detection
# ─────────────────────────────────────────────────────────────────────────────

def get_service_name(port: int) -> str:
    """
    Return the service name for a port.

    Checks the local COMMON_SERVICES map first, then the OS service database.
    Returns "unknown" if the port is not recognised.

    Args:
        port: TCP port number (1–65535).

    Returns:
        Service name string.
    """
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
#  Banner grabbing
# ─────────────────────────────────────────────────────────────────────────────

def grab_banner(ip: str, port: int) -> str:
    """
    Attempt to retrieve the service banner from an open port.

    Strategy:
      - HTTP ports  → send a HEAD request and parse the Server header.
      - HTTPS ports → return a note (TLS handshake not attempted here).
      - Others      → send CRLF and read the first line of the response.

    Args:
        ip:   Target IP address.
        port: Target port number.

    Returns:
        Banner string (may be empty on failure).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(BANNER_TIMEOUT)
            sock.connect((ip, port))

            if port in HTTPS_PORTS:
                return "TLS/SSL — use openssl s_client for full handshake"

            if port in HTTP_PORTS:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            else:
                sock.sendall(b"\r\n")

            raw = sock.recv(1024).decode("utf-8", errors="ignore")

            # For HTTP responses extract the Server header if present
            if raw.startswith("HTTP"):
                for line in raw.splitlines():
                    if line.lower().startswith("server:"):
                        return line.strip()
                # Fall back to status line
                return raw.splitlines()[0].strip()[:100]

            return raw.splitlines()[0].strip()[:100]

    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
#  Scan methods
# ─────────────────────────────────────────────────────────────────────────────

def tcp_connect_scan(ip: str, port: int) -> tuple[int, bool]:
    """
    Standard TCP connect scan — no elevated privileges required.

    Calls connect_ex(); a return value of 0 indicates the port is open.

    Args:
        ip:   Target IP address.
        port: Port to probe.

    Returns:
        Tuple (port, is_open).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(CONNECT_TIMEOUT)
            return (port, sock.connect_ex((ip, port)) == 0)
    except (socket.timeout, OSError):
        return (port, False)


def syn_scan_port(ip: str, port: int) -> tuple[int, bool]:
    """
    SYN (stealth) scan using Scapy.

    Sends a TCP SYN packet and inspects the response:
      - SYN-ACK (flags=0x12) → port is open; RST is sent to close cleanly.
      - RST     (flags=0x14) → port is closed.
      - No reply             → port is filtered.

    Requires root / Administrator privileges.
    Falls back silently to tcp_connect_scan if Scapy is not installed
    or if the process lacks required privileges.

    Args:
        ip:   Target IP address.
        port: Port to probe.

    Returns:
        Tuple (port, is_open).
    """
    try:
        from scapy.all import IP, TCP, sr1, send, conf  # type: ignore
        conf.verb = 0
        pkt  = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=CONNECT_TIMEOUT, verbose=0)

        if resp is None:
            return (port, False)

        if resp.haslayer(TCP):
            tcp_flags = resp[TCP].flags
            if tcp_flags == 0x12:          # SYN-ACK
                rst = IP(dst=ip) / TCP(dport=port, flags="R")
                send(rst, verbose=0)
                return (port, True)

        return (port, False)

    except ImportError:
        return tcp_connect_scan(ip, port)
    except PermissionError:
        return tcp_connect_scan(ip, port)
    except Exception:
        return (port, False)


# ─────────────────────────────────────────────────────────────────────────────
#  High-level scan orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def scan_target(
    ip:           str,
    start_port:   int,
    end_port:     int,
    scan_type:    str = "tcp",
    grab_banners: bool = True,
    logger:       Optional[logging.Logger] = None,
) -> dict:
    """
    Scan all ports in [start_port, end_port] on a single host.

    Steps:
      1. Thread-pool port probing with a tqdm progress bar.
      2. Banner grabbing for each open port (optional).
      3. Vulnerability hint lookup.
      4. OS fingerprinting via TTL.

    Args:
        ip:           Resolved IP address of the target.
        start_port:   First port to scan (inclusive).
        end_port:     Last port to scan (inclusive).
        scan_type:    "tcp" or "syn".
        grab_banners: Whether to attempt banner grabbing on open ports.
        logger:       Optional logger instance.

    Returns:
        dict with keys:
          ip          – scanned IP
          open_ports  – list of port-info dicts
          os_guess    – OS string
          ttl         – raw TTL value or None
    """
    ports     = list(range(start_port, end_port + 1))
    open_list: list[dict] = []
    scan_fn   = syn_scan_port if scan_type == "syn" else tcp_connect_scan

    if logger:
        logger.info(
            f"Starting {scan_type.upper()} scan on {ip} "
            f"ports {start_port}–{end_port}"
        )

    with tqdm(
        total=len(ports),
        desc=f"  {ip}",
        unit="port",
        ncols=72,
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
        colour="cyan",
    ) as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
            futures = {pool.submit(scan_fn, ip, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                pbar.update(1)

                if is_open:
                    service = get_service_name(port)
                    banner  = grab_banner(ip, port) if grab_banners else ""
                    hints   = VULNERABILITY_HINTS.get(port, {})

                    entry = {
                        "port":      port,
                        "service":   service,
                        "banner":    banner,
                        "risk":      hints.get("risk", "INFO"),
                        "vuln_hint": hints.get("hint", ""),
                    }
                    open_list.append(entry)

                    if logger:
                        logger.info(
                            f"[OPEN] {ip}:{port}  service={service}  "
                            f"risk={hints.get('risk','INFO')}"
                        )

    open_list.sort(key=lambda x: x["port"])

    # OS fingerprinting
    ttl      = get_ttl(ip)
    os_guess = detect_os(ttl) if ttl is not None else "Unknown (ICMP blocked)"

    if logger:
        logger.info(
            f"Scan complete for {ip} — {len(open_list)} open ports  "
            f"OS guess: {os_guess}"
        )

    return {
        "ip":         ip,
        "open_ports": open_list,
        "os_guess":   os_guess,
        "ttl":        ttl,
    }
