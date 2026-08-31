"""Scanning engine for authorized network asset discovery."""

from __future__ import annotations

import concurrent.futures
import logging
import socket
from typing import Optional

from tqdm import tqdm

from .utils import detect_os, get_ttl
from .vuln_hints import VULNERABILITY_HINTS

CONNECT_TIMEOUT = 1.0
BANNER_TIMEOUT = 2.0
MAX_THREADS = 64

COMMON_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MS-RPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
    2049: "NFS", 2181: "ZooKeeper", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    7001: "WebLogic", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter/HTTP",
    9200: "Elasticsearch", 9300: "ES-Transport", 11211: "Memcached",
    27017: "MongoDB", 28017: "MongoDB-Web",
}

HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
HTTPS_PORTS = {443, 8443, 9443}


def get_service_name(port: int) -> str:
    """Return a friendly service name using a local map and the OS database."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _connect(ip: str, port: int, timeout: float) -> socket.socket:
    """Create a TCP connection using the address family returned by getaddrinfo."""
    last_error: OSError | None = None
    for family, socktype, proto, _, address in socket.getaddrinfo(
        ip, port, type=socket.SOCK_STREAM
    ):
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(address)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise last_error or OSError("Unable to connect")


def grab_banner(ip: str, port: int) -> str:
    """Collect a small, non-invasive service banner from an open TCP port."""
    try:
        with _connect(ip, port, BANNER_TIMEOUT) as sock:
            if port in HTTPS_PORTS:
                return "TLS/SSL service detected"

            if port in HTTP_PORTS:
                request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                sock.sendall(request.encode("ascii", errors="ignore"))
            else:
                sock.sendall(b"\r\n")

            raw = sock.recv(1024).decode("utf-8", errors="ignore")
            lines = [line.strip() for line in raw.splitlines() if line.strip()]
            if not lines:
                return ""

            if lines[0].startswith("HTTP"):
                for line in lines:
                    if line.lower().startswith("server:"):
                        return line[:100]
            return lines[0][:100]
    except (OSError, UnicodeError):
        return ""


def tcp_connect_scan(ip: str, port: int) -> tuple[int, bool]:
    """Perform a normal TCP connect check without elevated privileges."""
    try:
        with _connect(ip, port, CONNECT_TIMEOUT):
            return port, True
    except OSError:
        return port, False


def syn_scan_port(ip: str, port: int) -> tuple[int, bool]:
    """Perform an optional SYN probe for controlled, authorized lab testing."""
    try:
        from scapy.all import IP, TCP, conf, send, sr1  # type: ignore

        conf.verb = 0
        response = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=CONNECT_TIMEOUT, verbose=0)
        if response is not None and response.haslayer(TCP):
            flags = int(response[TCP].flags)
            if flags & 0x12 == 0x12:
                send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=0)
                return port, True
        return port, False
    except (ImportError, PermissionError):
        return tcp_connect_scan(ip, port)
    except Exception:
        return port, False


def scan_target(
    ip: str,
    start_port: int,
    end_port: int,
    scan_type: str = "tcp",
    grab_banners: bool = True,
    logger: Optional[logging.Logger] = None,
) -> dict:
    """Scan one resolved host and return structured, sorted results."""
    if not 1 <= start_port <= end_port <= 65535:
        raise ValueError("Port range must be between 1 and 65535")
    if scan_type not in {"tcp", "syn"}:
        raise ValueError("scan_type must be 'tcp' or 'syn'")

    ports = range(start_port, end_port + 1)
    scan_fn = syn_scan_port if scan_type == "syn" else tcp_connect_scan
    open_list: list[dict] = []
    workers = min(MAX_THREADS, max(1, end_port - start_port + 1))

    if logger:
        logger.info("Starting %s scan on %s ports %s-%s", scan_type.upper(), ip, start_port, end_port)

    with tqdm(
        total=len(ports), desc=f"  {ip}", unit="port", ncols=72,
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
        disable=False,
    ) as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(scan_fn, ip, port) for port in ports]
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                pbar.update(1)
                if not is_open:
                    continue

                hints = VULNERABILITY_HINTS.get(port, {})
                entry = {
                    "port": port,
                    "service": hints.get("service") or get_service_name(port),
                    "banner": grab_banner(ip, port) if grab_banners else "",
                    "risk": hints.get("risk", "INFO"),
                    "vuln_hint": hints.get("hint", ""),
                }
                open_list.append(entry)
                if logger:
                    logger.info("[OPEN] %s:%s service=%s risk=%s", ip, port, entry["service"], entry["risk"])

    open_list.sort(key=lambda item: item["port"])
    ttl = get_ttl(ip)
    os_guess = detect_os(ttl) if ttl is not None else "Unknown (ICMP blocked)"

    return {"ip": ip, "open_ports": open_list, "os_guess": os_guess, "ttl": ttl}
