"""Scanning engine for authorized network asset discovery."""
from __future__ import annotations

import concurrent.futures
import logging
import socket
import threading
from typing import Callable, Optional

from tqdm import tqdm

from .config import settings
from .utils import detect_os, get_ttl, audit
from .vuln_hints import VULNERABILITY_HINTS

COMMON_SERVICES: dict[int, str] = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",69:"TFTP",80:"HTTP",110:"POP3",111:"RPCbind",135:"MS-RPC",139:"NetBIOS",143:"IMAP",161:"SNMP",389:"LDAP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",1433:"MSSQL",1521:"Oracle DB",2049:"NFS",2181:"ZooKeeper",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",5984:"CouchDB",6379:"Redis",7001:"WebLogic",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter/HTTP",9200:"Elasticsearch",9300:"ES-Transport",11211:"Memcached",27017:"MongoDB",28017:"MongoDB-Web"}
HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
HTTPS_PORTS = {443, 8443, 9443}


def get_service_name(port: int) -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _connect(ip: str, port: int, timeout: float) -> socket.socket:
    last_error: OSError | None = None
    for family, socktype, proto, _, address in socket.getaddrinfo(ip, port, type=socket.SOCK_STREAM):
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
    try:
        with _connect(ip, port, settings.banner_timeout) as sock:
            if port in HTTPS_PORTS:
                return "TLS/SSL service detected"
            if port in HTTP_PORTS:
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode("ascii", errors="ignore"))
            else:
                sock.sendall(b"\r\n")
            raw = sock.recv(1024).decode("utf-8", errors="ignore")
            lines = [x.strip() for x in raw.splitlines() if x.strip()]
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
    try:
        with _connect(ip, port, settings.socket_timeout):
            return port, True
    except OSError:
        return port, False


def syn_scan_port(ip: str, port: int) -> tuple[int, bool]:
    try:
        from scapy.all import IP, TCP, conf, send, sr1
        conf.verb = 0
        response = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=settings.socket_timeout, verbose=0)
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
    progress_callback: Optional[Callable[[int, int], None]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> dict:
    """Scan one resolved host and report per-port progress when requested."""
    if not 1 <= start_port <= end_port <= 65535:
        raise ValueError("Port range must be between 1 and 65535")
    if scan_type not in {"tcp", "syn"}:
        raise ValueError("scan_type must be 'tcp' or 'syn'")

    ports = list(range(start_port, end_port + 1))
    scan_fn = syn_scan_port if scan_type == "syn" else tcp_connect_scan
    open_list: list[dict] = []
    workers = min(64, max(1, len(ports)))
    completed = 0

    if logger:
        audit(logger, "scan_started", address=ip, scan_type=scan_type, port_start=start_port, port_end=end_port)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_fn, ip, port) for port in ports]
        try:
            with tqdm(total=len(ports), desc=f"  {ip}", unit="port", ncols=72, disable=bool(progress_callback)) as pbar:
                for future in concurrent.futures.as_completed(futures):
                    port, is_open = future.result()
                    completed += 1
                    pbar.update(1)
                    if progress_callback:
                        progress_callback(completed, len(ports))
                    if cancel_event is not None and cancel_event.is_set():
                        for pending in futures:
                            pending.cancel()
                        raise InterruptedError("Scan cancelled")
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
                        audit(logger, "port_open", address=ip, port=port, service=entry["service"], risk=entry["risk"])
        except InterruptedError:
            raise

    open_list.sort(key=lambda x: x["port"])
    ttl = get_ttl(ip)
    os_guess = detect_os(ttl) if ttl is not None else "Unknown (ICMP blocked)"
    return {"ip": ip, "open_ports": open_list, "os_guess": os_guess, "ttl": ttl}
