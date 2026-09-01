"""Lightweight, defensive service identification from safe TCP responses."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceInfo:
    service: str
    protocol: str = "tcp"
    product: str = ""
    version: str = ""
    confidence: float = 0.0


_PATTERNS: tuple[tuple[re.Pattern[str], ServiceInfo], ...] = (
    (re.compile(r"^SSH-[12]\.\d-OpenSSH[_ /-]?([\w.~-]+)?", re.I), ServiceInfo("ssh", product="OpenSSH", confidence=0.96)),
    (re.compile(r"^SSH-[12]\.\d-([\w.-]+)", re.I), ServiceInfo("ssh", confidence=0.90)),
    (re.compile(r"^220[- ](?:.*?)(?:vsftpd)[ /-]?([\w.]+)?", re.I), ServiceInfo("ftp", product="vsftpd", confidence=0.94)),
    (re.compile(r"^220[- ](?:.*?)(?:FileZilla Server)[ /-]?([\w.]+)?", re.I), ServiceInfo("ftp", product="FileZilla Server", confidence=0.94)),
    (re.compile(r"^220[- ]", re.I), ServiceInfo("ftp", confidence=0.78)),
    (re.compile(r"^\+OK(?:.*?)(?:Dovecot)[ /-]?([\w.]+)?", re.I), ServiceInfo("pop3", product="Dovecot", confidence=0.94)),
    (re.compile(r"^\* OK(?:.*?)(?:Dovecot)[ /-]?([\w.]+)?", re.I), ServiceInfo("imap", product="Dovecot", confidence=0.94)),
    (re.compile(r"^\+PONG$", re.I), ServiceInfo("redis", product="Redis", confidence=0.95)),
)


def _with_version(base: ServiceInfo, match: re.Match[str]) -> ServiceInfo:
    version = (match.group(1) or "").strip() if match.lastindex else ""
    return ServiceInfo(base.service, base.protocol, base.product, version, base.confidence)


def identify_from_banner(banner: str, port: int | None = None) -> ServiceInfo:
    """Identify a service from a bounded banner/response string.

    Port hints provide a conservative fallback only; protocol text has precedence.
    """
    text = (banner or "").strip()
    if text:
        http_match = re.search(r"^HTTP/\d(?:\.\d)?\s+\d{3}", text, re.I | re.M)
        if http_match:
            server_match = re.search(r"^Server:\s*([^\r\n/]+)(?:/([\w.+-]+))?", text, re.I | re.M)
            if server_match:
                return ServiceInfo(
                    "http",
                    product=server_match.group(1).strip(),
                    version=(server_match.group(2) or "").strip(),
                    confidence=0.98,
                )
            return ServiceInfo("http", confidence=0.98)

        for pattern, info in _PATTERNS:
            match = pattern.search(text)
            if match:
                return _with_version(info, match)

    port_map = {
        21: ServiceInfo("ftp", confidence=0.72),
        22: ServiceInfo("ssh", confidence=0.72),
        25: ServiceInfo("smtp", confidence=0.70),
        53: ServiceInfo("dns", confidence=0.68),
        80: ServiceInfo("http", confidence=0.70),
        110: ServiceInfo("pop3", confidence=0.68),
        143: ServiceInfo("imap", confidence=0.68),
        443: ServiceInfo("https", confidence=0.70),
        3306: ServiceInfo("mysql", confidence=0.65),
        5432: ServiceInfo("postgresql", confidence=0.65),
        6379: ServiceInfo("redis", confidence=0.65),
    }
    return port_map.get(port, ServiceInfo("unknown", confidence=0.0))
