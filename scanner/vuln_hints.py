"""Informational service-risk metadata.

These are configuration hints, not vulnerability findings. Open-port status alone
must never be interpreted as proof that a service is vulnerable.
"""

VULNERABILITY_HINTS: dict[int, dict[str, str]] = {
    21: {"service": "FTP", "risk": "HIGH", "hint": "Credentials may be exposed without TLS; prefer SFTP/FTPS."},
    22: {"service": "SSH", "risk": "MEDIUM", "hint": "Review authentication, root-login, patching, and access controls."},
    23: {"service": "Telnet", "risk": "CRITICAL", "hint": "Unencrypted remote administration; replace with SSH."},
    25: {"service": "SMTP", "risk": "MEDIUM", "hint": "Restrict relay behavior and require appropriate authentication."},
    53: {"service": "DNS", "risk": "MEDIUM", "hint": "Restrict recursive queries and zone transfers to trusted clients."},
    69: {"service": "TFTP", "risk": "HIGH", "hint": "Unauthenticated service; disable when not required."},
    80: {"service": "HTTP", "risk": "LOW", "hint": "Review transport security and redirect sensitive traffic to HTTPS."},
    110: {"service": "POP3", "risk": "HIGH", "hint": "Use TLS-protected mail access instead of plaintext authentication."},
    111: {"service": "RPCbind", "risk": "HIGH", "hint": "Restrict exposure and review associated RPC/NFS services."},
    135: {"service": "MS-RPC", "risk": "HIGH", "hint": "Restrict exposure and keep Windows services fully patched."},
    139: {"service": "NetBIOS", "risk": "HIGH", "hint": "Avoid unnecessary external exposure; review legacy dependencies."},
    143: {"service": "IMAP", "risk": "HIGH", "hint": "Use TLS-protected mail access."},
    161: {"service": "SNMP", "risk": "HIGH", "hint": "Prefer SNMPv3 and restrict management sources."},
    389: {"service": "LDAP", "risk": "MEDIUM", "hint": "Use LDAPS/StartTLS and restrict directory access."},
    443: {"service": "HTTPS", "risk": "LOW", "hint": "Review TLS versions, certificates, and cipher configuration."},
    445: {"service": "SMB", "risk": "CRITICAL", "hint": "Restrict network exposure and keep SMB hosts patched."},
    512: {"service": "rexec", "risk": "CRITICAL", "hint": "Legacy remote execution service; disable if not required."},
    513: {"service": "rlogin", "risk": "CRITICAL", "hint": "Legacy remote-login service; disable if not required."},
    514: {"service": "rsh", "risk": "CRITICAL", "hint": "Legacy remote-shell service; disable if not required."},
    993: {"service": "IMAPS", "risk": "LOW", "hint": "Verify certificate validity and TLS configuration."},
    995: {"service": "POP3S", "risk": "LOW", "hint": "Verify certificate validity and TLS configuration."},
    1433: {"service": "MSSQL", "risk": "HIGH", "hint": "Restrict database access to trusted networks and identities."},
    1521: {"service": "Oracle DB", "risk": "HIGH", "hint": "Restrict database access to trusted networks and identities."},
    2049: {"service": "NFS", "risk": "HIGH", "hint": "Restrict exports and network access to trusted hosts."},
    2181: {"service": "ZooKeeper", "risk": "HIGH", "hint": "Restrict access and review authentication/authorization settings."},
    3306: {"service": "MySQL", "risk": "HIGH", "hint": "Do not expose databases unnecessarily; enforce authentication."},
    3389: {"service": "RDP", "risk": "HIGH", "hint": "Restrict access and require strong authentication/NLA."},
    5432: {"service": "PostgreSQL", "risk": "HIGH", "hint": "Restrict database access and review authentication policy."},
    5900: {"service": "VNC", "risk": "HIGH", "hint": "Restrict management access and use strong authentication."},
    5984: {"service": "CouchDB", "risk": "HIGH", "hint": "Require authentication and restrict administrative access."},
    6379: {"service": "Redis", "risk": "CRITICAL", "hint": "Avoid public exposure; enforce authentication and network controls."},
    7001: {"service": "WebLogic", "risk": "HIGH", "hint": "Keep the platform patched and restrict administrative interfaces."},
    8080: {"service": "HTTP-Alt", "risk": "LOW", "hint": "Review for unintended application or administrative exposure."},
    8443: {"service": "HTTPS-Alt", "risk": "LOW", "hint": "Review TLS settings and administrative-interface exposure."},
    8888: {"service": "Jupyter/HTTP", "risk": "LOW", "hint": "Ensure notebook interfaces require authentication and are restricted."},
    9200: {"service": "Elasticsearch", "risk": "CRITICAL", "hint": "Restrict access and verify authentication/authorization settings."},
    9300: {"service": "ES-Transport", "risk": "HIGH", "hint": "Restrict cluster transport traffic to trusted nodes."},
    11211: {"service": "Memcached", "risk": "HIGH", "hint": "Never expose caching services broadly; restrict network access."},
    27017: {"service": "MongoDB", "risk": "CRITICAL", "hint": "Require authentication and restrict database network access."},
    28017: {"service": "MongoDB Web", "risk": "CRITICAL", "hint": "Disable legacy web administration interfaces when unnecessary."},
}

RISK_COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "cyan",
}

RISK_CSS_COLORS = {
    "CRITICAL": "#ff2d55",
    "HIGH": "#ff6b35",
    "MEDIUM": "#ffd60a",
    "LOW": "#30d158",
    "INFO": "#64d2ff",
}
