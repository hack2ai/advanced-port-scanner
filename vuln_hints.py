"""
vuln_hints.py — Vulnerability hints and risk metadata for well-known ports.
Used by scanner.py and the web dashboard to annotate results.
"""

VULNERABILITY_HINTS: dict[int, dict] = {
    21:    {"service": "FTP",           "risk": "HIGH",     "hint": "FTP transmits credentials in plaintext. Replace with SFTP or FTPS."},
    22:    {"service": "SSH",           "risk": "MEDIUM",   "hint": "Ensure key-based auth, disable root login, use fail2ban."},
    23:    {"service": "Telnet",        "risk": "CRITICAL", "hint": "Telnet is fully unencrypted. Immediately replace with SSH."},
    25:    {"service": "SMTP",          "risk": "MEDIUM",   "hint": "Open relay can be abused for spam. Enforce authentication."},
    53:    {"service": "DNS",           "risk": "MEDIUM",   "hint": "Exposed DNS allows zone transfer attacks. Restrict to trusted IPs."},
    69:    {"service": "TFTP",          "risk": "HIGH",     "hint": "TFTP has no authentication. Disable if not required."},
    80:    {"service": "HTTP",          "risk": "LOW",      "hint": "Unencrypted web traffic. Redirect all traffic to HTTPS."},
    110:   {"service": "POP3",          "risk": "HIGH",     "hint": "POP3 sends passwords in plaintext. Use POP3S on port 995."},
    111:   {"service": "RPCbind",       "risk": "HIGH",     "hint": "RPCbind can expose NFS/NIS services. Block at firewall."},
    135:   {"service": "MS-RPC",        "risk": "HIGH",     "hint": "Windows RPC (MS03-026 vulnerability). Restrict external access."},
    139:   {"service": "NetBIOS",       "risk": "HIGH",     "hint": "NetBIOS leaks system info. Block externally. Disable if unused."},
    143:   {"service": "IMAP",          "risk": "HIGH",     "hint": "IMAP transmits credentials plaintext. Use IMAPS on port 993."},
    161:   {"service": "SNMP",          "risk": "HIGH",     "hint": "SNMP v1/v2 have weak authentication. Use SNMPv3 with auth+priv."},
    389:   {"service": "LDAP",          "risk": "MEDIUM",   "hint": "Unencrypted LDAP. Use LDAPS (636) or StartTLS."},
    443:   {"service": "HTTPS",         "risk": "LOW",      "hint": "Verify TLS version (1.2+), cipher suites, and cert expiry."},
    445:   {"service": "SMB",           "risk": "CRITICAL", "hint": "Exploitable via EternalBlue/WannaCry. Keep patched, block externally."},
    512:   {"service": "rexec",         "risk": "CRITICAL", "hint": "Remote exec with no encryption. Disable immediately."},
    513:   {"service": "rlogin",        "risk": "CRITICAL", "hint": "rlogin is insecure and exploitable. Disable immediately."},
    514:   {"service": "rsh",           "risk": "CRITICAL", "hint": "Remote shell with no auth/encryption. Disable immediately."},
    993:   {"service": "IMAPS",         "risk": "LOW",      "hint": "Encrypted IMAP. Verify certificate and TLS version."},
    995:   {"service": "POP3S",         "risk": "LOW",      "hint": "Encrypted POP3. Verify certificate and TLS version."},
    1433:  {"service": "MSSQL",         "risk": "HIGH",     "hint": "Database exposed externally. Restrict to internal networks."},
    1521:  {"service": "Oracle DB",     "risk": "HIGH",     "hint": "Oracle DB exposed. Restrict to internal networks only."},
    2049:  {"service": "NFS",           "risk": "HIGH",     "hint": "NFS can expose filesystem. Restrict exports to trusted IPs only."},
    2181:  {"service": "ZooKeeper",     "risk": "HIGH",     "hint": "ZooKeeper has no auth by default. Restrict to internal networks."},
    3306:  {"service": "MySQL",         "risk": "HIGH",     "hint": "Database exposed. Bind to 127.0.0.1 or restrict via firewall."},
    3389:  {"service": "RDP",           "risk": "HIGH",     "hint": "RDP is a top attack vector. Require NLA + VPN. Keep patched."},
    4444:  {"service": "Backdoor/MSF",  "risk": "CRITICAL", "hint": "Port 4444 is the Metasploit default shell port. Investigate immediately!"},
    5432:  {"service": "PostgreSQL",    "risk": "HIGH",     "hint": "Database exposed. Restrict to localhost or internal IPs."},
    5900:  {"service": "VNC",           "risk": "HIGH",     "hint": "VNC can be brute-forced. Enforce strong passwords and use SSH tunneling."},
    5984:  {"service": "CouchDB",       "risk": "HIGH",     "hint": "CouchDB admin UI may be exposed. Require authentication."},
    6379:  {"service": "Redis",         "risk": "CRITICAL", "hint": "Redis often runs unauthenticated. Bind to 127.0.0.1 and set requirepass."},
    7001:  {"service": "WebLogic",      "risk": "HIGH",     "hint": "WebLogic has known RCE vulnerabilities. Keep up to date."},
    8080:  {"service": "HTTP-Alt",      "risk": "LOW",      "hint": "Check for unprotected admin panels (Jenkins, Tomcat, etc.)."},
    8443:  {"service": "HTTPS-Alt",     "risk": "LOW",      "hint": "Verify TLS config. Often used for admin UIs."},
    8888:  {"service": "HTTP-Alt",      "risk": "LOW",      "hint": "Jupyter Notebook often runs here — ensure auth is enabled."},
    9200:  {"service": "Elasticsearch", "risk": "CRITICAL", "hint": "Elasticsearch has no auth by default. Restrict to internal networks immediately."},
    9300:  {"service": "ES-Transport",  "risk": "HIGH",     "hint": "Elasticsearch cluster transport. Restrict to internal networks."},
    11211: {"service": "Memcached",     "risk": "HIGH",     "hint": "Memcached abused for DDoS amplification. Never expose externally."},
    27017: {"service": "MongoDB",       "risk": "CRITICAL", "hint": "MongoDB often runs without auth. Enable authentication and restrict access."},
    28017: {"service": "MongoDB Web",   "risk": "CRITICAL", "hint": "MongoDB web interface. Disable in production. Highly exploitable."},
}

# Risk level → rich color name
RISK_COLORS: dict[str, str] = {
    "CRITICAL": "bright_red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "cyan",
}

# Risk level → CSS/hex color for web dashboard
RISK_CSS_COLORS: dict[str, str] = {
    "CRITICAL": "#ff2d55",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#ffd60a",
    "LOW":      "#30d158",
    "INFO":     "#64d2ff",
}
