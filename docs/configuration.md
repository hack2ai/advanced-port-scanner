# Configuration

Configuration is centralized in `scanner/config.py` and can be overridden with environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `HOST` | `127.0.0.1` | Web bind address |
| `PORT` | `5000` | Web port |
| `MAX_CONCURRENT_JOBS` | `2` | Concurrent web scan jobs |
| `MAX_TARGETS` | `16` | Maximum targets per web request |
| `MAX_PORTS` | `4096` | Maximum ports in a web request |
| `SOCKET_TIMEOUT` | `0.5` | TCP connection timeout |
| `BANNER_TIMEOUT` | `0.75` | Banner probe timeout |
| `LOG_LEVEL` | `INFO` | Application log level |
| `SCAN_DB` | `data/scans.db` | SQLite history database |
| `REPORTS_DIR` | `reports` | Generated report directory |
| `AUTH_ENABLED` | `false` | Enable dashboard/API authentication |
| `AUTH_USERNAME` | empty | Configured login username when auth is enabled |
| `AUTH_PASSWORD_HASH` | empty | Werkzeug password hash; never use plaintext here |
| `AUTH_ROLE` | `operator` | `viewer`, `operator`, or `admin` |
| `SECRET_KEY` | empty | Random secret used to sign Flask sessions |
| `SECURE_COOKIES` | `false` | Set `true` when serving through HTTPS |

## Authentication

Authentication is intentionally disabled by default for local development. Before enabling it in a controlled deployment, set `AUTH_ENABLED=true`, a strong `SECRET_KEY`, `AUTH_USERNAME`, and a Werkzeug-compatible `AUTH_PASSWORD_HASH`.

Generate a password hash with Werkzeug rather than storing a plaintext password in configuration:

```python
from werkzeug.security import generate_password_hash
print(generate_password_hash("replace-with-a-strong-password"))
```

Use `AUTH_ROLE=viewer` for read-only access, `operator` for scan/cancel operations, and `admin` for future administrative capabilities.

When using HTTPS, set `SECURE_COOKIES=true` so authentication cookies are only sent over secure connections.

Start from `config.example.env` and keep secrets outside the repository. Do not commit production credentials.
