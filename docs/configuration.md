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

Start from `config.example.env` and adjust values for a controlled environment. Avoid committing secrets or production credentials.
