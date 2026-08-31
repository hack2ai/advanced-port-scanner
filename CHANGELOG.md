# Changelog

All notable changes to this project are documented here.

## [0.1.0] - 2026-08-31

### Added
- Professional `scanner/` and `web/` package layout.
- Concurrent TCP discovery with optional controlled-lab SYN probing.
- Lightweight service/banner detection and informational risk hints.
- Persistent SQLite scan history.
- Centralized environment-based configuration.
- Structured JSON audit logging.
- JSON, CSV, and TXT reporting.
- Flask dashboard and scan job API.
- Python packaging with the `aps` console entry point.
- Automated pytest tests and GitHub Actions CI.
- Non-root Docker runtime with reduced privileges and health checks.

### Security
- Added target and port validation.
- Added bounded target, port, worker, and job limits.
- Avoided shell execution for target resolution and ping commands.
- Documented authorized-use requirements and defensive scope.
