# Changelog

All notable changes to this project are documented here.

## [0.2.1] - 2026-09-01

### Fixed
- Hardened Docker deployment for process-local job and rate-limit state.
- Switched persistent Docker storage to managed volumes for SQLite data, reports, and logs.
- Added Docker runtime regression coverage for worker topology and storage configuration.
- Refreshed the public README and deployment documentation for the current release line.

## [0.2.0] - 2026-09-01

### Added
- Bounded asynchronous job manager with queue limits, cancellation, and live progress.
- Reusable scan profiles: `quick`, `standard`, `extended`, and `full`.
- Lightweight service fingerprinting with product/version/confidence metadata.
- HTML report generation alongside JSON, CSV, and TXT reports.
- Session authentication with viewer/operator/admin roles.
- Login and scan rate limiting, CSRF protection, and security response headers.
- Versioned `/api/v1` endpoints with consistent response envelopes and request IDs.
- Analytics based on persisted scan history, including targets, open ports, risk distribution, and top services.
- Dashboard integration for live jobs, history, details, and analytics.

### Security
- Added authenticated access controls for protected dashboard/API operations.
- Added cooperative job cancellation rather than abrupt worker termination.
- Added bounded resource controls for targets, ports, workers, and queued jobs.
- Added HTML escaping in report generation and dashboard rendering.
- Documented secure-cookie and production authentication configuration.

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
