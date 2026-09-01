# Observability

The v0.3 observability endpoint is available at `GET /api/v1/metrics`.

It reports a dependency-free snapshot derived from active in-process jobs and retained SQLite history:

- active, queued, and running jobs
- retained history count
- completed, failed, and cancelled scans
- average duration for retained scans
- total open ports in retained history

The endpoint is read-only and follows the normal `/api/v1` response envelope. Protected deployments require the viewer role or higher.

The current Docker deployment intentionally uses one Gunicorn worker because job and rate-limit state are process-local. Multi-process scaling requires a shared job and rate-limit backend.
