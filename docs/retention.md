# Retention

Long-running deployments should bound both SQLite history and generated reports.

The application exposes `HISTORY_RETENTION` and `REPORT_RETENTION` settings. Values are capped to a safe range when loaded from the environment.

Retention is applied after a scan is persisted. Only the oldest completed records/files are removed; active jobs are never deleted.
