"""Centralized configuration with environment-variable overrides."""
from __future__ import annotations
import os
from dataclasses import dataclass


def _int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def _float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    max_concurrent_jobs: int
    max_targets: int
    max_ports: int
    socket_timeout: float
    banner_timeout: float
    log_level: str
    scan_db: str
    reports_dir: str
    auth_enabled: bool
    auth_username: str
    auth_password_hash: str
    auth_role: str
    secret_key: str
    secure_cookies: bool
    auth_rate_limit: int
    auth_rate_window: int
    scan_rate_limit: int
    scan_rate_window: int


def load_settings() -> Settings:
    return Settings(
        host=os.getenv("HOST", "127.0.0.1"),
        port=_int("PORT", 5000, 1, 65535),
        max_concurrent_jobs=_int("MAX_CONCURRENT_JOBS", 2, 1, 32),
        max_targets=_int("MAX_TARGETS", 16, 1, 256),
        max_ports=_int("MAX_PORTS", 4096, 1, 65535),
        socket_timeout=_float("SOCKET_TIMEOUT", 0.5, 0.1, 10.0),
        banner_timeout=_float("BANNER_TIMEOUT", 0.75, 0.1, 10.0),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        scan_db=os.getenv("SCAN_DB", "data/scans.db"),
        reports_dir=os.getenv("REPORTS_DIR", "reports"),
        auth_enabled=_bool("AUTH_ENABLED", False),
        auth_username=os.getenv("AUTH_USERNAME", ""),
        auth_password_hash=os.getenv("AUTH_PASSWORD_HASH", ""),
        auth_role=os.getenv("AUTH_ROLE", "operator").lower(),
        secret_key=os.getenv("SECRET_KEY", ""),
        secure_cookies=_bool("SECURE_COOKIES", False),
        auth_rate_limit=_int("AUTH_RATE_LIMIT", 5, 1, 100),
        auth_rate_window=_int("AUTH_RATE_WINDOW", 60, 10, 3600),
        scan_rate_limit=_int("SCAN_RATE_LIMIT", 10, 1, 1000),
        scan_rate_window=_int("SCAN_RATE_WINDOW", 60, 10, 3600),
    )


settings = load_settings()
