"""Small security middleware helpers for the controlled Flask deployment."""
from __future__ import annotations

import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from typing import Callable

from flask import jsonify, request, session


class RateLimiter:
    """Process-local fixed-window limiter keyed by client address and route."""

    def __init__(self, limit: int = 20, window_seconds: int = 60) -> None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("Rate-limit values must be positive")
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > 2048:
                stale = [k for k, values in self._hits.items() if not values or values[-1] <= cutoff]
                for stale_key in stale[:1024]:
                    self._hits.pop(stale_key, None)
            return True


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def require_csrf(view: Callable):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.is_json:
            expected = session.get("csrf_token")
            supplied = request.headers.get("X-CSRF-Token")
            if expected and supplied and secrets.compare_digest(expected, supplied):
                return view(*args, **kwargs)
            if session.get("username"):
                return jsonify({"error": "CSRF token required"}), 403
        return view(*args, **kwargs)
    return wrapped


def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    )
    return response
