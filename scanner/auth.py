"""Minimal password authentication and role checks for the dashboard.

Designed as a foundation for controlled deployments. Credentials are supplied via
configuration as a username plus a Werkzeug-compatible password hash; no plaintext
passwords are persisted by the application.
"""
from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import Optional

from werkzeug.security import check_password_hash


@dataclass(frozen=True)
class User:
    username: str
    password_hash: str
    role: str = "viewer"

    def can(self, action: str) -> bool:
        if self.role == "admin":
            return True
        if self.role == "operator":
            return action in {"view", "scan", "cancel"}
        return action == "view"


def load_user(username: str, configured_username: str, configured_hash: str, role: str) -> Optional[User]:
    if not username or not configured_username or not configured_hash:
        return None
    if not secrets.compare_digest(username, configured_username):
        return None
    return User(username=configured_username, password_hash=configured_hash, role=role)


def authenticate(username: str, password: str, configured_username: str, configured_hash: str, role: str) -> Optional[User]:
    user = load_user(username, configured_username, configured_hash, role)
    if user is None:
        return None
    return user if check_password_hash(user.password_hash, password) else None
