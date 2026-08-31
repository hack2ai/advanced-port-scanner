from scanner.auth import User, authenticate
from werkzeug.security import generate_password_hash


def test_role_permissions():
    assert User("v", "x", "viewer").can("view") is True
    assert User("v", "x", "viewer").can("scan") is False
    assert User("o", "x", "operator").can("scan") is True
    assert User("o", "x", "operator").can("cancel") is True
    assert User("a", "x", "admin").can("anything") is True


def test_authenticate_with_password_hash():
    hashed = generate_password_hash("correct-password")
    assert authenticate("admin", "correct-password", "admin", hashed, "operator") is not None
    assert authenticate("admin", "wrong-password", "admin", hashed, "operator") is None
    assert authenticate("other", "correct-password", "admin", hashed, "operator") is None
