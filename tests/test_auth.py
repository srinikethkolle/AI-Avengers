import pytest
from backend.authentication.auth import (
    verify_password,
    issue_token,
    authenticate_token,
)


class TestAuth:
    def test_verify_password_valid(self):
        assert verify_password("alice", "secret123") is True
        assert verify_password("admin", "adminsecret123") is True

    def test_verify_password_invalid(self):
        assert verify_password("alice", "wrongpass") is False
        assert verify_password("nonexistent", "secret123") is False

    def test_issue_and_authenticate_token(self):
        token = issue_token("alice")
        assert isinstance(token, str)

        payload = authenticate_token(token)
        assert payload["sub"] == "alice"
        assert "read_report" in payload["permissions"]
        assert "delete_user" in payload["prohibited"]
        assert payload["active"] is True

    def test_authenticate_token_with_bearer_prefix(self):
        token = issue_token("alice")
        payload = authenticate_token(f"Bearer {token}")
        assert payload["sub"] == "alice"

    def test_authenticate_invalid_token(self):
        with pytest.raises(PermissionError):
            authenticate_token("invalid.token.string")

    def test_issue_token_unknown_user(self):
        with pytest.raises(PermissionError):
            issue_token("unknown_user")

