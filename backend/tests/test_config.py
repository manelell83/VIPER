"""
Tests for the settings (app/core/config.py): no insecure secret defaults.
"""

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_missing_jwt_secret_prevents_startup(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)

    with pytest.raises(ValidationError, match="JWT_SECRET"):
        Settings(_env_file=None)


def test_short_jwt_secret_is_rejected(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "too-short")

    with pytest.raises(ValidationError, match="JWT_SECRET"):
        Settings(_env_file=None)


def test_token_lifetime_is_bounded(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    monkeypatch.setenv("JWT_EXPIRATION_HOURS", "720")

    with pytest.raises(ValidationError, match="JWT_EXPIRATION_HOURS"):
        Settings(_env_file=None)
