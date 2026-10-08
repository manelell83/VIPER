"""JWT and password security utilities."""

from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import HTTPException, status

from app.core.config import settings

# Fixed in code (not configurable) so a misconfiguration cannot weaken it.
# Decoding only accepts this algorithm, which also rejects "alg": "none" tokens.
JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    """Hash a password using bcrypt (random salt, cost factor 12).

    bcrypt only uses the first 72 bytes of input; bcrypt>=5 raises ValueError
    for longer inputs, so callers must validate the length first.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against its bcrypt hash (constant-time comparison)."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        # Malformed hash or over-long password: treat as a failed login
        return False


def create_access_token(user_id: str, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT (HS256) whose subject is the user id."""
    lifetime = expires_delta or timedelta(hours=settings.JWT_EXPIRATION_HOURS)
    claims = {"sub": user_id, "exp": datetime.now(timezone.utc) + lifetime}
    return jwt.encode(claims, settings.JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> str:
    """Verify a JWT's signature and expiry and return the user id (401 otherwise).

    "exp" and "sub" are required: a token without an expiry is rejected rather
    than being valid forever.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except jwt.InvalidTokenError:     # bad signature, expired, malformed, missing claim...
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload["sub"]
