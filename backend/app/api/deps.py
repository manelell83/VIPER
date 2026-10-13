"""
Authentication / authorization dependencies shared by the API routes.

Usage:
    router-wide:  app.include_router(r, dependencies=[Depends(get_current_user)])
    per route:    def delete(..., admin: User = Depends(require_admin))
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_token
from app.models.user import User, ROLE_ADMIN

# Reads "Authorization: Bearer <token>". auto_error=False lets us return our own
# 401 (with the WWW-Authenticate header) instead of FastAPI's default 403.
_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Return the authenticated, active user or raise 401.

    The token only carries the user id; role and is_active are read from the
    database on every request, so deactivating a user or changing their role
    takes effect immediately (no need to wait for the token to expire).
    """
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized

    user_id = verify_token(credentials.credentials)   # raises 401 if invalid/expired
    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Allow the request only for users with the admin role (403 otherwise)."""
    if user.role != ROLE_ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user
