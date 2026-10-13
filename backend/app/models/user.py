"""User model for authentication and RBAC."""

from sqlalchemy import Column, String, Boolean, DateTime
from uuid import uuid4

from app.core.database import Base
from app.core.timeutil import iso_utc, utcnow

# Roles (RBAC):
#   admin   — everything an analyst can do + create users and delete scans
#   analyst — run scans and read all results
ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLES = (ROLE_ADMIN, ROLE_ANALYST)


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False, default=ROLE_ANALYST)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": iso_utc(self.created_at),
            "last_login": iso_utc(self.last_login),
        }
