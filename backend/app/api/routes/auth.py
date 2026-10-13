"""Authentication routes: login, current user, user creation (admin only)."""


from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core.database import get_db
from app.core.security import hash_password, verify_password, create_access_token
from app.models.user import User, ROLES, ROLE_ANALYST
from app.core.timeutil import utcnow

router = APIRouter(tags=["Auth"])

# A valid bcrypt hash of a random string. When the username does not exist we
# still run one bcrypt check against it, so the response time does not reveal
# whether the username is valid (user enumeration via timing).
_DUMMY_HASH = hash_password("viper-dummy-password-for-timing")


# ── Request / response models ────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(max_length=32)
    password: str = Field(max_length=128)


class CreateUserRequest(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,32}$")
    email: str = Field(max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=10)
    role: str = ROLE_ANALYST

    @field_validator("password")
    @classmethod
    def password_fits_bcrypt(cls, value: str) -> str:
        # bcrypt only uses the first 72 bytes of a password
        if len(value.encode("utf-8")) > 72:
            raise ValueError("password must be at most 72 bytes")
        return value

    @field_validator("role")
    @classmethod
    def role_is_known(cls, value: str) -> str:
        if value not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        return value


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict


# ── Routes ───────────────────────────────────────────────────────────────────

@router.post("/auth/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    """Check username/password and return a signed JWT access token."""
    user = db.query(User).filter(User.username == req.username).first()
    password_ok = verify_password(req.password, user.hashed_password if user else _DUMMY_HASH)

    # Same message for "unknown user" and "wrong password"
    if user is None or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")

    user.last_login = utcnow()
    db.commit()

    return {
        "access_token": create_access_token(user.id),
        "token_type": "bearer",
        "user": user.to_dict(),
    }


@router.get("/auth/me")
def get_me(user: User = Depends(get_current_user)):
    """Return the user the bearer token belongs to."""
    return user.to_dict()


@router.post("/auth/users", status_code=status.HTTP_201_CREATED)
def create_user(
    req: CreateUserRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Create a new user account. Admin only (there is no public sign-up)."""
    existing = db.query(User).filter(
        (User.username == req.username) | (User.email == req.email)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists",
        )

    user = User(
        username=req.username,
        email=req.email,
        hashed_password=hash_password(req.password),
        role=req.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user.to_dict()
