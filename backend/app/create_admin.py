"""
Create an admin account from the command line (there is no public sign-up).

    cd backend
    python -m app.create_admin --username admin --email admin@example.com

The password is prompted (not echoed). For non-interactive use (e.g. Docker),
set VIPER_ADMIN_PASSWORD instead.
"""

import argparse
import getpass
import os
import sys

from pydantic import ValidationError

from app.api.routes.auth import CreateUserRequest
from app.core.database import Base, SessionLocal, engine
from app.core.security import hash_password
from app.main import app  # noqa: F401  (registers all models before create_all)
from app.models.user import User, ROLE_ADMIN


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a V.I.P.E.R. admin user")
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    args = parser.parse_args()

    password = os.environ.get("VIPER_ADMIN_PASSWORD")
    if not password:
        password = getpass.getpass("Password (min. 10 characters): ")
        if password != getpass.getpass("Repeat password: "):
            print("Passwords do not match.", file=sys.stderr)
            return 1

    # Same validation rules as the API (username format, email, password length)
    try:
        req = CreateUserRequest(username=args.username, email=args.email,
                                password=password, role=ROLE_ADMIN)
    except ValidationError as exc:
        for err in exc.errors():
            print(f"{err['loc'][0]}: {err['msg']}", file=sys.stderr)
        return 1

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(User).filter((User.username == req.username) | (User.email == req.email)).first():
            print("A user with this username or email already exists.", file=sys.stderr)
            return 1
        db.add(User(username=req.username, email=req.email,
                    hashed_password=hash_password(req.password), role=ROLE_ADMIN))
        db.commit()
    finally:
        db.close()

    print(f"Admin user '{req.username}' created.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
