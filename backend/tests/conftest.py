"""
Pytest configuration and shared fixtures.

Fixtures:
  - test_db:      fresh in-memory SQLite database for each test
  - client:       TestClient authenticated as an "analyst" user
  - admin_client: TestClient authenticated as an "admin" user
  - anon_client:  TestClient without any token
All clients use test_db through the get_db dependency override.
"""

import os

# Point the app at an in-memory database *before* importing it, so the
# startup hook never creates a real viperv2.db file during tests.
os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.main import app
from app.core.database import Base, get_db
from app.core.security import create_access_token, hash_password
from app.models.user import User

TEST_PASSWORD = "correct-horse-battery"
# bcrypt is deliberately slow (~0.25 s); hash once and reuse for every test user
TEST_PASSWORD_HASH = hash_password(TEST_PASSWORD)


@pytest.fixture(scope="function")
def test_db() -> Session:
    """Create an isolated in-memory SQLite database for each test.

    StaticPool makes every checkout return the *same* connection. Without it,
    each new connection to "sqlite://" would open a brand-new, empty database,
    and TestClient (which runs the app in another thread) would not see the
    tables or rows created by the test.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # SQLite ignores foreign keys unless this pragma is set per connection
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()

    yield db

    db.close()
    engine.dispose()


def create_user(db: Session, username: str, role: str, is_active: bool = True) -> User:
    user = User(username=username, email=f"{username}@example.com",
                hashed_password=TEST_PASSWORD_HASH, role=role, is_active=is_active)
    db.add(user)
    db.commit()
    return user


@pytest.fixture(scope="function")
def make_client(test_db: Session):
    """Factory: make_client(role) returns a TestClient using test_db,
    with a valid bearer token for a user of that role (no token if role is None)."""
    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    opened = []

    def _make(role: str | None):
        test_client = TestClient(app)
        test_client.__enter__()          # runs the app's startup (lifespan)
        opened.append(test_client)
        if role is not None:
            user = (test_db.query(User).filter(User.username == f"{role}-user").first()
                    or create_user(test_db, f"{role}-user", role))
            test_client.headers["Authorization"] = f"Bearer {create_access_token(user.id)}"
        return test_client

    yield _make

    for test_client in opened:
        test_client.__exit__(None, None, None)
    app.dependency_overrides.clear()


@pytest.fixture
def client(make_client):
    return make_client("analyst")


@pytest.fixture
def admin_client(make_client):
    return make_client("admin")


@pytest.fixture
def anon_client(make_client):
    return make_client(None)
