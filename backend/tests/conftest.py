"""
Pytest configuration and shared fixtures.

Fixtures:
  - test_db: fresh in-memory SQLite database for each test
  - client:  FastAPI TestClient whose get_db dependency uses test_db
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


@pytest.fixture(scope="function")
def client(test_db: Session):
    """FastAPI TestClient that uses the per-test database."""
    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
