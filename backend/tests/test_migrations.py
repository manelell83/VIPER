"""
Tests for add_missing_columns(): databases created by an older version get the
new nullable columns added at startup, and existing data is kept.
"""

from sqlalchemy import create_engine, inspect, text

from app.core.database import Base, add_missing_columns
import app.main  # noqa: F401  (registers every model)


def test_adds_new_columns_to_an_old_table_and_keeps_rows():
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        # scan_sessions as it was before the authorization columns existed
        conn.execute(text(
            "CREATE TABLE scan_sessions (id VARCHAR PRIMARY KEY, type VARCHAR NOT NULL, target VARCHAR NOT NULL, "
            "interface VARCHAR, status VARCHAR, error TEXT, started_at DATETIME, completed_at DATETIME)"))
        conn.execute(text("INSERT INTO scan_sessions (id, type, target) VALUES ('s1', 'domain', 'example.com')"))
    Base.metadata.create_all(bind=engine)      # creates the other tables, leaves this one as is

    added = add_missing_columns(engine)

    assert {"scan_sessions.authorized_by", "scan_sessions.authorized_at",
            "scan_sessions.authorization_statement"} <= set(added)
    columns = {c["name"] for c in inspect(engine).get_columns("scan_sessions")}
    assert {"authorized_by", "authorized_at", "authorization_statement"} <= columns
    with engine.connect() as conn:
        assert conn.execute(text("SELECT target FROM scan_sessions WHERE id = 's1'")).scalar() == "example.com"


def test_is_idempotent():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(bind=engine)

    assert add_missing_columns(engine) == []
    assert add_missing_columns(engine) == []
