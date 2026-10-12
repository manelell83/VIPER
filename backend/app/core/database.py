import logging

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

log = logging.getLogger(__name__)

# SQLite only. check_same_thread=False is required because FastAPI serves
# requests from a thread pool, so a connection may be used by another thread.
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def add_missing_columns(bind=engine) -> list[str]:
    """Add columns that exist in the models but not yet in an existing database.

    create_all() creates missing tables but never alters existing ones, so a
    database created by an older version would lack newly added columns.
    Only nullable columns are added (SQLite cannot add a NOT NULL column
    without a default). Returns the "table.column" names that were added.
    """
    inspector = inspect(bind)
    existing_tables = set(inspector.get_table_names())
    added = []
    with bind.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue   # created by create_all()
            present = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in present:
                    continue
                if not column.nullable:
                    raise RuntimeError(f"Cannot add NOT NULL column {table.name}.{column.name} automatically")
                col_type = column.type.compile(dialect=bind.dialect)
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {col_type}'))
                added.append(f"{table.name}.{column.name}")
    for name in added:
        log.info("Database migrated: added column %s", name)
    return added
