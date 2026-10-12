"""Time helpers: every timestamp is stored in UTC and sent to clients as UTC.

The database (SQLite) stores naive datetimes, so we store UTC without tzinfo.
When sending a datetime to the browser it must say it is UTC (trailing "Z"):
an ISO string without an offset is read by JavaScript as *local* time, which
showed every start time one hour off (in UTC+1).
"""

from datetime import datetime, timezone
from typing import Optional


def utcnow() -> datetime:
    """Current time in UTC, as a naive datetime (replaces datetime.utcnow(), deprecated)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso_utc(value: Optional[datetime]) -> Optional[str]:
    """ISO 8601 string marked as UTC ("...Z"), or None."""
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat() + "Z"
