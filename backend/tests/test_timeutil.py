"""
Tests for app/core/timeutil.py: timestamps are UTC in the database and are
sent to the browser marked as UTC ("Z"), so they display in local time.
"""

from datetime import datetime, timedelta, timezone

from app.core.timeutil import iso_utc, utcnow


def test_utcnow_is_naive_utc():
    now = utcnow()

    assert now.tzinfo is None
    assert abs(now - datetime.now(timezone.utc).replace(tzinfo=None)) < timedelta(seconds=5)


def test_iso_utc_marks_naive_values_as_utc():
    assert iso_utc(datetime(2026, 10, 12, 9, 48, 15)) == "2026-10-12T09:48:15Z"


def test_iso_utc_converts_aware_values_to_utc():
    paris_summer = timezone(timedelta(hours=2))
    assert iso_utc(datetime(2026, 7, 1, 12, 0, tzinfo=paris_summer)) == "2026-07-01T10:00:00Z"


def test_iso_utc_none():
    assert iso_utc(None) is None


def test_api_dates_are_marked_utc(client, test_db):
    from app.models.scan import ScanSession

    scan = ScanSession(type="domain", target="example.com", status="completed",
                       started_at=datetime(2026, 10, 12, 9, 48, 15))
    test_db.add(scan)
    test_db.commit()

    body = client.get(f"/scan/status/{scan.id}").json()

    assert body["started_at"] == "2026-10-12T09:48:15Z"
