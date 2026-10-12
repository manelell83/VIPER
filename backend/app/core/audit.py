"""Scan authorization: the statement users must confirm, and the audit log.

Active scans (network and domain) can only start after the user explicitly
confirms they own the target or are authorised to scan it. The confirmation
is stored on the scan (who, when, exact statement) and written to the
"viper.audit" log.
"""

import logging
from datetime import datetime, timezone

# Stored verbatim with every scan, so the audit trail shows exactly what was confirmed.
AUTHORIZATION_STATEMENT = (
    "I confirm that I own this target or have explicit permission from its owner to scan it."
)

audit_log = logging.getLogger("viper.audit")


def configure_logging(audit_file: str) -> None:
    """Send app logs to the console and audit records to an append-only file.

    Without this, Python drops INFO messages (no handler is configured), so
    audit records would never be written anywhere. Safe to call twice.
    """
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    app_log = logging.getLogger("app")
    app_log.setLevel(logging.INFO)
    if not app_log.handlers:
        console = logging.StreamHandler()
        console.setFormatter(fmt)
        app_log.addHandler(console)

    audit_log.setLevel(logging.INFO)
    audit_log.propagate = False
    for handler in list(audit_log.handlers):     # reconfiguration: replace previous handlers
        audit_log.removeHandler(handler)
        handler.close()
    file_handler = logging.FileHandler(audit_file, mode="a", encoding="utf-8")
    file_handler.setFormatter(fmt)
    audit_log.addHandler(file_handler)
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    audit_log.addHandler(console)


def record_scan_authorization(scan, username: str) -> None:
    """Stamp a scan with the user's authorization confirmation and log it."""
    scan.authorized_by = username
    scan.authorized_at = datetime.now(timezone.utc).replace(tzinfo=None)   # stored as naive UTC
    scan.authorization_statement = AUTHORIZATION_STATEMENT
    audit_log.info(
        "scan authorized: user=%s scan_id=%s type=%s target=%s at=%sZ statement=%r",
        username, scan.id, scan.type, scan.target, scan.authorized_at.isoformat(), AUTHORIZATION_STATEMENT,
    )
