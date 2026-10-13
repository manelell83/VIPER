"""Model for a passive domain-recon session. The structured result (DNS,
WHOIS, subdomains, fingerprints and the linked entity graph) is stored as JSON."""

import json
from uuid import uuid4

from sqlalchemy import Column, String, DateTime, Text

from app.core.database import Base
from app.core.timeutil import iso_utc, utcnow


class ReconScan(Base):
    __tablename__ = "recon_scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    target = Column(String, nullable=False, index=True)   # the domain
    status = Column(String, default="running")            # running|completed|failed
    error = Column(Text, nullable=True)
    result_json = Column(Text, nullable=True)             # the full recon result
    created_by = Column(String, nullable=True)            # username who ran it
    created_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)

    def to_dict(self, include_result: bool = True) -> dict:
        data = {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "error": self.error,
            "created_by": self.created_by,
            "created_at": iso_utc(self.created_at),
            "completed_at": iso_utc(self.completed_at),
        }
        if include_result:
            try:
                data["result"] = json.loads(self.result_json) if self.result_json else None
            except Exception:
                data["result"] = None
        return data
