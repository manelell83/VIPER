"""Per-scan prioritization state: analyst overrides (human-in-the-loop) and the
cached narrative (executive summary + per-finding explanations)."""

import json
from uuid import uuid4

from sqlalchemy import Column, String, Text, DateTime

from app.core.database import Base
from app.core.timeutil import iso_utc, utcnow


class PrioritizationState(Base):
    __tablename__ = "prioritization_state"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    scan_id = Column(String, nullable=False, unique=True, index=True)

    # Analyst overrides: {vuln_id: {"manual_rank": int|null, "dismissed": bool}}
    overrides_json = Column(Text, default="{}")

    # Cached narrative (regenerated on demand)
    executive_summary = Column(Text, nullable=True)
    narrative_source = Column(String, nullable=True)      # "ai" | "template"
    narrative_model = Column(String, nullable=True)       # LLM model id, if AI
    explanations_json = Column(Text, default="{}")        # {cve_id: explanation}
    narrative_generated_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=utcnow)

    def overrides(self) -> dict:
        try:
            return json.loads(self.overrides_json or "{}")
        except Exception:
            return {}

    def explanations(self) -> dict:
        try:
            return json.loads(self.explanations_json or "{}")
        except Exception:
            return {}

    def narrative_dict(self) -> dict:
        if not self.executive_summary and not self.explanations():
            return None
        return {
            "executive_summary": self.executive_summary,
            "source": self.narrative_source,
            "model": self.narrative_model,
            "generated_at": iso_utc(self.narrative_generated_at),
        }
