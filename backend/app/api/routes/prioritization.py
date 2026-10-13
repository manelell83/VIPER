"""
AI Prioritization routes.

The ranking is deterministic (engine.py); the optional LLM only writes
explanations. The analyst stays in the loop: manual rank and dismissal are
persisted and applied over the deterministic order.
"""

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.timeutil import utcnow
from app.models.scan import ScanSession
from app.models.user import User
from app.prioritization.engine import prioritize_scan
from app.prioritization.llm import llm_available
from app.prioritization.models import PrioritizationState
from app.prioritization.narrative import build_narrative

router = APIRouter()


def _get_state(scan_id: str, db: Session) -> PrioritizationState:
    state = db.query(PrioritizationState).filter(PrioritizationState.scan_id == scan_id).first()
    if not state:
        state = PrioritizationState(id=str(uuid4()), scan_id=scan_id)
        db.add(state)
        db.commit()
    return state


def _apply_overrides(findings, overrides):
    """Apply analyst overrides and re-order: manual ranks first, then score."""
    for f in findings:
        ov = overrides.get(f["vuln_id"], {})
        f["manual_rank"] = ov.get("manual_rank")
        f["dismissed"] = bool(ov.get("dismissed"))

    def key(f):
        has_manual = f["manual_rank"] is not None
        return (f["dismissed"], not has_manual, f["manual_rank"] if has_manual else 0, -f["score"])

    findings.sort(key=key)
    for i, f in enumerate(findings, start=1):
        f["rank"] = i
    return findings


@router.get("/{scan_id}")
async def get_prioritization(scan_id: str, db: Session = Depends(get_db),
                             user: User = Depends(get_current_user)):
    """The ranked, scored findings with their factor breakdown and any cached
    explanations. Deterministic; no LLM call here."""
    if not db.query(ScanSession).filter(ScanSession.id == scan_id).first():
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = prioritize_scan(scan_id, db)
    state = _get_state(scan_id, db)
    _apply_overrides(findings, state.overrides())

    explanations = state.explanations()
    narrative = state.narrative_dict()
    for f in findings:
        f["explanation"] = {
            "text": explanations.get(f["cve_id"]),
            "source": state.narrative_source if explanations.get(f["cve_id"]) else None,
        }

    return {
        "scan_id": scan_id,
        "count": len(findings),
        "llm_available": llm_available(),
        "narrative": narrative,
        "items": findings,
    }


class NarrativeRequest(BaseModel):
    use_llm: bool = False   # opt in to the LLM; template is always the default


@router.post("/{scan_id}/narrative")
async def generate_narrative(scan_id: str, body: NarrativeRequest,
                             db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Generate (and cache) the executive summary + per-finding explanations.
    Template by default; the LLM is used only if requested AND a key is set."""
    if not db.query(ScanSession).filter(ScanSession.id == scan_id).first():
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = prioritize_scan(scan_id, db)
    summary, explanations, source, model = build_narrative(findings, use_llm=body.use_llm)

    state = _get_state(scan_id, db)
    import json
    state.executive_summary = summary
    state.explanations_json = json.dumps(explanations)
    state.narrative_source = source
    state.narrative_model = model
    state.narrative_generated_at = utcnow()
    db.commit()

    return {"executive_summary": summary, "source": source, "model": model,
            "requested_llm": body.use_llm, "llm_available": llm_available()}


class OverrideRequest(BaseModel):
    manual_rank: int | None = Field(default=None, ge=1, le=9999)
    dismissed: bool | None = None


@router.patch("/{scan_id}/items/{vuln_id}")
async def set_override(scan_id: str, vuln_id: str, body: OverrideRequest,
                       db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Analyst override (human-in-the-loop): pin a manual rank and/or dismiss."""
    if not db.query(ScanSession).filter(ScanSession.id == scan_id).first():
        raise HTTPException(status_code=404, detail="Scan not found")

    state = _get_state(scan_id, db)
    overrides = state.overrides()
    entry = overrides.get(vuln_id, {})
    if body.manual_rank is not None or (body.dismissed is None and "manual_rank" not in entry):
        entry["manual_rank"] = body.manual_rank
    if body.dismissed is not None:
        entry["dismissed"] = body.dismissed
    overrides[vuln_id] = entry

    import json
    state.overrides_json = json.dumps(overrides)
    db.commit()
    return {"vuln_id": vuln_id, "override": entry}
