"""
Optional LLM layer: rephrases the deterministic prioritization into an
executive summary and plain-language per-finding explanations.

Provider and key come from the environment (settings.LLM_PROVIDER /
LLM_API_KEY, falling back to ANTHROPIC_API_KEY) - never hardcoded. With no key,
or on any error, the caller uses the deterministic template instead.

Hard rule: the model is given ONLY the computed data and is told never to
invent scores or facts. It explains; it does not decide.
"""

import json
import logging
import os
from typing import Dict, List, Optional, Tuple

from app.core.config import settings

log = logging.getLogger(__name__)

MAX_FINDINGS_FOR_LLM = 15      # keep the prompt (and cost) bounded
MAX_TOKENS = 2000

SYSTEM_PROMPT = (
    "You are a security analyst assistant. You are given findings that a "
    "deterministic engine has already scored and ranked. Your job is to explain "
    "them in clear language for an analyst.\n"
    "STRICT RULES:\n"
    "- Use ONLY the data provided. Never invent CVEs, scores, versions, or facts.\n"
    "- Never change or recompute any score; refer to the scores as given.\n"
    "- Be concise and factual. No exploitation instructions.\n"
    "- The ranking is a decision aid, not absolute truth; say so in the summary.\n"
    'Return ONLY a JSON object: {"executive_summary": "...", '
    '"explanations": {"<cve_id>": "<1-2 sentence explanation>", ...}}.'
)


def _api_key() -> str:
    return settings.LLM_API_KEY or os.environ.get("ANTHROPIC_API_KEY", "")


def llm_available() -> bool:
    return settings.LLM_PROVIDER == "anthropic" and bool(_api_key())


def _facts(findings: List[dict]) -> List[dict]:
    """The computed data the model may use - nothing else."""
    out = []
    for f in findings[:MAX_FINDINGS_FOR_LLM]:
        out.append({
            "cve_id": f["cve_id"],
            "host": f["host_ip"],
            "service": f["affected_service"],
            "score": f["score"],
            "rank": f.get("rank"),
            "severity": f["severity"],
            "kev": f["kev"],
            "epss": f["epss"],
            "confirmed": f["confirmed"],
            "maturity": f["maturity"],
            "factors": [{"label": x["label"], "points": x["points"], "detail": x["detail"]}
                        for x in f["factors"] if x["points"] > 0],
        })
    return out


def generate_llm_narrative(findings: List[dict]) -> Optional[Tuple[str, Dict[str, str], str]]:
    """Return (executive_summary, {cve_id: explanation}, model) or None to fall back."""
    if not llm_available() or not findings:
        return None
    try:
        import anthropic
    except ImportError:
        log.info("anthropic SDK not installed; using template explanations")
        return None

    model = settings.LLM_MODEL
    payload = {"findings": _facts(findings)}
    try:
        client = anthropic.Anthropic(api_key=_api_key())
        resp = client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(payload)}],
        )
        text = "".join(block.text for block in resp.content if getattr(block, "type", None) == "text")
        data = _parse_json(text)
        if not isinstance(data, dict):
            return None
        summary = data.get("executive_summary") or ""
        explanations = data.get("explanations") or {}
        if not isinstance(explanations, dict):
            explanations = {}
        return summary, {str(k): str(v) for k, v in explanations.items()}, model
    except Exception as exc:
        log.warning("LLM narrative generation failed (%s); falling back to template", exc)
        return None


def _parse_json(text: str):
    """Parse a JSON object, tolerating code fences or surrounding prose."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
