"""
Plain-language explanations for prioritized findings.

Two sources, both grounded ONLY in the deterministic data from engine.py:
  - "template": deterministic sentences built from the score factors. Always
    available, no API key, the default.
  - "ai": the same facts rephrased by an LLM (see llm.py). Used only when a key
    is configured; falls back to the template on any error.

The AI never invents scores or facts - it only rewrites what the engine computed.
"""

import logging
from typing import Dict, List, Tuple

log = logging.getLogger(__name__)


def _top_factors(finding: dict, n: int = 3) -> List[dict]:
    return sorted((f for f in finding["factors"] if f["points"] > 0),
                  key=lambda f: -f["points"])[:n]


def template_explanation(finding: dict) -> str:
    """A deterministic one-paragraph explanation from the finding's factors."""
    drivers = _top_factors(finding)
    if drivers:
        reasons = "; ".join(f"{f['label'].lower()} ({f['detail']})" for f in drivers)
    else:
        reasons = "no strong urgency signals"
    conf = "confirmed by CPE" if finding["confirmed"] else "a weak keyword match (possible false positive)"
    return (f"{finding['cve_id']} on {finding['host_ip']} scores {finding['score']}/100. "
            f"Main drivers: {reasons}. This finding is {conf}. "
            f"Priority is a decision aid - verify before acting.")


def template_executive_summary(findings: List[dict]) -> str:
    """A deterministic executive summary of the ranked findings."""
    if not findings:
        return "No vulnerabilities were found in this scan."
    kev = sum(1 for f in findings if f["kev"])
    confirmed = sum(1 for f in findings if f["confirmed"])
    top = findings[0]
    lines = [
        f"{len(findings)} finding(s) were ranked by urgency from real signals "
        f"(exploitation evidence, EPSS, CVSS, match confidence, exposure, lateral movement).",
        f"{kev} are exploited in the wild (CISA KEV); {confirmed} are CPE-confirmed.",
        f"Top priority: {top['cve_id']} on {top['host_ip']} (score {top['score']}/100, "
        f"{top['affected_service'] or 'unknown service'}).",
        "This ranking is a decision aid for the analyst, not an absolute truth - confirm before acting.",
    ]
    return " ".join(lines)


def build_narrative(findings: List[dict], use_llm: bool) -> Tuple[str, Dict[str, str], str, str]:
    """Return (executive_summary, {cve_id: explanation}, source, model).

    Deterministic template by default. When use_llm is true and a key is
    configured, the LLM rephrases the same computed facts; any failure falls
    back to the template cleanly.
    """
    template_summary = template_executive_summary(findings)
    template_expl = {f["cve_id"]: template_explanation(f) for f in findings}

    if use_llm:
        from app.prioritization.llm import generate_llm_narrative
        result = generate_llm_narrative(findings)
        if result is not None:
            summary, expl, model = result
            # The LLM only covers what it returned; keep template for the rest.
            merged = {**template_expl, **{k: v for k, v in expl.items() if v}}
            return (summary or template_summary), merged, "ai", model

    return template_summary, template_expl, "template", None
