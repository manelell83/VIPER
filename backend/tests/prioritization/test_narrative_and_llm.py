"""
Tests for the narrative layer: deterministic template, and the optional LLM
(mocked - no real API call) with a clean fallback.
"""

import pytest

from app.prioritization import llm as llm_mod
from app.prioritization.llm import generate_llm_narrative, llm_available
from app.prioritization.narrative import build_narrative, template_executive_summary, template_explanation


def _finding(cve="CVE-2011-2523", score=100.0, kev=False, confirmed=True):
    return {
        "vuln_id": "v-" + cve, "cve_id": cve, "host_ip": "192.168.56.5",
        "affected_service": "vsftpd 2.3.4", "severity": "CRITICAL", "cvss": 9.8,
        "kev": kev, "epss": 0.96, "confirmed": confirmed, "maturity": "WEAPONIZED",
        "score": score, "rank": 1,
        "factors": [
            {"key": "exploitation", "label": "Exploit maturity: WEAPONIZED", "points": 25.0, "detail": "..."},
            {"key": "epss", "label": "Exploitation probability (EPSS)", "points": 19.2, "detail": "EPSS 96.0%"},
            {"key": "cvss", "label": "Severity (CVSS)", "points": 24.5, "detail": "CVSS 9.8"},
            {"key": "confidence", "label": "Match confidence (CPE-confirmed)", "points": 15.0, "detail": "..."},
        ],
    }


class TestTemplate:

    def test_explanation_names_the_top_drivers(self):
        text = template_explanation(_finding())
        assert "CVE-2011-2523" in text and "192.168.56.5" in text
        assert "100.0/100" in text or "100/100" in text
        assert "confirmed by CPE" in text
        assert "decision aid" in text.lower()

    def test_weak_match_is_flagged(self):
        text = template_explanation(_finding(confirmed=False))
        assert "weak keyword match" in text

    def test_executive_summary_counts_kev_and_confirmed(self):
        findings = [_finding("CVE-1", kev=True), _finding("CVE-2", confirmed=False)]
        summary = template_executive_summary(findings)
        assert "2 finding(s)" in summary
        assert "1 are exploited in the wild" in summary
        assert "decision aid" in summary.lower()

    def test_empty(self):
        assert "No vulnerabilities" in template_executive_summary([])


class TestBuildNarrative:

    def test_default_is_template(self):
        summary, expl, source, model = build_narrative([_finding()], use_llm=False)
        assert source == "template" and model is None
        assert expl["CVE-2011-2523"]

    def test_llm_requested_but_unavailable_falls_back(self, monkeypatch):
        monkeypatch.setattr(llm_mod, "llm_available", lambda: False)
        summary, expl, source, model = build_narrative([_finding()], use_llm=True)
        assert source == "template"

    def test_llm_result_is_merged_and_marked_ai(self, monkeypatch):
        def fake(findings):
            return ("AI exec summary", {"CVE-2011-2523": "AI explanation."}, "claude-opus-5-5")
        monkeypatch.setattr(llm_mod, "generate_llm_narrative", fake)

        summary, expl, source, model = build_narrative([_finding()], use_llm=True)
        assert source == "ai" and model == "claude-opus-5-5"
        assert summary == "AI exec summary"
        assert expl["CVE-2011-2523"] == "AI explanation."


class TestLlmClient:

    def test_unavailable_without_a_key(self, monkeypatch):
        monkeypatch.setattr(llm_mod.settings, "LLM_API_KEY", "")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "")
        assert llm_available() is False
        assert generate_llm_narrative([_finding()]) is None

    def test_parses_a_mocked_anthropic_response(self, monkeypatch):
        monkeypatch.setattr(llm_mod.settings, "LLM_API_KEY", "sk-test")
        monkeypatch.setattr(llm_mod.settings, "LLM_PROVIDER", "anthropic")

        class Block:
            type = "text"
            text = '{"executive_summary": "S", "explanations": {"CVE-2011-2523": "E"}}'

        class Resp:
            content = [Block()]

        class FakeMessages:
            def create(self, **kwargs):
                assert kwargs["model"] == "claude-opus-5-5"
                assert "do not" in kwargs["system"].lower() or "never invent" in kwargs["system"].lower()
                return Resp()

        class FakeClient:
            def __init__(self, **kwargs):
                self.messages = FakeMessages()

        import anthropic
        monkeypatch.setattr(anthropic, "Anthropic", FakeClient)

        result = generate_llm_narrative([_finding()])
        assert result is not None
        summary, expl, model = result
        assert summary == "S" and expl["CVE-2011-2523"] == "E" and model == "claude-opus-5-5"

    def test_malformed_llm_output_falls_back(self, monkeypatch):
        monkeypatch.setattr(llm_mod.settings, "LLM_API_KEY", "sk-test")
        monkeypatch.setattr(llm_mod.settings, "LLM_PROVIDER", "anthropic")

        class Block:
            type = "text"
            text = "sorry, I cannot produce JSON"

        class Resp:
            content = [Block()]

        class FakeClient:
            def __init__(self, **kwargs):
                self.messages = type("M", (), {"create": lambda self, **k: Resp()})()

        import anthropic
        monkeypatch.setattr(anthropic, "Anthropic", FakeClient)

        assert generate_llm_narrative([_finding()]) is None

    @pytest.mark.parametrize("text,expected", [
        ('{"a": 1}', {"a": 1}),
        ('```json\n{"a": 2}\n```', {"a": 2}),
        ('Here it is: {"a": 3} done', {"a": 3}),
        ("not json", None),
    ])
    def test_json_parser_is_tolerant(self, text, expected):
        assert llm_mod._parse_json(text) == expected
