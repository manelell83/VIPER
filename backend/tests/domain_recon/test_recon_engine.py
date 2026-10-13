"""
Tests for the recon engine: orchestration, graceful degradation and the
linked entity graph. All data sources are mocked - no network.
"""

import json

import pytest
from sqlalchemy.orm import Session

from app.domain_recon import recon_engine as engine
from app.domain_recon.models import ReconScan


@pytest.fixture
def recon(test_db: Session):
    r = ReconScan(target="example.com", status="running")
    test_db.add(r)
    test_db.commit()
    return r


@pytest.fixture
def sources(monkeypatch):
    """A small fake internet for example.com."""
    dns_db = {
        "example.com": {"A": ["93.184.216.34"], "AAAA": [], "MX": ["10 mail.example.com"],
                        "NS": ["a.ns.example.com"], "TXT": ["v=spf1 -all"], "CNAME": []},
        "www.example.com": {"A": ["93.184.216.34"], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []},
        "api.example.com": {"A": ["93.184.216.35"], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []},
    }
    monkeypatch.setattr(engine, "resolve_records", lambda d: dns_db.get(d, {k: [] for k in
                        ("A", "AAAA", "MX", "NS", "TXT", "CNAME")}))
    monkeypatch.setattr(engine, "reverse_dns", lambda ip: {"93.184.216.34": "example.com"}.get(ip, ""))

    async def fake_whois(domain, client):
        return {"domain": domain, "source": "rdap", "registrar": "RegX", "created": "1995-01-01",
                "updated": None, "expires": "2030-01-01", "owner": "Example Inc", "name_servers": ["a.ns.example.com"]}
    monkeypatch.setattr(engine, "lookup_whois", fake_whois)

    async def fake_subs(domain, client):
        return {"subdomains": ["www.example.com", "api.example.com"], "available": True, "error": None}
    monkeypatch.setattr(engine, "fetch_subdomains", fake_subs)

    async def fake_fp(host, client):
        reachable = host in ("example.com", "www.example.com")
        return {"host": host, "reachable": reachable, "url": f"https://{host}/" if reachable else None,
                "status": 200 if reachable else None, "server": "nginx" if reachable else None,
                "powered_by": None, "title": "Example" if reachable else None}
    monkeypatch.setattr(engine, "fingerprint", fake_fp)
    return dns_db


async def _run(recon, db):
    events = []

    async def emit(e):
        events.append(e)
    await engine.run_recon(recon.id, recon.target, db, emit)
    return events


class TestReconEngine:

    async def test_completes_and_stores_a_structured_result(self, test_db, recon, sources):
        events = await _run(recon, test_db)

        test_db.refresh(recon)
        assert recon.status == "completed" and recon.completed_at is not None
        result = json.loads(recon.result_json)

        assert result["dns"]["A"] == ["93.184.216.34"]
        assert result["whois"]["registrar"] == "RegX"
        assert result["subdomains"]["available"] is True
        assert set(result["subdomains"]["list"]) == {"www.example.com", "api.example.com"}
        assert {ip["ip"] for ip in result["ips"]} == {"93.184.216.34", "93.184.216.35"}
        assert any(ip["ip"] == "93.184.216.34" and ip["ptr"] == "example.com" for ip in result["ips"])
        assert {e["type"] for e in events} >= {"started", "dns_complete", "whois_complete",
                                               "subdomains_complete", "completed"}

    async def test_graph_links_domain_subdomain_ip_service(self, test_db, recon, sources):
        await _run(recon, test_db)
        graph = json.loads(recon.result_json)["graph"]

        types = {n["id"]: n["type"] for n in graph["nodes"]}
        assert types["domain:example.com"] == "domain"
        assert types["subdomain:api.example.com"] == "subdomain"
        assert types["ip:93.184.216.34"] == "ip"
        assert any(n["type"] == "service" for n in graph["nodes"])

        pairs = {(e["source"], e["target"]) for e in graph["edges"]}
        assert ("domain:example.com", "subdomain:api.example.com") in pairs       # domain -> subdomain
        assert ("subdomain:api.example.com", "ip:93.184.216.35") in pairs         # subdomain -> ip
        assert ("domain:example.com", "ip:93.184.216.34") in pairs                # apex -> ip
        # ip -> service exists for the reachable apex IP
        assert any(s.startswith("ip:93.184.216.34") and t.startswith("service:") for s, t in pairs)

    async def test_crtsh_unavailable_still_completes(self, test_db, recon, sources, monkeypatch):
        async def down(domain, client):
            return {"subdomains": [], "available": False, "error": "crt.sh unavailable (502). Skipped."}
        monkeypatch.setattr(engine, "fetch_subdomains", down)

        events = await _run(recon, test_db)

        test_db.refresh(recon)
        assert recon.status == "completed"
        result = json.loads(recon.result_json)
        assert result["subdomains"]["available"] is False
        assert "crt.sh unavailable" in result["subdomains"]["error"]
        # the subdomains_complete event carries the reason for the UI
        assert any(e["type"] == "subdomains_complete" and "crt.sh unavailable" in (e.get("message") or "")
                   for e in events)

    async def test_failure_marks_the_recon_failed_without_leaking_details(self, test_db, recon, monkeypatch):
        def boom(domain):
            raise RuntimeError("secret internal path C:\\x")
        monkeypatch.setattr(engine, "resolve_records", boom)

        events = await _run(recon, test_db)

        test_db.refresh(recon)
        assert recon.status == "failed"
        assert "secret" not in (recon.error or "")
        assert any(e["type"] == "error" for e in events)
