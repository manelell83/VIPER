"""
Tests for the recon API routes. The background recon task is replaced so no
network runs; these check validation, auth and persistence.
"""

import pytest
from sqlalchemy.orm import Session

from app.api.routes import recon as recon_routes
from app.domain_recon.models import ReconScan


@pytest.fixture(autouse=True)
def no_background(monkeypatch):
    started = []

    async def fake(recon_id, target):
        started.append((recon_id, target))
    monkeypatch.setattr(recon_routes, "_background_recon", fake)
    return started


class TestStartRecon:

    def test_starts_recon_for_a_valid_domain(self, client, test_db: Session, no_background):
        resp = client.post("/recon", json={"target": "example.com"})

        assert resp.status_code == 200
        recon_id = resp.json()["recon_id"]
        row = test_db.query(ReconScan).filter(ReconScan.id == recon_id).one()
        assert row.target == "example.com" and row.status == "running"
        assert no_background == [(recon_id, "example.com")]

    def test_normalizes_a_url_and_trailing_dot(self, client, test_db, no_background):
        resp = client.post("/recon", json={"target": "HTTPS://Example.COM./path"})

        assert resp.status_code == 200
        assert test_db.query(ReconScan).one().target == "example.com"

    @pytest.mark.parametrize("target", ["93.184.216.34", "not a domain", "localhost", "a..b", ""])
    def test_rejects_non_domains(self, client, target, no_background):
        resp = client.post("/recon", json={"target": target})
        assert resp.status_code == 422

    def test_requires_authentication(self, anon_client):
        assert anon_client.post("/recon", json={"target": "example.com"}).status_code == 401


class TestGetRecon:

    def test_returns_the_full_result(self, client, test_db):
        recon = ReconScan(target="example.com", status="completed",
                          result_json='{"domain": "example.com", "ips": []}')
        test_db.add(recon)
        test_db.commit()

        body = client.get(f"/recon/{recon.id}").json()
        assert body["status"] == "completed"
        assert body["result"]["domain"] == "example.com"

    def test_404_for_unknown_id(self, client):
        assert client.get("/recon/does-not-exist").status_code == 404

    def test_list_omits_the_heavy_result(self, client, test_db):
        test_db.add(ReconScan(target="a.com", status="completed", result_json='{"big": "x"}'))
        test_db.commit()

        body = client.get("/recon").json()
        assert len(body["recon"]) >= 1
        assert "result" not in body["recon"][0]
