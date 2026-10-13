"""
Tests for WHOIS/RDAP recon. HTTP is faked with httpx.MockTransport and the
python-whois fallback is monkeypatched, so no network or real whois runs.
"""

import datetime

import httpx
import pytest

from app.domain_recon import whois_recon
from app.domain_recon.whois_recon import lookup_whois

BOOTSTRAP = {"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                          [["org"], ["https://rdap.publicinterestregistry.org/rdap/"]]]}

RDAP_DOMAIN = {
    "events": [
        {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2024-09-09T15:39:04Z"},
    ],
    "nameservers": [{"ldhName": "ns1.example.com."}, {"ldhName": "ns2.example.com."}],
    "entities": [
        {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                           ["fn", {}, "text", "MarkMonitor Inc."]]]},
        {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Org"]]]},
    ],
}


@pytest.fixture(autouse=True)
def clear_bootstrap():
    whois_recon._bootstrap_cache = None
    yield
    whois_recon._bootstrap_cache = None


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestRdap:

    async def test_parses_a_covered_tld_via_rdap(self):
        def handler(request):
            if "dns.json" in request.url.path:
                return httpx.Response(200, json=BOOTSTRAP)
            assert request.url.host == "rdap.verisign.com"
            return httpx.Response(200, json=RDAP_DOMAIN)

        async with _client(handler) as c:
            r = await lookup_whois("example.com", c)

        assert r["source"] == "rdap"
        assert r["registrar"] == "MarkMonitor Inc."
        assert r["owner"] == "Example Org"
        assert r["created"] == "1997-09-15T04:00:00Z"
        assert r["expires"] == "2028-09-14T04:00:00Z"
        assert r["name_servers"] == ["ns1.example.com", "ns2.example.com"]

    async def test_rdap_404_reports_no_data_but_rdap_source(self):
        def handler(request):
            if "dns.json" in request.url.path:
                return httpx.Response(200, json=BOOTSTRAP)
            return httpx.Response(404)

        async with _client(handler) as c:
            r = await lookup_whois("nope.com", c)

        assert r["source"] == "rdap" and r["registrar"] is None

    async def test_uncovered_tld_falls_back_to_whois(self, monkeypatch):
        called = {}

        def fake_whois_sync(domain):
            called["domain"] = domain
            return {"domain": domain, "source": "whois", "registrar": "Registrar .ma",
                    "created": None, "updated": None, "expires": None, "owner": None, "name_servers": []}
        monkeypatch.setattr(whois_recon, "_lookup_whois_sync", fake_whois_sync)

        def handler(request):
            return httpx.Response(200, json=BOOTSTRAP)   # .ma not in bootstrap

        async with _client(handler) as c:
            r = await lookup_whois("example.ma", c)

        assert called["domain"] == "example.ma"
        assert r["source"] == "whois" and r["registrar"] == "Registrar .ma"

    async def test_rdap_server_error_falls_back_to_whois(self, monkeypatch):
        monkeypatch.setattr(whois_recon, "_lookup_whois_sync",
                            lambda d: {"domain": d, "source": "whois", "registrar": "fallback",
                                       "created": None, "updated": None, "expires": None,
                                       "owner": None, "name_servers": []})

        def handler(request):
            if "dns.json" in request.url.path:
                return httpx.Response(200, json=BOOTSTRAP)
            return httpx.Response(500)   # RDAP server down

        async with _client(handler) as c:
            r = await lookup_whois("example.com", c)

        assert r["source"] == "whois" and r["registrar"] == "fallback"


class TestWhoisFallback:

    def test_normalizes_whois_fields(self, monkeypatch):
        class FakeWhois(dict):
            pass
        fake = FakeWhois(registrar="GoDaddy",
                         creation_date=[datetime.datetime(2001, 3, 1), datetime.datetime(2001, 3, 2)],
                         expiration_date=datetime.datetime(2027, 3, 1),
                         updated_date=None, org="Example LLC",
                         name_servers=["NS1.EXAMPLE.COM.", "ns1.example.com", "NS2.EXAMPLE.COM"])

        import whois
        monkeypatch.setattr(whois, "whois", lambda d: fake)

        r = whois_recon._lookup_whois_sync("example.io")

        assert r["source"] == "whois"
        assert r["registrar"] == "GoDaddy"
        assert r["created"] == "2001-03-01T00:00:00"      # first date of the list
        assert r["expires"] == "2027-03-01T00:00:00"
        assert r["owner"] == "Example LLC"
        assert r["name_servers"] == ["ns1.example.com", "ns2.example.com"]   # deduped, lowercased

    def test_whois_exception_yields_empty(self, monkeypatch):
        import whois

        def boom(d):
            raise Exception("whois server unreachable")
        monkeypatch.setattr(whois, "whois", boom)

        r = whois_recon._lookup_whois_sync("broken.io")
        assert r["source"] == "whois" or r["source"] is None
        assert r["registrar"] is None and r["name_servers"] == []
