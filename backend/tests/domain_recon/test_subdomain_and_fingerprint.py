"""
Tests for crt.sh subdomain discovery and the HTTP fingerprint. HTTP is faked
with httpx.MockTransport - no network.
"""

import httpx

from app.domain_recon import subdomain_recon
from app.domain_recon.http_fingerprint import fingerprint
from app.domain_recon.subdomain_recon import fetch_subdomains


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestSubdomains:

    async def test_extracts_unique_hostnames(self):
        def handler(request):
            return httpx.Response(200, json=[
                {"name_value": "www.example.com\nexample.com"},
                {"name_value": "*.api.example.com"},
                {"name_value": "api.example.com"},
                {"name_value": "mail.other.com"},          # different domain -> ignored
            ])

        async with _client(handler) as c:
            result = await fetch_subdomains("example.com", c)

        assert result["available"] is True and result["error"] is None
        assert result["subdomains"] == ["api.example.com", "example.com", "www.example.com"]

    async def test_unavailable_after_retries_does_not_raise(self, monkeypatch):
        monkeypatch.setattr(subdomain_recon, "RETRIES", 2)
        monkeypatch.setattr(subdomain_recon.asyncio, "sleep", _noop)
        attempts = []

        def handler(request):
            attempts.append(1)
            return httpx.Response(502)

        async with _client(handler) as c:
            result = await fetch_subdomains("example.com", c)

        assert len(attempts) == 2
        assert result["available"] is False
        assert result["subdomains"] == []
        assert "crt.sh unavailable" in result["error"] and "502" in result["error"]

    async def test_retries_then_succeeds(self, monkeypatch):
        monkeypatch.setattr(subdomain_recon, "RETRIES", 3)
        monkeypatch.setattr(subdomain_recon.asyncio, "sleep", _noop)
        state = {"n": 0}

        def handler(request):
            state["n"] += 1
            if state["n"] < 2:
                raise httpx.ConnectTimeout("slow")
            return httpx.Response(200, json=[{"name_value": "a.example.com"}])

        async with _client(handler) as c:
            result = await fetch_subdomains("example.com", c)

        assert result["available"] is True and result["subdomains"] == ["a.example.com"]


class TestFingerprint:

    async def test_reads_headers_and_title(self):
        def handler(request):
            assert str(request.url).startswith("https://")
            return httpx.Response(200, headers={"server": "nginx/1.25", "x-powered-by": "PHP/8.2"},
                                  text="<html><head><TITLE>  Hello\n World </TITLE></head></html>")

        async with _client(handler) as c:
            fp = await fingerprint("example.com", c)

        assert fp["reachable"] is True and fp["status"] == 200
        assert fp["server"] == "nginx/1.25" and fp["powered_by"] == "PHP/8.2"
        assert fp["title"] == "Hello World"

    async def test_falls_back_from_https_to_http(self):
        def handler(request):
            if request.url.scheme == "https":
                raise httpx.ConnectError("no TLS")
            return httpx.Response(200, headers={"server": "Apache"}, text="<html></html>")

        async with _client(handler) as c:
            fp = await fingerprint("example.com", c)

        assert fp["reachable"] is True and fp["url"].startswith("http://")
        assert fp["server"] == "Apache" and fp["title"] is None

    async def test_unreachable_host(self):
        def handler(request):
            raise httpx.ConnectError("refused")

        async with _client(handler) as c:
            fp = await fingerprint("example.com", c)

        assert fp["reachable"] is False
        assert fp["status"] is None and fp["server"] is None

    async def test_non_html_has_no_title(self):
        def handler(request):
            return httpx.Response(200, headers={"server": "x", "content-type": "application/json"},
                                  text='{"not":"html"}')

        async with _client(handler) as c:
            fp = await fingerprint("api.example.com", c)

        assert fp["reachable"] is True and fp["title"] is None


async def _noop(*a, **k):
    pass
