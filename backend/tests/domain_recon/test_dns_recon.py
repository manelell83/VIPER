"""
Tests for DNS recon. dns.resolver is mocked with real dnspython record objects,
so formatting is exercised without any network call.
"""

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from app.domain_recon import dns_recon
from app.domain_recon.dns_recon import resolve_records, reverse_dns


def _records(rtype, *texts):
    """Build real dnspython rdata objects of a type (as resolve() yields)."""
    rdtype = dns.rdatatype.from_text(rtype)
    return [dns.rdata.from_text(dns.rdataclass.IN, rdtype, t) for t in texts]


@pytest.fixture
def dns_zone(monkeypatch):
    """dns_zone({"A": ["1.2.3.4"], "MX": ["10 mail.x.com."]}) fakes the resolver."""
    def set_(mapping):
        def fake_resolve(self, name, rtype):
            key = str(rtype)
            if key in mapping:
                return _records(key, *mapping[key])
            raise dns.resolver.NoAnswer
        monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
    return set_


class TestResolveRecords:

    def test_collects_all_types(self, dns_zone):
        dns_zone({
            "A": ["93.184.216.34"],
            "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
            "MX": ["10 mail.example.com.", "20 backup.example.com."],
            "NS": ["a.iana-servers.net.", "b.iana-servers.net."],
            "TXT": ['"v=spf1 -all"'],
            "CNAME": [],
        })
        result = resolve_records("example.com")

        assert result["A"] == ["93.184.216.34"]
        assert result["AAAA"] == ["2606:2800:220:1:248:1893:25c8:1946"]
        assert result["MX"] == ["10 mail.example.com", "20 backup.example.com"]   # trailing dot stripped
        assert result["NS"] == ["a.iana-servers.net", "b.iana-servers.net"]
        assert result["TXT"] == ["v=spf1 -all"]
        assert result["CNAME"] == []

    def test_missing_records_are_empty_lists(self, dns_zone):
        dns_zone({"A": ["1.2.3.4"]})
        result = resolve_records("example.com")

        assert result["A"] == ["1.2.3.4"]
        assert result["MX"] == [] and result["TXT"] == []
        assert set(result) == set(dns_recon.RECORD_TYPES)

    def test_nxdomain_yields_all_empty(self, monkeypatch):
        def nxdomain(self, name, rtype):
            raise dns.resolver.NXDOMAIN
        monkeypatch.setattr(dns.resolver.Resolver, "resolve", nxdomain)

        assert resolve_records("does-not-exist.invalid") == {t: [] for t in dns_recon.RECORD_TYPES}

    def test_timeout_is_swallowed(self, monkeypatch):
        def timeout(self, name, rtype):
            raise dns.resolver.LifetimeTimeout
        monkeypatch.setattr(dns.resolver.Resolver, "resolve", timeout)

        assert resolve_records("slow.example.com")["A"] == []


class TestReverseDns:

    def test_returns_ptr(self, monkeypatch):
        def fake_resolve(self, name, rtype):
            assert rtype == "PTR"
            return _records("PTR", "scanme.nmap.org.")
        monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)

        assert reverse_dns("45.33.32.156") == "scanme.nmap.org"

    def test_no_ptr_falls_back_then_returns_empty(self, monkeypatch):
        monkeypatch.setattr(dns.resolver.Resolver, "resolve",
                            lambda self, n, t: (_ for _ in ()).throw(dns.resolver.NXDOMAIN))
        monkeypatch.setattr(dns_recon.socket, "gethostbyaddr",
                            lambda ip: (_ for _ in ()).throw(OSError))

        assert reverse_dns("10.0.0.1") == ""
