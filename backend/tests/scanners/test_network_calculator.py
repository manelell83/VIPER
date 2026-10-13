"""
Unit tests for target validation and resolution (network_calculator.py).
"""

import socket

import pytest

from app.scanners.network_calculator import (
    calculate_subnet,
    is_valid_hostname,
    is_valid_scan_target,
    resolve_target,
)


class TestIsValidScanTarget:

    @pytest.mark.parametrize("value", [
        "192.168.1.10", "scanme.nmap.org", "localhost", "fqdn.example.", "a-b.c-d.e",
    ])
    def test_accepts_ipv4_and_hostnames(self, value):
        assert is_valid_scan_target(value)

    @pytest.mark.parametrize("value", [
        "", "x -oN file", "-iL", "-x.com", "x-.com", "a..b", "under_score",
        "a" * 64, "a." * 127 + "a",     # 64-char label / 255-char name
        "::1", "10.0.0.0/24",
    ])
    def test_rejects_everything_else(self, value):
        assert not is_valid_scan_target(value)

    def test_253_characters_is_the_maximum(self):
        name = ".".join(["a" * 63] * 3 + ["a" * 61])     # 63*3 + 61 + 3 dots = 253
        assert len(name) == 253 and is_valid_hostname(name)
        assert not is_valid_hostname(name + "a")


class TestResolveTarget:

    def test_ip_is_returned_without_dns_lookup(self, monkeypatch):
        def no_dns(name):
            raise AssertionError("DNS must not be queried for an IP address")
        monkeypatch.setattr(socket, "gethostbyname", no_dns)

        assert resolve_target("10.0.0.5") == "10.0.0.5"

    def test_hostname_is_resolved(self, monkeypatch):
        monkeypatch.setattr(socket, "gethostbyname", lambda name: "93.184.216.34")

        assert resolve_target("example.com") == "93.184.216.34"

    def test_unresolvable_name_raises_instead_of_passing_input_through(self, monkeypatch):
        def fail(name):
            raise socket.gaierror("Name or service not known")
        monkeypatch.setattr(socket, "gethostbyname", fail)

        with pytest.raises(ValueError, match="Could not resolve"):
            resolve_target("nothing.invalid")

    def test_idna_error_is_handled(self):
        # Python's IDNA codec raises UnicodeError for labels > 63 characters
        with pytest.raises(ValueError):
            resolve_target("a" * 64 + ".com")


def test_calculate_subnet():
    subnet = calculate_subnet("192.168.1.42", "255.255.255.0")

    assert subnet["network"] == "192.168.1.0/24"
    assert subnet["num_hosts"] == 254
    assert subnet["host_range"] == "192.168.1.1 - 192.168.1.254"
