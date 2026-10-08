"""
Unit tests for the port scanner (port_scanner.py).

- Nmap parsing is tested with the same PortScannerHostDict object python-nmap
  returns, so no nmap binary or network is needed.
- The socket fallback is tested against a real listening socket on localhost.
"""

import socket

import pytest
from nmap import PortScannerHostDict

from app.scanners import port_scanner
from app.scanners.port_scanner import _parse_nmap_host, _socket_scan, _get_service_name


def _nmap_host(**overrides):
    """One host as python-nmap returns it after `nmap -sV -O`."""
    host = {
        "hostnames": [{"name": "web01.lan", "type": "PTR"}],
        "addresses": {"ipv4": "10.0.0.5"},
        "status": {"state": "up", "reason": "arp-response"},
        "tcp": {
            80: {"state": "open", "name": "http", "product": "Apache httpd",
                 "version": "2.4.41", "extrainfo": "(Ubuntu)"},
            22: {"state": "open", "name": "ssh", "product": "OpenSSH",
                 "version": "8.2p1 Ubuntu 4ubuntu0.5", "extrainfo": "Ubuntu Linux; protocol 2.0"},
            25: {"state": "filtered", "name": "smtp", "product": "", "version": "", "extrainfo": ""},
        },
        "osmatch": [{"name": "Linux 5.4", "accuracy": "96"}, {"name": "Linux 4.15", "accuracy": "90"}],
    }
    host.update(overrides)
    return PortScannerHostDict(host)


class TestParseNmapHost:

    def test_ports_are_sorted_and_mapped(self):
        result = _parse_nmap_host(_nmap_host())

        assert [p["port"] for p in result["ports"]] == [22, 25, 80]
        ssh = result["ports"][0]
        assert ssh == {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 Ubuntu Linux; protocol 2.0",
        }

    def test_non_open_states_are_kept(self):
        result = _parse_nmap_host(_nmap_host())

        assert result["ports"][1]["state"] == "filtered"
        assert result["ports"][1]["version"] == ""

    def test_best_os_match_and_hostname(self):
        result = _parse_nmap_host(_nmap_host())

        assert result["os"] == "Linux 5.4"
        assert result["os_accuracy"] == 96          # converted from string
        assert result["hostname"] == "web01.lan"

    def test_host_without_os_or_hostname(self):
        host = _nmap_host(hostnames=[{"name": "", "type": ""}], osmatch=[], tcp={})

        result = _parse_nmap_host(host)

        assert result == {"ports": [], "os": None, "os_accuracy": None, "hostname": None}


class TestSocketFallback:

    def test_detects_a_listening_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))      # port 0 = let the OS pick a free port
            server.listen()
            port = server.getsockname()[1]

            result = _socket_scan("127.0.0.1", f"{port}-{port}")

        assert [p["port"] for p in result["ports"]] == [port]
        assert result["ports"][0]["state"] == "open"

    def test_closed_port_is_not_reported(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        # socket closed → nothing listens on that port any more

        assert _socket_scan("127.0.0.1", f"{port}-{port}")["ports"] == []

    @pytest.mark.parametrize("port, name", [(22, "ssh"), (3389, "rdp"), (12345, "")])
    def test_common_service_names(self, port, name):
        assert _get_service_name(port) == name


def test_falls_back_to_socket_scan_when_nmap_fails(monkeypatch):
    def broken_nmap(ip, port_range):
        raise FileNotFoundError("nmap program was not found in path")

    monkeypatch.setattr(port_scanner, "_nmap_scan", broken_nmap)
    monkeypatch.setattr(port_scanner, "_socket_scan", lambda ip, pr: {"fallback": (ip, pr)})

    assert port_scanner.port_scan("10.0.0.5", "1-100") == {"fallback": ("10.0.0.5", "1-100")}
