"""
Tests for host role inference from observed services. Roles are deduced, not
certified, and a host can hold several.
"""

import pytest

from app.scanners.host_role import classify_host, infer_roles


def _ports(*specs):
    return [{"port": p, "service": s, "state": "open"} for p, s in specs]


@pytest.mark.parametrize("port,service,expected", [
    (80, "http", "web"),
    (443, "https", "web"),
    (25, "smtp", "mail"),
    (993, "imaps", "mail"),
    (53, "domain", "dns"),
    (3306, "mysql", "database"),
    (5432, "postgresql", "database"),
    (27017, "mongodb", "database"),
    (445, "microsoft-ds", "file_sharing"),
    (21, "ftp", "file_sharing"),
    (22, "ssh", "remote_access"),
    (3389, "ms-wbt-server", "remote_access"),
    (23, "telnet", "remote_access"),
])
def test_single_service_maps_to_its_role(port, service, expected):
    assert classify_host(_ports((port, service)))["primary"] == expected


def test_role_can_match_by_service_name_on_an_unusual_port():
    # nmap sometimes reports http on a non-standard port
    assert "web" in infer_roles(_ports((9999, "http")))


class TestMultiRole:
    def test_metasploitable_like_host_is_multi_role(self):
        host = _ports((21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"),
                      (53, "domain"), (80, "http"), (139, "netbios-ssn"), (445, "netbios-ssn"))
        result = classify_host(host)

        assert set(result["roles"]) == {"web", "mail", "dns", "file_sharing", "remote_access"}
        assert result["inferred"] is True

    def test_primary_is_the_most_significant(self):
        # database outranks remote access
        assert classify_host(_ports((22, "ssh"), (3306, "mysql")))["primary"] == "database"


class TestFallbacks:
    def test_open_but_undistinctive_is_a_workstation(self):
        result = classify_host(_ports((49152, "unknown"), (9999, "msrpc")))
        assert result["primary"] == "workstation" and result["roles"] == ["workstation"]

    def test_no_open_ports_is_unknown(self):
        assert classify_host([])["primary"] == "unknown"
        assert classify_host([{"port": 80, "service": "http", "state": "closed"}])["primary"] == "unknown"
