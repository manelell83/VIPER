"""
Tests for the real network scan: prerequisites, host discovery, MAC vendors,
the network size limit and the network-scan pipeline.

Nothing here touches the real network: discovery, nmap and the NVD lookup
are replaced by fakes, so the tests check VIPER's logic only.
"""

import pytest
from sqlalchemy.orm import Session

from app.models.scan import Host, ScanSession
from app.scanners import arp_scanner, capabilities, scan_engine
from app.scanners.network_calculator import network_size
from app.scanners.oui import LOCALLY_ADMINISTERED, mac_vendor


# ── Prerequisites ─────────────────────────────────────────────────────────────

@pytest.fixture
def machine(monkeypatch):
    """Configure the detected prerequisites for a Windows machine, so the tests
    are deterministic regardless of the OS they run on (CI is Linux).

    machine(admin=..., npcap=..., nmap=..., pcap=..., windows=...).
    """
    def set_(admin=True, npcap=True, nmap="7.95", pcap=True, windows=True):
        monkeypatch.setattr(capabilities, "IS_WINDOWS", windows)
        monkeypatch.setattr(capabilities, "is_admin", lambda: admin)
        monkeypatch.setattr(capabilities, "npcap_installed", lambda: npcap)
        monkeypatch.setattr(capabilities, "nmap_version", lambda: nmap)
        monkeypatch.setattr(capabilities, "pcap_usable", lambda: pcap)
    return set_


class TestCapabilities:

    def test_everything_available(self, machine):
        machine()
        caps = capabilities.get_capabilities()

        assert caps["discovery_method"] == "arp"
        assert caps["os_detection"] is True
        assert caps["problems"] == []

    def test_without_admin_rights(self, machine):
        machine(admin=False)
        caps = capabilities.get_capabilities()

        assert caps["discovery_method"] == "ping"
        assert caps["os_detection"] is False
        problem = caps["problems"][0]
        assert problem["id"] == "admin" and problem["fix"] and problem["impact"]

    def test_without_npcap(self, machine):
        machine(npcap=False, pcap=False)   # no Npcap -> Scapy pcap unusable too
        caps = capabilities.get_capabilities()

        assert caps["discovery_method"] == "ping"
        assert [p["id"] for p in caps["problems"]] == ["npcap"]
        assert "npcap.com" in caps["problems"][0]["fix"]

    def test_without_nmap(self, machine):
        machine(nmap=None)
        caps = capabilities.get_capabilities()

        assert caps["service_detection"] is False and caps["os_detection"] is False
        assert "nmap.org" in caps["problems"][0]["fix"]

    def test_npcap_present_but_unusable_by_scapy(self, machine):
        # WinPcap-compatible install: files exist but Scapy cannot load wpcap.dll
        machine(npcap=True, pcap=False)
        caps = capabilities.get_capabilities()

        assert caps["discovery_method"] == "ping"
        assert [p["id"] for p in caps["problems"]] == ["pcap"]
        assert "WinPcap API-compatible" in caps["problems"][0]["fix"]

    def test_npcap_not_applicable_outside_windows(self, machine):
        machine(npcap=None, windows=False)     # Linux/macOS: root is enough for ARP

        assert capabilities.get_capabilities()["discovery_method"] == "arp"

    def test_endpoint(self, client, machine):
        machine(admin=False)
        body = client.get("/interfaces/capabilities").json()

        assert body["admin"] is False
        assert body["problems"][0]["id"] == "admin"


# ── MAC vendors ───────────────────────────────────────────────────────────────

class TestMacVendor:
    """Tests the wrapper logic. Scapy's OUI lookup is mocked, so results do not
    depend on the exact vendor strings in Scapy's bundled database (which vary
    by version and platform)."""

    @pytest.fixture
    def manuf(self, monkeypatch):
        """manuf("Acme Corp") makes Scapy's lookup return that for any prefix."""
        from scapy.all import conf

        def set_(value):
            monkeypatch.setattr(conf.manufdb, "_get_manuf", lambda mac: value)
        return set_

    def test_returns_the_vendor_for_a_globally_assigned_mac(self, manuf):
        manuf("Acme Corp")
        assert mac_vendor("08:00:27:12:34:56") == "Acme Corp"      # VirtualBox-style OUI

    def test_is_case_insensitive(self, manuf):
        manuf("Acme Corp")
        assert mac_vendor("08:00:27:AB:CD:EF") == "Acme Corp"

    def test_locally_administered_address_is_flagged_without_a_lookup(self, manuf):
        manuf("should not be used")   # bit set -> we must not consult the DB
        assert mac_vendor("0a:00:27:00:00:05") == LOCALLY_ADMINISTERED

    @pytest.mark.parametrize("mac", [None, "", "not-a-mac", "08-00-27-12-34-56"])
    def test_missing_or_invalid(self, mac):
        assert mac_vendor(mac) is None

    def test_scapy_error_is_handled(self, monkeypatch):
        from scapy.all import conf

        def boom(mac):
            raise RuntimeError("manuf db unavailable")
        monkeypatch.setattr(conf.manufdb, "_get_manuf", boom)
        assert mac_vendor("08:00:27:12:34:56") is None

    def test_real_lookup_returns_a_string_or_none(self):
        # Integration smoke test: whatever Scapy's DB holds, our wrapper must
        # return a non-empty vendor string or None - never the MAC itself.
        result = mac_vendor("08:00:27:12:34:56")
        assert result is None or (isinstance(result, str) and result and ":" not in result)

    def test_unknown_prefix_returns_none(self, monkeypatch):
        # Scapy's database returns the MAC itself when it does not know the prefix
        from scapy.all import conf
        monkeypatch.setattr(conf.manufdb, "_get_manuf", lambda mac: mac)

        assert mac_vendor("00:11:22:33:44:55") is None


# ── Network size limit ────────────────────────────────────────────────────────

@pytest.mark.parametrize("cidr, size", [("192.168.56.0/24", 254), ("172.19.0.0/16", 65534), ("10.0.0.4/30", 2)])
def test_network_size(cidr, size):
    assert network_size(cidr) == size


class TestNetworkSizeLimit:

    @pytest.fixture
    def interface(self, monkeypatch):
        from app.api.routes import scan as scan_routes
        calls = []

        async def fake_scan(scan_id, interface):
            calls.append(scan_id)

        monkeypatch.setattr(scan_routes, "_background_network_scan", fake_scan)

        def set_subnet(subnet):
            monkeypatch.setattr(scan_routes, "get_interface_by_name",
                                lambda name: {"name": name, "ip": subnet.split("/")[0], "subnet": subnet})
        set_subnet.calls = calls
        return set_subnet

    def test_slash_24_is_accepted(self, client, interface):
        interface("192.168.56.0/24")
        response = client.post("/scan/network", json={"interface": "eth0", "authorization_confirmed": True})

        assert response.status_code == 200

    def test_slash_16_is_refused_with_an_explanation(self, client, test_db: Session, interface):
        interface("172.19.0.0/16")
        response = client.post("/scan/network", json={"interface": "eth0", "authorization_confirmed": True})

        assert response.status_code == 422
        assert "65534 addresses" in response.json()["detail"]
        assert interface.calls == []
        assert test_db.query(ScanSession).count() == 0

    def test_interfaces_endpoint_flags_oversized_networks(self, client, monkeypatch):
        from app.api.routes import interfaces as iface_routes
        monkeypatch.setattr(iface_routes, "get_interfaces", lambda: [
            {"name": "vbox", "ip": "192.168.56.1", "subnet": "192.168.56.0/24"},
            {"name": "docker", "ip": "172.19.0.2", "subnet": "172.19.0.0/16"},
        ])
        body = client.get("/interfaces").json()

        flags = {i["name"]: (i["host_count"], i["scannable"]) for i in body["interfaces"]}
        assert flags == {"vbox": (254, True), "docker": (65534, False)}
        assert body["max_hosts"] == 254


# ── Host discovery ────────────────────────────────────────────────────────────

class TestDiscoverHosts:

    @pytest.fixture
    def fakes(self, monkeypatch):
        calls = {"arp": [], "ping": []}

        def fake_arp(subnet, interface_ip):
            calls["arp"].append((subnet, interface_ip))
            return [{"ip": "192.168.56.101", "mac": "08:00:27:aa:bb:cc", "hostname": ""}]

        def fake_ping(subnet):
            calls["ping"].append(subnet)
            return [{"ip": "192.168.56.101", "mac": "", "hostname": ""}]

        monkeypatch.setattr(arp_scanner, "_scapy_arp_scan", fake_arp)
        monkeypatch.setattr(arp_scanner, "_fallback_arp_scan", fake_ping)
        return calls

    def test_uses_arp_on_the_chosen_interface(self, machine, fakes):
        machine()
        result = arp_scanner.discover_hosts("192.168.56.0/24", "192.168.56.1")

        assert result["method"] == "arp" and result["note"] is None
        assert fakes["arp"] == [("192.168.56.0/24", "192.168.56.1")]
        assert fakes["ping"] == []

    def test_without_admin_rights_falls_back_to_ping_and_says_why(self, machine, fakes):
        machine(admin=False)
        result = arp_scanner.discover_hosts("192.168.56.0/24", "192.168.56.1")

        assert result["method"] == "ping"
        assert "administrator" in result["note"]
        assert fakes["arp"] == []

    def test_arp_failure_falls_back_to_ping_and_says_so(self, machine, fakes, monkeypatch):
        machine()

        def broken(subnet, interface_ip):
            raise OSError("capture failed")
        monkeypatch.setattr(arp_scanner, "_scapy_arp_scan", broken)

        result = arp_scanner.discover_hosts("192.168.56.0/24", "192.168.56.1")

        assert result["method"] == "ping"
        assert "ARP discovery failed" in result["note"]
        assert fakes["ping"] == ["192.168.56.0/24"]

    def test_never_falls_back_to_the_default_interface(self, monkeypatch):
        # No capture interface owns the requested IP: ARP must refuse to send
        # (Scapy would otherwise use the default route's interface).
        monkeypatch.setattr(arp_scanner, "_scapy_interface", lambda ip: None)

        with pytest.raises(RuntimeError, match="no capture interface"):
            arp_scanner._scapy_arp_scan("192.168.56.0/24", "192.168.56.1")


# ── Network scan pipeline ─────────────────────────────────────────────────────

@pytest.fixture
def events():
    received = []

    async def emit(event):
        received.append(event)
    emit.received = received
    return emit


@pytest.fixture
def network_scan(test_db: Session):
    scan = ScanSession(type="network", target="192.168.56.0/24", interface="vbox")
    test_db.add(scan)
    test_db.commit()
    return scan


@pytest.fixture
def lab(monkeypatch):
    """Fake 192.168.56.0/24 lab: one VirtualBox guest with SSH open."""
    monkeypatch.setattr(scan_engine, "get_interface_by_name",
                        lambda name: {"name": name, "ip": "192.168.56.1", "subnet": "192.168.56.0/24"})
    monkeypatch.setattr(scan_engine, "discover_hosts", lambda subnet, ip: {
        "hosts": [{"ip": "192.168.56.101", "mac": "08:00:27:aa:bb:cc", "hostname": "kali.lab"}],
        "method": "arp", "note": None,
    })
    monkeypatch.setattr(scan_engine, "port_scan", lambda ip: {
        "ports": [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh",
                   "product": "OpenSSH", "version": "OpenSSH 9.6p1"}],
        "os": "Linux 6.X", "os_accuracy": 98, "hostname": None,
    })

    async def no_cves(hosts, db, emit):
        return 0
    monkeypatch.setattr(scan_engine, "scan_all_hosts_vulnerabilities", no_cves)


async def test_pipeline_records_host_details(test_db, network_scan, events, lab):
    await scan_engine.run_network_scan(network_scan.id, "vbox", test_db, events)

    test_db.refresh(network_scan)
    assert network_scan.status == "completed"
    assert network_scan.discovery_method == "arp"
    host = test_db.query(Host).filter(Host.scan_id == network_scan.id).one()
    assert (host.ip, host.mac, host.mac_vendor) == ("192.168.56.101", "08:00:27:aa:bb:cc", "PCS Systemtechnik GmbH")
    assert (host.hostname, host.os, host.os_accuracy) == ("kali.lab", "Linux 6.X", 98)
    assert host.open_ports_count == 1
    assert any(e["type"] == "arp_complete" and "via ARP" in e["message"] for e in events.received)


async def test_pipeline_reports_the_ping_fallback(test_db, network_scan, events, lab, monkeypatch):
    monkeypatch.setattr(scan_engine, "discover_hosts", lambda subnet, ip: {
        "hosts": [], "method": "ping", "note": "ARP discovery unavailable (no admin) - ping sweep used instead.",
    })

    await scan_engine.run_network_scan(network_scan.id, "vbox", test_db, events)

    test_db.refresh(network_scan)
    assert network_scan.discovery_method == "ping"
    assert "ping sweep used instead" in network_scan.discovery_note
    assert any("ping sweep used instead" in (e.get("message") or "") for e in events.received)


async def test_pipeline_refuses_an_oversized_network(test_db, network_scan, events, lab, monkeypatch):
    monkeypatch.setattr(scan_engine, "get_interface_by_name",
                        lambda name: {"name": name, "ip": "172.19.0.2", "subnet": "172.19.0.0/16"})

    await scan_engine.run_network_scan(network_scan.id, "vbox", test_db, events)

    test_db.refresh(network_scan)
    assert network_scan.status == "failed"
    assert "65534 addresses" in network_scan.error
