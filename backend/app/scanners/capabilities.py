"""
What the network scanner can actually do on this machine.

Checked before a scan (and shown in the UI) so that missing prerequisites are
explained instead of failing silently:
  - administrator / root rights  -> needed for ARP discovery and OS detection
  - Npcap (Windows only)         -> packet capture driver used for ARP
  - Nmap                         -> port, service and OS detection

Nothing here sends network traffic.
"""

import ctypes
import os
import platform
import shutil
import subprocess
from typing import Optional

IS_WINDOWS = platform.system() == "Windows"

NPCAP_URL = "https://npcap.com/#download"
NMAP_URL = "https://nmap.org/download.html"


def is_admin() -> bool:
    """True if the backend runs with administrator (Windows) or root (Unix) rights."""
    try:
        if IS_WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def npcap_installed() -> Optional[bool]:
    """True/False on Windows; None elsewhere (not applicable)."""
    if not IS_WINDOWS:
        return None
    system32 = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32")
    return (os.path.exists(os.path.join(system32, "Npcap"))
            or os.path.exists(os.path.join(system32, "wpcap.dll")))


def pcap_usable() -> bool:
    """True if Scapy can actually open a packet-capture socket for ARP.

    Npcap files can be present yet unusable by Scapy: when Npcap is installed
    in "WinPcap API-compatible mode", wpcap.dll lands in System32 instead of
    System32\\Npcap, where Scapy looks. So we test the real capability instead
    of trusting the files alone.
    """
    try:
        from scapy.arch import libpcap
        return bool(getattr(libpcap, "conf").use_pcap)
    except Exception:
        return False


def nmap_version() -> Optional[str]:
    """Installed Nmap version (e.g. "7.95"), or None if Nmap is not found."""
    path = shutil.which("nmap")
    if not path:
        return None
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for word in out.split():
        if word[:1].isdigit():
            return word
    return "unknown"


def get_capabilities() -> dict:
    """Summary of the scanner's abilities, with a fix for each missing piece."""
    admin = is_admin()
    npcap = npcap_installed()
    nmap = nmap_version()
    # ARP needs admin rights and a packet-capture layer Scapy can actually use.
    pcap = pcap_usable() if IS_WINDOWS else True
    packet_capture = admin and pcap

    problems = []
    if not admin:
        problems.append({
            "id": "admin",
            "message": "The backend is not running with administrator/root rights.",
            "fix": ("Restart the backend from a terminal opened with \"Run as administrator\"."
                    if IS_WINDOWS else "Restart the backend with sudo."),
            "impact": "ARP discovery and OS detection are unavailable; a ping sweep is used instead.",
        })
    if npcap is False:
        problems.append({
            "id": "npcap",
            "message": "Npcap is not installed.",
            "fix": f"Install Npcap from {NPCAP_URL}, then restart the backend.",
            "impact": "ARP discovery is unavailable; a ping sweep is used instead.",
        })
    elif IS_WINDOWS and not pcap:
        # Npcap files exist but Scapy cannot load wpcap.dll (usually the
        # "WinPcap API-compatible mode" layout).
        problems.append({
            "id": "pcap",
            "message": "Npcap is installed but its capture library is not where Scapy expects it.",
            "fix": (f"Reinstall Npcap from {NPCAP_URL} with the default options "
                    "(leave \"Install in WinPcap API-compatible Mode\" unchecked), then restart the backend."),
            "impact": "ARP discovery is unavailable; a ping sweep is used instead (results are still real).",
        })
    if nmap is None:
        problems.append({
            "id": "nmap",
            "message": "Nmap was not found on the PATH.",
            "fix": f"Install Nmap from {NMAP_URL} and make sure it is on the PATH, then restart the backend.",
            "impact": "Service and OS detection are unavailable; only a basic TCP connect check runs.",
        })

    return {
        "platform": platform.system(),
        "admin": admin,
        "npcap": npcap,
        "nmap": nmap,
        "discovery_method": "arp" if packet_capture else "ping",
        "service_detection": nmap is not None,
        "os_detection": admin and nmap is not None,
        "problems": problems,
    }
