"""
Attack rules engine — defines what conditions make a host attackable
and what types of attack vectors exist.
Each rule is evaluated against a host's open ports, services, and CVEs.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AttackRule:
    id: str
    name: str
    attack_type: str        # REMOTE_ACCESS | LATERAL_MOVEMENT | PRIVILEGE_ESCALATION | DATA_ACCESS | PERSISTENCE
    ports: List[int]        # trigger if any of these ports are open
    services: List[str]     # trigger if any of these keywords appear in the service name
    base_score: float       # 0-100 base attack difficulty/impact
    attack_vector: str      # human-readable vector label
    description: str
    requires_cve: bool = False      # only trigger when a matching CVE is present
    min_cvss: float = 0.0           # minimum CVSS to trigger (when requires_cve=True)
    cvss_multiplier: float = 1.0    # score boost factor when CVEs are present
    is_entry_point: bool = True     # ATTACKER can directly reach this host
    is_pivot: bool = False          # host can reach other hosts via this vector


ATTACK_RULES: List[AttackRule] = [
    # ── REMOTE ACCESS ──────────────────────────────────────────────────────────
    AttackRule(
        id="ssh_remote",
        name="SSH Remote Access",
        attack_type="REMOTE_ACCESS",
        ports=[22],
        services=["ssh"],
        base_score=65.0,
        attack_vector="SSH CVE / Brute Force",
        description="SSH exposes direct remote access. Critical CVEs enable unauthenticated RCE.",
        is_entry_point=True,
        is_pivot=True,
        cvss_multiplier=1.4,
    ),
    AttackRule(
        id="rdp_remote",
        name="RDP Remote Desktop",
        attack_type="REMOTE_ACCESS",
        ports=[3389],
        services=["rdp", "ms-wbt-server", "ms-term-serv"],
        base_score=72.0,
        attack_vector="RDP BlueKeep / Credential Attack",
        description="RDP exposes Windows to remote takeover (BlueKeep CVE-2019-0708, DejaBlue).",
        is_entry_point=True,
        is_pivot=True,
        cvss_multiplier=1.5,
    ),
    AttackRule(
        id="telnet_remote",
        name="Telnet Cleartext",
        attack_type="REMOTE_ACCESS",
        ports=[23],
        services=["telnet"],
        base_score=82.0,
        attack_vector="Telnet Credential Intercept",
        description="Telnet transmits credentials in cleartext — MITM/intercept trivial.",
        is_entry_point=True,
        cvss_multiplier=1.2,
    ),
    AttackRule(
        id="vnc_remote",
        name="VNC Remote Desktop",
        attack_type="REMOTE_ACCESS",
        ports=[5900, 5901, 5902],
        services=["vnc", "rfb"],
        base_score=68.0,
        attack_vector="VNC Authentication Bypass",
        description="VNC desktop sharing susceptible to weak passwords and auth bypass CVEs.",
        is_entry_point=True,
        is_pivot=True,
        cvss_multiplier=1.3,
    ),
    AttackRule(
        id="ftp_access",
        name="FTP File Access",
        attack_type="REMOTE_ACCESS",
        ports=[21],
        services=["ftp"],
        base_score=60.0,
        attack_vector="FTP Anonymous / Credential Attack",
        description="FTP may allow anonymous access or credential-based file retrieval.",
        is_entry_point=True,
        cvss_multiplier=1.2,
    ),
    # ── WEB ATTACK SURFACE ────────────────────────────────────────────────────
    AttackRule(
        id="http_web",
        name="HTTP Web Attack Surface",
        attack_type="REMOTE_ACCESS",
        ports=[80, 8080, 8000, 8888, 8008],
        services=["http", "http-proxy", "http-alt"],
        base_score=55.0,
        attack_vector="HTTP Web Application Attack (SQLi/XSS/RFI)",
        description="HTTP service exposes web application attack surface.",
        is_entry_point=True,
        cvss_multiplier=1.3,
    ),
    AttackRule(
        id="https_web",
        name="HTTPS Web Surface",
        attack_type="REMOTE_ACCESS",
        ports=[443, 8443],
        services=["https", "ssl/http"],
        base_score=50.0,
        attack_vector="HTTPS Web Application Attack",
        description="HTTPS protects transit but not application logic — still web-attackable.",
        is_entry_point=True,
        cvss_multiplier=1.2,
    ),
    # ── LATERAL MOVEMENT ─────────────────────────────────────────────────────
    AttackRule(
        id="smb_lateral",
        name="SMB Lateral Movement",
        attack_type="LATERAL_MOVEMENT",
        ports=[445, 139],
        services=["smb", "netbios", "netbios-ssn", "microsoft-ds"],
        base_score=78.0,
        attack_vector="SMB Relay / EternalBlue / Pass-the-Hash",
        description="SMB enables lateral movement via relay attacks, pass-the-hash, or EternalBlue RCE.",
        is_entry_point=True,
        is_pivot=True,
        cvss_multiplier=1.6,
    ),
    AttackRule(
        id="winrm_lateral",
        name="WinRM/WMI Remote Execution",
        attack_type="LATERAL_MOVEMENT",
        ports=[5985, 5986],
        services=["wsman", "winrm"],
        base_score=72.0,
        attack_vector="WinRM Lateral Movement",
        description="WinRM/PowerShell Remoting enables lateral movement with valid credentials.",
        is_entry_point=False,
        is_pivot=True,
        cvss_multiplier=1.4,
    ),
    AttackRule(
        id="rpc_lateral",
        name="RPC Service Exploitation",
        attack_type="LATERAL_MOVEMENT",
        ports=[135, 593],
        services=["msrpc", "rpc", "epmap"],
        base_score=63.0,
        attack_vector="RPC Remote Execution",
        description="RPC services expose remote execution surfaces used in lateral movement.",
        is_entry_point=False,
        is_pivot=True,
        cvss_multiplier=1.3,
    ),
    AttackRule(
        id="ldap_pivot",
        name="LDAP Directory Enumeration",
        attack_type="LATERAL_MOVEMENT",
        ports=[389, 636, 3268, 3269],
        services=["ldap", "globalcatLDAP"],
        base_score=65.0,
        attack_vector="LDAP Anonymous Bind / Directory Traversal",
        description="LDAP may allow anonymous enumeration of domain users and structure.",
        is_entry_point=True,
        is_pivot=True,
        cvss_multiplier=1.4,
    ),
    # ── DATABASE ACCESS ───────────────────────────────────────────────────────
    AttackRule(
        id="mysql_data",
        name="MySQL Exposed",
        attack_type="DATA_ACCESS",
        ports=[3306],
        services=["mysql"],
        base_score=76.0,
        attack_vector="MySQL Credential Attack / SQL Injection",
        description="MySQL directly exposed — credential brute force or SQL injection.",
        is_entry_point=True,
        is_pivot=True,
        cvss_multiplier=1.5,
    ),
    AttackRule(
        id="mssql_data",
        name="MSSQL Exposed",
        attack_type="DATA_ACCESS",
        ports=[1433, 1434],
        services=["mssql", "ms-sql-s", "ms-sql"],
        base_score=80.0,
        attack_vector="MSSQL xp_cmdshell / Credential Attack",
        description="MSSQL xp_cmdshell can escalate from DB access to OS command execution.",
        is_entry_point=True,
        is_pivot=True,
        cvss_multiplier=1.6,
    ),
    AttackRule(
        id="postgres_data",
        name="PostgreSQL Exposed",
        attack_type="DATA_ACCESS",
        ports=[5432],
        services=["postgresql", "postgres"],
        base_score=72.0,
        attack_vector="PostgreSQL COPY / Credential Attack",
        description="PostgreSQL COPY command can lead to file read/write on the server.",
        is_entry_point=True,
        is_pivot=True,
        cvss_multiplier=1.4,
    ),
    AttackRule(
        id="mongodb_data",
        name="MongoDB Exposed",
        attack_type="DATA_ACCESS",
        ports=[27017, 27018],
        services=["mongodb"],
        base_score=77.0,
        attack_vector="MongoDB Unauthenticated Access",
        description="MongoDB often deployed without authentication — full data access.",
        is_entry_point=True,
        cvss_multiplier=1.5,
    ),
    AttackRule(
        id="redis_data",
        name="Redis Exposed",
        attack_type="DATA_ACCESS",
        ports=[6379],
        services=["redis"],
        base_score=84.0,
        attack_vector="Redis RCE via Config Write",
        description="Redis without auth allows config write → SSH key injection → RCE.",
        is_entry_point=True,
        is_pivot=True,
        cvss_multiplier=1.7,
    ),
    # ── PRIVILEGE ESCALATION (CVE-triggered) ─────────────────────────────────
    AttackRule(
        id="priv_esc_critical",
        name="Critical CVE Privilege Escalation",
        attack_type="PRIVILEGE_ESCALATION",
        ports=[],
        services=[],
        base_score=90.0,
        attack_vector="Critical CVE — Root/SYSTEM Access",
        description="CVSS 9+ vulnerability enables privilege escalation to root or SYSTEM.",
        requires_cve=True,
        min_cvss=9.0,
        is_entry_point=False,
        is_pivot=True,
        cvss_multiplier=1.8,
    ),
    AttackRule(
        id="priv_esc_high",
        name="High CVE Privilege Escalation",
        attack_type="PRIVILEGE_ESCALATION",
        ports=[],
        services=[],
        base_score=72.0,
        attack_vector="High CVE — Privilege Escalation",
        description="CVSS 7-9 vulnerability may enable privilege escalation.",
        requires_cve=True,
        min_cvss=7.0,
        is_entry_point=False,
        is_pivot=True,
        cvss_multiplier=1.5,
    ),
    # ── PERSISTENCE / INFO DISCLOSURE ────────────────────────────────────────
    AttackRule(
        id="snmp_info",
        name="SNMP Information Disclosure",
        attack_type="PERSISTENCE",
        ports=[161, 162],
        services=["snmp"],
        base_score=58.0,
        attack_vector="SNMP Community String Exposure",
        description="SNMP with default community strings leaks network config and topology.",
        is_entry_point=True,
        cvss_multiplier=1.2,
    ),
    AttackRule(
        id="smtp_relay",
        name="SMTP Open Relay",
        attack_type="PERSISTENCE",
        ports=[25, 465, 587],
        services=["smtp"],
        base_score=52.0,
        attack_vector="SMTP Open Relay / C2 Channel",
        description="SMTP may be used for phishing, open relay, or C2 communication.",
        is_entry_point=True,
        cvss_multiplier=1.2,
    ),
]


def evaluate_host_rules(
    open_ports: List[int],
    service_names: List[str],
    host_vulns: list,
) -> List[tuple]:
    """
    Evaluate all attack rules against a host's open ports, services, and CVEs.
    Returns list of (AttackRule, score, matched_cve_ids).
    """
    port_set = set(open_ports)
    service_lower = [s.lower() for s in service_names if s]

    results = []

    for rule in ATTACK_RULES:
        matched = False
        matched_cves: List[str] = []

        if rule.requires_cve:
            qualifying = [v for v in host_vulns if (v.cvss or 0) >= rule.min_cvss]
            if qualifying:
                matched = True
                matched_cves = [v.cve_id for v in qualifying[:5]]
        else:
            port_hit = bool(rule.ports) and bool(port_set & set(rule.ports))
            svc_hit = bool(rule.services) and any(
                kw in svc for kw in rule.services for svc in service_lower
            )
            matched = port_hit or svc_hit

            if matched and host_vulns:
                # Link a CVE to this rule if it affects one of the rule's ports
                # (exact number) or one of its service keywords.
                matched_cves = [
                    v.cve_id for v in host_vulns
                    if _port_number(v.affected_port) in rule.ports
                    or any(kw in (v.affected_service or "").lower() for kw in rule.services)
                ][:5]

        if matched:
            score = rule.base_score
            if matched_cves:
                best_cvss = max(
                    (v.cvss or 0) for v in host_vulns if v.cve_id in matched_cves
                ) if matched_cves else 0.0
                if best_cvss > 0:
                    boost = 1.0 + (best_cvss / 10.0) * (rule.cvss_multiplier - 1.0)
                    score = min(100.0, score * boost)
            results.append((rule, round(score, 1), matched_cves))

    return results


def _port_number(affected_port: Optional[str]) -> Optional[int]:
    """Extract the port number from a "22/tcp" string (None if missing/invalid)."""
    try:
        return int((affected_port or "").split("/")[0])
    except ValueError:
        return None
