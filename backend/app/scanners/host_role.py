"""
Infer a host's role from the services it actually exposes.

The role is DEDUCED from the open ports/services discovered by the scan - it is
not certified. An open port 53 does not prove the host is an authoritative DNS
server, only that something is listening there. Callers should present roles as
"inferred", and a host can legitimately hold several roles.
"""

from typing import Dict, List

# (role, trigger ports, service-name keywords). Ordered by significance: the
# first match is the host's primary role when it holds several.
ROLE_SIGNATURES = [
    ("database", {3306, 5432, 1433, 1434, 27017, 27018, 6379, 1521, 5984, 9200, 11211},
     ("mysql", "mariadb", "postgres", "mssql", "ms-sql", "mongodb", "mongo", "redis",
      "oracle", "couchdb", "elasticsearch", "memcached")),
    ("web", {80, 443, 8080, 8443, 8000, 8008, 8081, 8888},
     ("http", "https", "http-proxy", "http-alt", "ssl/http", "nginx", "apache")),
    ("mail", {25, 465, 587, 993, 110, 143},
     ("smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "pop", "submission")),
    ("dns", {53}, ("domain", "dns")),
    ("file_sharing", {445, 139, 21},
     ("smb", "netbios", "netbios-ssn", "microsoft-ds", "samba", "ftp")),
    ("remote_access", {22, 23, 3389, 5900, 5901, 5902, 5985, 5986},
     ("ssh", "telnet", "rdp", "ms-wbt-server", "ms-term-serv", "vnc", "rfb", "winrm", "wsman")),
]

# Human-readable labels (the frontend owns the icons/colours).
ROLE_LABELS = {
    "gateway": "Gateway / router",
    "web": "Web server",
    "mail": "Mail server",
    "dns": "DNS server",
    "database": "Database",
    "file_sharing": "File sharing",
    "remote_access": "Remote access / admin",
    "workstation": "Workstation / host",
    "unknown": "Unknown",
}


def _matches(signature_ports: set, keywords: tuple, port: int, service: str) -> bool:
    if port in signature_ports:
        return True
    return any(kw in service for kw in keywords)


def infer_roles(open_ports: List[Dict]) -> List[str]:
    """All roles a host matches, in significance order (may be empty).

    open_ports: list of {"port": int, "service": str, "state": "open", ...}.
    """
    roles = []
    live = [p for p in (open_ports or []) if p.get("state") == "open"]
    for role, ports, keywords in ROLE_SIGNATURES:
        for p in live:
            try:
                port_num = int(p.get("port"))
            except (TypeError, ValueError):
                continue
            if _matches(ports, keywords, port_num, (p.get("service") or "").lower()):
                roles.append(role)
                break
    return roles


def classify_host(open_ports: List[Dict]) -> Dict:
    """Return {"primary": role, "roles": [...], "inferred": True}.

    primary is the most significant matched role; a host with open ports but no
    distinctive service is a "workstation"; one with no open ports is "unknown".
    """
    roles = infer_roles(open_ports)
    has_open = any(p.get("state") == "open" for p in (open_ports or []))
    primary = roles[0] if roles else ("workstation" if has_open else "unknown")
    return {"primary": primary, "roles": roles or [primary], "inferred": True}
