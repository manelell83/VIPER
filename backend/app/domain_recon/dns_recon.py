"""
Passive DNS lookups for a domain: A, AAAA, MX, NS, TXT, CNAME records and
reverse DNS for the resolved IPs. Uses public resolvers only - no connection
to the target itself.
"""

import logging
import socket
from typing import Dict, List

import dns.resolver
import dns.reversename

log = logging.getLogger(__name__)

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
DNS_TIMEOUT = 5.0


def _format(rtype: str, rdata) -> str:
    if rtype == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
    if rtype == "TXT":
        # TXT values are one or more byte strings; join and decode
        return "".join(
            part.decode("utf-8", "replace") if isinstance(part, bytes) else str(part)
            for part in rdata.strings
        )
    if rtype in ("NS", "CNAME"):
        return rdata.to_text().rstrip(".")
    return rdata.to_text()


def _query(domain: str, rtype: str) -> List[str]:
    """Return the records of one type, or [] if none exist / lookup fails."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, rtype)
        return sorted(_format(rtype, r) for r in answers)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except Exception as exc:
        log.debug("DNS %s lookup for %s failed: %s", rtype, domain, exc)
        return []


def resolve_records(domain: str) -> Dict[str, List[str]]:
    """Look up every record type for the domain. Missing types map to []."""
    return {rtype: _query(domain, rtype) for rtype in RECORD_TYPES}


def reverse_dns(ip: str) -> str:
    """PTR record for an IP, or "" if none."""
    try:
        name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        return resolver.resolve(name, "PTR")[0].to_text().rstrip(".")
    except Exception:
        # Fall back to the OS resolver, then give up quietly
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""
