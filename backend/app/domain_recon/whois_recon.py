"""
Passive WHOIS/registration lookup for a domain.

RDAP first (structured JSON over HTTPS): the IANA bootstrap file says which
RDAP server owns each TLD. For TLDs with no RDAP server (e.g. .ma, .be, .io)
we fall back to python-whois. Either way we return the same small dict; a
lookup that yields nothing is not an error (the scan still completes).
"""

import asyncio
import logging
import time
from typing import Dict, Optional

import httpx

log = logging.getLogger(__name__)

IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL = 24 * 3600
HTTP_TIMEOUT = 15.0

_bootstrap_cache: Optional[tuple] = None   # (fetched_at, {tld: base_url})


def _empty(domain: str) -> Dict:
    return {"domain": domain, "source": None, "registrar": None, "created": None,
            "updated": None, "expires": None, "owner": None, "name_servers": []}


async def _get_bootstrap(client: httpx.AsyncClient) -> Dict[str, str]:
    """Map each TLD to its RDAP base URL, from the IANA bootstrap (cached)."""
    global _bootstrap_cache
    if _bootstrap_cache and (time.time() - _bootstrap_cache[0]) < BOOTSTRAP_TTL:
        return _bootstrap_cache[1]
    try:
        resp = await client.get(IANA_RDAP_BOOTSTRAP, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        mapping: Dict[str, str] = {}
        for tlds, urls in resp.json().get("services", []):
            base = next((u for u in urls if u.startswith("https")), urls[0] if urls else None)
            if base:
                for tld in tlds:
                    mapping[tld.lower()] = base.rstrip("/")
        _bootstrap_cache = (time.time(), mapping)
        return mapping
    except Exception as exc:
        log.warning("Could not load the IANA RDAP bootstrap: %s", exc)
        return _bootstrap_cache[1] if _bootstrap_cache else {}


def _parse_rdap(domain: str, data: dict) -> Dict:
    out = _empty(domain)
    out["source"] = "rdap"

    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    out["created"] = events.get("registration")
    out["updated"] = events.get("last changed") or events.get("last update of RDAP database")
    out["expires"] = events.get("expiration")

    ns = [n.get("ldhName", "").rstrip(".") for n in data.get("nameservers", [])]
    out["name_servers"] = sorted(n for n in ns if n)

    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        name = _vcard_field(entity, "fn")
        if "registrar" in roles and name:
            out["registrar"] = name
        if ("registrant" in roles or "administrative" in roles) and name and not out["owner"]:
            out["owner"] = name
    return out


def _vcard_field(entity: dict, field: str) -> Optional[str]:
    """Pull a field (e.g. "fn") from an RDAP jCard array."""
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            if item and item[0] == field:
                return item[3]
    except (IndexError, TypeError):
        pass
    return None


async def _lookup_rdap(domain: str, client: httpx.AsyncClient) -> Optional[Dict]:
    tld = domain.rsplit(".", 1)[-1].lower()
    base = (await _get_bootstrap(client)).get(tld)
    if not base:
        return None   # TLD not covered by RDAP -> caller falls back to whois
    try:
        resp = await client.get(f"{base}/domain/{domain}", timeout=HTTP_TIMEOUT,
                                headers={"Accept": "application/rdap+json"})
        if resp.status_code == 404:
            return _empty(domain) | {"source": "rdap"}   # no such domain, but RDAP answered
        resp.raise_for_status()
        return _parse_rdap(domain, resp.json())
    except Exception as exc:
        log.info("RDAP lookup for %s failed (%s); will try whois", domain, exc)
        return None


def _lookup_whois_sync(domain: str) -> Dict:
    """python-whois fallback (blocking). Returns the common dict shape."""
    try:
        import whois
        w = whois.whois(domain)
    except Exception as exc:
        log.info("whois lookup for %s failed: %s", domain, exc)
        return _empty(domain)

    def first(value):
        return value[0] if isinstance(value, list) and value else (None if isinstance(value, list) else value)

    def iso(value):
        value = first(value)
        return value.isoformat() if hasattr(value, "isoformat") else (str(value) if value else None)

    ns = w.get("name_servers") or []
    if isinstance(ns, str):
        ns = [ns]
    return {
        "domain": domain,
        "source": "whois",
        "registrar": first(w.get("registrar")),
        "created": iso(w.get("creation_date")),
        "updated": iso(w.get("updated_date")),
        "expires": iso(w.get("expiration_date")),
        "owner": first(w.get("org")) or first(w.get("name")),
        "name_servers": sorted({str(n).rstrip(".").lower() for n in ns if n}),
    }


async def lookup_whois(domain: str, client: Optional[httpx.AsyncClient] = None) -> Dict:
    """RDAP first, python-whois as a fallback for TLDs RDAP does not cover."""
    owns_client = client is None
    client = client or httpx.AsyncClient()
    try:
        rdap = await _lookup_rdap(domain, client)
        if rdap is not None:
            return rdap
        return await asyncio.to_thread(_lookup_whois_sync, domain)
    finally:
        if owns_client:
            await client.aclose()
